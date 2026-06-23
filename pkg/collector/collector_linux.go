// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

//go:build linux

package collector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/jfut/prec/pkg/config"
	"github.com/jfut/prec/pkg/events"
	"github.com/jfut/prec/pkg/filter"
	"github.com/jfut/prec/pkg/logger"
)

const (
	schedExecSubsystem     = "sched"
	schedExecEvent         = "sched_process_exec"
	schedExitEvent         = "sched_process_exit"
	syscallsSubsystem      = "syscalls"
	sysEnterExitEvent      = "sys_enter_exit"
	sysEnterExitGroupEvent = "sys_enter_exit_group"
	sysEnterExecveEvent    = "sys_enter_execve"
	sysEnterExecveatEvent  = "sys_enter_execveat"
	sysExitExecveEvent     = "sys_exit_execve"
	sysExitExecveatEvent   = "sys_exit_execveat"

	schedExecFilenameField = "filename"
	sysExitCodeField       = "error_code"
	sysRetField            = "ret"
	sysFilenameField       = "filename"

	execFilenameMaxBytes = 256

	perfEventTypeExec        = 1
	perfEventTypeExitGroup   = 2
	perfEventTypeProcessExit = 3
	perfEventTypeExitStatus  = 4
	perfEventTypeExecEnter   = 5
	perfEventTypeExecResult  = 6

	perfSampleSize            = 32 + execFilenameMaxBytes
	perfSampleStackStart      = -perfSampleSize
	perfSampleTypeOffset      = 0
	perfSamplePidTgidOffset   = 8
	perfSampleStatusOffset    = 16
	perfSampleKtimeOffset     = 24
	perfSampleFilenameOffset  = 32
	perfSampleFilenameOnStack = perfSampleStackStart + perfSampleFilenameOffset
	perfSampleKtimeOnStack    = perfSampleStackStart + perfSampleKtimeOffset
)

const (
	kernelTimeRefreshInterval = 1024
	buildFromPIDMaxAttempts   = 3
	buildFromPIDRetryDelay    = 2 * time.Millisecond
)

type execAttempt struct {
	tgid      int
	filename  string
	timestamp uint64
}

// Service handles eBPF event collection and JSONL writing.
type Service struct {
	cfg     config.Config
	matcher filter.Matcher
	writer  *logger.JSONLWriter

	mu               sync.Mutex
	pendingEvents    map[int]events.CommandEvent
	pendingStatuses  map[int]int
	pendingStartMono map[int]uint64
	pendingExecve    map[int]execAttempt
	lostTotal        uint64
	eventSeq         uint64
	eventIDPrefix    string
	timeConverter    *kernelTimeConverter
}

type kernelTimeConverter struct {
	mu         sync.RWMutex
	offsetNS   int64
	convCount  uint64
	lastUpdate time.Time
}

func newKernelTimeConverter() (*kernelTimeConverter, error) {
	c := &kernelTimeConverter{}
	if err := c.refresh(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *kernelTimeConverter) format(kernelMonoNS uint64) string {
	if kernelMonoNS == 0 {
		return ""
	}
	count := atomic.AddUint64(&c.convCount, 1)
	if count%kernelTimeRefreshInterval == 0 {
		_ = c.refresh()
	}

	c.mu.RLock()
	offsetNS := c.offsetNS
	c.mu.RUnlock()

	wallNS := saturatingAddInt64(offsetNS, kernelMonoNS)
	return time.Unix(0, wallNS).In(time.Local).Format(time.RFC3339Nano)
}

func (c *kernelTimeConverter) refresh() error {
	var realTS unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &realTS); err != nil {
		return err
	}
	var monoTS unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &monoTS); err != nil {
		return err
	}

	offset := unix.TimespecToNsec(realTS) - unix.TimespecToNsec(monoTS)
	c.mu.Lock()
	c.offsetNS = offset
	c.lastUpdate = time.Now()
	c.mu.Unlock()
	return nil
}

func saturatingAddInt64(left int64, right uint64) int64 {
	const maxInt64 = int64(1<<63 - 1)
	if right > uint64(maxInt64) {
		return maxInt64
	}
	add := int64(right)
	if add > 0 && left > maxInt64-add {
		return maxInt64
	}
	return left + add
}

func NewService(cfg config.Config, writer *logger.JSONLWriter) (*Service, error) {
	matcher, err := filter.NewMatcher(cfg)
	if err != nil {
		return nil, fmt.Errorf("init matcher: %w", err)
	}

	return &Service{
		cfg:     cfg,
		matcher: matcher,
		writer:  writer,
		// Keep start event details until the process exits so end records can be emitted.
		pendingEvents:    make(map[int]events.CommandEvent),
		pendingStatuses:  make(map[int]int),
		pendingStartMono: make(map[int]uint64),
		pendingExecve:    make(map[int]execAttempt),
	}, nil
}

func (s *Service) initEventIDSeed() error {
	if s.eventIDPrefix == "" {
		s.eventIDPrefix = newEventIDPrefix()
	}
	return nil
}

func newEventIDPrefix() string {
	// Freeze event_id prefix at precd start time so IDs are compact and human-readable.
	return time.Now().In(time.Local).Format("20060102150405")
}

func (s *Service) nextEventID() string {
	seq := atomic.AddUint64(&s.eventSeq, 1)
	return fmt.Sprintf("%s-%d", s.eventIDPrefix, seq)
}

func (s *Service) Run(stop <-chan struct{}) error {
	if err := s.initEventIDSeed(); err != nil {
		return fmt.Errorf("init event id seed: %w", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	eventsMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "prec_events",
		Type:       ebpf.PerfEventArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: uint32(runtime.NumCPU()),
	})
	if err != nil {
		return fmt.Errorf("create perf event map: %w", err)
	}
	defer eventsMap.Close()

	filenameDataLocOffset, err := tracepointFieldOffset(schedExecSubsystem, schedExecEvent, schedExecFilenameField)
	if err != nil {
		return fmt.Errorf("resolve sched_process_exec filename offset: %w", err)
	}

	execProgSpec := &ebpf.ProgramSpec{
		Name:    "prec_exec_trace",
		Type:    ebpf.TracePoint,
		License: "GPL",
		// Extract pid_tgid and filename from the tracepoint, then emit to the perf ring.
		Instructions: buildExecTraceInstructions(eventsMap.FD(), filenameDataLocOffset),
	}

	execProg, err := ebpf.NewProgram(execProgSpec)
	if err != nil {
		return fmt.Errorf("load sched_process_exec ebpf program: %w", err)
	}
	defer execProg.Close()

	execTP, err := link.Tracepoint(schedExecSubsystem, schedExecEvent, execProg, nil)
	if err != nil {
		return fmt.Errorf("attach sched_process_exec tracepoint: %w", err)
	}
	defer execTP.Close()

	processExitProgSpec := &ebpf.ProgramSpec{
		Name:    "prec_process_exit_trace",
		Type:    ebpf.TracePoint,
		License: "GPL",
		// Emit pid_tgid when a task exits so userspace can flush the cached exec event.
		Instructions: buildProcessExitTraceInstructions(eventsMap.FD()),
	}
	processExitProg, err := ebpf.NewProgram(processExitProgSpec)
	if err != nil {
		return fmt.Errorf("load sched_process_exit ebpf program: %w", err)
	}
	defer processExitProg.Close()

	processExitTP, err := link.Tracepoint(schedExecSubsystem, schedExitEvent, processExitProg, nil)
	if err != nil {
		return fmt.Errorf("attach sched_process_exit tracepoint: %w", err)
	}
	defer processExitTP.Close()

	type statusSource struct {
		event     string
		eventType int
	}
	statusSources := []statusSource{
		{event: sysEnterExitGroupEvent, eventType: perfEventTypeExitGroup},
		{event: sysEnterExitEvent, eventType: perfEventTypeExitStatus},
	}
	statusTPCount := 0
	for _, src := range statusSources {
		exitCodeOffset, exitCodeSize, err := tracepointFieldOffsetAndSize(syscallsSubsystem, src.event, sysExitCodeField)
		if err != nil {
			continue
		}

		statusProgSpec := &ebpf.ProgramSpec{
			Name:    "prec_exit_status_trace_" + src.event,
			Type:    ebpf.TracePoint,
			License: "GPL",
			// Capture the user-provided exit code from exit(2)/exit_group(2) entry.
			Instructions: buildExitStatusTraceInstructions(eventsMap.FD(), exitCodeOffset, exitCodeSize, src.eventType),
		}
		statusProg, err := ebpf.NewProgram(statusProgSpec)
		if err != nil {
			return fmt.Errorf("load %s ebpf program: %w", src.event, err)
		}
		defer statusProg.Close()

		statusTP, err := link.Tracepoint(syscallsSubsystem, src.event, statusProg, nil)
		if err != nil {
			return fmt.Errorf("attach %s tracepoint: %w", src.event, err)
		}
		defer statusTP.Close()
		statusTPCount++
	}
	if statusTPCount == 0 {
		return errors.New("attach exit status tracepoints: no usable sys_enter_exit* tracepoint found")
	}

	timeConverter, err := newKernelTimeConverter()
	if err != nil {
		return fmt.Errorf("init kernel timestamp converter: %w", err)
	}
	s.timeConverter = timeConverter

	enterEvents := []string{sysEnterExecveEvent, sysEnterExecveatEvent}
	enterTPCount := 0
	for _, enterEvent := range enterEvents {
		filenameOffset, filenameSize, err := tracepointFieldOffsetAndSize(syscallsSubsystem, enterEvent, sysFilenameField)
		if err != nil {
			continue
		}

		enterProgSpec := &ebpf.ProgramSpec{
			Name:    "prec_exec_enter_trace_" + enterEvent,
			Type:    ebpf.TracePoint,
			License: "GPL",
			// Cache syscall filename by thread so userspace can report failed exec attempts.
			Instructions: buildExecEnterTraceInstructions(eventsMap.FD(), filenameOffset, filenameSize),
		}
		enterProg, err := ebpf.NewProgram(enterProgSpec)
		if err != nil {
			return fmt.Errorf("load %s ebpf program: %w", enterEvent, err)
		}
		defer enterProg.Close()

		enterTP, err := link.Tracepoint(syscallsSubsystem, enterEvent, enterProg, nil)
		if err != nil {
			return fmt.Errorf("attach %s tracepoint: %w", enterEvent, err)
		}
		defer enterTP.Close()
		enterTPCount++
	}
	if enterTPCount == 0 {
		return errors.New("attach exec enter tracepoints: no usable sys_enter_execve* tracepoint found")
	}

	exitEvents := []string{sysExitExecveEvent, sysExitExecveatEvent}
	exitTPCount := 0
	for _, exitEvent := range exitEvents {
		retOffset, retSize, err := tracepointFieldOffsetAndSize(syscallsSubsystem, exitEvent, sysRetField)
		if err != nil {
			continue
		}

		exitProgSpec := &ebpf.ProgramSpec{
			Name:    "prec_exec_result_trace_" + exitEvent,
			Type:    ebpf.TracePoint,
			License: "GPL",
			// Capture syscall return values and keep only failed exec attempts in userspace.
			Instructions: buildExecResultTraceInstructions(eventsMap.FD(), retOffset, retSize),
		}
		exitProg, err := ebpf.NewProgram(exitProgSpec)
		if err != nil {
			return fmt.Errorf("load %s ebpf program: %w", exitEvent, err)
		}
		defer exitProg.Close()

		exitTP, err := link.Tracepoint(syscallsSubsystem, exitEvent, exitProg, nil)
		if err != nil {
			return fmt.Errorf("attach %s tracepoint: %w", exitEvent, err)
		}
		defer exitTP.Close()
		exitTPCount++
	}
	if exitTPCount == 0 {
		return errors.New("attach exec result tracepoints: no usable sys_exit_execve* tracepoint found")
	}

	rd, err := perf.NewReader(eventsMap, os.Getpagesize()*8)
	if err != nil {
		return fmt.Errorf("open perf reader: %w", err)
	}
	defer rd.Close()

	go func() {
		<-stop
		_ = rd.Close()
	}()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read perf event: %w", err)
		}
		if rec.LostSamples > 0 {
			if err := s.handleLostSamples(rec.LostSamples); err != nil {
				return err
			}
			continue
		}
		evType, tgid, tid, rawStatus, kernelMonoNS, exeHint, ok := parsePerfSample(rec.RawSample)
		if !ok {
			continue
		}
		timestamp := ""
		if s.timeConverter != nil {
			timestamp = s.timeConverter.format(kernelMonoNS)
		}

		switch evType {
		case perfEventTypeExec:
			eventID := s.nextEventID()
			ev, err := s.buildStartEventWithRetry(tgid, exeHint, timestamp, eventID)
			if err != nil {
				continue
			}
			if !s.matcher.Match(ev) {
				continue
			}
			if err := s.writer.WriteEvent(ev); err != nil {
				return fmt.Errorf("write command start event: %w", err)
			}
			s.rememberExecEvent(tgid, ev, kernelMonoNS)
		case perfEventTypeExecEnter:
			s.rememberExecAttempt(tid, tgid, exeHint, kernelMonoNS)
		case perfEventTypeExecResult:
			if rawStatus >= 0 {
				s.dropExecAttempt(tid)
				continue
			}
			execErrno := -rawStatus
			ev, ok, err := s.buildExecFailureEvent(tid, int(execErrno), timestamp)
			if err != nil {
				continue
			}
			if !ok {
				continue
			}
			if !s.matcher.Match(ev) {
				continue
			}
			if err := s.writer.WriteEvent(ev); err != nil {
				return fmt.Errorf("write exec failure event: %w", err)
			}
		case perfEventTypeExitGroup:
			s.rememberExitStatus(tgid, int(rawStatus), true)
		case perfEventTypeExitStatus:
			s.rememberExitStatus(tgid, int(rawStatus), false)
		case perfEventTypeProcessExit:
			// sched_process_exit is emitted per-thread. Finalize only when the thread-group leader exits.
			if tid != tgid {
				continue
			}
			s.dropExecAttemptsByTGID(tgid)
			startEvent, status, startMonoNS, ok := s.finalizeEvent(tgid)
			if !ok {
				continue
			}
			durationNS := computeDurationNS(startMonoNS, kernelMonoNS)
			endEvent := events.BuildCommandEndEvent(startEvent, timestamp, durationNS, status)
			if err := s.writer.WriteEvent(endEvent); err != nil {
				return fmt.Errorf("write command end event: %w", err)
			}
		}
	}
}

func (s *Service) buildStartEventWithRetry(tgid int, exeHint string, timestamp string, eventID string) (events.CommandEvent, error) {
	return buildFromPIDWithRetry(buildFromPIDMaxAttempts, buildFromPIDRetryDelay, func() (events.CommandEvent, error) {
		return events.BuildFromPID(tgid, s.cfg.MaxArgs, s.cfg.MaxArgLength, exeHint, timestamp, eventID)
	})
}

func buildFromPIDWithRetry(maxAttempts int, retryDelay time.Duration, builder func() (events.CommandEvent, error)) (events.CommandEvent, error) {
	// Retry /proc snapshot reads because very short-lived processes can disappear
	// right after sched_process_exec on slower environments such as arm64 hosts.
	if maxAttempts <= 0 {
		maxAttempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		ev, err := builder()
		if err == nil {
			return ev, nil
		}
		lastErr = err
		if attempt+1 < maxAttempts && retryDelay > 0 {
			time.Sleep(retryDelay)
		}
	}
	return events.CommandEvent{}, lastErr
}

func (s *Service) handleLostSamples(lost uint64) error {
	total := atomic.AddUint64(&s.lostTotal, lost)
	action := s.cfg.LostSamplesAction
	if action == "" {
		action = config.LostSamplesActionLog
	}
	if action == config.LostSamplesActionIgnore {
		return nil
	}

	lossEvent := events.BuildCollectorLossEvent(lost, total)
	if err := s.writer.WriteEvent(lossEvent); err != nil {
		return fmt.Errorf("write lost-samples event: %w", err)
	}
	if action == config.LostSamplesActionStop {
		return fmt.Errorf("lost perf samples detected: dropped=%d total=%d", lost, total)
	}
	return nil
}

func buildExecTraceInstructions(eventsMapFD int, filenameDataLocOffset int16) asm.Instructions {
	instructions := asm.Instructions{
		// Save tracepoint context in R6 for reuse across helper calls.
		asm.Mov.Reg(asm.R6, asm.R1),
	}
	instructions = append(instructions, buildPerfSampleStackZeroInstructions()...)
	instructions = append(instructions,
		// Mark this sample as an exec event.
		asm.Mov.Imm(asm.R0, perfEventTypeExec),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleTypeOffset, asm.R0, asm.Byte),

		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSamplePidTgidOffset, asm.R0, asm.DWord),

		// Use kernel monotonic time for event ordering and wall-clock conversion in userspace.
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleKtimeOffset, asm.R0, asm.DWord),

		// Decode __data_loc filename and build a pointer to the actual string.
		asm.LoadMem(asm.R7, asm.R6, filenameDataLocOffset, asm.Word),
		asm.And.Imm(asm.R7, 0xffff),
		asm.Mov.Reg(asm.R8, asm.R6),
		asm.Add.Reg(asm.R8, asm.R7),

		// Copy the kernel string into record.filename.
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, perfSampleFilenameOnStack),
		asm.Mov.Imm(asm.R2, execFilenameMaxBytes),
		asm.Mov.Reg(asm.R3, asm.R8),
		asm.FnProbeReadKernelStr.Call(),

		// Emit type + pid_tgid + filename together as a perf event sample.
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.LoadMapPtr(asm.R2, eventsMapFD),
		asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
		asm.Mov.Reg(asm.R4, asm.RFP),
		asm.Add.Imm(asm.R4, perfSampleStackStart),
		asm.Mov.Imm(asm.R5, perfSampleSize),
		asm.FnPerfEventOutput.Call(),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	)
	return instructions
}

func buildExitStatusTraceInstructions(eventsMapFD int, exitCodeOffset int16, exitCodeSize asm.Size, eventType int) asm.Instructions {
	instructions := asm.Instructions{
		// Save tracepoint context in R6 for reuse across helper calls.
		asm.Mov.Reg(asm.R6, asm.R1),
	}
	instructions = append(instructions, buildPerfSampleStackZeroInstructions()...)
	instructions = append(instructions,
		// Mark this sample as an exit-status event.
		asm.Mov.Imm(asm.R0, int32(eventType)),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleTypeOffset, asm.R0, asm.Byte),

		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSamplePidTgidOffset, asm.R0, asm.DWord),

		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleKtimeOffset, asm.R0, asm.DWord),

		asm.LoadMem(asm.R7, asm.R6, exitCodeOffset, exitCodeSize),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleStatusOffset, asm.R7, asm.DWord),

		asm.Mov.Reg(asm.R1, asm.R6),
		asm.LoadMapPtr(asm.R2, eventsMapFD),
		asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
		asm.Mov.Reg(asm.R4, asm.RFP),
		asm.Add.Imm(asm.R4, perfSampleStackStart),
		asm.Mov.Imm(asm.R5, perfSampleSize),
		asm.FnPerfEventOutput.Call(),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	)
	return instructions
}

func buildProcessExitTraceInstructions(eventsMapFD int) asm.Instructions {
	instructions := asm.Instructions{
		// Save tracepoint context in R6 for perf_event_output helper.
		asm.Mov.Reg(asm.R6, asm.R1),
	}
	instructions = append(instructions, buildPerfSampleStackZeroInstructions()...)
	instructions = append(instructions,
		// Mark this sample as a process-exit event.
		asm.Mov.Imm(asm.R0, perfEventTypeProcessExit),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleTypeOffset, asm.R0, asm.Byte),

		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSamplePidTgidOffset, asm.R0, asm.DWord),

		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleKtimeOffset, asm.R0, asm.DWord),

		asm.Mov.Reg(asm.R1, asm.R6),
		asm.LoadMapPtr(asm.R2, eventsMapFD),
		asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
		asm.Mov.Reg(asm.R4, asm.RFP),
		asm.Add.Imm(asm.R4, perfSampleStackStart),
		asm.Mov.Imm(asm.R5, perfSampleSize),
		asm.FnPerfEventOutput.Call(),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	)
	return instructions
}

func buildExecEnterTraceInstructions(eventsMapFD int, filenameOffset int16, filenameSize asm.Size) asm.Instructions {
	instructions := asm.Instructions{
		// Save tracepoint context in R6 for reuse across helper calls.
		asm.Mov.Reg(asm.R6, asm.R1),
	}
	instructions = append(instructions, buildPerfSampleStackZeroInstructions()...)
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, perfEventTypeExecEnter),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleTypeOffset, asm.R0, asm.Byte),

		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSamplePidTgidOffset, asm.R0, asm.DWord),

		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleKtimeOffset, asm.R0, asm.DWord),

		// Read filename pointer from tracepoint args and copy the user string.
		asm.LoadMem(asm.R7, asm.R6, filenameOffset, filenameSize),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, perfSampleFilenameOnStack),
		asm.Mov.Imm(asm.R2, execFilenameMaxBytes),
		asm.Mov.Reg(asm.R3, asm.R7),
		asm.FnProbeReadUserStr.Call(),

		asm.Mov.Reg(asm.R1, asm.R6),
		asm.LoadMapPtr(asm.R2, eventsMapFD),
		asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
		asm.Mov.Reg(asm.R4, asm.RFP),
		asm.Add.Imm(asm.R4, perfSampleStackStart),
		asm.Mov.Imm(asm.R5, perfSampleSize),
		asm.FnPerfEventOutput.Call(),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	)
	return instructions
}

func buildExecResultTraceInstructions(eventsMapFD int, retOffset int16, retSize asm.Size) asm.Instructions {
	instructions := asm.Instructions{
		// Save tracepoint context in R6 for reuse across helper calls.
		asm.Mov.Reg(asm.R6, asm.R1),
	}
	instructions = append(instructions, buildPerfSampleStackZeroInstructions()...)
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, perfEventTypeExecResult),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleTypeOffset, asm.R0, asm.Byte),

		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSamplePidTgidOffset, asm.R0, asm.DWord),

		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleKtimeOffset, asm.R0, asm.DWord),

		asm.LoadMem(asm.R7, asm.R6, retOffset, retSize),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleStatusOffset, asm.R7, asm.DWord),

		asm.Mov.Reg(asm.R1, asm.R6),
		asm.LoadMapPtr(asm.R2, eventsMapFD),
		asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
		asm.Mov.Reg(asm.R4, asm.RFP),
		asm.Add.Imm(asm.R4, perfSampleStackStart),
		asm.Mov.Imm(asm.R5, perfSampleSize),
		asm.FnPerfEventOutput.Call(),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	)
	return instructions
}

func buildPerfSampleStackZeroInstructions() asm.Instructions {
	// perf_event_output may read the whole sample. Zero all bytes to avoid
	// verifier rejection due to stack padding that is not explicitly written.
	// Especially on aarch64, without this zeroing the verifier can reject with:
	// run collector: load sched_process_exec ebpf program: load program: permission denied: invalid indirect read from stack R4 off -288+1 size 288
	// The kernel log may append extra omitted lines after this message.
	instructions := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0),
	}
	for off := perfSampleStackStart; off < 0; off += 8 {
		instructions = append(instructions, asm.StoreMem(asm.RFP, int16(off), asm.R0, asm.DWord))
	}
	return instructions
}

func parsePerfSample(rawSample []byte) (eventType int, tgid int, tid int, status int64, kernelMonoNS uint64, exeHint string, ok bool) {
	if len(rawSample) < perfSampleSize {
		return 0, 0, 0, 0, 0, "", false
	}
	eventType = int(rawSample[perfSampleTypeOffset])
	pidTgid := binary.LittleEndian.Uint64(rawSample[perfSamplePidTgidOffset : perfSamplePidTgidOffset+8])
	tgid = int(uint32(pidTgid >> 32))
	tid = int(uint32(pidTgid))
	kernelMonoNS = binary.LittleEndian.Uint64(rawSample[perfSampleKtimeOffset : perfSampleKtimeOffset+8])
	if tgid <= 0 || tid <= 0 {
		return 0, 0, 0, 0, 0, "", false
	}

	switch eventType {
	case perfEventTypeExec, perfEventTypeExecEnter:
		exeHint = parseFilenameHint(rawSample)
	case perfEventTypeExitGroup, perfEventTypeExitStatus, perfEventTypeExecResult:
		status = int64(binary.LittleEndian.Uint64(rawSample[perfSampleStatusOffset : perfSampleStatusOffset+8]))
	case perfEventTypeProcessExit:
		// no extra payload
	default:
		return 0, 0, 0, 0, 0, "", false
	}
	return eventType, tgid, tid, status, kernelMonoNS, exeHint, true
}

func parseFilenameHint(rawSample []byte) string {
	if len(rawSample) <= perfSampleFilenameOffset {
		return ""
	}
	filenameBytes := rawSample[perfSampleFilenameOffset:]
	if len(filenameBytes) > execFilenameMaxBytes {
		filenameBytes = filenameBytes[:execFilenameMaxBytes]
	}
	if idx := bytesIndexByte(filenameBytes, 0); idx >= 0 {
		filenameBytes = filenameBytes[:idx]
	}
	return strings.TrimSpace(string(filenameBytes))
}

func (s *Service) rememberExecEvent(pid int, ev events.CommandEvent, kernelMonoNS uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pendingStatuses, pid)
	s.pendingEvents[pid] = ev
	s.pendingStartMono[pid] = kernelMonoNS
}

func (s *Service) rememberExecAttempt(tid int, tgid int, filename string, kernelMonoNS uint64) {
	if tid <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendingExecve[tid] = execAttempt{tgid: tgid, filename: filename, timestamp: kernelMonoNS}
}

func (s *Service) dropExecAttempt(tid int) {
	if tid <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pendingExecve, tid)
}

func (s *Service) dropExecAttemptsByTGID(tgid int) {
	if tgid <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for tid, attempt := range s.pendingExecve {
		if attempt.tgid == tgid {
			delete(s.pendingExecve, tid)
		}
	}
}

func (s *Service) buildExecFailureEvent(tid int, execErrno int, timestamp string) (events.CommandEvent, bool, error) {
	attempt, ok := s.takeExecAttempt(tid)
	if !ok {
		return events.CommandEvent{}, false, nil
	}

	if strings.TrimSpace(timestamp) == "" && s.timeConverter != nil {
		timestamp = s.timeConverter.format(attempt.timestamp)
	}
	ev, err := events.BuildExecFailureEvent(attempt.tgid, attempt.filename, execErrno, s.cfg.MaxArgLength, timestamp)
	if err != nil {
		return events.CommandEvent{}, false, err
	}
	return ev, true, nil
}

func (s *Service) takeExecAttempt(tid int) (execAttempt, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	attempt, ok := s.pendingExecve[tid]
	if !ok {
		return execAttempt{}, false
	}
	delete(s.pendingExecve, tid)
	return attempt, true
}

func (s *Service) rememberExitStatus(pid int, status int, fromExitGroup bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	normalized := normalizeExitStatus(status)
	if fromExitGroup {
		// exit_group is the process exit status source. Keep it authoritative.
		s.pendingStatuses[pid] = normalized
		return
	}
	if _, exists := s.pendingStatuses[pid]; exists {
		return
	}
	s.pendingStatuses[pid] = normalized
}

func (s *Service) finalizeEvent(pid int) (events.CommandEvent, *int, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ev, ok := s.pendingEvents[pid]
	if !ok {
		delete(s.pendingStatuses, pid)
		delete(s.pendingStartMono, pid)
		return events.CommandEvent{}, nil, 0, false
	}
	delete(s.pendingEvents, pid)
	startMonoNS := s.pendingStartMono[pid]
	delete(s.pendingStartMono, pid)

	var exitStatus *int
	if status, found := s.pendingStatuses[pid]; found {
		delete(s.pendingStatuses, pid)
		exitStatus = &status
	}
	return ev, exitStatus, startMonoNS, true
}

func computeDurationNS(startMonoNS uint64, endMonoNS uint64) int64 {
	if startMonoNS == 0 || endMonoNS < startMonoNS {
		return 0
	}
	delta := endMonoNS - startMonoNS
	if delta > uint64(1<<63-1) {
		return int64(1<<63 - 1)
	}
	return int64(delta)
}

func normalizeExitStatus(status int) int {
	// Shell-visible exit status is always the low 8 bits from exit(2)/exit_group(2).
	return status & 0xff
}

func tracepointFieldOffset(subsystem string, event string, fieldNeedle string) (int16, error) {
	offset, _, err := tracepointFieldOffsetAndSize(subsystem, event, fieldNeedle)
	return offset, err
}

func tracepointFieldOffsetAndSize(subsystem string, event string, fieldNeedle string) (int16, asm.Size, error) {
	formatPaths := []string{
		fmt.Sprintf("/sys/kernel/tracing/events/%s/%s/format", subsystem, event),
		fmt.Sprintf("/sys/kernel/debug/tracing/events/%s/%s/format", subsystem, event),
	}

	var lastErr error
	for _, path := range formatPaths {
		b, err := os.ReadFile(path)
		if err != nil {
			lastErr = err
			continue
		}
		offset, size, err := parseFieldFromFormat(string(b), fieldNeedle)
		if err != nil {
			return 0, 0, fmt.Errorf("%s: %w", path, err)
		}
		return offset, size, nil
	}
	if lastErr != nil {
		return 0, 0, lastErr
	}
	return 0, 0, errors.New("tracepoint format not found")
}

func parseOffsetFromFormat(formatText string, fieldNeedle string) (int16, error) {
	offset, _, err := parseFieldFromFormat(formatText, fieldNeedle)
	return offset, err
}

func parseFieldFromFormat(formatText string, fieldNeedle string) (int16, asm.Size, error) {
	for _, line := range strings.Split(formatText, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "field:") || !strings.Contains(line, fieldNeedle) {
			continue
		}
		i := strings.Index(line, "offset:")
		if i < 0 {
			return 0, 0, fmt.Errorf("offset not found in line: %s", line)
		}
		v := line[i+len("offset:"):]
		j := strings.Index(v, ";")
		if j < 0 {
			return 0, 0, fmt.Errorf("offset terminator not found in line: %s", line)
		}
		n, err := strconv.ParseInt(strings.TrimSpace(v[:j]), 10, 16)
		if err != nil {
			return 0, 0, fmt.Errorf("parse offset: %w", err)
		}

		sizePos := strings.Index(line, "size:")
		if sizePos < 0 {
			return 0, 0, fmt.Errorf("size not found in line: %s", line)
		}
		sizeRaw := line[sizePos+len("size:"):]
		sizeEnd := strings.Index(sizeRaw, ";")
		if sizeEnd < 0 {
			return 0, 0, fmt.Errorf("size terminator not found in line: %s", line)
		}
		sizeValue, err := strconv.ParseInt(strings.TrimSpace(sizeRaw[:sizeEnd]), 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("parse size: %w", err)
		}
		switch sizeValue {
		case 1:
			return int16(n), asm.Byte, nil
		case 2:
			return int16(n), asm.Half, nil
		case 4:
			return int16(n), asm.Word, nil
		case 8:
			return int16(n), asm.DWord, nil
		default:
			return 0, 0, fmt.Errorf("unsupported field size: %d", sizeValue)
		}
	}
	return 0, 0, fmt.Errorf("field not found: %s", fieldNeedle)
}

func bytesIndexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}
