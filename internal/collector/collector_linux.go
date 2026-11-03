// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

//go:build linux

package collector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/jfut/prec/internal/config"
	"github.com/jfut/prec/internal/events"
	"github.com/jfut/prec/internal/filter"
	"github.com/jfut/prec/internal/logger"
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
	sysEnterOpenAtEvent    = "sys_enter_openat"
	sysExitOpenAtEvent     = "sys_exit_openat"
	sysEnterDup2Event      = "sys_enter_dup2"
	sysExitDup2Event       = "sys_exit_dup2"
	sysEnterDup3Event      = "sys_enter_dup3"
	sysExitDup3Event       = "sys_exit_dup3"
	sysEnterWriteEvent     = "sys_enter_write"
	sysExitWriteEvent      = "sys_exit_write"
	sysEnterPWrite64Event  = "sys_enter_pwrite64"
	sysExitPWrite64Event   = "sys_exit_pwrite64"
	sysEnterWriteVEvent    = "sys_enter_writev"
	sysExitWriteVEvent     = "sys_exit_writev"
	sysEnterPWriteVEvent   = "sys_enter_pwritev"
	sysExitPWriteVEvent    = "sys_exit_pwritev"
	sysEnterPWriteV2Event  = "sys_enter_pwritev2"
	sysExitPWriteV2Event   = "sys_exit_pwritev2"

	schedExecFilenameField = "filename"
	sysExitCodeField       = "error_code"
	sysRetField            = "ret"
	sysFilenameField       = "filename"
	sysFlagsField          = "flags"
	sysFDField             = "fd"
	sysDirFDField          = "dfd"

	execFilenameMaxBytes = 256

	perfEventTypeExec        = 1
	perfEventTypeExitGroup   = 2
	perfEventTypeProcessExit = 3
	perfEventTypeExitStatus  = 4
	perfEventTypeExecEnter   = 5
	perfEventTypeExecResult  = 6
	perfEventTypeOpenEnter   = 7
	perfEventTypeOpenResult  = 8
	perfEventTypeWriteEnter  = 13
	perfEventTypeWriteResult = 14
	perfEventTypeDupEnter    = 17
	perfEventTypeDupResult   = 18

	perfSampleStatus2Offset   = 32 + execFilenameMaxBytes
	perfSampleSize            = perfSampleStatus2Offset + 8
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
	perfReaderPages           = 64
	lostSamplesLogInterval    = time.Second
	fileIdentityCheckInterval = time.Second
)

type execAttempt struct {
	tgid      int
	filename  string
	timestamp uint64
}

type fileOpenAttempt struct {
	tgid      int
	filename  string
	dirfd     int
	flags     int64
	timestamp uint64
}

type ioAttempt struct {
	tgid      int
	fd        int
	timestamp uint64
}

type dupAttempt struct {
	tgid  int
	oldfd int
	newfd int
}

type fileDescriptorKey struct {
	tgid int
	fd   int
}

type openFileState struct {
	event                 events.CommandEvent
	identity              fileIdentity
	lastIdentityCheckMono uint64
}

type fileIdentity struct {
	dev   uint64
	ino   uint64
	valid bool
}

type fileSaveDedupKey struct {
	tgid int
	path string
}

var userHomeCaches atomic.Pointer[sync.Map]

func currentUserHomeCache() *sync.Map {
	if cache := userHomeCaches.Load(); cache != nil {
		return cache
	}
	userHomeCaches.CompareAndSwap(nil, new(sync.Map))
	return userHomeCaches.Load()
}

// Service handles eBPF event collection and JSONL writing.
type Service struct {
	cfg               config.Config
	matcher           filter.Matcher
	capturePolicy     capturePolicy
	captureReadOpens  bool
	writer            *logger.JSONLWriter
	buildStartEventFn func(tgid int, exeHint string, timestamp string, eventID string) (events.CommandEvent, error)

	mu               sync.Mutex
	pendingEvents    map[int]events.CommandEvent
	pendingStatuses  map[int]int
	pendingStartMono map[int]uint64
	pendingExecve    map[int]execAttempt
	pendingOpen      map[int]fileOpenAttempt
	pendingWrite     map[int]ioAttempt
	pendingDup       map[int]dupAttempt
	openFiles        map[fileDescriptorKey]openFileState
	recentFileSaves  map[fileSaveDedupKey]uint64
	lastFileSaveGC   uint64
	lostTotal        uint64
	pendingLostLog   uint64
	lastLostLogAt    time.Time
	eventSeq         uint64
	eventIDPrefix    string
	timeConverter    *kernelTimeConverter
}

type kernelTimeConverter struct {
	mu        sync.RWMutex
	offsetNS  int64
	convCount uint64
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
	capturePolicy, err := compileCaptureFilter(cfg.CaptureFilter)
	if err != nil {
		return nil, fmt.Errorf("init capture_filter: %w", err)
	}

	return &Service{
		cfg:           cfg,
		matcher:       matcher,
		capturePolicy: capturePolicy,
		// Read-only opens are enabled only with an explicit early filter to bound event volume.
		captureReadOpens: cfg.CollectFileOpen && !capturePolicy.empty(),
		writer:           writer,
		// Keep start event details until the process exits so end records can be emitted.
		pendingEvents:    make(map[int]events.CommandEvent),
		pendingStatuses:  make(map[int]int),
		pendingStartMono: make(map[int]uint64),
		pendingExecve:    make(map[int]execAttempt),
		pendingOpen:      make(map[int]fileOpenAttempt),
		pendingWrite:     make(map[int]ioAttempt),
		pendingDup:       make(map[int]dupAttempt),
		openFiles:        make(map[fileDescriptorKey]openFileState),
		recentFileSaves:  make(map[fileSaveDedupKey]uint64),
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

	identities, refresher, err := newCaptureIdentityMap(s.capturePolicy)
	if err != nil {
		return fmt.Errorf("init capture_filter identities: %w", err)
	}
	if identities != nil {
		defer func() { _ = identities.Close() }()
		s.capturePolicy.identitiesMapFD = identities.FD()
	}
	if !s.capturePolicy.empty() {
		processes, err := newCaptureProcessMap()
		if err != nil {
			return err
		}
		defer func() { _ = processes.Close() }()
		s.capturePolicy.processes = processes
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
		Instructions: buildExecTraceInstructions(eventsMap.FD(), filenameDataLocOffset, s.capturePolicy),
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
		Instructions: buildProcessExitTraceInstructions(eventsMap.FD(), s.capturePolicy),
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
			Instructions: buildExitStatusTraceInstructions(eventsMap.FD(), exitCodeOffset, exitCodeSize, src.eventType, s.capturePolicy),
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
			Instructions: buildExecEnterTraceInstructions(eventsMap.FD(), filenameOffset, filenameSize, s.capturePolicy),
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
			Instructions: buildExecResultTraceInstructions(eventsMap.FD(), retOffset, retSize, s.capturePolicy),
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

	if s.cfg.CollectFileOpen || s.cfg.CollectFileSave {
		cleanupFileTracepoints, err := s.attachFileTracepoints(eventsMap.FD())
		if err != nil {
			return err
		}
		if cleanupFileTracepoints != nil {
			defer cleanupFileTracepoints()
		}
	}

	rd, err := perf.NewReader(eventsMap, os.Getpagesize()*perfReaderPages)
	if err != nil {
		return fmt.Errorf("open perf reader: %w", err)
	}
	defer rd.Close()

	if refresher != nil {
		stopRefresh := refresher.start(stop, time.Duration(s.cfg.CaptureFilterRefreshSec)*time.Second)
		defer stopRefresh()
	}

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
		evType, tgid, tid, rawStatus, rawStatus2, kernelMonoNS, exeHint, ok := parsePerfSample(rec.RawSample)
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
		case perfEventTypeOpenEnter:
			s.rememberFileOpenAttempt(tid, tgid, exeHint, int(rawStatus2), rawStatus, kernelMonoNS)
		case perfEventTypeOpenResult:
			if rawStatus < 0 {
				s.dropFileOpenAttempt(tid)
				continue
			}
			fileOpenEvent, ok, err := s.buildFileOpenEvent(tid, int(rawStatus), timestamp)
			if err != nil {
				continue
			}
			if !ok {
				s.rememberOpenFileFallback(tgid, int(rawStatus), timestamp)
				continue
			}
			s.rememberOpenFile(tgid, int(rawStatus), fileOpenEvent)
			if !s.cfg.CollectFileOpen {
				continue
			}
			if !s.shouldRecordFileEvent(fileOpenEvent) {
				continue
			}
			if !s.matcher.Match(fileOpenEvent) {
				continue
			}
			if err := s.writer.WriteEvent(fileOpenEvent); err != nil {
				return fmt.Errorf("write file open event: %w", err)
			}
		case perfEventTypeDupEnter:
			s.rememberDupAttempt(tid, tgid, int(rawStatus), int(rawStatus2))
		case perfEventTypeDupResult:
			if rawStatus < 0 {
				s.dropDupAttempt(tid)
				continue
			}
			s.rememberDuplicatedFile(tid)
		case perfEventTypeWriteEnter:
			fd := int(rawStatus)
			if fd < 0 {
				continue
			}
			s.rememberIOAttempt(s.pendingWrite, tid, tgid, fd, kernelMonoNS)
		case perfEventTypeWriteResult:
			if rawStatus <= 0 {
				s.dropIOAttempt(s.pendingWrite, tid)
				continue
			}
			bytesWritten := rawStatus
			fileSaveEvent, ok := s.buildRegularFileSaveEvent(tid, bytesWritten, kernelMonoNS, timestamp)
			if !ok {
				continue
			}
			if !s.shouldRecordFileEvent(fileSaveEvent) {
				continue
			}
			if !s.matcher.Match(fileSaveEvent) {
				continue
			}
			if err := s.writer.WriteEvent(fileSaveEvent); err != nil {
				return fmt.Errorf("write file save event: %w", err)
			}
		case perfEventTypeExitGroup:
			s.rememberExitStatus(tgid, int(rawStatus), true)
		case perfEventTypeExitStatus:
			s.rememberExitStatus(tgid, int(rawStatus), false)
		case perfEventTypeProcessExit:
			if err := s.handleProcessExit(tgid, tid, kernelMonoNS, timestamp); err != nil {
				return err
			}
		}
	}
}

func (s *Service) handleProcessExit(tgid, tid int, kernelMonoNS uint64, timestamp string) error {
	// Exit notifications for tracked processes remain valid after an identity
	// refresh. Finalize cached starts and file state without reapplying filters.
	if tid != tgid {
		return nil
	}
	s.dropExecAttemptsByTGID(tgid)
	s.dropFileStateByTGID(tgid)
	startEvent, status, startMonoNS, ok := s.finalizeEvent(tgid)
	if !ok {
		return nil
	}
	durationNS := computeDurationNS(startMonoNS, kernelMonoNS)
	endEvent := events.BuildCommandEndEvent(startEvent, timestamp, durationNS, status)
	if err := s.writer.WriteEvent(endEvent); err != nil {
		return fmt.Errorf("write command end event: %w", err)
	}
	return nil
}

type closeFunc func()

func (s *Service) attachFileTracepoints(eventsMapFD int) (closeFunc, error) {
	type closeable interface {
		Close() error
	}
	closeables := make([]closeable, 0, 20)
	cleanup := func() {
		for i := len(closeables) - 1; i >= 0; i-- {
			_ = closeables[i].Close()
		}
	}
	fail := func(err error) (closeFunc, error) {
		cleanup()
		return nil, err
	}
	addTracepoint := func(event string, spec *ebpf.ProgramSpec) error {
		prog, err := ebpf.NewProgram(spec)
		if err != nil {
			return fmt.Errorf("load %s ebpf program: %w", event, err)
		}
		closeables = append(closeables, prog)
		tp, err := link.Tracepoint(syscallsSubsystem, event, prog, nil)
		if err != nil {
			return fmt.Errorf("attach %s tracepoint: %w", event, err)
		}
		closeables = append(closeables, tp)
		return nil
	}
	addOptionalFDIOTracepoints := func(enterEvent string, exitEvent string, enterName string, exitName string) (bool, error) {
		fdOffset, fdSize, err := tracepointFieldOffsetAndSize(syscallsSubsystem, enterEvent, sysFDField)
		if err != nil {
			return false, nil
		}
		retOffset, retSize, err := tracepointFieldOffsetAndSize(syscallsSubsystem, exitEvent, sysRetField)
		if err != nil {
			return false, nil
		}
		if err := addTracepoint(enterEvent, &ebpf.ProgramSpec{
			Name:         enterName,
			Type:         ebpf.TracePoint,
			License:      "GPL",
			Instructions: buildSimpleFDEnterTraceInstructions(eventsMapFD, perfEventTypeWriteEnter, fdOffset, fdSize, s.capturePolicy),
		}); err != nil {
			return false, err
		}
		if err := addTracepoint(exitEvent, &ebpf.ProgramSpec{
			Name:         exitName,
			Type:         ebpf.TracePoint,
			License:      "GPL",
			Instructions: buildSimpleResultTraceInstructions(eventsMapFD, perfEventTypeWriteResult, retOffset, retSize, s.capturePolicy),
		}); err != nil {
			return false, err
		}
		return true, nil
	}

	if s.cfg.CollectFileOpen || s.cfg.CollectFileSave {
		openRetOffset, openRetSize, err := tracepointFieldOffsetAndSize(syscallsSubsystem, sysExitOpenAtEvent, sysRetField)
		if err != nil {
			return fail(fmt.Errorf("attach file tracepoints: resolve %s/%s field %s: %w", syscallsSubsystem, sysExitOpenAtEvent, sysRetField, err))
		}
		if err := addTracepoint(sysExitOpenAtEvent, &ebpf.ProgramSpec{
			Name:    "prec_file_open_result_trace",
			Type:    ebpf.TracePoint,
			License: "GPL",
			// Capture openat return fd so userspace can seed fd tracking for file_open and shell redirections.
			Instructions: buildSimpleResultTraceInstructions(eventsMapFD, perfEventTypeOpenResult, openRetOffset, openRetSize, s.capturePolicy),
		}); err != nil {
			return fail(fmt.Errorf("attach file tracepoints: %w", err))
		}
	}

	if s.cfg.CollectFileOpen || s.cfg.CollectFileSave {
		dup2OldFDOffset, dup2OldFDSize, err := tracepointFieldOffsetAndSize(syscallsSubsystem, sysEnterDup2Event, "oldfd")
		if err != nil {
			return fail(fmt.Errorf("attach file tracepoints: resolve %s/%s field oldfd: %w", syscallsSubsystem, sysEnterDup2Event, err))
		}
		dup2NewFDOffset, dup2NewFDSize, err := tracepointFieldOffsetAndSize(syscallsSubsystem, sysEnterDup2Event, "newfd")
		if err != nil {
			return fail(fmt.Errorf("attach file tracepoints: resolve %s/%s field newfd: %w", syscallsSubsystem, sysEnterDup2Event, err))
		}
		if err := addTracepoint(sysEnterDup2Event, &ebpf.ProgramSpec{
			Name:         "prec_file_dup2_enter_trace",
			Type:         ebpf.TracePoint,
			License:      "GPL",
			Instructions: buildTwoFDEnterTraceInstructions(eventsMapFD, perfEventTypeDupEnter, dup2OldFDOffset, dup2OldFDSize, dup2NewFDOffset, dup2NewFDSize, s.capturePolicy),
		}); err != nil {
			return fail(fmt.Errorf("attach file tracepoints: %w", err))
		}

		dup2RetOffset, dup2RetSize, err := tracepointFieldOffsetAndSize(syscallsSubsystem, sysExitDup2Event, sysRetField)
		if err != nil {
			return fail(fmt.Errorf("attach file tracepoints: resolve %s/%s field %s: %w", syscallsSubsystem, sysExitDup2Event, sysRetField, err))
		}
		if err := addTracepoint(sysExitDup2Event, &ebpf.ProgramSpec{
			Name:         "prec_file_dup2_result_trace",
			Type:         ebpf.TracePoint,
			License:      "GPL",
			Instructions: buildSimpleResultTraceInstructions(eventsMapFD, perfEventTypeDupResult, dup2RetOffset, dup2RetSize, s.capturePolicy),
		}); err != nil {
			return fail(fmt.Errorf("attach file tracepoints: %w", err))
		}

		dup3OldFDOffset, dup3OldFDSize, err := tracepointFieldOffsetAndSize(syscallsSubsystem, sysEnterDup3Event, "oldfd")
		if err == nil {
			dup3NewFDOffset, dup3NewFDSize, err := tracepointFieldOffsetAndSize(syscallsSubsystem, sysEnterDup3Event, "newfd")
			if err == nil {
				if err := addTracepoint(sysEnterDup3Event, &ebpf.ProgramSpec{
					Name:         "prec_file_dup3_enter_trace",
					Type:         ebpf.TracePoint,
					License:      "GPL",
					Instructions: buildTwoFDEnterTraceInstructions(eventsMapFD, perfEventTypeDupEnter, dup3OldFDOffset, dup3OldFDSize, dup3NewFDOffset, dup3NewFDSize, s.capturePolicy),
				}); err != nil {
					return fail(fmt.Errorf("attach file tracepoints: %w", err))
				}
				dup3RetOffset, dup3RetSize, err := tracepointFieldOffsetAndSize(syscallsSubsystem, sysExitDup3Event, sysRetField)
				if err == nil {
					if err := addTracepoint(sysExitDup3Event, &ebpf.ProgramSpec{
						Name:         "prec_file_dup3_result_trace",
						Type:         ebpf.TracePoint,
						License:      "GPL",
						Instructions: buildSimpleResultTraceInstructions(eventsMapFD, perfEventTypeDupResult, dup3RetOffset, dup3RetSize, s.capturePolicy),
					}); err != nil {
						return fail(fmt.Errorf("attach file tracepoints: %w", err))
					}
				}
			}
		}
	}

	if s.cfg.CollectFileOpen || s.cfg.CollectFileSave {
		filenameOffset, filenameSize, err := tracepointFieldOffsetAndSize(syscallsSubsystem, sysEnterOpenAtEvent, sysFilenameField)
		if err != nil {
			return fail(fmt.Errorf("attach file tracepoints: resolve %s/%s field %s: %w", syscallsSubsystem, sysEnterOpenAtEvent, sysFilenameField, err))
		}
		dirfdOffset, dirfdSize, err := tracepointFieldOffsetAndSize(syscallsSubsystem, sysEnterOpenAtEvent, sysDirFDField)
		if err != nil {
			return fail(fmt.Errorf("attach file tracepoints: resolve %s/%s field %s: %w", syscallsSubsystem, sysEnterOpenAtEvent, sysDirFDField, err))
		}
		flagsOffset, flagsSize, err := tracepointFieldOffsetAndSize(syscallsSubsystem, sysEnterOpenAtEvent, sysFlagsField)
		if err != nil {
			return fail(fmt.Errorf("attach file tracepoints: resolve %s/%s field %s: %w", syscallsSubsystem, sysEnterOpenAtEvent, sysFlagsField, err))
		}
		if err := addTracepoint(sysEnterOpenAtEvent, &ebpf.ProgramSpec{
			Name:    "prec_file_open_enter_trace",
			Type:    ebpf.TracePoint,
			License: "GPL",
			// Keep openat args per-thread until sys_exit_openat returns the file descriptor.
			// This is also required for file_save tracking because /proc/<pid>/fd lookups are racy.
			Instructions: buildOpenEnterTraceInstructions(eventsMapFD, filenameOffset, filenameSize, dirfdOffset, dirfdSize, flagsOffset, flagsSize, s.captureReadOpens, s.capturePolicy),
		}); err != nil {
			return fail(fmt.Errorf("attach file tracepoints: %w", err))
		}
	}

	if s.cfg.CollectFileSave {
		attachedPairs := 0
		attached, err := addOptionalFDIOTracepoints(sysEnterWriteEvent, sysExitWriteEvent, "prec_file_save_enter_trace", "prec_file_save_result_trace")
		if err != nil {
			return fail(fmt.Errorf("attach file tracepoints: %w", err))
		}
		if attached {
			attachedPairs++
		}
		attached, err = addOptionalFDIOTracepoints(sysEnterPWrite64Event, sysExitPWrite64Event, "prec_file_save_pwrite64_enter_trace", "prec_file_save_pwrite64_result_trace")
		if err != nil {
			return fail(fmt.Errorf("attach file tracepoints: %w", err))
		}
		if attached {
			attachedPairs++
		}
		attached, err = addOptionalFDIOTracepoints(sysEnterWriteVEvent, sysExitWriteVEvent, "prec_file_save_writev_enter_trace", "prec_file_save_writev_result_trace")
		if err != nil {
			return fail(fmt.Errorf("attach file tracepoints: %w", err))
		}
		if attached {
			attachedPairs++
		}
		attached, err = addOptionalFDIOTracepoints(sysEnterPWriteVEvent, sysExitPWriteVEvent, "prec_file_save_pwritev_enter_trace", "prec_file_save_pwritev_result_trace")
		if err != nil {
			return fail(fmt.Errorf("attach file tracepoints: %w", err))
		}
		if attached {
			attachedPairs++
		}
		attached, err = addOptionalFDIOTracepoints(sysEnterPWriteV2Event, sysExitPWriteV2Event, "prec_file_save_pwritev2_enter_trace", "prec_file_save_pwritev2_result_trace")
		if err != nil {
			return fail(fmt.Errorf("attach file tracepoints: %w", err))
		}
		if attached {
			attachedPairs++
		}
		if attachedPairs == 0 {
			return fail(errors.New("attach file tracepoints: no usable write-family syscall tracepoint found"))
		}
	}

	return cleanup, nil
}

func (s *Service) buildStartEventWithRetry(tgid int, exeHint string, timestamp string, eventID string) (events.CommandEvent, error) {
	if s.buildStartEventFn != nil {
		return s.buildStartEventFn(tgid, exeHint, timestamp, eventID)
	}
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

	lossValue, shouldLog := s.consumeLostSamplesForLog(lost)
	if !shouldLog {
		if action == config.LostSamplesActionStop {
			return fmt.Errorf("lost perf samples detected: dropped=%d total=%d", lost, total)
		}
		return nil
	}

	lossEvent := events.BuildCollectorLossEvent(lossValue, total)
	// Give loss markers an event ID so downstream consumers can place gaps in the same timeline.
	lossEvent.EventID = s.nextEventID()
	if err := s.writer.WriteEvent(lossEvent); err != nil {
		return fmt.Errorf("write lost-samples event: %w", err)
	}
	if action == config.LostSamplesActionStop {
		return fmt.Errorf("lost perf samples detected: dropped=%d total=%d", lost, total)
	}
	return nil
}

func (s *Service) consumeLostSamplesForLog(lost uint64) (uint64, bool) {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.pendingLostLog += lost
	if !s.lastLostLogAt.IsZero() && now.Sub(s.lastLostLogAt) < lostSamplesLogInterval {
		return 0, false
	}

	value := s.pendingLostLog
	s.pendingLostLog = 0
	s.lastLostLogAt = now
	return value, true
}

func buildExecTraceInstructions(eventsMapFD int, filenameDataLocOffset int16, policy capturePolicy) asm.Instructions {
	instructions := startCaptureTraceInstructions(policy)
	instructions = appendCaptureTraceBody(instructions, buildPerfSampleStackZeroInstructions(), policy)
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

func buildExitStatusTraceInstructions(eventsMapFD int, exitCodeOffset int16, exitCodeSize asm.Size, eventType int, policy capturePolicy) asm.Instructions {
	instructions := startCaptureExitInstructions(policy, false)
	instructions = appendCaptureExitBody(instructions, buildPerfSampleStackZeroInstructions(), policy)
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

func buildProcessExitTraceInstructions(eventsMapFD int, policy capturePolicy) asm.Instructions {
	instructions := startCaptureExitInstructions(policy, true)
	instructions = appendCaptureExitBody(instructions, buildPerfSampleStackZeroInstructions(), policy)
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

func buildExecEnterTraceInstructions(eventsMapFD int, filenameOffset int16, filenameSize asm.Size, policy capturePolicy) asm.Instructions {
	instructions := startCaptureTraceInstructions(policy)
	instructions = appendCaptureTraceBody(instructions, buildPerfSampleStackZeroInstructions(), policy)
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

func buildExecResultTraceInstructions(eventsMapFD int, retOffset int16, retSize asm.Size, policy capturePolicy) asm.Instructions {
	instructions := startCaptureTraceInstructions(policy)
	instructions = appendCaptureTraceBody(instructions, buildPerfSampleStackZeroInstructions(), policy)
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

func buildOpenEnterTraceInstructions(eventsMapFD int, filenameOffset int16, filenameSize asm.Size, dirfdOffset int16, dirfdSize asm.Size, flagsOffset int16, flagsSize asm.Size, captureReadOpens bool, policy capturePolicy) asm.Instructions {
	const trackedOpenMask = unix.O_ACCMODE | unix.O_CREAT | unix.O_TRUNC | unix.O_APPEND | unix.O_EXCL

	instructions := startCaptureTraceInstructions(policy)
	instructions = appendCaptureTraceBody(instructions, buildPerfSampleStackZeroInstructions(), policy)
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, perfEventTypeOpenEnter),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleTypeOffset, asm.R0, asm.Byte),

		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSamplePidTgidOffset, asm.R0, asm.DWord),

		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleKtimeOffset, asm.R0, asm.DWord),
	)
	if !captureReadOpens {
		instructions = append(instructions,
			// Drop read-only opens in-kernel unless an explicit early filter bounds their volume.
			asm.LoadMem(asm.R7, asm.R6, flagsOffset, flagsSize),
			asm.Mov.Reg(asm.R8, asm.R7),
			asm.And.Imm(asm.R8, trackedOpenMask),
			asm.JEq.Imm(asm.R8, 0, "skip_open_enter"),
		)
	}
	instructions = append(instructions,
		// Read filename pointer from tracepoint args and copy the user string.
		asm.LoadMem(asm.R7, asm.R6, filenameOffset, filenameSize),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, perfSampleFilenameOnStack),
		asm.Mov.Imm(asm.R2, execFilenameMaxBytes),
		asm.Mov.Reg(asm.R3, asm.R7),
		asm.FnProbeReadUserStr.Call(),

		// Preserve open flags in status payload for userspace create detection.
		asm.LoadMem(asm.R7, asm.R6, flagsOffset, flagsSize),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleStatusOffset, asm.R7, asm.DWord),

		// Preserve dirfd in status2 so userspace can resolve relative openat targets.
		asm.LoadMem(asm.R7, asm.R6, dirfdOffset, dirfdSize),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleStatus2Offset, asm.R7, asm.DWord),

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
	if !captureReadOpens {
		instructions = append(instructions,
			asm.Mov.Imm(asm.R0, 0).WithSymbol("skip_open_enter"),
			asm.Return(),
		)
	}
	return instructions
}

func buildSimpleFDEnterTraceInstructions(eventsMapFD int, eventType int, fdOffset int16, fdSize asm.Size, policy capturePolicy) asm.Instructions {
	instructions := startCaptureTraceInstructions(policy)
	instructions = appendCaptureTraceBody(instructions, buildPerfSampleStackZeroInstructions(), policy)
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, int32(eventType)),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleTypeOffset, asm.R0, asm.Byte),

		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSamplePidTgidOffset, asm.R0, asm.DWord),

		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleKtimeOffset, asm.R0, asm.DWord),

		asm.LoadMem(asm.R7, asm.R6, fdOffset, fdSize),
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

func buildTwoFDEnterTraceInstructions(eventsMapFD int, eventType int, firstFDOffset int16, firstFDSize asm.Size, secondFDOffset int16, secondFDSize asm.Size, policy capturePolicy) asm.Instructions {
	instructions := startCaptureTraceInstructions(policy)
	instructions = appendCaptureTraceBody(instructions, buildPerfSampleStackZeroInstructions(), policy)
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, int32(eventType)),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleTypeOffset, asm.R0, asm.Byte),

		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSamplePidTgidOffset, asm.R0, asm.DWord),

		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleKtimeOffset, asm.R0, asm.DWord),

		asm.LoadMem(asm.R7, asm.R6, firstFDOffset, firstFDSize),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleStatusOffset, asm.R7, asm.DWord),

		asm.LoadMem(asm.R7, asm.R6, secondFDOffset, secondFDSize),
		asm.StoreMem(asm.RFP, perfSampleStackStart+perfSampleStatus2Offset, asm.R7, asm.DWord),

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

func buildSimpleResultTraceInstructions(eventsMapFD int, eventType int, retOffset int16, retSize asm.Size, policy capturePolicy) asm.Instructions {
	instructions := startCaptureTraceInstructions(policy)
	instructions = appendCaptureTraceBody(instructions, buildPerfSampleStackZeroInstructions(), policy)
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, int32(eventType)),
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

func parsePerfSample(rawSample []byte) (eventType int, tgid int, tid int, status int64, status2 int64, kernelMonoNS uint64, exeHint string, ok bool) {
	if len(rawSample) < perfSampleSize {
		return 0, 0, 0, 0, 0, 0, "", false
	}
	eventType = int(rawSample[perfSampleTypeOffset])
	pidTgid := binary.LittleEndian.Uint64(rawSample[perfSamplePidTgidOffset : perfSamplePidTgidOffset+8])
	tgid = int(uint32(pidTgid >> 32))
	tid = int(uint32(pidTgid))
	kernelMonoNS = binary.LittleEndian.Uint64(rawSample[perfSampleKtimeOffset : perfSampleKtimeOffset+8])
	if tgid <= 0 || tid <= 0 {
		return 0, 0, 0, 0, 0, 0, "", false
	}

	switch eventType {
	case perfEventTypeExec, perfEventTypeExecEnter:
		exeHint = parseFilenameHint(rawSample)
	case perfEventTypeOpenEnter:
		exeHint = parseFilenameHint(rawSample)
		status = parsePerfSampleInt64(rawSample, perfSampleStatusOffset)
		status2 = parsePerfSampleInt64(rawSample, perfSampleStatus2Offset)
	case perfEventTypeDupEnter:
		status = parsePerfSampleInt64(rawSample, perfSampleStatusOffset)
		status2 = parsePerfSampleInt64(rawSample, perfSampleStatus2Offset)
	case perfEventTypeExitGroup,
		perfEventTypeExitStatus,
		perfEventTypeExecResult,
		perfEventTypeOpenResult,
		perfEventTypeDupResult,
		perfEventTypeWriteEnter,
		perfEventTypeWriteResult:
		status = parsePerfSampleInt64(rawSample, perfSampleStatusOffset)
	case perfEventTypeProcessExit:
		// no extra payload
	default:
		return 0, 0, 0, 0, 0, 0, "", false
	}
	return eventType, tgid, tid, status, status2, kernelMonoNS, exeHint, true
}

func parsePerfSampleInt64(rawSample []byte, offset int) int64 {
	v := binary.LittleEndian.Uint64(rawSample[offset : offset+8])
	if v <= uint64(^uint32(0)) && v&uint64(1<<31) != 0 {
		return int64(int32(uint32(v)))
	}
	return int64(v)
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

func (s *Service) rememberFileOpenAttempt(tid int, tgid int, filename string, dirfd int, flags int64, kernelMonoNS uint64) {
	if tid <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendingOpen[tid] = fileOpenAttempt{
		tgid:      tgid,
		filename:  filename,
		dirfd:     dirfd,
		flags:     flags,
		timestamp: kernelMonoNS,
	}
}

func (s *Service) takeFileOpenAttempt(tid int) (fileOpenAttempt, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	attempt, ok := s.pendingOpen[tid]
	if !ok {
		return fileOpenAttempt{}, false
	}
	delete(s.pendingOpen, tid)
	return attempt, true
}

func (s *Service) dropFileOpenAttempt(tid int) {
	if tid <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pendingOpen, tid)
}

func (s *Service) rememberDupAttempt(tid int, tgid int, oldfd int, newfd int) {
	if tid <= 0 || oldfd < 0 || newfd < 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendingDup[tid] = dupAttempt{tgid: tgid, oldfd: oldfd, newfd: newfd}
}

func (s *Service) takeDupAttempt(tid int) (dupAttempt, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	attempt, ok := s.pendingDup[tid]
	if !ok {
		return dupAttempt{}, false
	}
	delete(s.pendingDup, tid)
	return attempt, true
}

func (s *Service) dropDupAttempt(tid int) {
	if tid <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pendingDup, tid)
}

func (s *Service) rememberDuplicatedFile(tid int) {
	attempt, ok := s.takeDupAttempt(tid)
	if !ok {
		debugFileEventf("dup-result tid=%d dropped: no pending dup attempt", tid)
		return
	}
	if attempt.tgid <= 0 || attempt.oldfd < 0 || attempt.newfd < 0 {
		return
	}
	oldKey := fileDescriptorKey{tgid: attempt.tgid, fd: attempt.oldfd}
	newKey := fileDescriptorKey{tgid: attempt.tgid, fd: attempt.newfd}

	s.mu.Lock()
	openState, ok := s.openFiles[oldKey]
	s.mu.Unlock()
	if !ok {
		path, pathOK := resolveRegularFilePath(attempt.tgid, attempt.oldfd)
		if !pathOK {
			debugFileEventf("dup-result tid=%d oldfd=%d newfd=%d dropped: old fd not tracked", tid, attempt.oldfd, attempt.newfd)
			return
		}
		identity, _ := resolveRegularFileIdentity(attempt.tgid, attempt.oldfd)
		base, err := s.buildFileBaseEvent(attempt.tgid, "")
		if err != nil {
			debugFileEventf("dup-result tid=%d oldfd=%d newfd=%d dropped: build file base event: %v", tid, attempt.oldfd, attempt.newfd, err)
			return
		}
		openEvent := events.BuildFileOpenEvent(base, path, attempt.oldfd, 0)
		setFileIdentity(&openEvent, identity)
		openState = openFileState{event: openEvent, identity: identity}
	}
	s.mu.Lock()
	s.openFiles[newKey] = openState
	s.mu.Unlock()
	debugFileEventf("dup-result tid=%d tracked oldfd=%d newfd=%d path=%s", tid, attempt.oldfd, attempt.newfd, openState.event.FilePath)
}

func (s *Service) buildFileOpenEvent(tid int, fd int, timestamp string) (events.CommandEvent, bool, error) {
	attempt, ok := s.takeFileOpenAttempt(tid)
	if !ok {
		debugFileEventf("open-result tid=%d fd=%d dropped: no pending open attempt", tid, fd)
		return events.CommandEvent{}, false, nil
	}
	if strings.TrimSpace(timestamp) == "" && s.timeConverter != nil {
		timestamp = s.timeConverter.format(attempt.timestamp)
	}

	base, err := s.buildFileBaseEvent(attempt.tgid, timestamp)
	if err != nil {
		debugFileEventf("open-result tid=%d fd=%d dropped: build file base event: %v", tid, fd, err)
		return events.CommandEvent{}, false, err
	}

	path := normalizeFilePath(attempt.filename, base.Cwd, resolveProcessFDPath(attempt.tgid, attempt.dirfd), attempt.dirfd != unix.AT_FDCWD)
	openFlags := int(attempt.flags)
	if !shouldEmitFileOpenEvent(openFlags, s.captureReadOpens) {
		debugFileEventf("open-result tid=%d fd=%d dropped: flags not tracked flags=%#x", tid, fd, openFlags)
		return events.CommandEvent{}, false, nil
	}
	if !shouldTrackFilePath(path) {
		debugFileEventf("open-result tid=%d fd=%d dropped: path not tracked path=%s", tid, fd, path)
		return events.CommandEvent{}, false, nil
	}
	openEvent := events.BuildFileOpenEvent(base, path, fd, openFlags)
	identity, _ := resolveRegularFileIdentity(attempt.tgid, fd)
	setFileIdentity(&openEvent, identity)
	debugFileEventf("open-result tid=%d fd=%d emit path=%s flags=%#x source=%s", tid, fd, path, openFlags, openEvent.Source)
	return openEvent, true, nil
}

func (s *Service) rememberOpenFile(tgid int, fd int, openEvent events.CommandEvent) {
	if tgid <= 0 || fd < 0 {
		return
	}
	key := fileDescriptorKey{tgid: tgid, fd: fd}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.openFiles[key] = openFileState{
		event:    openEvent,
		identity: fileIdentityFromEvent(openEvent),
	}
}

func (s *Service) rememberOpenFileFallback(tgid int, fd int, timestamp string) {
	if tgid <= 0 || fd < 0 {
		return
	}
	path, ok := resolveRegularFilePath(tgid, fd)
	if !ok {
		debugFileEventf("open-fallback tgid=%d fd=%d dropped: resolve regular file path failed", tgid, fd)
		return
	}
	base, err := s.buildFileBaseEvent(tgid, timestamp)
	if err != nil {
		debugFileEventf("open-fallback tgid=%d fd=%d dropped: build file base event: %v", tgid, fd, err)
		return
	}
	openEvent := events.BuildFileOpenEvent(base, path, fd, 0)
	identity, _ := resolveRegularFileIdentity(tgid, fd)
	setFileIdentity(&openEvent, identity)
	key := fileDescriptorKey{tgid: tgid, fd: fd}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.openFiles[key] = openFileState{event: openEvent, identity: identity}
	debugFileEventf("open-fallback tgid=%d fd=%d tracked path=%s", tgid, fd, path)
}

func (s *Service) rememberIOAttempt(pool map[int]ioAttempt, tid int, tgid int, fd int, kernelMonoNS uint64) {
	if tid <= 0 || fd < 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pool[tid] = ioAttempt{tgid: tgid, fd: fd, timestamp: kernelMonoNS}
}

func (s *Service) takeIOAttempt(pool map[int]ioAttempt, tid int) (ioAttempt, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	attempt, ok := pool[tid]
	if !ok {
		return ioAttempt{}, false
	}
	delete(pool, tid)
	return attempt, true
}

func (s *Service) dropIOAttempt(pool map[int]ioAttempt, tid int) {
	if tid <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(pool, tid)
}

func (s *Service) buildRegularFileSaveEvent(tid int, bytesCount int64, kernelMonoNS uint64, timestamp string) (events.CommandEvent, bool) {
	if bytesCount <= 0 {
		debugFileEventf("write-result tid=%d dropped: bytes=%d", tid, bytesCount)
		return events.CommandEvent{}, false
	}
	attempt, ok := s.takeIOAttempt(s.pendingWrite, tid)
	if !ok {
		debugFileEventf("write-result tid=%d dropped: no pending write attempt", tid)
		return events.CommandEvent{}, false
	}
	path, identity, ok := s.resolveTrackedRegularFilePath(attempt.tgid, attempt.fd, kernelMonoNS)
	if !ok {
		debugFileEventf("write-result tid=%d fd=%d dropped: resolve regular file path failed tgid=%d", tid, attempt.fd, attempt.tgid)
		return events.CommandEvent{}, false
	}
	if strings.TrimSpace(timestamp) == "" && s.timeConverter != nil {
		timestamp = s.timeConverter.format(attempt.timestamp)
	}
	base, err := s.buildFileBaseEvent(attempt.tgid, timestamp)
	if err != nil {
		debugFileEventf("write-result tid=%d fd=%d dropped: build file base event: %v", tid, attempt.fd, err)
		return events.CommandEvent{}, false
	}
	if shouldDropPrecdSelfLogWrite(base, path, s.cfg.LogPath) {
		debugFileEventf("write-result tid=%d fd=%d dropped: precd self log write path=%s", tid, attempt.fd, path)
		return events.CommandEvent{}, false
	}
	if s.shouldSuppressDuplicateFileSave(attempt.tgid, path, kernelMonoNS) {
		debugFileEventf("write-result tid=%d fd=%d dropped: duplicate write path=%s", tid, attempt.fd, path)
		return events.CommandEvent{}, false
	}
	ev := events.BuildFileSaveEvent(base, path, attempt.fd, bytesCount)
	setFileIdentity(&ev, identity)
	debugFileEventf("write-result tid=%d fd=%d emit path=%s bytes=%d source=%s", tid, attempt.fd, path, bytesCount, ev.Source)
	return ev, true
}

func (s *Service) resolveTrackedRegularFilePath(tgid int, fd int, kernelMonoNS uint64) (string, fileIdentity, bool) {
	if tgid <= 0 || fd < 0 {
		return "", fileIdentity{}, false
	}
	key := fileDescriptorKey{tgid: tgid, fd: fd}

	s.mu.Lock()
	openState, ok := s.openFiles[key]
	if ok && shouldTrackFilePath(openState.event.FilePath) {
		needsIdentityCheck := openState.identity.valid && kernelMonoNS != 0 &&
			(openState.lastIdentityCheckMono == 0 || kernelMonoNS < openState.lastIdentityCheckMono ||
				kernelMonoNS-openState.lastIdentityCheckMono >= uint64(fileIdentityCheckInterval))
		if !needsIdentityCheck {
			s.mu.Unlock()
			debugFileEventf("write-path tgid=%d fd=%d tracked path=%s", tgid, fd, openState.event.FilePath)
			return openState.event.FilePath, openState.identity, true
		}
	}
	s.mu.Unlock()

	path, identity, ok := resolveRegularFile(tgid, fd)
	if !ok || !shouldTrackFilePath(path) {
		return "", fileIdentity{}, false
	}

	if openState.identity.valid {
		if identity != openState.identity {
			debugFileEventf("write-path tgid=%d fd=%d identity changed; refreshing path=%s", tgid, fd, path)
		}
		openState.event.FilePath = path
		setFileIdentity(&openState.event, identity)
		openState.identity = identity
		openState.lastIdentityCheckMono = kernelMonoNS
		s.mu.Lock()
		s.openFiles[fileDescriptorKey{tgid: tgid, fd: fd}] = openState
		s.mu.Unlock()
	}
	return path, identity, true
}

func (s *Service) shouldRecordFileEvent(ev events.CommandEvent) bool {
	if !shouldTrackFilePath(ev.FilePath) {
		return false
	}
	if !matchesConfiguredFileScope(ev, s.cfg.CollectFileScope) {
		return false
	}
	if !matchesConfiguredFileSource(ev.Source, s.cfg.CollectFileSource) {
		return false
	}
	if shouldDropPrecdSelfLogWrite(ev, ev.FilePath, s.cfg.LogPath) {
		return false
	}
	return true
}

func (s *Service) shouldSuppressDuplicateFileSave(tgid int, path string, kernelMonoNS uint64) bool {
	windowSec := s.cfg.FileSaveDedupSec
	cleanPath := strings.TrimSpace(path)
	if windowSec <= 0 || tgid <= 0 || cleanPath == "" {
		return false
	}

	windowNS := uint64(time.Duration(windowSec) * time.Second)
	key := fileSaveDedupKey{tgid: tgid, path: filepath.Clean(cleanPath)}

	s.mu.Lock()
	defer s.mu.Unlock()

	if kernelMonoNS != 0 && (s.lastFileSaveGC == 0 || kernelMonoNS-s.lastFileSaveGC >= windowNS) {
		cutoff := uint64(0)
		if kernelMonoNS > windowNS {
			cutoff = kernelMonoNS - windowNS
		}
		for existingKey, lastMonoNS := range s.recentFileSaves {
			if lastMonoNS < cutoff {
				delete(s.recentFileSaves, existingKey)
			}
		}
		s.lastFileSaveGC = kernelMonoNS
	}

	lastMonoNS, ok := s.recentFileSaves[key]
	if ok {
		if kernelMonoNS != 0 && kernelMonoNS <= lastMonoNS {
			return true
		}
		if kernelMonoNS != 0 && kernelMonoNS-lastMonoNS < windowNS {
			return true
		}
		if kernelMonoNS == 0 {
			return true
		}
	}
	s.recentFileSaves[key] = kernelMonoNS
	return false
}

func matchesConfiguredFileSource(eventSource string, configuredSource string) bool {
	switch strings.ToLower(strings.TrimSpace(configuredSource)) {
	case "", "user":
		return eventSource == events.SourceUser
	case "system":
		return eventSource == events.SourceSystem
	case "any":
		return eventSource == events.SourceUser || eventSource == events.SourceSystem
	default:
		return false
	}
}

func matchesConfiguredFileScope(ev events.CommandEvent, scope string) bool {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "", "user_visible":
		return isUserVisibleFilePath(ev)
	case "home":
		return isUserHomeFilePath(ev)
	case "all":
		return true
	default:
		return false
	}
}

func isUserHomeFilePath(ev events.CommandEvent) bool {
	path := normalizeScopedFilePath(ev.FilePath)
	if path == "" {
		return false
	}
	home := lookupUserHome(ev.UID)
	if home == "" {
		return false
	}
	return path == home || strings.HasPrefix(path, home+"/")
}

func isUserVisibleFilePath(ev events.CommandEvent) bool {
	path := normalizeScopedFilePath(ev.FilePath)
	if path == "" {
		return false
	}
	if strings.HasSuffix(strings.TrimSpace(ev.FilePath), " (deleted)") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	if len(parts) == 0 {
		return false
	}
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if strings.HasPrefix(part, ".") {
			// Allow leaf dotfiles such as .env or ~/.bashrc, but exclude hidden directories and nested app state.
			if i == len(parts)-1 {
				continue
			}
			return false
		}
	}
	base := parts[len(parts)-1]
	lowerBase := strings.ToLower(base)
	switch {
	case strings.HasPrefix(base, "etilqs_"):
		return false
	case strings.HasSuffix(lowerBase, ".swp"),
		strings.HasSuffix(lowerBase, ".swo"),
		strings.HasSuffix(lowerBase, ".swx"),
		strings.HasSuffix(lowerBase, ".tmp"),
		strings.HasSuffix(lowerBase, ".log"),
		strings.HasSuffix(lowerBase, "-wal"),
		strings.HasSuffix(lowerBase, "-journal"):
		return false
	default:
		return true
	}
}

func normalizeScopedFilePath(path string) string {
	cleanPath := strings.TrimSpace(path)
	if strings.HasSuffix(cleanPath, " (deleted)") {
		cleanPath = strings.TrimSpace(strings.TrimSuffix(cleanPath, " (deleted)"))
	}
	if cleanPath == "" || !filepath.IsAbs(cleanPath) {
		return ""
	}
	return filepath.Clean(cleanPath)
}

func lookupUserHome(uid uint32) string {
	// Keep the generation for the whole lookup, including its eventual store.
	cache := currentUserHomeCache()
	if home, ok := cache.Load(uid); ok {
		return home.(string)
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		cache.Store(uid, "")
		return ""
	}
	home := filepath.Clean(strings.TrimSpace(u.HomeDir))
	cache.Store(uid, home)
	return home
}

func (s *Service) dropFileStateByTGID(tgid int) {
	if tgid <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for tid, attempt := range s.pendingOpen {
		if attempt.tgid == tgid {
			delete(s.pendingOpen, tid)
		}
	}
	for tid, attempt := range s.pendingWrite {
		if attempt.tgid == tgid {
			delete(s.pendingWrite, tid)
		}
	}
	for tid, attempt := range s.pendingDup {
		if attempt.tgid == tgid {
			delete(s.pendingDup, tid)
		}
	}
	for key := range s.openFiles {
		if key.tgid == tgid {
			delete(s.openFiles, key)
		}
	}
	for key := range s.recentFileSaves {
		if key.tgid == tgid {
			delete(s.recentFileSaves, key)
		}
	}
}

func normalizeFilePath(rawPath string, cwd string, dirfdPath string, useDirFD bool) string {
	path := strings.TrimSpace(rawPath)
	if path == "" {
		return ""
	}
	if strings.HasPrefix(path, "/") {
		return path
	}
	baseDir := strings.TrimSpace(dirfdPath)
	if useDirFD {
		if baseDir == "" {
			return path
		}
	} else if baseDir == "" {
		baseDir = cwd
	}
	if baseDir == "" {
		return path
	}
	return filepath.Clean(filepath.Join(baseDir, path))
}

func shouldEmitFileOpenEvent(openFlags int, captureReadOpens bool) bool {
	if captureReadOpens {
		return true
	}
	accessMode := openFlags & unix.O_ACCMODE
	if accessMode == unix.O_WRONLY || accessMode == unix.O_RDWR {
		return true
	}
	return openFlags&(unix.O_CREAT|unix.O_TRUNC|unix.O_APPEND|unix.O_EXCL) != 0
}

func (s *Service) buildFileBaseEvent(tgid int, timestamp string) (events.CommandEvent, error) {
	if base, ok := s.pendingProcessEvent(tgid); ok {
		if strings.TrimSpace(timestamp) == "" {
			timestamp = base.Timestamp
		}
		base.Timestamp = timestamp
		base.EventID = s.nextEventID()
		base.RecordType = events.RecordTypeStart
		base.EndTimestamp = ""
		base.ExitStatus = nil
		base.DurationNS = nil
		base.ExecErrno = nil
		base.ExecError = ""
		base.LostSamples = nil
		base.LostTotal = nil
		base.FilePath = ""
		base.FileFD = nil
		base.FileBytes = nil
		base.FileFlags = nil
		base.FileDev = nil
		base.FileIno = nil
		base.Source = events.ClassifyFileEventSource(base)
		return base, nil
	}
	base, err := s.buildStartEventWithRetry(tgid, "", timestamp, s.nextEventID())
	if err != nil {
		return events.CommandEvent{}, err
	}
	base.Source = events.ClassifyFileEventSource(base)
	return base, nil
}

func (s *Service) pendingProcessEvent(tgid int) (events.CommandEvent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ev, ok := s.pendingEvents[tgid]
	return ev, ok
}

func resolveProcessFDPath(tgid int, fd int) string {
	if tgid <= 0 || fd < 0 || fd == unix.AT_FDCWD {
		return ""
	}
	target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(tgid), "fd", strconv.Itoa(fd)))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(target)
}

func resolveRegularFilePath(tgid int, fd int) (string, bool) {
	path, _, ok := resolveRegularFile(tgid, fd)
	return path, ok
}

func resolveRegularFileIdentity(tgid int, fd int) (fileIdentity, bool) {
	_, identity, ok := resolveRegularFile(tgid, fd)
	return identity, ok
}

func resolveRegularFile(tgid int, fd int) (string, fileIdentity, bool) {
	if tgid <= 0 || fd < 0 || fd == unix.AT_FDCWD {
		return "", fileIdentity{}, false
	}
	procFDPath := filepath.Join("/proc", strconv.Itoa(tgid), "fd", strconv.Itoa(fd))
	info, err := os.Stat(procFDPath)
	if err != nil || !info.Mode().IsRegular() {
		return "", fileIdentity{}, false
	}
	target, err := os.Readlink(procFDPath)
	if err != nil {
		return "", fileIdentity{}, false
	}
	identity, ok := fileIdentityFromFileInfo(info)
	if !ok {
		return strings.TrimSpace(target), fileIdentity{}, true
	}
	return strings.TrimSpace(target), identity, true
}

func fileIdentityFromEvent(ev events.CommandEvent) fileIdentity {
	if ev.FileDev == nil || ev.FileIno == nil {
		return fileIdentity{}
	}
	return fileIdentity{dev: *ev.FileDev, ino: *ev.FileIno, valid: true}
}

func fileIdentityFromFileInfo(info os.FileInfo) (fileIdentity, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, false
	}
	return fileIdentity{dev: uint64(stat.Dev), ino: uint64(stat.Ino), valid: true}, true
}

func setFileIdentity(ev *events.CommandEvent, identity fileIdentity) {
	if !identity.valid {
		return
	}
	dev := identity.dev
	ino := identity.ino
	ev.FileDev = &dev
	ev.FileIno = &ino
}

func shouldTrackFilePath(path string) bool {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return false
	}
	switch {
	case strings.HasPrefix(cleanPath, "anon_inode:"):
		return false
	case strings.HasPrefix(cleanPath, "/dev/"):
		return false
	case strings.HasPrefix(cleanPath, "/proc/"):
		return false
	case strings.HasPrefix(cleanPath, "/sys/"):
		return false
	default:
		return true
	}
}

func shouldDropPrecdSelfLogWrite(base events.CommandEvent, filePath string, logPath string) bool {
	if strings.TrimSpace(logPath) == "" || strings.TrimSpace(filePath) == "" {
		return false
	}
	name := strings.ToLower(strings.TrimSpace(base.Comm))
	if name == "" {
		name = strings.ToLower(filepath.Base(strings.TrimSpace(base.Exe)))
	}
	if name != "precd" {
		return false
	}
	return filepath.Clean(filePath) == filepath.Clean(logPath)
}

func debugFileEventf(format string, args ...any) {
	if os.Getenv("PREC_DEBUG_FILE_EVENTS") == "" {
		return
	}
	message := fmt.Sprintf(format, args...)
	target := strings.TrimSpace(os.Getenv("PREC_DEBUG_FILE_TARGET"))
	if target != "" && !strings.Contains(message, target) {
		return
	}
	fmt.Fprintf(os.Stderr, "prec-debug: %s\n", message)
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
		if !strings.Contains(line, "field:") {
			continue
		}
		fieldDecl, fieldName, ok := parseFieldDeclaration(line)
		if !ok {
			continue
		}
		if fieldDecl != fieldNeedle && fieldName != fieldNeedle {
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

func parseFieldDeclaration(line string) (fieldDecl string, fieldName string, ok bool) {
	fieldPos := strings.Index(line, "field:")
	if fieldPos < 0 {
		return "", "", false
	}
	raw := strings.TrimSpace(line[fieldPos+len("field:"):])
	fieldEnd := strings.Index(raw, ";")
	if fieldEnd < 0 {
		return "", "", false
	}
	fieldDecl = strings.TrimSpace(raw[:fieldEnd])
	if fieldDecl == "" {
		return "", "", false
	}
	parts := strings.Fields(fieldDecl)
	if len(parts) == 0 {
		return "", "", false
	}
	fieldName = parts[len(parts)-1]
	return fieldDecl, fieldName, true
}

func bytesIndexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}
