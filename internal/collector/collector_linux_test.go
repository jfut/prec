// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

//go:build linux

package collector

import (
	"bufio"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/jfut/prec/internal/config"
	"github.com/jfut/prec/internal/events"
	"github.com/jfut/prec/internal/logger"
)

func TestParseOffsetFromFormat(t *testing.T) {
	t.Parallel()

	format := `name: sched_process_exec
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:__data_loc char[] filename;	offset:12;	size:4;	signed:1;
	field:pid_t pid;	offset:16;	size:4;	signed:1;
`

	got, err := parseOffsetFromFormat(format, "__data_loc char[] filename")
	if err != nil {
		t.Fatalf("parseOffsetFromFormat returned error: %v", err)
	}
	if got != 12 {
		t.Fatalf("got=%d want=%d", got, 12)
	}
}

func TestParseFilenameHint(t *testing.T) {
	t.Parallel()

	raw := make([]byte, perfSampleSize)
	copy(raw[perfSampleFilenameOffset:], []byte("/usr/bin/curl\x00garbage"))

	got := parseFilenameHint(raw)
	if got != "/usr/bin/curl" {
		t.Fatalf("got=%q want=%q", got, "/usr/bin/curl")
	}
}

func TestParsePerfSampleExec(t *testing.T) {
	t.Parallel()

	raw := make([]byte, perfSampleSize)
	raw[perfSampleTypeOffset] = perfEventTypeExec
	// bpf_get_current_pid_tgid() packs tgid in high 32 bits and tid in low 32 bits.
	pidTgid := (uint64(4321) << 32) | 4321
	for i := 0; i < 8; i++ {
		raw[perfSamplePidTgidOffset+i] = byte(pidTgid >> (8 * i))
	}
	ktime := uint64(987654321)
	for i := 0; i < 8; i++ {
		raw[perfSampleKtimeOffset+i] = byte(ktime >> (8 * i))
	}
	copy(raw[perfSampleFilenameOffset:], []byte("/bin/echo\x00"))

	eventType, tgid, tid, status, gotKtime, exeHint, ok := parsePerfSample(raw)
	if !ok {
		t.Fatalf("expected ok")
	}
	if eventType != perfEventTypeExec {
		t.Fatalf("eventType=%d want=%d", eventType, perfEventTypeExec)
	}
	if tgid != 4321 {
		t.Fatalf("tgid=%d want=%d", tgid, 4321)
	}
	if tid != 4321 {
		t.Fatalf("tid=%d want=%d", tid, 4321)
	}
	if status != 0 {
		t.Fatalf("status=%d want=0", status)
	}
	if gotKtime != ktime {
		t.Fatalf("ktime=%d want=%d", gotKtime, ktime)
	}
	if exeHint != "/bin/echo" {
		t.Fatalf("exeHint=%q want=%q", exeHint, "/bin/echo")
	}
}

func TestParsePerfSampleExecResultNegative(t *testing.T) {
	t.Parallel()

	raw := make([]byte, perfSampleSize)
	raw[perfSampleTypeOffset] = perfEventTypeExecResult
	pidTgid := (uint64(5000) << 32) | 5001
	for i := 0; i < 8; i++ {
		raw[perfSamplePidTgidOffset+i] = byte(pidTgid >> (8 * i))
	}
	ret := int64(-2)
	for i := 0; i < 8; i++ {
		raw[perfSampleStatusOffset+i] = byte(uint64(ret) >> (8 * i))
	}

	eventType, tgid, tid, status, _, _, ok := parsePerfSample(raw)
	if !ok {
		t.Fatalf("expected ok")
	}
	if eventType != perfEventTypeExecResult {
		t.Fatalf("eventType=%d want=%d", eventType, perfEventTypeExecResult)
	}
	if tgid != 5000 || tid != 5001 {
		t.Fatalf("unexpected tgid/tid: %d/%d", tgid, tid)
	}
	if status != -2 {
		t.Fatalf("status=%d want=-2", status)
	}
}

func TestBuildPerfSampleStackZeroInstructions(t *testing.T) {
	t.Parallel()

	got := buildPerfSampleStackZeroInstructions()
	wantStores := perfSampleSize / 8
	if len(got) != 1+wantStores {
		t.Fatalf("instruction count=%d want=%d", len(got), 1+wantStores)
	}

	for i := 0; i < wantStores; i++ {
		ins := got[i+1]
		if ins.OpCode != asm.StoreMemOp(asm.DWord) {
			t.Fatalf("instruction[%d] opcode=%v want=%v", i+1, ins.OpCode, asm.StoreMemOp(asm.DWord))
		}
		if ins.Dst != asm.RFP {
			t.Fatalf("instruction[%d] dst=%v want=%v", i+1, ins.Dst, asm.RFP)
		}
		if ins.Src != asm.R0 {
			t.Fatalf("instruction[%d] src=%v want=%v", i+1, ins.Src, asm.R0)
		}
		wantOffset := int16(perfSampleStackStart + i*8)
		if ins.Offset != wantOffset {
			t.Fatalf("instruction[%d] offset=%d want=%d", i+1, ins.Offset, wantOffset)
		}
	}
}

func TestNormalizeExitStatus(t *testing.T) {
	t.Parallel()

	if got := normalizeExitStatus(260); got != 4 {
		t.Fatalf("got=%d want=%d", got, 4)
	}
}

func TestRememberExitStatusPriority(t *testing.T) {
	t.Parallel()

	svc := &Service{
		pendingStatuses: map[int]int{},
	}

	svc.rememberExitStatus(100, 0, false)
	svc.rememberExitStatus(100, 60, true)
	svc.rememberExitStatus(100, 1, false)

	got := svc.pendingStatuses[100]
	if got != 60 {
		t.Fatalf("got=%d want=%d", got, 60)
	}
}

func TestNextEventIDUsesStartTimePrefixAndCounter(t *testing.T) {
	t.Parallel()

	svc := &Service{
		eventIDPrefix: "20260517102452",
	}

	first := svc.nextEventID()
	second := svc.nextEventID()

	if first != "20260517102452-1" {
		t.Fatalf("first=%q want=%q", first, "20260517102452-1")
	}
	if second != "20260517102452-2" {
		t.Fatalf("second=%q want=%q", second, "20260517102452-2")
	}
}

func TestFinalizeEventReturnsStartStatusAndClearsState(t *testing.T) {
	t.Parallel()

	svc := &Service{
		pendingEvents:    map[int]events.CommandEvent{},
		pendingStatuses:  map[int]int{},
		pendingStartMono: map[int]uint64{},
	}
	start := events.CommandEvent{
		Timestamp:  "2026-05-23T10:00:00Z",
		EventID:    "boot-1",
		PID:        1234,
		RecordType: events.RecordTypeStart,
	}

	svc.rememberExecEvent(1234, start, 101_000)
	svc.rememberExitStatus(1234, 260, true)

	gotStart, gotStatus, gotStartMono, ok := svc.finalizeEvent(1234)
	if !ok {
		t.Fatalf("finalizeEvent returned ok=false")
	}
	if gotStart.EventID != start.EventID {
		t.Fatalf("event_id=%q want=%q", gotStart.EventID, start.EventID)
	}
	if gotStatus == nil || *gotStatus != 4 {
		t.Fatalf("status=%v want=4", gotStatus)
	}
	if gotStartMono != 101_000 {
		t.Fatalf("start_mono=%d want=%d", gotStartMono, 101_000)
	}

	if len(svc.pendingEvents) != 0 || len(svc.pendingStatuses) != 0 || len(svc.pendingStartMono) != 0 {
		t.Fatalf("state was not cleared: events=%d statuses=%d start_mono=%d", len(svc.pendingEvents), len(svc.pendingStatuses), len(svc.pendingStartMono))
	}
}

func TestComputeDurationNS(t *testing.T) {
	t.Parallel()

	if got := computeDurationNS(0, 100); got != 0 {
		t.Fatalf("got=%d want=0", got)
	}
	if got := computeDurationNS(500, 400); got != 0 {
		t.Fatalf("got=%d want=0", got)
	}
	if got := computeDurationNS(100, 1200); got != 1100 {
		t.Fatalf("got=%d want=1100", got)
	}
	overflowStart := uint64(1)
	overflowEnd := uint64(math.MaxUint64)
	if got := computeDurationNS(overflowStart, overflowEnd); got != math.MaxInt64 {
		t.Fatalf("overflow got=%d want=%d", got, int64(math.MaxInt64))
	}
}

func TestBuildFromPIDWithRetry(t *testing.T) {
	t.Parallel()

	attempts := 0
	got, err := buildFromPIDWithRetry(3, 0, func() (events.CommandEvent, error) {
		attempts++
		if attempts < 3 {
			return events.CommandEvent{}, errors.New("temporary")
		}
		return events.CommandEvent{PID: 42}, nil
	})
	if err != nil {
		t.Fatalf("buildFromPIDWithRetry returned error: %v", err)
	}
	if got.PID != 42 {
		t.Fatalf("pid=%d want=42", got.PID)
	}
	if attempts != 3 {
		t.Fatalf("attempts=%d want=3", attempts)
	}
}

func TestBuildFromPIDWithRetryFailure(t *testing.T) {
	t.Parallel()

	attempts := 0
	wantErr := errors.New("still failing")
	_, err := buildFromPIDWithRetry(2, 0, func() (events.CommandEvent, error) {
		attempts++
		return events.CommandEvent{}, wantErr
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts=%d want=2", attempts)
	}
}

func TestHandleLostSamplesLogMode(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "prec.log")
	w, err := logger.NewJSONLWriter(logPath, config.CompressNo, 0)
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}
	defer w.Close()

	svc := &Service{
		cfg:    config.Config{LostSamplesAction: config.LostSamplesActionLog},
		writer: w,
	}

	if err := svc.handleLostSamples(7); err != nil {
		t.Fatalf("handleLostSamples: %v", err)
	}

	got := readLossEventsFromLog(t, logPath)
	if len(got) != 1 {
		t.Fatalf("got=%d want=1", len(got))
	}
	if got[0].RecordType != events.RecordTypeLoss {
		t.Fatalf("record_type=%q want=%q", got[0].RecordType, events.RecordTypeLoss)
	}
	if got[0].LostSamples == nil || *got[0].LostSamples != 7 {
		t.Fatalf("lost_samples=%v want=7", got[0].LostSamples)
	}
	if got[0].LostTotal == nil || *got[0].LostTotal != 7 {
		t.Fatalf("lost_samples_total=%v want=7", got[0].LostTotal)
	}
}

func TestHandleLostSamplesIgnoreMode(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "prec.log")
	w, err := logger.NewJSONLWriter(logPath, config.CompressNo, 0)
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}
	defer w.Close()

	svc := &Service{
		cfg:    config.Config{LostSamplesAction: config.LostSamplesActionIgnore},
		writer: w,
	}

	if err := svc.handleLostSamples(3); err != nil {
		t.Fatalf("handleLostSamples: %v", err)
	}

	lines := readRawLines(t, logPath)
	if len(lines) != 0 {
		t.Fatalf("unexpected log lines: %v", lines)
	}
}

func TestHandleLostSamplesStopMode(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "prec.log")
	w, err := logger.NewJSONLWriter(logPath, config.CompressNo, 0)
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}
	defer w.Close()

	svc := &Service{
		cfg:    config.Config{LostSamplesAction: config.LostSamplesActionStop},
		writer: w,
	}

	err = svc.handleLostSamples(11)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "lost perf samples detected") {
		t.Fatalf("unexpected error: %v", err)
	}

	got := readLossEventsFromLog(t, logPath)
	if len(got) != 1 {
		t.Fatalf("got=%d want=1", len(got))
	}
	if got[0].LostTotal == nil || *got[0].LostTotal != 11 {
		t.Fatalf("lost_samples_total=%v want=11", got[0].LostTotal)
	}
}

func readLossEventsFromLog(t *testing.T, path string) []events.CommandEvent {
	t.Helper()
	lines := readRawLines(t, path)
	out := make([]events.CommandEvent, 0, len(lines))
	for _, line := range lines {
		var ev events.CommandEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		out = append(out, ev)
	}
	return out
}

func readRawLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	out := make([]string, 0)
	s := bufio.NewScanner(f)
	for s.Scan() {
		out = append(out, s.Text())
	}
	if err := s.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}
