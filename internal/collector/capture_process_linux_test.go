// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

//go:build linux

package collector

import (
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/jfut/prec/internal/config"
	"github.com/jfut/prec/internal/events"
	"github.com/jfut/prec/internal/logger"
	"golang.org/x/sys/unix"
)

func newCaptureTestProgram(t *testing.T, instructions asm.Instructions, uidGID, pidTGID uint64) *ebpf.Program {
	t.Helper()
	// Verify the actual tracepoint guard first. Tracepoints have no test-run
	// interface, so only identity helpers are replaced in the socket test harness.
	trace, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.TracePoint,
		License:      "GPL",
		Instructions: instructions,
	})
	if err != nil {
		t.Fatalf("verify tracepoint guard: %+v", err)
	}
	if err := trace.Close(); err != nil {
		t.Fatal(err)
	}
	for i := range instructions {
		if !instructions[i].IsBuiltinCall() {
			continue
		}
		metadata := instructions[i].Metadata
		switch instructions[i].Constant {
		case int64(asm.FnGetCurrentUidGid):
			instructions[i] = asm.LoadImm(asm.R0, int64(uidGID), asm.DWord)
		case int64(asm.FnGetCurrentPidTgid):
			instructions[i] = asm.LoadImm(asm.R0, int64(pidTGID), asm.DWord)
		}
		instructions[i].Metadata = metadata
	}
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SocketFilter,
		License:      "GPL",
		Instructions: instructions,
	})
	if err != nil {
		t.Fatalf("load socket guard: %+v", err)
	}
	t.Cleanup(func() { _ = program.Close() })
	return program
}

func TestCaptureProcessLifecycleKernel(t *testing.T) {
	policy, err := compileCaptureFilter([]string{"+user=tomcat&&group=tomcat"})
	if err != nil {
		t.Fatal(err)
	}
	identities, refresher, err := newCaptureIdentityMap(policy)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("eBPF unavailable: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = identities.Close() }()
	processes, err := newCaptureProcessMap()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = processes.Close() }()
	policy.identitiesMapFD, policy.processes = identities.FD(), processes
	// The registration prefix is shared by all collectors. Verify complete
	// programs as well as the runnable guards to catch stack/register conflicts.
	eventMap, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerfEventArray, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = eventMap.Close() }()
	for name, instructions := range map[string]asm.Instructions{
		"exec":        buildExecTraceInstructions(eventMap.FD(), 8, policy),
		"status":      buildExitStatusTraceInstructions(eventMap.FD(), 16, asm.DWord, perfEventTypeExitGroup, policy),
		"exit":        buildProcessExitTraceInstructions(eventMap.FD(), policy),
		"exec-enter":  buildExecEnterTraceInstructions(eventMap.FD(), 16, asm.DWord, policy),
		"exec-result": buildExecResultTraceInstructions(eventMap.FD(), 16, asm.DWord, policy),
		"open":        buildOpenEnterTraceInstructions(eventMap.FD(), 24, asm.DWord, 16, asm.DWord, 32, asm.DWord, true, policy),
		"write":       buildSimpleFDEnterTraceInstructions(eventMap.FD(), perfEventTypeWriteEnter, 16, asm.DWord, policy),
		"dup":         buildTwoFDEnterTraceInstructions(eventMap.FD(), perfEventTypeDupEnter, 16, asm.DWord, 24, asm.DWord, policy),
		"io-result":   buildSimpleResultTraceInstructions(eventMap.FD(), perfEventTypeWriteResult, 16, asm.DWord, policy),
	} {
		program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.TracePoint, License: "GPL", Instructions: instructions})
		if err != nil {
			t.Fatalf("verify %s collector: %+v", name, err)
		}
		if err := program.Close(); err != nil {
			t.Fatal(err)
		}
	}
	const tgid = 1234
	const uidGID = uint64(48) | uint64(82)<<32
	const leader = uint64(tgid) | uint64(tgid)<<32
	body := func() asm.Instructions {
		return asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()}
	}
	start := newCaptureTestProgram(t,
		appendCaptureTraceBody(startCaptureTraceInstructions(policy), body(), policy), uidGID, leader)
	status := newCaptureTestProgram(t,
		appendCaptureExitBody(startCaptureExitInstructions(policy, false), body(), policy), uidGID, leader)
	exit := newCaptureTestProgram(t,
		appendCaptureExitBody(startCaptureExitInstructions(policy, true), body(), policy), uidGID, leader)
	threadExit := newCaptureTestProgram(t,
		appendCaptureExitBody(startCaptureExitInstructions(policy, true), body(), policy), uidGID, leader+1)
	otherExit := newCaptureTestProgram(t,
		appendCaptureExitBody(startCaptureExitInstructions(policy, true), body(), policy), uidGID, leader+uint64(1<<32)+1)
	check := func(program *ebpf.Program, want uint32) {
		t.Helper()
		got, _, err := program.Test(make([]byte, 64))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("guard returned %d, want %d", got, want)
		}
	}
	var uid, gid uint64 = 48, 82
	var userErr error
	refresher.lookupUID = func(string) (uint64, error) { return uid, userErr }
	refresher.lookupGID = func(string) (uint64, error) { return gid, nil }
	refresh := func() {
		t.Helper()
		if err := refresher.refresh(); err != nil {
			t.Fatal(err)
		}
	}
	refresh()
	check(status, 0) // No exit traffic for processes that have never been admitted.
	check(start, 1)
	uid, gid = 49, 83
	refresh()
	check(start, 0) // Old credentials no longer admit new capture events.
	check(status, 1)
	check(threadExit, 1)
	check(status, 1) // A worker thread must not remove the shared TGID entry.
	check(otherExit, 0)
	userErr = user.UnknownUserError("tomcat")
	refresh()
	check(status, 1) // Account deletion must not prevent finalization either.
	check(exit, 1)
	check(status, 0)
	check(exit, 0) // Removal prevents stale entries from authorizing a reused PID.
	var marker uint32
	if err := processes.Lookup(uint32(tgid), &marker); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("process entry survived leader exit: %v", err)
	}

	// Registration failure must not emit a new event whose state would have no
	// exit notification. A full tiny map makes this failure deterministic.
	full, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = full.Close() }()
	if err := full.Put(uint32(tgid+1), uint32(1)); err != nil {
		t.Fatal(err)
	}
	policy.processes = full
	userErr, uid, gid = nil, 48, 82
	refresh()
	failedStart := newCaptureTestProgram(t,
		appendCaptureTraceBody(startCaptureTraceInstructions(policy), body(), policy), uidGID, leader)
	check(failedStart, 0)
	if err := full.Lookup(uint32(tgid), &marker); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("failed registration created an entry: %v", err)
	}
}

func TestHandleProcessExitClearsTrackedState(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "prec.log")
	writer, err := logger.NewJSONLWriter(path, config.CompressNo, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Close() }()
	svc, err := NewService(config.Default(), writer)
	if err != nil {
		t.Fatal(err)
	}
	const pid = 1234
	svc.rememberExecEvent(pid, events.CommandEvent{EventID: "before-refresh", PID: pid, UID: 48}, 100)
	svc.rememberExitStatus(pid, 7, true)
	svc.pendingExecve[pid] = execAttempt{tgid: pid}
	svc.pendingOpen[pid] = fileOpenAttempt{tgid: pid}
	svc.pendingWrite[pid] = ioAttempt{tgid: pid}
	svc.pendingDup[pid] = dupAttempt{tgid: pid}
	svc.openFiles[fileDescriptorKey{tgid: pid, fd: 3}] = openFileState{}
	svc.recentFileSaves[fileSaveDedupKey{tgid: pid, path: "/tmp/test"}] = 100
	if err := svc.handleProcessExit(pid, pid+1, 200, "2026-11-03T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if len(svc.pendingEvents) != 1 || len(svc.openFiles) != 1 {
		t.Fatal("worker exit removed shared process state")
	}
	if err := svc.handleProcessExit(pid, pid, 200, "2026-11-03T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if len(svc.pendingEvents)+len(svc.pendingStatuses)+len(svc.pendingStartMono)+len(svc.pendingExecve)+len(svc.pendingOpen)+len(svc.pendingWrite)+len(svc.pendingDup)+len(svc.openFiles)+len(svc.recentFileSaves) != 0 {
		t.Fatal("process state survived finalization")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var end events.CommandEvent
	if err := json.Unmarshal(data, &end); err != nil {
		t.Fatal(err)
	}
	if end.RecordType != events.RecordTypeEnd || end.EventID != "before-refresh" || end.ExitStatus == nil || *end.ExitStatus != 7 || end.DurationNS == nil || *end.DurationNS != 100 {
		t.Fatalf("incorrect end record: %+v", end)
	}
}
