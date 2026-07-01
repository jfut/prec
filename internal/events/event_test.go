// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeArgv(t *testing.T) {
	t.Parallel()

	argv := []string{"curl", "https://example.com"}
	got := normalizeArgv(argv, "/bin/curl", "")
	if got[0] != "/bin/curl" {
		t.Fatalf("got=%q want=%q", got[0], "/bin/curl")
	}
}

func TestResolveExecutablePathFromProcPath(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	procDir := filepath.Join(tmp, "proc")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}

	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cmdPath := filepath.Join(binDir, "mycmd")
	if err := os.WriteFile(cmdPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	environ := "PATH=" + binDir + "\x00HOME=/tmp\x00"
	if err := os.WriteFile(filepath.Join(procDir, "environ"), []byte(environ), 0o600); err != nil {
		t.Fatal(err)
	}

	got := resolveExecutablePath(procDir, 0, "", []string{"mycmd"}, "")
	if got != cmdPath {
		t.Fatalf("got=%q want=%q", got, cmdPath)
	}
}

func TestReadTTYNr(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	p := filepath.Join(tmp, "stat")
	line := "1234 (curl) S 1 2 3 34821 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
	if err := os.WriteFile(p, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := readTTYNr(p)
	if err != nil {
		t.Fatalf("readTTYNr returned error: %v", err)
	}
	if got != 34821 {
		t.Fatalf("got=%d want=%d", got, 34821)
	}
}

func TestReadAuditUint32(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	p := filepath.Join(tmp, "loginuid")
	if err := os.WriteFile(p, []byte("1000\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := readAuditUint32(p)
	if got == nil || *got != 1000 {
		t.Fatalf("got=%v want=1000", got)
	}
}

func TestBuildCollectorLossEvent(t *testing.T) {
	t.Parallel()

	ev := BuildCollectorLossEvent(5, 9)
	if ev.RecordType != RecordTypeLoss {
		t.Fatalf("record_type=%q want=%q", ev.RecordType, RecordTypeLoss)
	}
	if ev.Source != SourceSystem {
		t.Fatalf("source=%q want=%q", ev.Source, SourceSystem)
	}
	if ev.LostSamples == nil || *ev.LostSamples != 5 {
		t.Fatalf("lost_samples=%v want=5", ev.LostSamples)
	}
	if ev.LostTotal == nil || *ev.LostTotal != 9 {
		t.Fatalf("lost_samples_total=%v want=9", ev.LostTotal)
	}
}

func TestBuildExecFailureEvent(t *testing.T) {
	t.Parallel()

	ts := "2026-05-23T00:00:00Z"
	ev, err := BuildExecFailureEvent(os.Getpid(), "missing-cmd", 2, 1024, ts)
	if err != nil {
		t.Fatalf("BuildExecFailureEvent: %v", err)
	}
	if ev.RecordType != RecordTypeFail {
		t.Fatalf("record_type=%q want=%q", ev.RecordType, RecordTypeFail)
	}
	if ev.Timestamp != ts {
		t.Fatalf("timestamp=%q want=%q", ev.Timestamp, ts)
	}
	if ev.ExecErrno == nil || *ev.ExecErrno != 2 {
		t.Fatalf("exec_errno=%v want=2", ev.ExecErrno)
	}
	if ev.Argc != 1 || len(ev.Argv) != 1 {
		t.Fatalf("unexpected argv: %+v", ev.Argv)
	}
}

func TestBuildCommandEndEvent(t *testing.T) {
	t.Parallel()

	start := CommandEvent{
		Timestamp:  "2026-05-23T10:00:00Z",
		EventID:    "boot-999",
		PID:        1234,
		UID:        1000,
		User:       "admin",
		RecordType: RecordTypeStart,
		Argv:       []string{"/bin/sleep", "3"},
		Source:     SourceUser,
	}
	exitStatus := 0
	durationNS := int64(3_456_000_000)
	ev := BuildCommandEndEvent(start, "2026-05-23T10:00:03.456Z", durationNS, &exitStatus)

	if ev.RecordType != RecordTypeEnd {
		t.Fatalf("record_type=%q want=%q", ev.RecordType, RecordTypeEnd)
	}
	if ev.EventID != start.EventID {
		t.Fatalf("event_id=%q want=%q", ev.EventID, start.EventID)
	}
	if ev.PID != start.PID {
		t.Fatalf("pid=%d want=%d", ev.PID, start.PID)
	}
	if ev.Source != start.Source {
		t.Fatalf("source=%q want=%q", ev.Source, start.Source)
	}
	if ev.Timestamp != "2026-05-23T10:00:03.456Z" {
		t.Fatalf("timestamp=%q want=%q", ev.Timestamp, "2026-05-23T10:00:03.456Z")
	}
	if ev.DurationNS == nil || *ev.DurationNS != durationNS {
		t.Fatalf("duration_ns=%v want=%d", ev.DurationNS, durationNS)
	}
	if ev.ExitStatus == nil || *ev.ExitStatus != 0 {
		t.Fatalf("exit_status=%v want=0", ev.ExitStatus)
	}

	// end keeps only fields required for join and timing.
	if ev.UID != 0 || ev.User != "" || ev.Comm != "" || len(ev.Argv) != 0 {
		t.Fatalf("end should be compact: %+v", ev)
	}
}

func TestMarshalJSONCommandEndIsCompact(t *testing.T) {
	t.Parallel()

	start := CommandEvent{
		EventID: "boot-999",
		PID:     1234,
		Source:  SourceSystem,
	}
	exitStatus := 0
	durationNS := int64(1_234_567)
	ev := BuildCommandEndEvent(start, "2026-05-23T10:00:03.456Z", durationNS, &exitStatus)

	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal(end): %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal(end json): %v", err)
	}

	wantKeys := map[string]struct{}{
		"timestamp":   {},
		"event_id":    {},
		"pid":         {},
		"source":      {},
		"record_type": {},
		"exit_status": {},
		"duration_ns": {},
	}
	if len(got) != len(wantKeys) {
		t.Fatalf("end json keys len=%d want=%d json=%s", len(got), len(wantKeys), string(raw))
	}
	for key := range wantKeys {
		if _, ok := got[key]; !ok {
			t.Fatalf("missing key %q in end json=%s", key, string(raw))
		}
	}
}
