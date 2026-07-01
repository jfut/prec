// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package cli

import (
	"path/filepath"
	"testing"

	"github.com/jfut/prec/internal/events"
)

func TestCollectFilteredEventsAcrossRotatedLogs(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	paths := []string{
		filepath.Join(tmpDir, "prec.log.2.gz"),
		filepath.Join(tmpDir, "prec.log.1.zst"),
		filepath.Join(tmpDir, "prec.log.1"),
		filepath.Join(tmpDir, "prec.log"),
	}

	eventsByPath := map[string][]events.CommandEvent{
		paths[0]: {
			{Timestamp: "2026-05-22T01:00:00Z", PID: 1, User: "u", Group: "g", Source: events.SourceUser, Argv: []string{"cmd1"}},
		},
		paths[1]: {
			{Timestamp: "2026-05-22T01:30:00Z", PID: 15, User: "u", Group: "g", Source: events.SourceUser, Argv: []string{"cmd15"}},
		},
		paths[2]: {
			{Timestamp: "2026-05-22T02:00:00Z", PID: 2, User: "u", Group: "g", Source: events.SourceSystem, Argv: []string{"cmd2"}},
			{Timestamp: "2026-05-22T03:00:00Z", PID: 3, User: "u", Group: "g", Source: events.SourceUser, Argv: []string{"cmd3"}},
		},
		paths[3]: {
			{Timestamp: "2026-05-22T04:00:00Z", PID: 4, User: "u", Group: "g", Source: events.SourceUser, Argv: []string{"cmd4"}},
		},
	}

	if err := writeTestLogFile(paths[0], eventsByPath[paths[0]], "gz", true); err != nil {
		t.Fatalf("write gzip log: %v", err)
	}
	if err := writeTestLogFile(paths[1], eventsByPath[paths[1]], "zstd", false); err != nil {
		t.Fatalf("write zstd log: %v", err)
	}
	if err := writeTestLogFile(paths[2], eventsByPath[paths[2]], "none", false); err != nil {
		t.Fatalf("write plain log 1: %v", err)
	}
	if err := writeTestLogFile(paths[3], eventsByPath[paths[3]], "none", false); err != nil {
		t.Fatalf("write plain log 2: %v", err)
	}

	lf, err := buildQueryFilter([]string{"source=user"})
	if err != nil {
		t.Fatalf("buildQueryFilter: %v", err)
	}

	got, err := collectFilteredEvents(paths, 0, lf)
	if err != nil {
		t.Fatalf("collectFilteredEvents: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("got len=%d want=4", len(got))
	}
	if got[0].PID != 1 || got[1].PID != 15 || got[2].PID != 3 || got[3].PID != 4 {
		t.Fatalf("unexpected pid order: %v", []int{got[0].PID, got[1].PID, got[2].PID, got[3].PID})
	}

	limited, err := collectFilteredEvents(paths, 2, lf)
	if err != nil {
		t.Fatalf("collectFilteredEvents(limit): %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("got len=%d want=2", len(limited))
	}
	if limited[0].PID != 3 || limited[1].PID != 4 {
		t.Fatalf("unexpected limited pid order: %v", []int{limited[0].PID, limited[1].PID})
	}
}

func TestCollectFilteredEventsWithJoinSkipsCommandEndBeforeDecode(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "prec.log")
	durationNS := int64(2_000_000_000)
	exitStatus := 0

	evs := []events.CommandEvent{
		{
			Timestamp:  "2026-05-24T12:00:00Z",
			EventID:    "boot-40",
			PID:        4001,
			User:       "root",
			Group:      "root",
			Source:     events.SourceUser,
			Argv:       []string{"/bin/sleep", "2"},
			RecordType: events.RecordTypeStart,
		},
		{
			Timestamp:  "2026-05-24T12:00:02Z",
			EventID:    "boot-40",
			PID:        4001,
			RecordType: events.RecordTypeEnd,
			DurationNS: &durationNS,
			ExitStatus: &exitStatus,
		},
	}
	if err := writeTestLogFile(path, evs, "none", false); err != nil {
		t.Fatalf("write log: %v", err)
	}

	lf, err := buildQueryFilter([]string{"source=user"})
	if err != nil {
		t.Fatalf("buildQueryFilter: %v", err)
	}

	noEnd, err := collectFilteredEventsWithJoin([]string{path}, 0, lf, nil, false)
	if err != nil {
		t.Fatalf("collectFilteredEventsWithJoin(noEnd): %v", err)
	}
	if len(noEnd) != 1 {
		t.Fatalf("noEnd len=%d want=1", len(noEnd))
	}
	if noEnd[0].DurationNS != nil || noEnd[0].ExitStatus != nil || noEnd[0].EndTimestamp != "" {
		t.Fatalf("noEnd should keep start-only fields: %+v", noEnd[0])
	}

	withEnd, err := collectFilteredEventsWithJoin([]string{path}, 0, lf, nil, true)
	if err != nil {
		t.Fatalf("collectFilteredEventsWithJoin(withEnd): %v", err)
	}
	if len(withEnd) != 1 {
		t.Fatalf("withEnd len=%d want=1", len(withEnd))
	}
	if withEnd[0].DurationNS == nil || *withEnd[0].DurationNS != durationNS {
		t.Fatalf("withEnd duration_ns=%v want=%d", withEnd[0].DurationNS, durationNS)
	}
	if withEnd[0].ExitStatus == nil || *withEnd[0].ExitStatus != exitStatus {
		t.Fatalf("withEnd exit_status=%v want=%d", withEnd[0].ExitStatus, exitStatus)
	}
}

func TestCollectFilteredEventsWithJoinFastTailZstd(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "prec.log")

	durationNS := int64(2_000_000_000)
	exitStatus := 0
	evs := []events.CommandEvent{
		{
			Timestamp:  "2026-05-24T12:00:00Z",
			EventID:    "boot-50",
			PID:        5001,
			User:       "root",
			Group:      "root",
			Source:     events.SourceUser,
			Argv:       []string{"/bin/echo", "u1"},
			RecordType: events.RecordTypeStart,
		},
		{
			Timestamp:  "2026-05-24T12:00:01Z",
			EventID:    "boot-50",
			PID:        5001,
			RecordType: events.RecordTypeEnd,
			DurationNS: &durationNS,
			ExitStatus: &exitStatus,
		},
		{
			Timestamp:  "2026-05-24T12:00:02Z",
			EventID:    "boot-51",
			PID:        5002,
			User:       "root",
			Group:      "root",
			Source:     events.SourceSystem,
			Argv:       []string{"/bin/echo", "system"},
			RecordType: events.RecordTypeStart,
		},
		{
			Timestamp:  "2026-05-24T12:00:03Z",
			EventID:    "boot-52",
			PID:        5003,
			User:       "root",
			Group:      "root",
			Source:     events.SourceUser,
			Argv:       []string{"/bin/echo", "u2"},
			RecordType: events.RecordTypeStart,
		},
		{
			Timestamp:  "2026-05-24T12:00:04Z",
			EventID:    "boot-53",
			PID:        5004,
			User:       "root",
			Group:      "root",
			Source:     events.SourceUser,
			Argv:       []string{"/bin/echo", "u3"},
			RecordType: events.RecordTypeStart,
		},
	}
	if err := writeTestZstdFrameLogFile(path, evs); err != nil {
		t.Fatalf("write frame zstd log: %v", err)
	}

	lf, err := buildQueryFilter([]string{"source=user"})
	if err != nil {
		t.Fatalf("buildQueryFilter: %v", err)
	}

	got, err := collectFilteredEventsWithJoin([]string{path}, 2, lf, nil, false)
	if err != nil {
		t.Fatalf("collectFilteredEventsWithJoin: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got len=%d want=2", len(got))
	}
	if got[0].PID != 5003 || got[1].PID != 5004 {
		t.Fatalf("unexpected pid order: %v", []int{got[0].PID, got[1].PID})
	}
	if got[0].RecordType != events.RecordTypeCommand || got[1].RecordType != events.RecordTypeCommand {
		t.Fatalf("record_type should be merged command: got=%q,%q", got[0].RecordType, got[1].RecordType)
	}
}

func TestCollectFilteredEventsWithJoinFastTailGzip(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "prec.log")

	durationNS := int64(2_000_000_000)
	exitStatus := 0
	evs := []events.CommandEvent{
		{
			Timestamp:  "2026-05-24T12:10:00Z",
			EventID:    "boot-60",
			PID:        6001,
			User:       "root",
			Group:      "root",
			Source:     events.SourceUser,
			Argv:       []string{"/bin/echo", "u1"},
			RecordType: events.RecordTypeStart,
		},
		{
			Timestamp:  "2026-05-24T12:10:01Z",
			EventID:    "boot-60",
			PID:        6001,
			RecordType: events.RecordTypeEnd,
			DurationNS: &durationNS,
			ExitStatus: &exitStatus,
		},
		{
			Timestamp:  "2026-05-24T12:10:02Z",
			EventID:    "boot-61",
			PID:        6002,
			User:       "root",
			Group:      "root",
			Source:     events.SourceSystem,
			Argv:       []string{"/bin/echo", "system"},
			RecordType: events.RecordTypeStart,
		},
		{
			Timestamp:  "2026-05-24T12:10:03Z",
			EventID:    "boot-62",
			PID:        6003,
			User:       "root",
			Group:      "root",
			Source:     events.SourceUser,
			Argv:       []string{"/bin/echo", "u2"},
			RecordType: events.RecordTypeStart,
		},
		{
			Timestamp:  "2026-05-24T12:10:04Z",
			EventID:    "boot-63",
			PID:        6004,
			User:       "root",
			Group:      "root",
			Source:     events.SourceUser,
			Argv:       []string{"/bin/echo", "u3"},
			RecordType: events.RecordTypeStart,
		},
	}
	if err := writeTestGzipFrameLogFile(path, evs); err != nil {
		t.Fatalf("write frame gzip log: %v", err)
	}

	lf, err := buildQueryFilter([]string{"source=user"})
	if err != nil {
		t.Fatalf("buildQueryFilter: %v", err)
	}

	got, err := collectFilteredEventsWithJoin([]string{path}, 2, lf, nil, false)
	if err != nil {
		t.Fatalf("collectFilteredEventsWithJoin: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got len=%d want=2", len(got))
	}
	if got[0].PID != 6003 || got[1].PID != 6004 {
		t.Fatalf("unexpected pid order: %v", []int{got[0].PID, got[1].PID})
	}
	if got[0].RecordType != events.RecordTypeCommand || got[1].RecordType != events.RecordTypeCommand {
		t.Fatalf("record_type should be merged command: got=%q,%q", got[0].RecordType, got[1].RecordType)
	}
}
