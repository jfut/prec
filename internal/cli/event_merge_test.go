// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package cli

import (
	"testing"

	"github.com/jfut/prec/internal/events"
)

func TestMergeEventsForListJoinsStartEnd(t *testing.T) {
	t.Parallel()

	start := events.CommandEvent{
		Timestamp:  "2026-05-23T10:00:00Z",
		EventID:    "boot-1",
		PID:        101,
		User:       "admin",
		Group:      "admin",
		Argv:       []string{"/bin/sleep", "3"},
		RecordType: events.RecordTypeStart,
	}
	durationNS := int64(3_000_000_000)
	exitStatus := 0
	end := events.CommandEvent{
		Timestamp:  "2026-05-23T10:00:03Z",
		EventID:    "boot-1",
		PID:        101,
		RecordType: events.RecordTypeEnd,
		DurationNS: &durationNS,
		ExitStatus: &exitStatus,
	}
	openStart := events.CommandEvent{
		Timestamp:  "2026-05-23T10:00:05Z",
		EventID:    "boot-2",
		PID:        202,
		User:       "admin",
		Group:      "admin",
		Argv:       []string{"/usr/bin/tail", "-f", "/var/log/messages"},
		RecordType: events.RecordTypeStart,
	}
	execFailure := events.CommandEvent{
		Timestamp:  "2026-05-23T10:00:06Z",
		PID:        303,
		RecordType: events.RecordTypeFail,
		ExecErrno:  intPtr(2),
	}
	loss := events.CommandEvent{
		Timestamp:   "2026-05-23T10:00:07Z",
		RecordType:  events.RecordTypeLoss,
		LostSamples: int64Ptr(1),
	}

	got := mergeEventsForList([]events.CommandEvent{start, end, openStart, execFailure, loss}, nil)
	if len(got) != 4 {
		t.Fatalf("got len=%d want=4", len(got))
	}

	if got[0].RecordType != events.RecordTypeCommand {
		t.Fatalf("record_type=%q want=%q", got[0].RecordType, events.RecordTypeCommand)
	}
	if got[0].EndTimestamp != end.Timestamp {
		t.Fatalf("end_timestamp=%q want=%q", got[0].EndTimestamp, end.Timestamp)
	}
	if got[0].DurationNS == nil || *got[0].DurationNS != durationNS {
		t.Fatalf("duration_ns=%v want=%d", got[0].DurationNS, durationNS)
	}
	if got[0].ExitStatus == nil || *got[0].ExitStatus != exitStatus {
		t.Fatalf("exit_status=%v want=%d", got[0].ExitStatus, exitStatus)
	}

	if got[1].RecordType != events.RecordTypeCommand {
		t.Fatalf("open command record_type=%q want=%q", got[1].RecordType, events.RecordTypeCommand)
	}
	if got[1].EndTimestamp != "" || got[1].DurationNS != nil || got[1].ExitStatus != nil {
		t.Fatalf("open command should have empty end fields: %+v", got[1])
	}

	if got[2].RecordType != events.RecordTypeFail {
		t.Fatalf("record_type=%q want=%q", got[2].RecordType, events.RecordTypeFail)
	}
	if got[3].RecordType != events.RecordTypeLoss {
		t.Fatalf("record_type=%q want=%q", got[3].RecordType, events.RecordTypeLoss)
	}
}

func TestMergeEventsForStreamingStartThenEnd(t *testing.T) {
	t.Parallel()

	state := newCommandJoinState()
	start := events.CommandEvent{
		Timestamp:  "2026-05-23T10:00:00Z",
		EventID:    "boot-10",
		PID:        900,
		User:       "admin",
		Group:      "admin",
		Argv:       []string{"/bin/sleep", "3"},
		RecordType: events.RecordTypeStart,
	}
	durationNS := int64(3_000_000_000)
	exitStatus := 0
	end := events.CommandEvent{
		Timestamp:  "2026-05-23T10:00:03Z",
		EventID:    "boot-10",
		PID:        900,
		RecordType: events.RecordTypeEnd,
		DurationNS: &durationNS,
		ExitStatus: &exitStatus,
	}

	startOut, keep := mergeEventForStreaming(state, start, true)
	if !keep {
		t.Fatalf("start event should be emitted")
	}
	if len(state.pending) != 1 {
		t.Fatalf("pending len after start=%d want=1", len(state.pending))
	}
	if startOut.RecordType != events.RecordTypeCommand {
		t.Fatalf("start record_type=%q want=%q", startOut.RecordType, events.RecordTypeCommand)
	}
	if startOut.EndTimestamp != "" || startOut.DurationNS != nil || startOut.ExitStatus != nil {
		t.Fatalf("start should be provisional: %+v", startOut)
	}

	endOut, keep := mergeEventForStreaming(state, end, true)
	if !keep {
		t.Fatalf("end event should finalize the command")
	}
	if len(state.pending) != 0 {
		t.Fatalf("pending len after end=%d want=0", len(state.pending))
	}
	if endOut.RecordType != events.RecordTypeCommand {
		t.Fatalf("end record_type=%q want=%q", endOut.RecordType, events.RecordTypeCommand)
	}
	if endOut.EndTimestamp != end.Timestamp {
		t.Fatalf("end_timestamp=%q want=%q", endOut.EndTimestamp, end.Timestamp)
	}
	if endOut.DurationNS == nil || *endOut.DurationNS != durationNS {
		t.Fatalf("duration_ns=%v want=%d", endOut.DurationNS, durationNS)
	}
	if endOut.ExitStatus == nil || *endOut.ExitStatus != exitStatus {
		t.Fatalf("exit_status=%v want=%d", endOut.ExitStatus, exitStatus)
	}
}

func TestMergeEventsStreamingSkipsCommandEndWhenNotRequired(t *testing.T) {
	t.Parallel()

	start := events.CommandEvent{
		Timestamp:  "2026-05-23T10:00:00Z",
		EventID:    "boot-30",
		PID:        2001,
		User:       "admin",
		Group:      "admin",
		Argv:       []string{"/bin/sleep", "3"},
		RecordType: events.RecordTypeStart,
	}
	durationNS := int64(3_000_000_000)
	exitStatus := 0
	end := events.CommandEvent{
		Timestamp:  "2026-05-23T10:00:03Z",
		EventID:    "boot-30",
		PID:        2001,
		RecordType: events.RecordTypeEnd,
		DurationNS: &durationNS,
		ExitStatus: &exitStatus,
	}

	state := newCommandJoinState()
	_, keep := mergeEventForStreaming(state, start, false)
	if !keep {
		t.Fatalf("start event should be emitted without end processing")
	}
	if len(state.pending) != 0 {
		t.Fatalf("pending must stay empty when end is disabled: %d", len(state.pending))
	}
	if _, keep := mergeEventForStreaming(state, end, false); keep {
		t.Fatalf("end event should be skipped")
	}
}

func TestMergeEventsDurationQueryMatchesOnlyFinalizedRecord(t *testing.T) {
	t.Parallel()

	lf, err := buildQueryFilter([]string{"duration>=0000-00-00 00:00:01"})
	if err != nil {
		t.Fatalf("buildQueryFilter: %v", err)
	}

	state := newCommandJoinState()
	start := events.CommandEvent{
		Timestamp:  "2026-05-23T10:00:00Z",
		EventID:    "boot-20",
		PID:        1001,
		RecordType: events.RecordTypeStart,
		Argv:       []string{"/bin/sleep", "3"},
	}
	durationNS := int64(3_000_000_000)
	end := events.CommandEvent{
		Timestamp:  "2026-05-23T10:00:03Z",
		EventID:    "boot-20",
		PID:        1001,
		RecordType: events.RecordTypeEnd,
		DurationNS: &durationNS,
	}

	startOut, keep := mergeEventForStreaming(state, start, true)
	if !keep {
		t.Fatalf("start event should be emitted")
	}
	if matchFilter(startOut, lf) {
		t.Fatalf("provisional record must not match duration query")
	}

	endOut, keep := mergeEventForStreaming(state, end, true)
	if !keep {
		t.Fatalf("end event should finalize the command")
	}
	if !matchFilter(endOut, lf) {
		t.Fatalf("finalized record must match duration query")
	}
}
