// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package cli

import "github.com/jfut/prec/internal/events"

type commandJoinState struct {
	pending map[string]events.CommandEvent
}

func newCommandJoinState() *commandJoinState {
	return &commandJoinState{pending: make(map[string]events.CommandEvent)}
}

func mergeEventsForList(raw []events.CommandEvent, joinState *commandJoinState) []events.CommandEvent {
	state := joinState
	if state == nil {
		state = newCommandJoinState()
	}

	rawLen := len(raw)
	// Compact in place because each source record emits at most one list row.
	out := raw[:0]
	indexByEventID := make(map[string]int)
	for _, ev := range raw {
		if ev.RecordType == events.RecordTypeCommand {
			// Old single-record command logs are not supported after start/end split.
			continue
		}
		if isMergeCandidateRecordType(ev.RecordType) {
			merged, keep := mergeEventForStreaming(state, ev, true)
			if !keep {
				continue
			}
			if merged.EventID == "" {
				out = append(out, merged)
				continue
			}
			idx, exists := indexByEventID[merged.EventID]
			if !exists {
				indexByEventID[merged.EventID] = len(out)
				out = append(out, merged)
				continue
			}
			out[idx] = merged
			continue
		}
		out = append(out, ev)
	}
	clear(raw[len(out):rawLen])
	return out
}

func mergeEventForStreaming(state *commandJoinState, ev events.CommandEvent, includeCommandEnd bool) (events.CommandEvent, bool) {
	if !includeCommandEnd {
		return mergedEventWithoutCommandEnd(ev)
	}
	if state == nil {
		state = newCommandJoinState()
	}

	if !isMergeCandidateRecordType(ev.RecordType) {
		if ev.RecordType == events.RecordTypeCommand {
			return events.CommandEvent{}, false
		}
		return ev, true
	}
	if ev.EventID == "" {
		return events.CommandEvent{}, false
	}

	switch ev.RecordType {
	case events.RecordTypeStart:
		merged := mergedCommandFromStart(ev)
		state.pending[ev.EventID] = merged
		return merged, true
	case events.RecordTypeEnd:
		start, ok := state.pending[ev.EventID]
		if !ok {
			return events.CommandEvent{}, false
		}
		merged := applyCommandEnd(start, ev)
		// The command is finalized, so remove it from pending to keep memory usage stable.
		delete(state.pending, ev.EventID)
		return merged, true
	default:
		return events.CommandEvent{}, false
	}
}

func isMergeCandidateRecordType(recordType string) bool {
	return recordType == events.RecordTypeStart || recordType == events.RecordTypeEnd
}

func mergedCommandFromStart(start events.CommandEvent) events.CommandEvent {
	merged := start
	merged.RecordType = events.RecordTypeCommand
	merged.EndTimestamp = ""
	merged.DurationNS = nil
	merged.ExitStatus = nil
	return merged
}

func applyCommandEnd(start events.CommandEvent, end events.CommandEvent) events.CommandEvent {
	merged := start
	merged.RecordType = events.RecordTypeCommand
	merged.EndTimestamp = end.Timestamp
	if end.DurationNS != nil {
		durationNS := *end.DurationNS
		merged.DurationNS = &durationNS
	}
	if end.ExitStatus != nil {
		exitStatus := *end.ExitStatus
		merged.ExitStatus = &exitStatus
	}
	return merged
}

func mergedEventWithoutCommandEnd(ev events.CommandEvent) (events.CommandEvent, bool) {
	switch ev.RecordType {
	case events.RecordTypeStart:
		return mergedCommandFromStart(ev), true
	case events.RecordTypeEnd, events.RecordTypeCommand:
		return events.CommandEvent{}, false
	default:
		return ev, true
	}
}
