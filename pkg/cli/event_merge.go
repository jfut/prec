// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package cli

import "github.com/jfut/prec/pkg/events"

type commandJoinState struct {
	pending map[string]events.CommandEvent
}

func newCommandJoinState() *commandJoinState {
	return &commandJoinState{pending: make(map[string]events.CommandEvent)}
}

func mergeEventsForList(raw []events.CommandEvent, joinState *commandJoinState, includeCommandEnd bool) []events.CommandEvent {
	state := joinState
	if state == nil {
		state = newCommandJoinState()
	}

	out := make([]events.CommandEvent, 0, len(raw))
	indexByEventID := make(map[string]int)
	for _, ev := range raw {
		if ev.RecordType == events.RecordTypeCommand {
			// Old single-record command logs are not supported after start/end split.
			continue
		}
		if isMergeCandidateRecordType(ev.RecordType) {
			for _, merged := range mergeEventsForStreaming(state, ev, includeCommandEnd) {
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
			}
			continue
		}
		out = append(out, ev)
	}
	return out
}

func mergeEventsForStreaming(state *commandJoinState, ev events.CommandEvent, includeCommandEnd bool) []events.CommandEvent {
	if state == nil {
		state = newCommandJoinState()
	}

	if !includeCommandEnd {
		switch ev.RecordType {
		case events.RecordTypeStart:
			return []events.CommandEvent{mergedCommandFromStart(ev)}
		case events.RecordTypeEnd, events.RecordTypeCommand:
			return nil
		default:
			return []events.CommandEvent{ev}
		}
	}

	if !isMergeCandidateRecordType(ev.RecordType) {
		if ev.RecordType == events.RecordTypeCommand {
			return nil
		}
		return []events.CommandEvent{ev}
	}
	if ev.EventID == "" {
		return nil
	}

	switch ev.RecordType {
	case events.RecordTypeStart:
		merged := mergedCommandFromStart(ev)
		state.pending[ev.EventID] = merged
		return []events.CommandEvent{merged}
	case events.RecordTypeEnd:
		start, ok := state.pending[ev.EventID]
		if !ok {
			return nil
		}
		merged := applyCommandEnd(start, ev)
		// The command is finalized, so remove it from pending to keep memory usage stable.
		delete(state.pending, ev.EventID)
		return []events.CommandEvent{merged}
	default:
		return nil
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
