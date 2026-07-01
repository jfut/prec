// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package events

import "encoding/json"

func (ev CommandEvent) MarshalJSON() ([]byte, error) {
	// end is intentionally serialized with only join/timing fields to keep logs compact.
	if ev.RecordType == RecordTypeEnd {
		type compactCommandEnd struct {
			Timestamp  string `json:"timestamp"`
			EventID    string `json:"event_id,omitempty"`
			PID        int    `json:"pid"`
			Source     string `json:"source,omitempty"`
			RecordType string `json:"record_type,omitempty"`
			ExitStatus *int   `json:"exit_status,omitempty"`
			DurationNS *int64 `json:"duration_ns,omitempty"`
		}
		return json.Marshal(compactCommandEnd{
			Timestamp:  ev.Timestamp,
			EventID:    ev.EventID,
			PID:        ev.PID,
			Source:     ev.Source,
			RecordType: ev.RecordType,
			ExitStatus: ev.ExitStatus,
			DurationNS: ev.DurationNS,
		})
	}

	type alias CommandEvent
	return json.Marshal(alias(ev))
}
