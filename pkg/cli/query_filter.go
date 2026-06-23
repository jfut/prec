// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package cli

import (
	"github.com/jfut/prec/pkg/events"
	"github.com/jfut/prec/pkg/query"
)

func buildQueryFilter(specs []string) (listFilter, error) {
	compiled, err := query.Build(specs)
	if err != nil {
		return listFilter{}, err
	}
	return listFilter{
		compiled:              compiled,
		needsFinalizedCommand: compiled.NeedsFinalizedCommand(),
	}, nil
}

func matchFilter(ev events.CommandEvent, lf listFilter) bool {
	return lf.compiled.Match(ev)
}

func parseDurationValue(raw string) (int64, error) {
	return query.ParseDurationValue(raw)
}

func formatDurationValue(durationNS *int64) string {
	return query.FormatDurationValue(durationNS)
}
