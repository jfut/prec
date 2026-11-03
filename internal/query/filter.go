// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package query

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jfut/prec/internal/events"
)

var operators = []string{"!~=", ">=", "<=", "!=", "~=", ">", "<", "="}

const (
	fieldTypeString   = "string"
	fieldTypeNumber   = "number"
	fieldTypeTime     = "time"
	fieldTypeArray    = "array"
	fieldTypeDuration = "duration"

	secondsPerMinute = int64(60)
	secondsPerHour   = int64(60 * 60)
	secondsPerDay    = int64(24 * 60 * 60)
	secondsPerMonth  = int64(30 * 24 * 60 * 60)
	secondsPerYear   = int64(365 * 24 * 60 * 60)
	maxDurationSec   = int64(1<<63-1) / int64(time.Second)
)

// Predicate evaluates whether one event satisfies one condition.
type Predicate func(events.CommandEvent) bool

// Filter is a compiled query expression set.
type Filter struct {
	predicates            []Predicate
	needsFinalizedCommand bool
}

// Build compiles query specs into a reusable filter.
func Build(specs []string) (Filter, error) {
	out := Filter{
		predicates: make([]Predicate, 0),
	}
	// Treat repeated --query specs as cumulative AND conditions.
	// Inside one spec, support OR by "||" and AND by "&&".
	for _, spec := range specs {
		pred, needsFinalized, err := parseSpecExpression(spec)
		if err != nil {
			return Filter{}, err
		}
		out.predicates = append(out.predicates, pred)
		if needsFinalized {
			out.needsFinalizedCommand = true
		}
	}
	return out, nil
}

// Match returns true when all predicates match the event.
func (f Filter) Match(ev events.CommandEvent) bool {
	for _, pred := range f.predicates {
		if !pred(ev) {
			return false
		}
	}
	return true
}

// NeedsFinalizedCommand tells callers whether end records must be joined first.
func (f Filter) NeedsFinalizedCommand() bool {
	return f.needsFinalizedCommand
}

// SpecHasKey reports whether one query spec contains at least one clause key.
func SpecHasKey(spec string, key string) bool {
	orTerms, err := splitByDelimiter(spec, "||")
	if err != nil {
		return false
	}
	for _, orTerm := range orTerms {
		clauses, err := splitByAndDelimiters(orTerm)
		if err != nil {
			return false
		}
		for _, clause := range clauses {
			if clauseHasKey(clause, key) {
				return true
			}
		}
	}
	return false
}

func parseSpecExpression(spec string) (Predicate, bool, error) {
	orTerms, err := splitByDelimiter(spec, "||")
	if err != nil {
		return nil, false, err
	}
	disjunction := make([][]Predicate, 0, len(orTerms))
	needsFinalizedCommand := false
	for _, orTerm := range orTerms {
		clauses, err := splitByAndDelimiters(orTerm)
		if err != nil {
			return nil, false, err
		}
		conjunction := make([]Predicate, 0, len(clauses))
		for _, clause := range clauses {
			pred, needsFinalized, err := parseClause(clause)
			if err != nil {
				return nil, false, err
			}
			conjunction = append(conjunction, pred)
			if needsFinalized {
				needsFinalizedCommand = true
			}
		}
		disjunction = append(disjunction, conjunction)
	}
	return func(ev events.CommandEvent) bool {
		for _, conjunction := range disjunction {
			matched := true
			for _, pred := range conjunction {
				if !pred(ev) {
					matched = false
					break
				}
			}
			if matched {
				return true
			}
		}
		return false
	}, needsFinalizedCommand, nil
}

func splitByDelimiter(spec string, delimiter string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("invalid --query: empty clause")
	}
	out := make([]string, 0, 1)
	start := 0
	for {
		offset := strings.Index(spec[start:], delimiter)
		if offset < 0 {
			token := strings.TrimSpace(spec[start:])
			if token == "" {
				return nil, errors.New("invalid --query: empty clause")
			}
			out = append(out, token)
			return out, nil
		}
		pos := start + offset
		token := strings.TrimSpace(spec[start:pos])
		if token == "" {
			return nil, errors.New("invalid --query: empty clause")
		}
		out = append(out, token)
		start = pos + len(delimiter)
		if start >= len(spec) {
			return nil, errors.New("invalid --query: empty clause")
		}
	}
}

func splitByAndDelimiters(spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("invalid --query: empty clause")
	}
	out := make([]string, 0, 1)
	start := 0
	for i := 0; i < len(spec); {
		switch {
		case strings.HasPrefix(spec[i:], "&&"):
			token := strings.TrimSpace(spec[start:i])
			if token == "" {
				return nil, errors.New("invalid --query: empty clause")
			}
			out = append(out, token)
			i += 2
			start = i
		default:
			i++
		}
	}
	token := strings.TrimSpace(spec[start:])
	if token == "" {
		return nil, errors.New("invalid --query: empty clause")
	}
	out = append(out, token)
	return out, nil
}

func clauseHasKey(clause string, key string) bool {
	op, opPos := findOperator(clause)
	if op == "" || opPos <= 0 {
		return false
	}
	return strings.TrimSpace(clause[:opPos]) == key
}

func parseClause(clause string) (Predicate, bool, error) {
	op, opPos := findOperator(clause)
	if opPos <= 0 {
		return nil, false, fmt.Errorf("invalid --query clause: %s", clause)
	}
	key := strings.TrimSpace(clause[:opPos])
	val := strings.TrimSpace(clause[opPos+len(op):])
	if key == "" {
		return nil, false, errors.New("invalid --query: empty key")
	}
	if val == "" {
		return nil, false, fmt.Errorf("invalid --query: empty value for %s", key)
	}

	fieldType, ok := fieldTypeFor(key)
	if !ok {
		return nil, false, fmt.Errorf("invalid --query key: %s", key)
	}

	switch fieldType {
	case fieldTypeNumber:
		if !isSupportedNumberOperator(op) {
			return nil, false, fmt.Errorf("invalid --query operator for numeric field %s: %s", key, op)
		}
		right, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return nil, false, fmt.Errorf("invalid --query value for numeric field %s: %s", key, val)
		}
		return func(ev events.CommandEvent) bool {
			left, ok := numericValue(key, ev)
			if !ok {
				return false
			}
			return compareInt64(left, right, op)
		}, isFinalizedOnlyField(key), nil
	case fieldTypeTime:
		if !isSupportedNumberOperator(op) {
			return nil, false, fmt.Errorf("invalid --query operator for timestamp: %s", op)
		}
		right, err := parseQueryTime(val)
		if err != nil {
			return nil, false, fmt.Errorf("invalid --query value for timestamp: %s", val)
		}
		return func(ev events.CommandEvent) bool {
			left, ok := timeValue(key, ev)
			if !ok {
				return false
			}
			return compareTime(left, right, op)
		}, isFinalizedOnlyField(key), nil
	case fieldTypeString:
		if !isSupportedStringOperator(op) {
			return nil, false, fmt.Errorf("invalid --query operator for string field %s: %s", key, op)
		}
		if key == "source" {
			normalized, err := normalizeSourceValue(val)
			if err != nil {
				return nil, false, err
			}
			val = normalized
		}
		if key == "record_type" {
			normalized, err := normalizeRecordTypeValue(val)
			if err != nil {
				return nil, false, err
			}
			val = normalized
		}
		return func(ev events.CommandEvent) bool {
			return compareString(stringValue(key, ev), val, op)
		}, false, nil
	case fieldTypeArray:
		if !isSupportedStringOperator(op) {
			return nil, false, fmt.Errorf("invalid --query operator for array field %s: %s", key, op)
		}
		return func(ev events.CommandEvent) bool {
			left := strings.Join(ev.Argv, " ")
			return compareString(left, val, op)
		}, false, nil
	case fieldTypeDuration:
		if !isSupportedNumberOperator(op) {
			return nil, false, fmt.Errorf("invalid --query operator for duration field %s: %s", key, op)
		}
		rightNS, err := ParseDurationValue(val)
		if err != nil {
			return nil, false, fmt.Errorf("invalid --query value for duration: %s", val)
		}
		return func(ev events.CommandEvent) bool {
			leftNS, ok := durationValue(key, ev)
			if !ok {
				return false
			}
			return compareInt64(leftNS, rightNS, op)
		}, true, nil
	default:
		return nil, false, fmt.Errorf("invalid --query field type: %s", key)
	}
}

func findOperator(clause string) (string, int) {
	for _, op := range operators {
		idx := strings.Index(clause, op)
		if idx > 0 {
			return op, idx
		}
	}
	return "", -1
}

func fieldTypeFor(field string) (string, bool) {
	switch field {
	case "uid", "gid", "auid", "session_id", "pid", "ppid", "argc", "tty_nr", "exit_status", "duration_ns", "exec_errno", "lost_samples", "lost_samples_total", "parent_tty_nr", "file_fd", "file_bytes", "file_flags", "file_dev", "file_ino":
		return fieldTypeNumber, true
	case "timestamp", "end_timestamp":
		return fieldTypeTime, true
	case "duration":
		return fieldTypeDuration, true
	case "argv":
		return fieldTypeArray, true
	case "command", "record_type":
		return fieldTypeString, true
	default:
		if hasCommandEventField(field) {
			// Treat non-explicit fields as string to avoid per-field parser changes.
			return fieldTypeString, true
		}
		return "", false
	}
}

func isFinalizedOnlyField(field string) bool {
	switch field {
	case "end_timestamp", "exit_status", "duration_ns":
		return true
	default:
		return false
	}
}

func numericValue(field string, ev events.CommandEvent) (int64, bool) {
	switch field {
	case "uid":
		return int64(ev.UID), true
	case "gid":
		return int64(ev.GID), true
	case "auid":
		if ev.AUID == nil {
			return 0, false
		}
		return int64(*ev.AUID), true
	case "session_id":
		if ev.SessionID == nil {
			return 0, false
		}
		return int64(*ev.SessionID), true
	case "pid":
		return int64(ev.PID), true
	case "ppid":
		return int64(ev.PPID), true
	case "argc":
		return int64(ev.Argc), true
	case "tty_nr":
		return ev.TTYNr, true
	case "exit_status":
		if ev.ExitStatus == nil {
			return 0, false
		}
		return int64(*ev.ExitStatus), true
	case "duration_ns":
		if ev.DurationNS == nil {
			return 0, false
		}
		return *ev.DurationNS, true
	case "exec_errno":
		if ev.ExecErrno == nil {
			return 0, false
		}
		return int64(*ev.ExecErrno), true
	case "lost_samples":
		if ev.LostSamples == nil {
			return 0, false
		}
		return *ev.LostSamples, true
	case "lost_samples_total":
		if ev.LostTotal == nil {
			return 0, false
		}
		return *ev.LostTotal, true
	case "parent_tty_nr":
		return ev.ParentTTYNr, true
	case "file_fd":
		if ev.FileFD == nil {
			return 0, false
		}
		return int64(*ev.FileFD), true
	case "file_bytes":
		if ev.FileBytes == nil {
			return 0, false
		}
		return *ev.FileBytes, true
	case "file_flags":
		if ev.FileFlags == nil {
			return 0, false
		}
		return int64(*ev.FileFlags), true
	case "file_dev":
		if ev.FileDev == nil || *ev.FileDev > uint64(^uint64(0)>>1) {
			return 0, false
		}
		return int64(*ev.FileDev), true
	case "file_ino":
		if ev.FileIno == nil || *ev.FileIno > uint64(^uint64(0)>>1) {
			return 0, false
		}
		return int64(*ev.FileIno), true
	default:
		return 0, false
	}
}

func durationValue(field string, ev events.CommandEvent) (int64, bool) {
	switch field {
	case "duration":
		if ev.DurationNS == nil {
			return 0, false
		}
		return *ev.DurationNS, true
	default:
		return 0, false
	}
}

func stringValue(field string, ev events.CommandEvent) string {
	switch field {
	case "command":
		return commandText(ev)
	case "record_type":
		if ev.RecordType == "" {
			return events.RecordTypeCommand
		}
		return ev.RecordType
	default:
		if val, ok := commandEventFieldStringValue(field, ev); ok {
			return val
		}
		return ""
	}
}

func hasCommandEventField(key string) bool {
	switch key {
	case "timestamp", "end_timestamp", "event_id", "uid", "gid", "auid", "session_id",
		"user", "group", "pid", "ppid", "comm", "exe", "cwd", "argv", "argc",
		"cgroup", "tty", "tty_nr", "source", "record_type", "exit_status", "duration_ns",
		"exec_errno", "exec_error", "lost_samples", "lost_samples_total", "parent_comm",
		"parent_exe", "parent_cmdline", "parent_tty", "parent_tty_nr", "file_path", "file_fd",
		"file_bytes", "file_flags", "file_dev", "file_ino":
		return true
	default:
		return false
	}
}

func commandEventFieldStringValue(key string, ev events.CommandEvent) (string, bool) {
	switch key {
	case "event_id":
		return ev.EventID, true
	case "user":
		return ev.User, true
	case "group":
		return ev.Group, true
	case "comm":
		return ev.Comm, true
	case "exe":
		return ev.Exe, true
	case "cwd":
		return ev.Cwd, true
	case "cgroup":
		return ev.Cgroup, true
	case "tty":
		return ev.TTY, true
	case "source":
		return ev.Source, true
	case "exec_error":
		return ev.ExecError, true
	case "parent_comm":
		return ev.ParentComm, true
	case "parent_exe":
		return ev.ParentExe, true
	case "parent_cmdline":
		return ev.ParentCmdline, true
	case "parent_tty":
		return ev.ParentTTY, true
	case "file_path":
		return ev.FilePath, true
	default:
		return "", false
	}
}

func timeValue(field string, ev events.CommandEvent) (time.Time, bool) {
	switch field {
	case "timestamp":
		return parseEventTimestamp(ev.Timestamp)
	case "end_timestamp":
		return parseEventTimestamp(ev.EndTimestamp)
	default:
		return time.Time{}, false
	}
}

func parseEventTimestamp(raw string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func parseQueryTime(raw string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, raw)
}

// ParseDurationValue parses YYYY-MM-DD HH:MM:SS into nanoseconds.
func ParseDurationValue(raw string) (int64, error) {
	trimmed := strings.TrimSpace(raw)
	dateTime := strings.Fields(trimmed)
	if len(dateTime) != 2 {
		return 0, errors.New("invalid duration format")
	}
	dateParts := strings.Split(dateTime[0], "-")
	timeParts := strings.Split(dateTime[1], ":")
	if len(dateParts) != 3 || len(timeParts) != 3 {
		return 0, errors.New("invalid duration format")
	}
	parts := append(dateParts, timeParts...)
	values := make([]int64, len(parts))
	for i, part := range parts {
		if part == "" {
			return 0, errors.New("invalid duration format")
		}
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return 0, errors.New("invalid duration format")
			}
		}
		value, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return 0, errors.New("invalid duration format")
		}
		values[i] = value
	}
	months, days := values[1], values[2]
	hours, minutes, seconds := values[3], values[4], values[5]
	if months >= 12 || days >= 31 || hours >= 24 || minutes >= 60 || seconds >= 60 {
		return 0, errors.New("duration component out of range")
	}

	units := [...]int64{secondsPerYear, secondsPerMonth, secondsPerDay, secondsPerHour, secondsPerMinute, 1}
	var totalSec int64
	for i, value := range values {
		if value > (maxDurationSec-totalSec)/units[i] {
			return 0, errors.New("duration is too large")
		}
		totalSec += value * units[i]
	}
	return totalSec * int64(time.Second), nil
}

// FormatDurationValue converts nanoseconds into YYYY-MM-DD HH:MM:SS.
func FormatDurationValue(durationNS *int64) string {
	if durationNS == nil {
		return ""
	}

	totalSec := *durationNS / int64(time.Second)
	if totalSec < 0 {
		totalSec = 0
	}

	years := totalSec / secondsPerYear
	totalSec %= secondsPerYear
	months := totalSec / secondsPerMonth
	totalSec %= secondsPerMonth
	days := totalSec / secondsPerDay
	totalSec %= secondsPerDay
	hours := totalSec / secondsPerHour
	totalSec %= secondsPerHour
	minutes := totalSec / secondsPerMinute
	seconds := totalSec % secondsPerMinute

	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", years, months, days, hours, minutes, seconds)
}

func normalizeSourceValue(raw string) (string, error) {
	switch raw {
	case events.SourceUser:
		return events.SourceUser, nil
	case events.SourceSystem:
		return events.SourceSystem, nil
	default:
		return "", fmt.Errorf("invalid --query value for source: %s", raw)
	}
}

func normalizeRecordTypeValue(raw string) (string, error) {
	switch raw {
	case events.RecordTypeCommand:
		return events.RecordTypeCommand, nil
	case events.RecordTypeFail:
		return events.RecordTypeFail, nil
	case events.RecordTypeLoss:
		return events.RecordTypeLoss, nil
	case events.RecordTypeFileOpen:
		return events.RecordTypeFileOpen, nil
	case events.RecordTypeFileSave:
		return events.RecordTypeFileSave, nil
	default:
		return "", fmt.Errorf("invalid --query value for record_type: %s", raw)
	}
}

func isSupportedNumberOperator(op string) bool {
	switch op {
	case "=", "!=", ">", ">=", "<", "<=":
		return true
	default:
		return false
	}
}

func isSupportedStringOperator(op string) bool {
	switch op {
	case "=", "!=", "~=", "!~=":
		return true
	default:
		return false
	}
}

func compareInt64(left int64, right int64, op string) bool {
	switch op {
	case "=":
		return left == right
	case "!=":
		return left != right
	case ">":
		return left > right
	case ">=":
		return left >= right
	case "<":
		return left < right
	case "<=":
		return left <= right
	default:
		return false
	}
}

func compareTime(left time.Time, right time.Time, op string) bool {
	switch op {
	case "=":
		return left.Equal(right)
	case "!=":
		return !left.Equal(right)
	case ">":
		return left.After(right)
	case ">=":
		return left.After(right) || left.Equal(right)
	case "<":
		return left.Before(right)
	case "<=":
		return left.Before(right) || left.Equal(right)
	default:
		return false
	}
}

func compareString(left string, right string, op string) bool {
	switch op {
	case "=":
		return left == right
	case "!=":
		return left != right
	case "~=":
		return strings.Contains(left, right)
	case "!~=":
		return !strings.Contains(left, right)
	default:
		return false
	}
}

func commandText(ev events.CommandEvent) string {
	cmd := strings.Join(ev.Argv, " ")
	if cmd == "" {
		cmd = ev.Exe
	}
	if cmd == "" {
		cmd = ev.Comm
	}
	return cmd
}
