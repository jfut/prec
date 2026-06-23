// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package query

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jfut/prec/pkg/events"
)

var operators = []string{"!~=", ">=", "<=", "!=", "~=", ">", "<", "="}

var (
	commandEventFieldIndexOnce sync.Once
	commandEventFieldIndex     map[string]int
)

const (
	fieldTypeString   = "string"
	fieldTypeNumber   = "number"
	fieldTypeTime     = "time"
	fieldTypeArray    = "array"
	fieldTypeDuration = "duration"
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
	case "uid", "gid", "auid", "session_id", "pid", "ppid", "argc", "tty_nr", "exit_status", "duration_ns", "exec_errno", "lost_samples", "lost_samples_total", "parent_tty_nr":
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
	initCommandEventFieldIndex()
	_, ok := commandEventFieldIndex[key]
	return ok
}

func commandEventFieldStringValue(key string, ev events.CommandEvent) (string, bool) {
	initCommandEventFieldIndex()
	idx, ok := commandEventFieldIndex[key]
	if !ok {
		return "", false
	}
	v := reflect.ValueOf(ev).Field(idx)
	return stringifyReflectValue(v), true
}

func initCommandEventFieldIndex() {
	commandEventFieldIndexOnce.Do(func() {
		t := reflect.TypeOf(events.CommandEvent{})
		idx := make(map[string]int, t.NumField())
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("json")
			if tag == "" {
				continue
			}
			name := strings.TrimSpace(strings.Split(tag, ",")[0])
			if name == "" || name == "-" {
				continue
			}
			idx[name] = i
		}
		commandEventFieldIndex = idx
	})
}

func stringifyReflectValue(v reflect.Value) string {
	if !v.IsValid() {
		return ""
	}
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return ""
		}
		return stringifyReflectValue(v.Elem())
	}
	if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.String {
		parts := make([]string, v.Len())
		for i := 0; i < v.Len(); i++ {
			parts[i] = v.Index(i).String()
		}
		return strings.Join(parts, " ")
	}
	return fmt.Sprint(v.Interface())
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
	const (
		secPerMinute = int64(60)
		secPerHour   = int64(60 * 60)
		secPerDay    = int64(24 * 60 * 60)
		secPerMonth  = int64(30 * 24 * 60 * 60)
		secPerYear   = int64(365 * 24 * 60 * 60)
	)

	trimmed := strings.TrimSpace(raw)
	var years, months, days, hours, minutes, seconds int64
	n, err := fmt.Sscanf(trimmed, "%d-%d-%d %d:%d:%d", &years, &months, &days, &hours, &minutes, &seconds)
	if err != nil || n != 6 {
		return 0, errors.New("invalid duration format")
	}
	if years < 0 || months < 0 || days < 0 || hours < 0 || minutes < 0 || seconds < 0 {
		return 0, errors.New("duration must be non-negative")
	}
	if months >= 12 || days >= 31 || hours >= 24 || minutes >= 60 || seconds >= 60 {
		return 0, errors.New("duration component out of range")
	}

	totalSec := years*secPerYear +
		months*secPerMonth +
		days*secPerDay +
		hours*secPerHour +
		minutes*secPerMinute +
		seconds
	return totalSec * int64(time.Second), nil
}

// FormatDurationValue converts nanoseconds into YYYY-MM-DD HH:MM:SS.
func FormatDurationValue(durationNS *int64) string {
	if durationNS == nil {
		return ""
	}

	const (
		secPerMinute = int64(60)
		secPerHour   = int64(60 * 60)
		secPerDay    = int64(24 * 60 * 60)
		secPerMonth  = int64(30 * 24 * 60 * 60)
		secPerYear   = int64(365 * 24 * 60 * 60)
	)

	totalSec := *durationNS / int64(time.Second)
	if totalSec < 0 {
		totalSec = 0
	}

	years := totalSec / secPerYear
	totalSec %= secPerYear
	months := totalSec / secPerMonth
	totalSec %= secPerMonth
	days := totalSec / secPerDay
	totalSec %= secPerDay
	hours := totalSec / secPerHour
	totalSec %= secPerHour
	minutes := totalSec / secPerMinute
	seconds := totalSec % secPerMinute

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
	case events.RecordTypeStart:
		return events.RecordTypeStart, nil
	case events.RecordTypeEnd:
		return events.RecordTypeEnd, nil
	case events.RecordTypeFail:
		return events.RecordTypeFail, nil
	case events.RecordTypeLoss:
		return events.RecordTypeLoss, nil
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
