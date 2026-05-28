package cli

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jfut/prec/pkg/events"
)

// outputFormatter hides per-format encoding details from list/follow flows.
type outputFormatter interface {
	Header() string
	Format(ev events.CommandEvent) string
}

type simpleTextFormatter struct {
	fullTime bool
}

func (f simpleTextFormatter) Header() string {
	return ""
}

func (f simpleTextFormatter) Format(ev events.CommandEvent) string {
	return formatEventSimple(ev, f.fullTime)
}

type structuredTextFormatter struct {
	fullTime bool
	fields   []string
}

func (f structuredTextFormatter) Header() string {
	return ""
}

func (f structuredTextFormatter) Format(ev events.CommandEvent) string {
	return strings.Join(csvRecord(ev, outputOptions{fullTime: f.fullTime}, f.fields), " ")
}

type jsonFormatter struct {
	fullTime bool
	fields   []string
}

func (f jsonFormatter) Header() string {
	return ""
}

func (f jsonFormatter) Format(ev events.CommandEvent) string {
	b, err := json.Marshal(jsonRecord(ev, outputOptions{fullTime: f.fullTime}, f.fields))
	if err != nil {
		return ""
	}
	return string(b)
}

type csvFormatter struct {
	fullTime bool
	fields   []string
}

func (f csvFormatter) Header() string {
	return csvHeaderLine(f.fields)
}

func (f csvFormatter) Format(ev events.CommandEvent) string {
	line, err := csvRecordLine(csvRecord(ev, outputOptions{fullTime: f.fullTime}, f.fields))
	if err != nil {
		return ""
	}
	return line
}

func newOutputFormatter(opt outputOptions) outputFormatter {
	fields := resolveStructuredOutputFields(opt)

	switch opt.format {
	case outputFormatJSON:
		return jsonFormatter{fullTime: opt.fullTime, fields: fields}
	case outputFormatCSV:
		return csvFormatter{fullTime: opt.fullTime, fields: fields}
	default:
		if len(opt.fields) > 0 {
			return structuredTextFormatter{fullTime: opt.fullTime, fields: fields}
		}
		return simpleTextFormatter{fullTime: opt.fullTime}
	}
}

func formatEventForOutput(ev events.CommandEvent, opt outputOptions) string {
	return newOutputFormatter(opt).Format(ev)
}

func formatEventSimple(ev events.CommandEvent, fullTime bool) string {
	userName := ev.User
	if userName == "" {
		userName = "-"
	}
	groupName := ev.Group
	if groupName == "" {
		groupName = "-"
	}
	return fmt.Sprintf("%s %s %s %s", formatTimestamp(ev.Timestamp, fullTime), userName, groupName, commandText(ev))
}

func formatTimestamp(raw string, fullTime bool) string {
	if raw == "" {
		return ""
	}
	if fullTime {
		return raw
	}
	t, ok := parseTimestamp(raw)
	if !ok {
		return raw
	}
	return t.Format("2006-01-02 15:04:05")
}

func renderEvents(eventsIn []events.CommandEvent, opt outputOptions) []string {
	return renderEventsWithFormatter(eventsIn, opt, newOutputFormatter(opt))
}

func renderEventsWithFormatter(eventsIn []events.CommandEvent, opt outputOptions, formatter outputFormatter) []string {
	if !opt.tree {
		lines := make([]string, 0, len(eventsIn))
		for _, ev := range eventsIn {
			lines = append(lines, formatter.Format(ev))
		}
		return lines
	}
	return renderEventTreeWithFormatter(eventsIn, formatter)
}

type treeRenderNode struct {
	ev    events.CommandEvent
	depth int
}

func renderEventTreeWithFormatter(eventsIn []events.CommandEvent, formatter outputFormatter) []string {
	nodes := make([]treeRenderNode, 0, len(eventsIn))
	pidToIndex := make(map[int]int, len(eventsIn))
	lines := make([]string, 0, len(eventsIn))

	for _, ev := range eventsIn {
		depth := 0
		if idx, ok := pidToIndex[ev.PPID]; ok {
			depth = nodes[idx].depth + 1
		} else if idx, ok := findSyntheticTreeParent(nodes, ev); ok {
			depth = nodes[idx].depth + 1
		}

		nodes = append(nodes, treeRenderNode{ev: ev, depth: depth})
		pidToIndex[ev.PID] = len(nodes) - 1
		lines = append(lines, treePrefix(depth)+formatter.Format(ev))
	}
	return lines
}

func treePrefix(depth int) string {
	if depth <= 0 {
		return ""
	}
	// Use a unified `- style for tree output.
	return strings.Repeat("  ", depth-1) + "`- "
}

func findSyntheticTreeParent(nodes []treeRenderNode, cur events.CommandEvent) (int, bool) {
	for i := len(nodes) - 1; i >= 0; i-- {
		if shouldLinkAsTreeChild(nodes[i].ev, cur) {
			return i, true
		}
	}
	return 0, false
}

func shouldLinkAsTreeChild(parent events.CommandEvent, cur events.CommandEvent) bool {
	if parent.UID != cur.UID {
		return false
	}
	if parent.Source != cur.Source {
		return false
	}
	if parent.PPID != cur.PPID {
		return false
	}
	if parent.ParentTTYNr != 0 && cur.ParentTTYNr != 0 && parent.ParentTTYNr != cur.ParentTTYNr {
		return false
	}
	if canonicalTreeCommand(parent) != canonicalTreeCommand(cur) {
		return false
	}

	parentTS, okParent := parseTimestamp(parent.Timestamp)
	curTS, okCur := parseTimestamp(cur.Timestamp)
	if !okParent || !okCur {
		return false
	}
	delta := curTS.Sub(parentTS)
	return delta >= 0 && delta <= treeLinkWindow
}

func canonicalTreeCommand(ev events.CommandEvent) string {
	argv := ev.Argv
	if len(argv) >= 4 && strings.HasSuffix(filepath.Base(argv[0]), "aqua") && argv[1] == "exec" && argv[2] == "--" {
		return normalizeArgvForTree(argv[3:])
	}
	return normalizeArgvForTree(argv)
}

func normalizeArgvForTree(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	tokens := append([]string(nil), argv...)
	tokens[0] = filepath.Base(tokens[0])
	return strings.Join(tokens, " ")
}

func parseTimestamp(raw string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func csvHeaderLine(fields []string) string {
	line, err := csvRecordLine(fields)
	if err != nil {
		return ""
	}
	return line
}

func csvRecord(ev events.CommandEvent, opt outputOptions, fields []string) []string {
	record := make([]string, 0, len(fields))
	for _, field := range fields {
		record = append(record, formatOutputFieldValue(field, ev, opt.fullTime))
	}
	return record
}

func jsonRecord(ev events.CommandEvent, opt outputOptions, fields []string) map[string]any {
	record := make(map[string]any, len(fields))
	for _, field := range fields {
		record[field] = outputFieldValue(field, ev, opt.fullTime)
	}
	return record
}

func csvRecordLine(record []string) (string, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if err := w.Write(record); err != nil {
		return "", err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return "", err
	}
	return strings.TrimSuffix(b.String(), "\n"), nil
}

func parseOutputFields(spec string) ([]string, error) {
	if spec == "" {
		return nil, nil
	}
	rawFields := strings.Split(spec, ",")
	fields := make([]string, 0, len(rawFields))
	seen := make(map[string]struct{}, len(rawFields))
	currentOp := byte(0)
	initialized := false

	// If the first token starts with +|-, start from defaults; otherwise use explicit-only mode.
	initDefault := func() {
		fields = append(fields, defaultOutputFields()...)
		seen = make(map[string]struct{}, len(fields)+len(rawFields))
		for _, field := range fields {
			seen[field] = struct{}{}
		}
		initialized = true
	}
	initExplicit := func() {
		fields = make([]string, 0, len(rawFields))
		seen = make(map[string]struct{}, len(rawFields))
		initialized = true
	}

	for _, raw := range rawFields {
		token := strings.TrimSpace(raw)
		if token == "" {
			return nil, fmt.Errorf("invalid --fields: empty field name")
		}

		op := byte(0)
		fieldToken := token
		if token[0] == '+' || token[0] == '-' {
			op = token[0]
			fieldToken = strings.TrimSpace(token[1:])
			if fieldToken == "" {
				return nil, fmt.Errorf("invalid --fields: empty field name")
			}
			currentOp = op
		} else if currentOp == '+' || currentOp == '-' {
			op = currentOp
		}

		var expanded []string
		if fieldToken == "all" {
			expanded = allOutputFields()
		} else {
			if !isSupportedOutputField(fieldToken) {
				return nil, fmt.Errorf("invalid --fields name: %s", fieldToken)
			}
			expanded = []string{fieldToken}
		}

		if op == 0 {
			if !initialized {
				initExplicit()
			}
			for _, field := range expanded {
				if _, ok := seen[field]; ok {
					continue
				}
				seen[field] = struct{}{}
				fields = append(fields, field)
			}
			continue
		}

		if !initialized {
			initDefault()
		}
		switch op {
		case '+':
			for _, field := range expanded {
				if _, ok := seen[field]; ok {
					continue
				}
				seen[field] = struct{}{}
				fields = append(fields, field)
			}
		case '-':
			for _, field := range expanded {
				if _, ok := seen[field]; !ok {
					continue
				}
				delete(seen, field)
				next := make([]string, 0, len(fields)-1)
				for _, existing := range fields {
					if existing == field {
						continue
					}
					next = append(next, existing)
				}
				fields = next
			}
		}
	}
	return fields, nil
}

func isSupportedOutputField(field string) bool {
	switch field {
	case "timestamp",
		"end_timestamp",
		"event_id",
		"command",
		"uid",
		"gid",
		"auid",
		"session_id",
		"user",
		"group",
		"pid",
		"ppid",
		"comm",
		"exe",
		"cwd",
		"argv",
		"argc",
		"cgroup",
		"tty",
		"tty_nr",
		"source",
		"record_type",
		"exit_status",
		"duration_ns",
		"duration",
		"exec_errno",
		"exec_error",
		"lost_samples",
		"lost_samples_total",
		"parent_comm",
		"parent_exe",
		"parent_cmdline",
		"parent_tty",
		"parent_tty_nr":
		return true
	default:
		return false
	}
}

func formatOutputFieldValue(field string, ev events.CommandEvent, fullTime bool) string {
	v := outputFieldValue(field, ev, fullTime)
	switch val := v.(type) {
	case string:
		return val
	case []string:
		return strings.Join(val, " ")
	case uint32:
		return strconv.FormatUint(uint64(val), 10)
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case nil:
		return ""
	default:
		return fmt.Sprint(val)
	}
}

func outputFieldValue(field string, ev events.CommandEvent, fullTime bool) any {
	switch field {
	case "timestamp":
		return formatTimestamp(ev.Timestamp, fullTime)
	case "end_timestamp":
		return formatTimestamp(ev.EndTimestamp, fullTime)
	case "event_id":
		return ev.EventID
	case "command":
		return commandText(ev)
	case "uid":
		return ev.UID
	case "gid":
		return ev.GID
	case "auid":
		if ev.AUID == nil {
			return nil
		}
		return *ev.AUID
	case "session_id":
		if ev.SessionID == nil {
			return nil
		}
		return *ev.SessionID
	case "user":
		return ev.User
	case "group":
		return ev.Group
	case "pid":
		return ev.PID
	case "ppid":
		return ev.PPID
	case "comm":
		return ev.Comm
	case "exe":
		return ev.Exe
	case "cwd":
		return ev.Cwd
	case "argv":
		return ev.Argv
	case "argc":
		return ev.Argc
	case "cgroup":
		return ev.Cgroup
	case "tty":
		return ev.TTY
	case "tty_nr":
		return ev.TTYNr
	case "source":
		return ev.Source
	case "record_type":
		if ev.RecordType == "" {
			return events.RecordTypeCommand
		}
		return ev.RecordType
	case "exit_status":
		if ev.ExitStatus == nil {
			return nil
		}
		return *ev.ExitStatus
	case "duration_ns":
		if ev.DurationNS == nil {
			return nil
		}
		return *ev.DurationNS
	case "duration":
		return formatDurationValue(ev.DurationNS)
	case "exec_errno":
		if ev.ExecErrno == nil {
			return nil
		}
		return *ev.ExecErrno
	case "exec_error":
		return ev.ExecError
	case "lost_samples":
		if ev.LostSamples == nil {
			return nil
		}
		return *ev.LostSamples
	case "lost_samples_total":
		if ev.LostTotal == nil {
			return nil
		}
		return *ev.LostTotal
	case "parent_comm":
		return ev.ParentComm
	case "parent_exe":
		return ev.ParentExe
	case "parent_cmdline":
		return ev.ParentCmdline
	case "parent_tty":
		return ev.ParentTTY
	case "parent_tty_nr":
		return ev.ParentTTYNr
	default:
		return ""
	}
}

func resolveStructuredOutputFields(opt outputOptions) []string {
	if len(opt.fields) > 0 {
		out := make([]string, len(opt.fields))
		copy(out, opt.fields)
		return out
	}
	return defaultOutputFields()
}

func requiresCommandEndProcessing(lf listFilter, opt outputOptions) bool {
	if lf.needsFinalizedCommand {
		return true
	}
	for _, field := range resolveStructuredOutputFields(opt) {
		if isFinalizedOnlyOutputField(field) {
			return true
		}
	}
	return false
}

func isFinalizedOnlyOutputField(field string) bool {
	switch field {
	case "end_timestamp", "exit_status", "duration_ns", "duration":
		return true
	default:
		return false
	}
}

func defaultOutputFields() []string {
	return []string{"timestamp", "user", "group", "command"}
}

func allOutputFields() []string {
	return []string{
		"timestamp",
		"user",
		"group",
		"command",
		"end_timestamp",
		"event_id",
		"uid",
		"gid",
		"auid",
		"session_id",
		"pid",
		"ppid",
		"comm",
		"exe",
		"cwd",
		"argv",
		"argc",
		"cgroup",
		"tty",
		"tty_nr",
		"source",
		"record_type",
		"exit_status",
		"duration_ns",
		"duration",
		"exec_errno",
		"exec_error",
		"lost_samples",
		"lost_samples_total",
		"parent_comm",
		"parent_exe",
		"parent_cmdline",
		"parent_tty",
		"parent_tty_nr",
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
