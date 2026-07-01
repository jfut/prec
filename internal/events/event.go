// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package events

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// CommandEvent is one JSONL record that represents a single exec event.
type CommandEvent struct {
	Timestamp     string   `json:"timestamp"`
	EndTimestamp  string   `json:"end_timestamp,omitempty"`
	EventID       string   `json:"event_id,omitempty"`
	UID           uint32   `json:"uid"`
	GID           uint32   `json:"gid"`
	AUID          *uint32  `json:"auid,omitempty"`
	SessionID     *uint32  `json:"session_id,omitempty"`
	User          string   `json:"user"`
	Group         string   `json:"group"`
	PID           int      `json:"pid"`
	PPID          int      `json:"ppid"`
	Comm          string   `json:"comm"`
	Exe           string   `json:"exe"`
	Cwd           string   `json:"cwd"`
	Argv          []string `json:"argv"`
	Argc          int      `json:"argc"`
	Cgroup        string   `json:"cgroup,omitempty"`
	TTY           string   `json:"tty,omitempty"`
	TTYNr         int64    `json:"tty_nr,omitempty"`
	Source        string   `json:"source,omitempty"`
	RecordType    string   `json:"record_type,omitempty"`
	ExitStatus    *int     `json:"exit_status,omitempty"`
	DurationNS    *int64   `json:"duration_ns,omitempty"`
	ExecErrno     *int     `json:"exec_errno,omitempty"`
	ExecError     string   `json:"exec_error,omitempty"`
	LostSamples   *int64   `json:"lost_samples,omitempty"`
	LostTotal     *int64   `json:"lost_samples_total,omitempty"`
	ParentComm    string   `json:"parent_comm,omitempty"`
	ParentExe     string   `json:"parent_exe,omitempty"`
	ParentCmdline string   `json:"parent_cmdline,omitempty"`
	ParentTTY     string   `json:"parent_tty,omitempty"`
	ParentTTYNr   int64    `json:"parent_tty_nr,omitempty"`
}

type statusInfo struct {
	UID  uint32
	GID  uint32
	PPID int
	Name string
}

var userCache sync.Map
var groupCache sync.Map

func BuildFromPID(pid int, maxArgs int, maxArgLength int, exeHint string, kernelTimestamp string, eventID string) (CommandEvent, error) {
	procDir := filepath.Join("/proc", strconv.Itoa(pid))

	st, err := parseStatus(filepath.Join(procDir, "status"))
	if err != nil {
		return CommandEvent{}, err
	}

	comm, _ := readTrimmed(filepath.Join(procDir, "comm"))
	if comm == "" {
		comm = st.Name
	}

	exe, _ := os.Readlink(filepath.Join(procDir, "exe"))
	cwd, _ := os.Readlink(filepath.Join(procDir, "cwd"))

	argv, _ := parseCmdline(filepath.Join(procDir, "cmdline"), maxArgs, maxArgLength)
	if len(argv) == 0 && exe != "" {
		argv = []string{exe}
	}

	cgroup, _ := parseCgroup(filepath.Join(procDir, "cgroup"))
	tty := readTTY(procDir)
	ttyNr, _ := readTTYNr(filepath.Join(procDir, "stat"))
	userName := lookupUser(st.UID)
	groupName := lookupGroup(st.GID)
	auid := readAuditUint32(filepath.Join(procDir, "loginuid"))
	sessionID := readAuditUint32(filepath.Join(procDir, "sessionid"))

	if exe == "" {
		if len(argv) > 0 {
			exe = argv[0]
		} else {
			exe = comm
		}
	}
	if exeHint != "" {
		exe = exeHint
	}
	exe = resolveExecutablePath(procDir, st.PPID, exe, argv, cwd)
	argv = normalizeArgv(argv, exe, cwd)

	ev := CommandEvent{
		Timestamp:  normalizeTimestamp(kernelTimestamp),
		EventID:    eventID,
		UID:        st.UID,
		GID:        st.GID,
		AUID:       auid,
		SessionID:  sessionID,
		User:       userName,
		Group:      groupName,
		PID:        pid,
		PPID:       st.PPID,
		Comm:       comm,
		Exe:        exe,
		Cwd:        cwd,
		Argv:       argv,
		Argc:       len(argv),
		Cgroup:     cgroup,
		TTY:        tty,
		TTYNr:      ttyNr,
		RecordType: RecordTypeStart,
	}
	parent, ok := readProcSnapshot(st.PPID)
	if ok {
		ev.ParentComm = parent.Comm
		ev.ParentExe = parent.Exe
		ev.ParentCmdline = parent.Cmdline
		ev.ParentTTY = parent.TTY
		ev.ParentTTYNr = parent.TTYNr
		ev.Source = classifyCommandSource(ev, &parent)
	} else {
		ev.Source = classifyCommandSource(ev, nil)
	}
	return ev, nil
}

func BuildCommandEndEvent(start CommandEvent, endTimestamp string, durationNS int64, exitStatus *int) CommandEvent {
	// Keep end records compact for storage while preserving join and timing fields.
	ev := CommandEvent{
		Timestamp:  normalizeTimestamp(endTimestamp),
		EventID:    start.EventID,
		PID:        start.PID,
		Source:     start.Source,
		RecordType: RecordTypeEnd,
		DurationNS: &durationNS,
	}
	if exitStatus != nil {
		status := *exitStatus
		ev.ExitStatus = &status
	}
	return ev
}

func BuildExecFailureEvent(pid int, attemptedExe string, execErrno int, maxArgLength int, kernelTimestamp string) (CommandEvent, error) {
	procDir := filepath.Join("/proc", strconv.Itoa(pid))

	st, err := parseStatus(filepath.Join(procDir, "status"))
	if err != nil {
		return CommandEvent{}, err
	}

	comm, _ := readTrimmed(filepath.Join(procDir, "comm"))
	if comm == "" {
		comm = st.Name
	}

	cwd, _ := os.Readlink(filepath.Join(procDir, "cwd"))
	cgroup, _ := parseCgroup(filepath.Join(procDir, "cgroup"))
	tty := readTTY(procDir)
	ttyNr, _ := readTTYNr(filepath.Join(procDir, "stat"))
	userName := lookupUser(st.UID)
	groupName := lookupGroup(st.GID)
	auid := readAuditUint32(filepath.Join(procDir, "loginuid"))
	sessionID := readAuditUint32(filepath.Join(procDir, "sessionid"))

	exe := strings.TrimSpace(attemptedExe)
	if p, ok := absolutizePath(exe, cwd); ok {
		exe = p
	}
	if exe == "" {
		exe = comm
	}
	if maxArgLength > 0 && len(exe) > maxArgLength {
		exe = exe[:maxArgLength]
	}
	argv := []string{exe}

	errnoValue := execErrno
	errnoName := syscall.Errno(execErrno).Error()
	if errnoName == "errno "+strconv.Itoa(execErrno) {
		errnoName = ""
	}

	ev := CommandEvent{
		Timestamp:  normalizeTimestamp(kernelTimestamp),
		UID:        st.UID,
		GID:        st.GID,
		AUID:       auid,
		SessionID:  sessionID,
		User:       userName,
		Group:      groupName,
		PID:        pid,
		PPID:       st.PPID,
		Comm:       comm,
		Exe:        exe,
		Cwd:        cwd,
		Argv:       argv,
		Argc:       len(argv),
		Cgroup:     cgroup,
		TTY:        tty,
		TTYNr:      ttyNr,
		RecordType: RecordTypeFail,
		ExecErrno:  &errnoValue,
		ExecError:  errnoName,
	}
	parent, ok := readProcSnapshot(st.PPID)
	if ok {
		ev.ParentComm = parent.Comm
		ev.ParentExe = parent.Exe
		ev.ParentCmdline = parent.Cmdline
		ev.ParentTTY = parent.TTY
		ev.ParentTTYNr = parent.TTYNr
		ev.Source = classifyCommandSource(ev, &parent)
	} else {
		ev.Source = classifyCommandSource(ev, nil)
	}
	return ev, nil
}

func BuildCollectorLossEvent(lost uint64, total uint64) CommandEvent {
	uid := uint32(os.Geteuid())
	gid := uint32(os.Getegid())
	lostI64 := saturatingUint64ToInt64(lost)
	totalI64 := saturatingUint64ToInt64(total)

	// Keep dropped-sample records explicit so incident timelines can explain gaps.
	return CommandEvent{
		Timestamp:   normalizeTimestamp(""),
		UID:         uid,
		GID:         gid,
		User:        lookupUser(uid),
		Group:       lookupGroup(gid),
		Comm:        "precd",
		Exe:         "precd",
		Argv:        []string{"precd", "loss"},
		Argc:        2,
		Source:      SourceSystem,
		RecordType:  RecordTypeLoss,
		LostSamples: &lostI64,
		LostTotal:   &totalI64,
	}
}

func normalizeTimestamp(raw string) string {
	if strings.TrimSpace(raw) != "" {
		return raw
	}
	return time.Now().Format(time.RFC3339Nano)
}

func parseStatus(path string) (statusInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return statusInfo{}, fmt.Errorf("open status: %w", err)
	}
	defer f.Close()

	out := statusInfo{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, err := strconv.ParseUint(fields[1], 10, 32)
				if err == nil {
					out.UID = uint32(v)
				}
			}
		}
		if strings.HasPrefix(line, "Gid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, err := strconv.ParseUint(fields[1], 10, 32)
				if err == nil {
					out.GID = uint32(v)
				}
			}
		}
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, err := strconv.Atoi(fields[1])
				if err == nil {
					out.PPID = v
				}
			}
		}
		if strings.HasPrefix(line, "Name:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				out.Name = fields[1]
			}
		}
	}
	if err := s.Err(); err != nil {
		return statusInfo{}, fmt.Errorf("scan status: %w", err)
	}

	return out, nil
}

func parseCmdline(path string, maxArgs int, maxArgLength int) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cmdline: %w", err)
	}
	if len(b) == 0 {
		return nil, nil
	}

	parts := strings.Split(string(b), "\x00")
	out := make([]string, 0, maxArgs)
	for _, p := range parts {
		if p == "" {
			continue
		}
		if len(out) >= maxArgs {
			break
		}
		if len(p) > maxArgLength {
			p = p[:maxArgLength]
		}
		out = append(out, p)
	}
	return out, nil
}

func parseCgroup(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read cgroup: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			continue
		}
		if parts[2] != "" && parts[2] != "/" {
			return parts[2], nil
		}
	}
	return "", nil
}

func readTTY(procDir string) string {
	linkPath := filepath.Join(procDir, "fd", "0")
	v, err := os.Readlink(linkPath)
	if err != nil {
		return ""
	}
	if strings.HasPrefix(v, "/dev/") {
		return v
	}
	return ""
}

func readTTYNr(statPath string) (int64, error) {
	b, err := os.ReadFile(statPath)
	if err != nil {
		return 0, err
	}

	line := strings.TrimSpace(string(b))
	end := strings.LastIndex(line, ")")
	if end < 0 || end+2 >= len(line) {
		return 0, fmt.Errorf("invalid stat format")
	}

	rest := strings.Fields(line[end+2:])
	// rest: state ppid pgrp session tty_nr ...
	if len(rest) < 5 {
		return 0, fmt.Errorf("invalid stat fields")
	}

	ttyNr, err := strconv.ParseInt(rest[4], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse tty_nr: %w", err)
	}
	return ttyNr, nil
}

func normalizeArgv(argv []string, exe string, cwd string) []string {
	if len(argv) == 0 {
		if exe == "" {
			return nil
		}
		return []string{exe}
	}

	out := append([]string(nil), argv...)
	if exe != "" && filepath.IsAbs(exe) {
		out[0] = exe
		return out
	}
	if p, ok := absolutizePath(out[0], cwd); ok {
		out[0] = p
	}
	return out
}

func resolveExecutablePath(procDir string, parentPID int, exe string, argv []string, cwd string) string {
	if exe != "" && filepath.IsAbs(exe) {
		return exe
	}
	if len(argv) == 0 {
		return exe
	}

	arg0 := argv[0]
	if p, ok := absolutizePath(arg0, cwd); ok && isExecutableFile(p) {
		return p
	}
	if strings.Contains(arg0, "/") {
		return exe
	}

	if p := lookupInProcPath(procDir, arg0); p != "" {
		return p
	}
	if p := lookupInParentProcPath(parentPID, arg0); p != "" {
		return p
	}
	if p, err := exec.LookPath(arg0); err == nil && filepath.IsAbs(p) {
		return p
	}
	return exe
}

func absolutizePath(path string, cwd string) (string, bool) {
	if path == "" {
		return "", false
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path), true
	}
	if strings.Contains(path, "/") && cwd != "" {
		return filepath.Clean(filepath.Join(cwd, path)), true
	}
	return "", false
}

func lookupInProcPath(procDir string, name string) string {
	if name == "" || strings.Contains(name, "/") {
		return ""
	}

	envPath, ok := readProcEnvPath(filepath.Join(procDir, "environ"))
	if !ok {
		return ""
	}
	for _, dir := range strings.Split(envPath, ":") {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, name)
		if isExecutableFile(candidate) {
			return candidate
		}
	}
	return ""
}

func lookupInParentProcPath(parentPID int, name string) string {
	if parentPID <= 0 || name == "" || strings.Contains(name, "/") {
		return ""
	}
	procDir := filepath.Join("/proc", strconv.Itoa(parentPID))
	return lookupInProcPath(procDir, name)
}

func readProcEnvPath(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return "", false
	}
	for _, field := range strings.Split(string(b), "\x00") {
		if strings.HasPrefix(field, "PATH=") {
			return strings.TrimPrefix(field, "PATH="), true
		}
	}
	return "", false
}

func isExecutableFile(path string) bool {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return false
	}
	return st.Mode().Perm()&0o111 != 0
}

func readTrimmed(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func readAuditUint32(path string) *uint32 {
	v, ok := readUint32(path)
	if !ok {
		return nil
	}
	return &v
}

func readUint32(path string) (uint32, bool) {
	raw, err := readTrimmed(path)
	if err != nil || raw == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

func saturatingUint64ToInt64(v uint64) int64 {
	const maxInt64 = uint64(1<<63 - 1)
	if v > maxInt64 {
		return int64(maxInt64)
	}
	return int64(v)
}

func lookupUser(uid uint32) string {
	if v, ok := userCache.Load(uid); ok {
		return v.(string)
	}

	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		// Cache empty results too, to avoid repeated lookups for missing UIDs.
		userCache.Store(uid, "")
		return ""
	}
	userCache.Store(uid, u.Username)
	return u.Username
}

func lookupGroup(gid uint32) string {
	if v, ok := groupCache.Load(gid); ok {
		return v.(string)
	}

	g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10))
	if err != nil {
		// Cache empty results too, to avoid repeated lookups for missing GIDs.
		groupCache.Store(gid, "")
		return ""
	}
	groupCache.Store(gid, g.Name)
	return g.Name
}
