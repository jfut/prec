package events

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	SourceUser           = "user"
	SourceSystem         = "system"
	RecordTypeStart      = "start"
	RecordTypeEnd        = "end"
	RecordTypeCommand    = "command"
	RecordTypeFail       = "fail"
	RecordTypeLoss       = "loss"
	maxCmdlineTextLength = 512
)

type procSnapshot struct {
	Comm    string
	Exe     string
	Cmdline string
	TTY     string
	TTYNr   int64
}

var shellNames = map[string]struct{}{
	"bash": {},
	"zsh":  {},
	"sh":   {},
	"dash": {},
	"ksh":  {},
	"fish": {},
	"csh":  {},
	"tcsh": {},
}

func classifyCommandSourceFromLineage(ev CommandEvent, lineage []procSnapshot) string {
	if len(lineage) == 0 {
		return classifyCommandSource(ev, nil)
	}
	return classifyCommandSource(ev, &lineage[0])
}

func classifyCommandSource(ev CommandEvent, parent *procSnapshot) string {
	// Limit user to commands run with a TTY through a user shell.
	if isUserShellExecution(ev, parent) {
		return SourceUser
	}

	// Classify everything else as system.
	return SourceSystem
}

func isUserShellExecution(ev CommandEvent, parent *procSnapshot) bool {
	if parent == nil {
		return false
	}
	if !hasInteractiveTTY(ev) && !hasInteractiveTTYSnapshot(*parent) {
		return false
	}
	// Classify as user only when the immediate parent is a shell.
	return isShellName(parent.Comm) || isShellName(parent.Exe)
}

func hasInteractiveTTY(ev CommandEvent) bool {
	if isInteractiveTTY(ev.TTY) {
		return true
	}
	// Fallback for environments where /proc/<pid>/fd/0 is not readable.
	return ev.TTYNr != 0
}

func hasInteractiveTTYSnapshot(snapshot procSnapshot) bool {
	if isInteractiveTTY(snapshot.TTY) {
		return true
	}
	return snapshot.TTYNr != 0
}

func isInteractiveTTY(tty string) bool {
	// Exclude /dev/null and empty values, and accept only typical interactive TTY or PTS.
	switch {
	case tty == "", tty == "/dev/null":
		return false
	case tty == "/dev/tty", strings.HasPrefix(tty, "/dev/pts/"):
		return true
	default:
		return false
	}
}

func readProcSnapshot(pid int) (procSnapshot, bool) {
	if pid <= 1 {
		return procSnapshot{}, false
	}

	procDir := filepath.Join("/proc", strconv.Itoa(pid))
	comm, err := readTrimmed(filepath.Join(procDir, "comm"))
	if err != nil {
		return procSnapshot{}, false
	}

	exe, _ := os.Readlink(filepath.Join(procDir, "exe"))
	cmdline, _ := readCmdlineText(filepath.Join(procDir, "cmdline"), maxCmdlineTextLength)
	tty := readTTY(procDir)
	ttyNr, _ := readTTYNr(filepath.Join(procDir, "stat"))

	return procSnapshot{
		Comm:    comm,
		Exe:     exe,
		Cmdline: cmdline,
		TTY:     tty,
		TTYNr:   ttyNr,
	}, true
}

func readCmdlineText(path string, limit int) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", nil
	}

	s := strings.ReplaceAll(string(b), "\x00", " ")
	s = strings.TrimSpace(s)
	if limit > 0 && len(s) > limit {
		s = s[:limit]
	}
	return s, nil
}

func isShellName(s string) bool {
	_, ok := shellNames[strings.ToLower(filepath.Base(s))]
	return ok
}
