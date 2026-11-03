// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

//go:build linux

package collector

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/asm"
	"github.com/jfut/prec/internal/config"
	"github.com/jfut/prec/internal/events"
	"github.com/jfut/prec/internal/logger"
	"golang.org/x/sys/unix"
)

func TestCompileCaptureFilter(t *testing.T) {
	t.Parallel()

	current, err := user.Current()
	if err != nil {
		t.Fatalf("current user lookup failed: %v", err)
	}
	currentGroup, err := user.LookupGroupId(current.Gid)
	if err != nil {
		t.Fatalf("current group lookup failed: %v", err)
	}

	policy, err := compileCaptureFilter([]string{
		"+uid>=1000&&gid!=0",
		"+user=" + current.Username,
		"+group=" + currentGroup.Name,
		"+comm=php-fpm",
	})
	if err != nil {
		t.Fatalf("compileCaptureFilter returned error: %v", err)
	}
	if len(policy.rules) != 4 {
		t.Fatalf("compiled rules=%d want=4", len(policy.rules))
	}
	if !policy.hasComm {
		t.Fatalf("compiled policy does not record comm usage")
	}
	if policy.rules[0][0].field != captureFieldUID || policy.rules[0][0].op != ">=" || policy.rules[0][0].value != 1000 {
		t.Fatalf("unexpected numeric clause: %+v", policy.rules[0][0])
	}
}

func TestCompileCaptureFilterRejectsUnsupportedRules(t *testing.T) {
	t.Parallel()

	tests := []string{
		"-uid=1000",
		"+file_path=/etc/shadow",
		"+comm~=php",
		"+uid=",
	}
	for _, raw := range tests {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			if _, err := compileCaptureFilter([]string{raw}); err == nil {
				t.Fatalf("compileCaptureFilter(%q) succeeded", raw)
			}
		})
	}
}

func TestCompileCaptureFilterNamedIdentities(t *testing.T) {
	t.Parallel()

	// Identical names share a snapshot slot within each kind, while user and
	// group names remain separate even when their spelling is the same.
	policy, err := compileCaptureFilter([]string{
		"+user=tomcat&&group=tomcat||user!=tomcat",
		"+uid=48",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantIdentities := []captureIdentity{
		{field: captureFieldUID, name: "tomcat"},
		{field: captureFieldGID, name: "tomcat"},
	}
	if !reflect.DeepEqual(policy.identities, wantIdentities) {
		t.Fatalf("identities = %+v, want %+v", policy.identities, wantIdentities)
	}
	if policy.rules[0][0].identityIndex != 0 || policy.rules[0][1].identityIndex != 1 || policy.rules[1][0].identityIndex != 0 {
		t.Fatalf("unexpected snapshot slot assignment: %+v", policy.rules)
	}
	if policy.rules[2][0].text != "" || policy.rules[2][0].value != 48 {
		t.Fatalf("numeric rule became dynamic: %+v", policy.rules[2])
	}
	if _, err := compileCaptureFilter([]string{"+user=missing&&file_path=/etc/shadow"}); err == nil {
		t.Fatal("missing user hid an unsupported field")
	}
}

func TestCompileCaptureFilterIdentityLimit(t *testing.T) {
	t.Parallel()
	rules := make([]string, captureIdentityMax+1)
	for i := range rules {
		rules[i] = fmt.Sprintf("+user=service%d", i)
	}
	if _, err := compileCaptureFilter(rules[:captureIdentityMax]); err != nil {
		t.Fatalf("maximum supported names rejected: %v", err)
	}
	if _, err := compileCaptureFilter(rules); err == nil {
		t.Fatal("accepted more named identities than map offsets can address")
	}
}

func TestParseOffsetFromFormat(t *testing.T) {
	t.Parallel()

	format := `name: sched_process_exec
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:__data_loc char[] filename;	offset:12;	size:4;	signed:1;
	field:pid_t pid;	offset:16;	size:4;	signed:1;
`

	got, err := parseOffsetFromFormat(format, "__data_loc char[] filename")
	if err != nil {
		t.Fatalf("parseOffsetFromFormat returned error: %v", err)
	}
	if got != 12 {
		t.Fatalf("got=%d want=%d", got, 12)
	}
}

func TestParseFieldFromFormatMatchesExactFieldName(t *testing.T) {
	t.Parallel()

	format := `name: sys_enter_openat
format:
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:int flags;	offset:32;	size:8;	signed:0;
`

	got, size, err := parseFieldFromFormat(format, "flags")
	if err != nil {
		t.Fatalf("parseFieldFromFormat returned error: %v", err)
	}
	if got != 32 || size != asm.DWord {
		t.Fatalf("got offset/size=%d/%v want=%d/%v", got, size, 32, asm.DWord)
	}
}

func TestParseFilenameHint(t *testing.T) {
	t.Parallel()

	raw := make([]byte, perfSampleSize)
	copy(raw[perfSampleFilenameOffset:], []byte("/usr/bin/curl\x00garbage"))

	got := parseFilenameHint(raw)
	if got != "/usr/bin/curl" {
		t.Fatalf("got=%q want=%q", got, "/usr/bin/curl")
	}
}

func TestParsePerfSampleExec(t *testing.T) {
	t.Parallel()

	raw := make([]byte, perfSampleSize)
	raw[perfSampleTypeOffset] = perfEventTypeExec
	// bpf_get_current_pid_tgid() packs tgid in high 32 bits and tid in low 32 bits.
	pidTgid := (uint64(4321) << 32) | 4321
	for i := 0; i < 8; i++ {
		raw[perfSamplePidTgidOffset+i] = byte(pidTgid >> (8 * i))
	}
	ktime := uint64(987654321)
	for i := 0; i < 8; i++ {
		raw[perfSampleKtimeOffset+i] = byte(ktime >> (8 * i))
	}
	copy(raw[perfSampleFilenameOffset:], []byte("/bin/echo\x00"))

	eventType, tgid, tid, status, status2, gotKtime, exeHint, ok := parsePerfSample(raw)
	if !ok {
		t.Fatalf("expected ok")
	}
	if eventType != perfEventTypeExec {
		t.Fatalf("eventType=%d want=%d", eventType, perfEventTypeExec)
	}
	if tgid != 4321 {
		t.Fatalf("tgid=%d want=%d", tgid, 4321)
	}
	if tid != 4321 {
		t.Fatalf("tid=%d want=%d", tid, 4321)
	}
	if status != 0 {
		t.Fatalf("status=%d want=0", status)
	}
	if status2 != 0 {
		t.Fatalf("status2=%d want=0", status2)
	}
	if gotKtime != ktime {
		t.Fatalf("ktime=%d want=%d", gotKtime, ktime)
	}
	if exeHint != "/bin/echo" {
		t.Fatalf("exeHint=%q want=%q", exeHint, "/bin/echo")
	}
}

func TestParsePerfSampleExecResultNegative(t *testing.T) {
	t.Parallel()

	raw := make([]byte, perfSampleSize)
	raw[perfSampleTypeOffset] = perfEventTypeExecResult
	pidTgid := (uint64(5000) << 32) | 5001
	for i := 0; i < 8; i++ {
		raw[perfSamplePidTgidOffset+i] = byte(pidTgid >> (8 * i))
	}
	ret := int64(-2)
	for i := 0; i < 8; i++ {
		raw[perfSampleStatusOffset+i] = byte(uint64(ret) >> (8 * i))
	}

	eventType, tgid, tid, status, status2, _, _, ok := parsePerfSample(raw)
	if !ok {
		t.Fatalf("expected ok")
	}
	if eventType != perfEventTypeExecResult {
		t.Fatalf("eventType=%d want=%d", eventType, perfEventTypeExecResult)
	}
	if tgid != 5000 || tid != 5001 {
		t.Fatalf("unexpected tgid/tid: %d/%d", tgid, tid)
	}
	if status != -2 {
		t.Fatalf("status=%d want=-2", status)
	}
	if status2 != 0 {
		t.Fatalf("status2=%d want=0", status2)
	}
}

func TestParsePerfSampleFileOpenEnter(t *testing.T) {
	t.Parallel()

	raw := make([]byte, perfSampleSize)
	raw[perfSampleTypeOffset] = perfEventTypeOpenEnter
	pidTgid := (uint64(7000) << 32) | 7001
	for i := 0; i < 8; i++ {
		raw[perfSamplePidTgidOffset+i] = byte(pidTgid >> (8 * i))
	}
	flags := int64(unix.O_CREAT | unix.O_WRONLY)
	for i := 0; i < 8; i++ {
		raw[perfSampleStatusOffset+i] = byte(uint64(flags) >> (8 * i))
	}
	dirfd := int64(9)
	for i := 0; i < 8; i++ {
		raw[perfSampleStatus2Offset+i] = byte(uint64(dirfd) >> (8 * i))
	}
	copy(raw[perfSampleFilenameOffset:], []byte("tmp/file.log\x00"))

	eventType, tgid, tid, status, status2, _, exeHint, ok := parsePerfSample(raw)
	if !ok {
		t.Fatalf("expected ok")
	}
	if eventType != perfEventTypeOpenEnter {
		t.Fatalf("eventType=%d want=%d", eventType, perfEventTypeOpenEnter)
	}
	if tgid != 7000 || tid != 7001 {
		t.Fatalf("unexpected tgid/tid: %d/%d", tgid, tid)
	}
	if status != flags {
		t.Fatalf("status=%d want=%d", status, flags)
	}
	if status2 != dirfd {
		t.Fatalf("status2=%d want=%d", status2, dirfd)
	}
	if exeHint != "tmp/file.log" {
		t.Fatalf("exeHint=%q want=%q", exeHint, "tmp/file.log")
	}
}

func TestParsePerfSampleFileOpenEnterSignExtendsDirFD(t *testing.T) {
	t.Parallel()

	raw := make([]byte, perfSampleSize)
	raw[perfSampleTypeOffset] = perfEventTypeOpenEnter
	pidTgid := (uint64(7000) << 32) | 7001
	for i := 0; i < 8; i++ {
		raw[perfSamplePidTgidOffset+i] = byte(pidTgid >> (8 * i))
	}
	dirfd := int32(unix.AT_FDCWD)
	for i := 0; i < 4; i++ {
		raw[perfSampleStatus2Offset+i] = byte(uint32(dirfd) >> (8 * i))
	}
	copy(raw[perfSampleFilenameOffset:], []byte("tmp/file.log\x00"))

	_, _, _, _, status2, _, _, ok := parsePerfSample(raw)
	if !ok {
		t.Fatalf("expected ok")
	}
	if status2 != int64(unix.AT_FDCWD) {
		t.Fatalf("status2=%d want=%d", status2, unix.AT_FDCWD)
	}
}

func TestNormalizeFilePathPrefersDirFDBase(t *testing.T) {
	t.Parallel()

	got := normalizeFilePath("nested/file.log", "/cwd", "/tracked/root", true)
	if got != "/tracked/root/nested/file.log" {
		t.Fatalf("got=%q want=%q", got, "/tracked/root/nested/file.log")
	}
}

func TestNormalizeFilePathFallsBackToCWD(t *testing.T) {
	t.Parallel()

	got := normalizeFilePath("nested/file.log", "/cwd", "", false)
	if got != "/cwd/nested/file.log" {
		t.Fatalf("got=%q want=%q", got, "/cwd/nested/file.log")
	}
}

func TestNormalizeFilePathDoesNotFallbackToCWDWhenDirFDMissing(t *testing.T) {
	t.Parallel()

	got := normalizeFilePath("nested/file.log", "/cwd", "", true)
	if got != "nested/file.log" {
		t.Fatalf("got=%q want=%q", got, "nested/file.log")
	}
}

func TestResolveRegularFilePathAcceptsRegularFile(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, "demo.log")
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("os.Create: %v", err)
	}
	defer f.Close()

	got, ok := resolveRegularFilePath(os.Getpid(), int(f.Fd()))
	if !ok {
		t.Fatalf("resolveRegularFilePath returned ok=false")
	}
	if got != p {
		t.Fatalf("got=%q want=%q", got, p)
	}
}

func TestResolveRegularFileIdentityAcceptsRegularFile(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, "identity.log")
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("os.Create: %v", err)
	}
	defer f.Close()

	identity, ok := resolveRegularFileIdentity(os.Getpid(), int(f.Fd()))
	if !ok || !identity.valid {
		t.Fatalf("resolveRegularFileIdentity returned invalid identity: %+v", identity)
	}
	if identity.dev == 0 || identity.ino == 0 {
		t.Fatalf("unexpected zero identity: %+v", identity)
	}
}

func TestResolveRegularFilePathRejectsDevice(t *testing.T) {
	t.Parallel()

	f, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("os.OpenFile: %v", err)
	}
	defer f.Close()

	if got, ok := resolveRegularFilePath(os.Getpid(), int(f.Fd())); ok {
		t.Fatalf("got=%q want non-regular target to be rejected", got)
	}
}

func TestTracepointFieldOffsetAndSizeAny(t *testing.T) {
	t.Parallel()

	format := `name: sys_enter_unlinkat
format:
	field:const char * pathname;	offset:24;	size:8;	signed:0;
	field:int dfd;	offset:16;	size:8;	signed:1;
`

	offset, size, err := parseFieldFromFormat(format, "pathname")
	if err != nil {
		t.Fatalf("parseFieldFromFormat returned error: %v", err)
	}
	if offset != 24 || size != asm.DWord {
		t.Fatalf("got offset/size=%d/%v want=%d/%v", offset, size, 24, asm.DWord)
	}
}

func TestBuildFileOpenEventUsesPendingProcessSnapshot(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "a.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("os.OpenFile: %v", err)
	}
	defer f.Close()
	pid := os.Getpid()

	svc := &Service{
		pendingEvents: map[int]events.CommandEvent{
			pid: {
				Timestamp:  "2026-05-23T10:00:00Z",
				EventID:    "boot-200",
				UID:        1000,
				GID:        1000,
				User:       "admin",
				Group:      "admin",
				PID:        pid,
				PPID:       1,
				Comm:       "touch",
				Exe:        "/usr/bin/touch",
				Cwd:        tmpDir,
				Argv:       []string{"touch", "a.log"},
				Argc:       2,
				Source:     events.SourceUser,
				RecordType: events.RecordTypeStart,
			},
		},
		pendingOpen: map[int]fileOpenAttempt{
			2001: {
				tgid:      pid,
				filename:  "a.log",
				dirfd:     unix.AT_FDCWD,
				flags:     int64(unix.O_CREAT | unix.O_EXCL | unix.O_WRONLY),
				timestamp: 120,
			},
		},
	}
	svc.buildStartEventFn = func(tgid int, exeHint string, timestamp string, eventID string) (events.CommandEvent, error) {
		return events.CommandEvent{}, errors.New("proc is already gone")
	}

	openEvent, ok, err := svc.buildFileOpenEvent(2001, int(f.Fd()), "2026-05-23T10:00:01Z")
	if err != nil {
		t.Fatalf("buildFileOpenEvent returned error: %v", err)
	}
	if !ok {
		t.Fatalf("buildFileOpenEvent returned ok=false")
	}
	if openEvent.RecordType != events.RecordTypeFileOpen {
		t.Fatalf("open record_type=%q want=%q", openEvent.RecordType, events.RecordTypeFileOpen)
	}
	if openEvent.FilePath != path {
		t.Fatalf("open file_path=%q want=%q", openEvent.FilePath, path)
	}
	if openEvent.EventID == "boot-200" || openEvent.EventID == "" {
		t.Fatalf("file event should receive a fresh event_id, got %q", openEvent.EventID)
	}
}

func TestBuildFileOpenEventsDropsUntrackedPath(t *testing.T) {
	t.Parallel()

	pid := os.Getpid()
	svc := &Service{
		pendingEvents: map[int]events.CommandEvent{
			pid: {
				Timestamp:  "2026-05-23T10:00:00Z",
				EventID:    "boot-201",
				UID:        1000,
				GID:        1000,
				User:       "admin",
				Group:      "admin",
				PID:        pid,
				PPID:       1,
				Comm:       "bash",
				Exe:        "/usr/bin/bash",
				Cwd:        "/tmp",
				Argv:       []string{"bash", "-c", "echo > /dev/null"},
				Argc:       3,
				Source:     events.SourceUser,
				RecordType: events.RecordTypeStart,
			},
		},
		pendingOpen: map[int]fileOpenAttempt{
			2002: {
				tgid:      pid,
				filename:  "/dev/null",
				dirfd:     unix.AT_FDCWD,
				flags:     int64(unix.O_WRONLY | unix.O_TRUNC),
				timestamp: 120,
			},
		},
	}

	_, ok, err := svc.buildFileOpenEvent(2002, 3, "2026-05-23T10:00:01Z")
	if err != nil {
		t.Fatalf("buildFileOpenEvent returned error: %v", err)
	}
	if ok {
		t.Fatalf("buildFileOpenEvent should drop untracked paths")
	}
}

func TestShouldDropPrecdSelfLogWrite(t *testing.T) {
	t.Parallel()

	base := events.CommandEvent{
		Comm: "precd",
		Exe:  "/usr/bin/precd",
	}
	if !shouldDropPrecdSelfLogWrite(base, "/var/log/prec/prec.log", "/var/log/prec/prec.log") {
		t.Fatalf("precd self log write should be dropped")
	}
	if shouldDropPrecdSelfLogWrite(base, "/tmp/other.log", "/var/log/prec/prec.log") {
		t.Fatalf("different path must not be dropped")
	}
	if shouldDropPrecdSelfLogWrite(events.CommandEvent{Comm: "bash", Exe: "/usr/bin/bash"}, "/var/log/prec/prec.log", "/var/log/prec/prec.log") {
		t.Fatalf("non-precd writer must not be dropped")
	}
}

func TestShouldSuppressDuplicateFileSave(t *testing.T) {
	t.Parallel()

	svc := &Service{
		cfg: config.Config{
			FileSaveDedupSec: 1,
		},
		recentFileSaves: make(map[fileSaveDedupKey]uint64),
	}

	if svc.shouldSuppressDuplicateFileSave(1234, "/tmp/a.log", uint64(10*time.Second)) {
		t.Fatalf("first save must not be suppressed")
	}
	if !svc.shouldSuppressDuplicateFileSave(1234, "/tmp/a.log", uint64(10*time.Second)+500_000_000) {
		t.Fatalf("duplicate save in window must be suppressed")
	}
	if svc.shouldSuppressDuplicateFileSave(1234, "/tmp/b.log", uint64(10*time.Second)+500_000_000) {
		t.Fatalf("different path must not be suppressed")
	}
	if svc.shouldSuppressDuplicateFileSave(5678, "/tmp/a.log", uint64(10*time.Second)+500_000_000) {
		t.Fatalf("different process must not be suppressed")
	}
	if svc.shouldSuppressDuplicateFileSave(1234, "/tmp/a.log", uint64(11*time.Second)) {
		t.Fatalf("save after window must not be suppressed")
	}
}

func TestShouldEmitFileOpenEvent(t *testing.T) {
	t.Parallel()

	if shouldEmitFileOpenEvent(unix.O_RDONLY, false) {
		t.Fatalf("read-only open must not be emitted")
	}
	if !shouldEmitFileOpenEvent(unix.O_RDONLY, true) {
		t.Fatalf("read-only open must be emitted with capture filter")
	}
	if !shouldEmitFileOpenEvent(unix.O_RDWR, false) {
		t.Fatalf("read-write open must be emitted")
	}
	if !shouldEmitFileOpenEvent(unix.O_WRONLY, false) {
		t.Fatalf("write-only open must be emitted")
	}
	if !shouldEmitFileOpenEvent(unix.O_RDONLY|unix.O_CREAT, false) {
		t.Fatalf("create open must be emitted")
	}
}

func TestShouldTrackFilePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want bool
	}{
		{path: "a", want: true},
		{path: "/tmp/a", want: true},
		{path: "/dev/null", want: false},
		{path: "/proc/self/mem", want: false},
		{path: "/sys/kernel/debug", want: false},
		{path: "anon_inode:[eventfd]", want: false},
	}

	for _, tt := range tests {
		if got := shouldTrackFilePath(tt.path); got != tt.want {
			t.Fatalf("path=%q got=%v want=%v", tt.path, got, tt.want)
		}
	}
}

func TestShouldRecordFileEventDropsUntrackedPath(t *testing.T) {
	t.Parallel()

	svc := &Service{cfg: config.Config{CollectFileScope: "all"}}
	if svc.shouldRecordFileEvent(events.CommandEvent{
		FilePath: "anon_inode:[eventfd]",
		Source:   events.SourceUser,
	}) {
		t.Fatalf("anon_inode path must be dropped")
	}
	if !svc.shouldRecordFileEvent(events.CommandEvent{
		FilePath: "/tmp/a",
		Source:   events.SourceUser,
	}) {
		t.Fatalf("regular path must be kept")
	}
}

func TestMatchesConfiguredFileScope(t *testing.T) {
	t.Parallel()

	homeDir := t.TempDir()
	cache := currentUserHomeCache()
	cache.Store(uint32(1000), homeDir)
	t.Cleanup(func() {
		cache.Delete(uint32(1000))
	})

	if !matchesConfiguredFileScope(events.CommandEvent{
		UID:      1000,
		FilePath: filepath.Join(homeDir, "project", "a.txt"),
	}, "user_visible") {
		t.Fatalf("regular file under home must match user_visible")
	}
	if !matchesConfiguredFileScope(events.CommandEvent{
		UID:      1000,
		FilePath: "/storage/work/project/a.txt",
	}, "user_visible") {
		t.Fatalf("regular file outside home must match user_visible")
	}
	if matchesConfiguredFileScope(events.CommandEvent{
		UID:      1000,
		FilePath: filepath.Join(homeDir, ".codex", "logs.sqlite-wal"),
	}, "user_visible") {
		t.Fatalf("hidden app-state path must not match user_visible")
	}
	if matchesConfiguredFileScope(events.CommandEvent{
		UID:      1000,
		FilePath: filepath.Join(homeDir, "tmp", "etilqs_abc"),
	}, "user_visible") {
		t.Fatalf("editor temp file must not match user_visible")
	}
	if !matchesConfiguredFileScope(events.CommandEvent{
		UID:      1000,
		FilePath: filepath.Join(homeDir, ".bashrc"),
	}, "user_visible") {
		t.Fatalf("top-level dotfile must match user_visible")
	}
	if !matchesConfiguredFileScope(events.CommandEvent{
		UID:      1000,
		FilePath: "/storage/work/project/.env",
	}, "user_visible") {
		t.Fatalf("leaf dotfile must match user_visible")
	}
	if !matchesConfiguredFileScope(events.CommandEvent{
		UID:      1000,
		FilePath: filepath.Join(homeDir, ".codex", "logs.sqlite-wal"),
	}, "home") {
		t.Fatalf("home scope must include hidden app-state path")
	}
}

func TestMatchesConfiguredFileSource(t *testing.T) {
	t.Parallel()

	if !matchesConfiguredFileSource(events.SourceUser, "user") {
		t.Fatalf("user source must match user config")
	}
	if matchesConfiguredFileSource(events.SourceSystem, "user") {
		t.Fatalf("system source must not match user config")
	}
	if !matchesConfiguredFileSource(events.SourceSystem, "system") {
		t.Fatalf("system source must match system config")
	}
	if !matchesConfiguredFileSource(events.SourceUser, "any") {
		t.Fatalf("user source must match any config")
	}
	if !matchesConfiguredFileSource(events.SourceSystem, "any") {
		t.Fatalf("system source must match any config")
	}
}

func TestBuildPerfSampleStackZeroInstructions(t *testing.T) {
	t.Parallel()

	got := buildPerfSampleStackZeroInstructions()
	wantStores := perfSampleSize / 8
	if len(got) != 1+wantStores {
		t.Fatalf("instruction count=%d want=%d", len(got), 1+wantStores)
	}

	for i := 0; i < wantStores; i++ {
		ins := got[i+1]
		if ins.OpCode != asm.StoreMemOp(asm.DWord) {
			t.Fatalf("instruction[%d] opcode=%v want=%v", i+1, ins.OpCode, asm.StoreMemOp(asm.DWord))
		}
		if ins.Dst != asm.RFP {
			t.Fatalf("instruction[%d] dst=%v want=%v", i+1, ins.Dst, asm.RFP)
		}
		if ins.Src != asm.R0 {
			t.Fatalf("instruction[%d] src=%v want=%v", i+1, ins.Src, asm.R0)
		}
		wantOffset := int16(perfSampleStackStart + i*8)
		if ins.Offset != wantOffset {
			t.Fatalf("instruction[%d] offset=%d want=%d", i+1, ins.Offset, wantOffset)
		}
	}
}

func TestNormalizeExitStatus(t *testing.T) {
	t.Parallel()

	if got := normalizeExitStatus(260); got != 4 {
		t.Fatalf("got=%d want=%d", got, 4)
	}
}

func TestRememberExitStatusPriority(t *testing.T) {
	t.Parallel()

	svc := &Service{
		pendingStatuses: map[int]int{},
	}

	svc.rememberExitStatus(100, 0, false)
	svc.rememberExitStatus(100, 60, true)
	svc.rememberExitStatus(100, 1, false)

	got := svc.pendingStatuses[100]
	if got != 60 {
		t.Fatalf("got=%d want=%d", got, 60)
	}
}

func TestNextEventIDUsesStartTimePrefixAndCounter(t *testing.T) {
	t.Parallel()

	svc := &Service{
		eventIDPrefix: "20260517102452",
	}

	first := svc.nextEventID()
	second := svc.nextEventID()

	if first != "20260517102452-1" {
		t.Fatalf("first=%q want=%q", first, "20260517102452-1")
	}
	if second != "20260517102452-2" {
		t.Fatalf("second=%q want=%q", second, "20260517102452-2")
	}
}

func TestFinalizeEventReturnsStartStatusAndClearsState(t *testing.T) {
	t.Parallel()

	svc := &Service{
		pendingEvents:    map[int]events.CommandEvent{},
		pendingStatuses:  map[int]int{},
		pendingStartMono: map[int]uint64{},
	}
	start := events.CommandEvent{
		Timestamp:  "2026-05-23T10:00:00Z",
		EventID:    "boot-1",
		PID:        1234,
		RecordType: events.RecordTypeStart,
	}

	svc.rememberExecEvent(1234, start, 101_000)
	svc.rememberExitStatus(1234, 260, true)

	gotStart, gotStatus, gotStartMono, ok := svc.finalizeEvent(1234)
	if !ok {
		t.Fatalf("finalizeEvent returned ok=false")
	}
	if gotStart.EventID != start.EventID {
		t.Fatalf("event_id=%q want=%q", gotStart.EventID, start.EventID)
	}
	if gotStatus == nil || *gotStatus != 4 {
		t.Fatalf("status=%v want=4", gotStatus)
	}
	if gotStartMono != 101_000 {
		t.Fatalf("start_mono=%d want=%d", gotStartMono, 101_000)
	}

	if len(svc.pendingEvents) != 0 || len(svc.pendingStatuses) != 0 || len(svc.pendingStartMono) != 0 {
		t.Fatalf("state was not cleared: events=%d statuses=%d start_mono=%d", len(svc.pendingEvents), len(svc.pendingStatuses), len(svc.pendingStartMono))
	}
}

func TestComputeDurationNS(t *testing.T) {
	t.Parallel()

	if got := computeDurationNS(0, 100); got != 0 {
		t.Fatalf("got=%d want=0", got)
	}
	if got := computeDurationNS(500, 400); got != 0 {
		t.Fatalf("got=%d want=0", got)
	}
	if got := computeDurationNS(100, 1200); got != 1100 {
		t.Fatalf("got=%d want=1100", got)
	}
	overflowStart := uint64(1)
	overflowEnd := uint64(math.MaxUint64)
	if got := computeDurationNS(overflowStart, overflowEnd); got != math.MaxInt64 {
		t.Fatalf("overflow got=%d want=%d", got, int64(math.MaxInt64))
	}
}

func TestBuildFromPIDWithRetry(t *testing.T) {
	t.Parallel()

	attempts := 0
	got, err := buildFromPIDWithRetry(3, 0, func() (events.CommandEvent, error) {
		attempts++
		if attempts < 3 {
			return events.CommandEvent{}, errors.New("temporary")
		}
		return events.CommandEvent{PID: 42}, nil
	})
	if err != nil {
		t.Fatalf("buildFromPIDWithRetry returned error: %v", err)
	}
	if got.PID != 42 {
		t.Fatalf("pid=%d want=42", got.PID)
	}
	if attempts != 3 {
		t.Fatalf("attempts=%d want=3", attempts)
	}
}

func TestBuildFromPIDWithRetryFailure(t *testing.T) {
	t.Parallel()

	attempts := 0
	wantErr := errors.New("still failing")
	_, err := buildFromPIDWithRetry(2, 0, func() (events.CommandEvent, error) {
		attempts++
		return events.CommandEvent{}, wantErr
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts=%d want=2", attempts)
	}
}

func TestHandleLostSamplesLogMode(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "prec.log")
	w, err := logger.NewJSONLWriter(logPath, config.CompressNo, 0)
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}
	defer w.Close()

	svc := &Service{
		cfg:    config.Config{LostSamplesAction: config.LostSamplesActionLog},
		writer: w,
	}

	if err := svc.handleLostSamples(7); err != nil {
		t.Fatalf("handleLostSamples: %v", err)
	}

	got := readLossEventsFromLog(t, logPath)
	if len(got) != 1 {
		t.Fatalf("got=%d want=1", len(got))
	}
	if got[0].RecordType != events.RecordTypeLoss {
		t.Fatalf("record_type=%q want=%q", got[0].RecordType, events.RecordTypeLoss)
	}
	if got[0].LostSamples == nil || *got[0].LostSamples != 7 {
		t.Fatalf("lost_samples=%v want=7", got[0].LostSamples)
	}
	if got[0].LostTotal == nil || *got[0].LostTotal != 7 {
		t.Fatalf("lost_samples_total=%v want=7", got[0].LostTotal)
	}
}

func TestHandleLostSamplesLogModeRateLimitsOutput(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "prec.log")
	w, err := logger.NewJSONLWriter(logPath, config.CompressNo, 0)
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}
	defer w.Close()

	svc := &Service{
		cfg:    config.Config{LostSamplesAction: config.LostSamplesActionLog},
		writer: w,
	}

	if err := svc.handleLostSamples(3); err != nil {
		t.Fatalf("first handleLostSamples: %v", err)
	}
	if err := svc.handleLostSamples(5); err != nil {
		t.Fatalf("second handleLostSamples: %v", err)
	}

	got := readLossEventsFromLog(t, logPath)
	if len(got) != 1 {
		t.Fatalf("got=%d want=1", len(got))
	}
	if got[0].LostSamples == nil || *got[0].LostSamples != 3 {
		t.Fatalf("lost_samples=%v want=3", got[0].LostSamples)
	}
	if got[0].LostTotal == nil || *got[0].LostTotal != 3 {
		t.Fatalf("lost_samples_total=%v want=3", got[0].LostTotal)
	}
}

func TestHandleLostSamplesIgnoreMode(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "prec.log")
	w, err := logger.NewJSONLWriter(logPath, config.CompressNo, 0)
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}
	defer w.Close()

	svc := &Service{
		cfg:    config.Config{LostSamplesAction: config.LostSamplesActionIgnore},
		writer: w,
	}

	if err := svc.handleLostSamples(3); err != nil {
		t.Fatalf("handleLostSamples: %v", err)
	}

	lines := readRawLines(t, logPath)
	if len(lines) != 0 {
		t.Fatalf("unexpected log lines: %v", lines)
	}
}

func TestHandleLostSamplesStopMode(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "prec.log")
	w, err := logger.NewJSONLWriter(logPath, config.CompressNo, 0)
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}
	defer w.Close()

	svc := &Service{
		cfg:    config.Config{LostSamplesAction: config.LostSamplesActionStop},
		writer: w,
	}

	err = svc.handleLostSamples(11)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "lost perf samples detected") {
		t.Fatalf("unexpected error: %v", err)
	}

	got := readLossEventsFromLog(t, logPath)
	if len(got) != 1 {
		t.Fatalf("got=%d want=1", len(got))
	}
	if got[0].LostTotal == nil || *got[0].LostTotal != 11 {
		t.Fatalf("lost_samples_total=%v want=11", got[0].LostTotal)
	}
}

func readLossEventsFromLog(t *testing.T, path string) []events.CommandEvent {
	t.Helper()
	lines := readRawLines(t, path)
	out := make([]events.CommandEvent, 0, len(lines))
	for _, line := range lines {
		var ev events.CommandEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		out = append(out, ev)
	}
	return out
}

func readRawLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	out := make([]string, 0)
	s := bufio.NewScanner(f)
	for s.Scan() {
		out = append(out, s.Text())
	}
	if err := s.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}
