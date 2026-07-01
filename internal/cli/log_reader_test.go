// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package cli

import (
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jfut/prec/internal/config"
	"github.com/jfut/prec/internal/events"
)

func TestOpenLogReaderDetectsCompressionByMagic(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "prec.log.1")
	evs := []events.CommandEvent{
		{Timestamp: "2026-05-22T04:00:00Z", PID: 40, User: "u", Group: "g", Source: events.SourceUser, Argv: []string{"cmd40"}},
	}
	if err := writeTestLogFile(path, evs, "zstd", false); err != nil {
		t.Fatalf("write zstd log: %v", err)
	}

	lf, err := buildQueryFilter([]string{"source=user"})
	if err != nil {
		t.Fatalf("buildQueryFilter: %v", err)
	}
	got, err := collectFilteredEvents([]string{path}, 0, lf)
	if err != nil {
		t.Fatalf("collectFilteredEvents: %v", err)
	}
	if len(got) != 1 || got[0].PID != 40 {
		t.Fatalf("unexpected events: %+v", got)
	}
}

func TestOpenLogReaderUnwrapsLayeredCompression(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "prec.log-20260615.gz")
	evs := []events.CommandEvent{
		{Timestamp: "2026-06-15T04:00:00Z", PID: 55, User: "u", Group: "g", Source: events.SourceUser, Argv: []string{"cmd55"}},
	}
	if err := writeTestLayeredLogFile(path, evs, logCompressionZstd, logCompressionGzip); err != nil {
		t.Fatalf("write layered log: %v", err)
	}

	lf, err := buildQueryFilter([]string{"source=user"})
	if err != nil {
		t.Fatalf("buildQueryFilter: %v", err)
	}
	got, err := collectFilteredEvents([]string{path}, 0, lf)
	if err != nil {
		t.Fatalf("collectFilteredEvents: %v", err)
	}
	if len(got) != 1 || got[0].PID != 55 {
		t.Fatalf("unexpected events: %+v", got)
	}
}

func TestIsReplacedByName(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "prec.log")
	rotated := filepath.Join(tmpDir, "prec.log.1")
	if err := os.WriteFile(logPath, []byte("first\n"), 0o644); err != nil {
		t.Fatalf("write initial log: %v", err)
	}

	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open initial log: %v", err)
	}
	defer f.Close()

	replaced, err := isReplacedByName(logPath, f)
	if err != nil {
		t.Fatalf("isReplacedByName(before): %v", err)
	}
	if replaced {
		t.Fatalf("unexpected replaced=true before rotation")
	}

	if err := os.Rename(logPath, rotated); err != nil {
		t.Fatalf("rename log: %v", err)
	}
	if err := os.WriteFile(logPath, []byte("second\n"), 0o644); err != nil {
		t.Fatalf("write recreated log: %v", err)
	}

	replaced, err = isReplacedByName(logPath, f)
	if err != nil {
		t.Fatalf("isReplacedByName(after): %v", err)
	}
	if !replaced {
		t.Fatalf("expected replaced=true after rotation")
	}
}

func TestReopenFollowFileByName(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "prec.log")
	rotated := filepath.Join(tmpDir, "prec.log.1")
	if err := os.WriteFile(logPath, []byte("first\n"), 0o644); err != nil {
		t.Fatalf("write initial log: %v", err)
	}

	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open initial log: %v", err)
	}
	defer f.Close()

	if err := os.Rename(logPath, rotated); err != nil {
		t.Fatalf("rename log: %v", err)
	}
	if err := os.WriteFile(logPath, []byte("second\n"), 0o644); err != nil {
		t.Fatalf("write recreated log: %v", err)
	}

	next, replaced, err := reopenFollowFileByName(logPath, f)
	if err != nil {
		t.Fatalf("reopenFollowFileByName: %v", err)
	}
	defer next.Close()
	if !replaced {
		t.Fatalf("expected replaced=true")
	}
	currentInfo, err := next.Stat()
	if err != nil {
		t.Fatalf("stat next: %v", err)
	}
	pathInfo, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat path: %v", err)
	}
	if !os.SameFile(currentInfo, pathInfo) {
		t.Fatalf("reopened file does not match current path")
	}
}

func TestRewindIfShrunk(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "prec.log")
	if err := os.WriteFile(logPath, []byte("12345\n"), 0o644); err != nil {
		t.Fatalf("write initial log: %v", err)
	}

	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()

	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		t.Fatalf("seek end: %v", err)
	}
	if err := os.Truncate(logPath, 0); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	rewound, err := rewindIfShrunk(f)
	if err != nil {
		t.Fatalf("rewindIfShrunk: %v", err)
	}
	if !rewound {
		t.Fatalf("expected rewound=true")
	}
	offset, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatalf("seek current: %v", err)
	}
	if offset != 0 {
		t.Fatalf("offset=%d want=0", offset)
	}
}

func TestDetectLogCompressionWithHint(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "prec.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	got, err := detectLogCompression(path, config.CompressZstd)
	if err != nil {
		t.Fatalf("detectLogCompression: %v", err)
	}
	if got != logCompressionZstd {
		t.Fatalf("got=%q want=%q", got, logCompressionZstd)
	}
}

func TestCompressedTailReaderReadsFrames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		mode  string
		first string
		next  string
	}{
		{name: "gzip", mode: logCompressionGzip, first: "line-gz-1", next: "line-gz-2"},
		{name: "zstd", mode: logCompressionZstd, first: "line-zstd-1", next: "line-zstd-2"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var (
				mu    sync.Mutex
				lines []string
			)

			reader := newCompressedTailReader()
			defer reader.Close()

			handleLine := func(line string) {
				mu.Lock()
				lines = append(lines, line)
				mu.Unlock()
			}

			if err := reader.Reset(tt.mode, handleLine); err != nil {
				t.Fatalf("reset: %v", err)
			}
			chunk, err := encodeCompressedFrame(tt.mode, tt.first+"\n")
			if err != nil {
				t.Fatalf("encode first frame: %v", err)
			}
			if err := reader.Feed(chunk); err != nil {
				t.Fatalf("feed first frame: %v", err)
			}
			waitForLineCount(t, &mu, &lines, 1)

			if err := reader.Reset(tt.mode, handleLine); err != nil {
				t.Fatalf("reset after truncate: %v", err)
			}
			chunk, err = encodeCompressedFrame(tt.mode, tt.next+"\n")
			if err != nil {
				t.Fatalf("encode second frame: %v", err)
			}
			if err := reader.Feed(chunk); err != nil {
				t.Fatalf("feed second frame: %v", err)
			}
			waitForLineCount(t, &mu, &lines, 2)

			mu.Lock()
			got := append([]string(nil), lines...)
			mu.Unlock()
			if got[0] != tt.first || got[1] != tt.next {
				t.Fatalf("got=%v want=[%s %s]", got, tt.first, tt.next)
			}
		})
	}
}
