// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package logger

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"

	"github.com/jfut/prec/internal/config"
	"github.com/jfut/prec/internal/events"
)

func TestJSONLWriterReopenSwitchesOutputFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mode   string
		level  int
		readAs string
	}{
		{name: "no", mode: config.CompressNo, level: 0, readAs: config.CompressNo},
		{name: "gz", mode: config.CompressGzip, level: config.DefaultGzipCompressLevel, readAs: config.CompressGzip},
		{name: "zstd", mode: config.CompressZstd, level: config.DefaultZstdCompressLevel, readAs: config.CompressZstd},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tmpDir := t.TempDir()
			logPath := filepath.Join(tmpDir, "prec.log")
			rotatedPath := filepath.Join(tmpDir, "prec.log.1")

			w, err := NewJSONLWriter(logPath, tt.mode, tt.level)
			if err != nil {
				t.Fatalf("NewJSONLWriter: %v", err)
			}
			defer w.Close()

			first := events.CommandEvent{
				Timestamp: "2026-05-23T00:00:01Z",
				PID:       1,
				User:      "u",
				Group:     "g",
				Source:    events.SourceUser,
				Argv:      []string{"first"},
			}
			if err := w.WriteEvent(first); err != nil {
				t.Fatalf("WriteEvent(first): %v", err)
			}

			if err := os.Rename(logPath, rotatedPath); err != nil {
				t.Fatalf("rename to rotated: %v", err)
			}

			if err := w.Reopen(); err != nil {
				t.Fatalf("Reopen: %v", err)
			}

			second := events.CommandEvent{
				Timestamp: "2026-05-23T00:00:02Z",
				PID:       2,
				User:      "u",
				Group:     "g",
				Source:    events.SourceUser,
				Argv:      []string{"second"},
			}
			if err := w.WriteEvent(second); err != nil {
				t.Fatalf("WriteEvent(second): %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			gotRotated, err := readEvents(rotatedPath, tt.readAs)
			if err != nil {
				t.Fatalf("readEvents(rotated): %v", err)
			}
			gotCurrent, err := readEvents(logPath, tt.readAs)
			if err != nil {
				t.Fatalf("readEvents(current): %v", err)
			}

			if len(gotRotated) != 1 || len(gotCurrent) != 1 {
				t.Fatalf("unexpected event counts: rotated=%d current=%d", len(gotRotated), len(gotCurrent))
			}
			if gotRotated[0].PID != 1 || gotCurrent[0].PID != 2 {
				t.Fatalf("unexpected event PID: rotated=%d current=%d", gotRotated[0].PID, gotCurrent[0].PID)
			}
		})
	}
}

func TestJSONLWriterReopenAfterClose(t *testing.T) {
	t.Parallel()

	logPath := filepath.Join(t.TempDir(), "prec.log")
	w, err := NewJSONLWriter(logPath, config.CompressNo, 0)
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.Reopen(); err == nil {
		t.Fatalf("Reopen should fail on closed writer")
	}
}

func readEvents(path string, mode string) ([]events.CommandEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var reader io.Reader = f
	switch mode {
	case config.CompressNo:
	case config.CompressGzip:
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		reader = gz
	case config.CompressZstd:
		dec, err := zstd.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer dec.Close()
		reader = dec
	default:
		return nil, fmt.Errorf("unsupported mode: %s", mode)
	}

	scanner := bufio.NewScanner(reader)
	out := make([]events.CommandEvent, 0)
	for scanner.Scan() {
		var ev events.CommandEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
