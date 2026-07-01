// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package cli

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/jfut/prec/internal/events"
)

func intPtr(v int) *int {
	return &v
}

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func int64Ptr(v int64) *int64 {
	return &v
}

func waitForLineCount(t *testing.T, mu *sync.Mutex, lines *[]string, want int) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(*lines)
		mu.Unlock()
		if n >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	got := len(*lines)
	mu.Unlock()
	t.Fatalf("timeout waiting lines: got=%d want>=%d", got, want)
}

func encodeCompressedFrame(mode string, payload string) ([]byte, error) {
	switch mode {
	case logCompressionGzip:
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		if _, err := w.Write([]byte(payload)); err != nil {
			w.Close()
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		return b.Bytes(), nil
	case logCompressionZstd:
		enc, err := zstd.NewWriter(nil)
		if err != nil {
			return nil, err
		}
		defer enc.Close()
		return enc.EncodeAll([]byte(payload), nil), nil
	default:
		return nil, fmt.Errorf("unsupported mode: %s", mode)
	}
}

func writeTestLogFile(path string, eventsIn []events.CommandEvent, compression string, addInvalidLine bool) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if compression == "none" {
		for _, ev := range eventsIn {
			b, err := json.Marshal(ev)
			if err != nil {
				return err
			}
			if _, err := f.Write(append(b, '\n')); err != nil {
				return err
			}
		}
		if addInvalidLine {
			if _, err := f.WriteString("invalid\n"); err != nil {
				return err
			}
		}
		return nil
	}

	if compression == "gz" {
		// Generate gzip logs in the same JSONL format used in production.
		gzWriter := gzip.NewWriter(f)
		for _, ev := range eventsIn {
			b, err := json.Marshal(ev)
			if err != nil {
				gzWriter.Close()
				return err
			}
			if _, err := gzWriter.Write(append(b, '\n')); err != nil {
				gzWriter.Close()
				return err
			}
		}
		if addInvalidLine {
			if _, err := gzWriter.Write([]byte("invalid\n")); err != nil {
				gzWriter.Close()
				return err
			}
		}
		return gzWriter.Close()
	}

	if compression == "zstd" {
		enc, err := zstd.NewWriter(f)
		if err != nil {
			return err
		}
		for _, ev := range eventsIn {
			b, err := json.Marshal(ev)
			if err != nil {
				enc.Close()
				return err
			}
			if _, err := enc.Write(append(b, '\n')); err != nil {
				enc.Close()
				return err
			}
		}
		if addInvalidLine {
			if _, err := enc.Write([]byte("invalid\n")); err != nil {
				enc.Close()
				return err
			}
		}
		return enc.Close()
	}

	return fmt.Errorf("unsupported compression mode: %s", compression)
}

func writeTestLayeredLogFile(path string, eventsIn []events.CommandEvent, layers ...string) error {
	var payload bytes.Buffer
	for _, ev := range eventsIn {
		b, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		if _, err := payload.Write(append(b, '\n')); err != nil {
			return err
		}
	}

	encoded := payload.Bytes()
	for _, layer := range layers {
		next, err := encodeCompressedFrame(layer, string(encoded))
		if err != nil {
			return err
		}
		encoded = next
	}

	// Build a layered rotated log that matches precd compression plus logrotate compress.
	return os.WriteFile(path, encoded, 0o644)
}

func writeTestZstdFrameLogFile(path string, eventsIn []events.CommandEvent) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc, err := zstd.NewWriter(nil)
	if err != nil {
		return err
	}
	defer enc.Close()

	for _, ev := range eventsIn {
		b, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		frame := enc.EncodeAll(append(b, '\n'), nil)
		if _, err := f.Write(frame); err != nil {
			return err
		}
	}
	return nil
}

func writeTestGzipFrameLogFile(path string, eventsIn []events.CommandEvent) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, ev := range eventsIn {
		b, err := json.Marshal(ev)
		if err != nil {
			return err
		}

		var frame bytes.Buffer
		gzWriter := gzip.NewWriter(&frame)
		if _, err := gzWriter.Write(append(b, '\n')); err != nil {
			gzWriter.Close()
			return err
		}
		if err := gzWriter.Close(); err != nil {
			return err
		}
		if _, err := f.Write(frame.Bytes()); err != nil {
			return err
		}
	}
	return nil
}
