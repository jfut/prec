// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"

	"github.com/jfut/prec/pkg/config"
	"github.com/jfut/prec/pkg/events"
)

// JSONLWriter appends events line by line to a root-owned log file.
type JSONLWriter struct {
	mu            sync.Mutex
	logPath       string
	f             *os.File
	enc           *json.Encoder
	compress      string
	compressLevel int
	zstdEncoder   *zstd.Encoder
}

func NewJSONLWriter(logPath string, compress string, compressLevel int) (*JSONLWriter, error) {
	dir := filepath.Dir(logPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	if err := f.Chmod(0o640); err != nil {
		f.Close()
		return nil, fmt.Errorf("chmod log file: %w", err)
	}

	mode := strings.ToLower(strings.TrimSpace(compress))
	if mode == "" {
		mode = config.CompressNo
	}

	w := &JSONLWriter{
		logPath:       logPath,
		f:             f,
		compress:      mode,
		compressLevel: compressLevel,
	}

	switch mode {
	case config.CompressNo:
		w.enc = json.NewEncoder(f)
	case config.CompressGzip:
		gz, err := gzip.NewWriterLevel(io.Discard, compressLevel)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("init gzip writer: %w", err)
		}
		gz.Close()
	case config.CompressZstd:
		enc, err := zstd.NewWriter(
			nil,
			zstd.WithEncoderConcurrency(1),
			zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(compressLevel)),
		)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("init zstd encoder: %w", err)
		}
		w.zstdEncoder = enc
	default:
		f.Close()
		return nil, fmt.Errorf("unsupported compress mode: %s", mode)
	}

	return w, nil
}

func (w *JSONLWriter) WriteEvent(ev events.CommandEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	switch w.compress {
	case config.CompressNo:
		if err := w.enc.Encode(ev); err != nil {
			return fmt.Errorf("write event: %w", err)
		}
		return nil
	case config.CompressGzip:
		return w.writeGzipEvent(ev)
	case config.CompressZstd:
		return w.writeZstdEvent(ev)
	default:
		return fmt.Errorf("unsupported compress mode: %s", w.compress)
	}
}

func (w *JSONLWriter) Reopen() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return fmt.Errorf("logger is closed")
	}

	nextFile, nextEnc, nextZstd, err := w.openOutputs()
	if err != nil {
		return err
	}

	oldFile := w.f
	oldZstd := w.zstdEncoder

	w.f = nextFile
	w.enc = nextEnc
	w.zstdEncoder = nextZstd

	var firstErr error
	if err := closeZstdEncoder(oldZstd); err != nil {
		firstErr = err
	}
	if err := oldFile.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func (w *JSONLWriter) writeGzipEvent(ev events.CommandEvent) error {
	line, err := marshalJSONL(ev)
	if err != nil {
		return err
	}

	// Append one event per gzip frame to limit damage if corruption occurs mid-stream.
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, w.compressLevel)
	if err != nil {
		return fmt.Errorf("init gzip writer: %w", err)
	}
	if _, err := gz.Write(line); err != nil {
		gz.Close()
		return fmt.Errorf("gzip write: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("gzip close: %w", err)
	}
	if _, err := w.f.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	return nil
}

func (w *JSONLWriter) writeZstdEvent(ev events.CommandEvent) error {
	line, err := marshalJSONL(ev)
	if err != nil {
		return err
	}
	compressed := w.zstdEncoder.EncodeAll(line, nil)
	if _, err := w.f.Write(compressed); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	return nil
}

func marshalJSONL(ev events.CommandEvent) ([]byte, error) {
	line, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("write event: %w", err)
	}
	line = append(line, '\n')
	return line, nil
}

func closeZstdEncoder(enc *zstd.Encoder) error {
	if enc == nil {
		return nil
	}
	err := enc.Close()
	if err != nil {
		return err
	}
	return nil
}

func (w *JSONLWriter) openOutputs() (*os.File, *json.Encoder, *zstd.Encoder, error) {
	f, err := os.OpenFile(w.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open log file: %w", err)
	}
	if err := f.Chmod(0o640); err != nil {
		f.Close()
		return nil, nil, nil, fmt.Errorf("chmod log file: %w", err)
	}

	switch w.compress {
	case config.CompressNo:
		return f, json.NewEncoder(f), nil, nil
	case config.CompressGzip:
		// Re-validate that the configured gzip level is still valid during reopen.
		gz, err := gzip.NewWriterLevel(io.Discard, w.compressLevel)
		if err != nil {
			f.Close()
			return nil, nil, nil, fmt.Errorf("init gzip writer: %w", err)
		}
		gz.Close()
		return f, nil, nil, nil
	case config.CompressZstd:
		enc, err := zstd.NewWriter(
			nil,
			zstd.WithEncoderConcurrency(1),
			zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(w.compressLevel)),
		)
		if err != nil {
			f.Close()
			return nil, nil, nil, fmt.Errorf("init zstd encoder: %w", err)
		}
		return f, nil, enc, nil
	default:
		f.Close()
		return nil, nil, nil, fmt.Errorf("unsupported compress mode: %s", w.compress)
	}
}

func (w *JSONLWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}

	var firstErr error
	if err := closeZstdEncoder(w.zstdEncoder); err != nil {
		firstErr = err
	}
	if err := w.f.Close(); err != nil && firstErr == nil {
		firstErr = err
	}

	w.f = nil
	w.enc = nil
	w.zstdEncoder = nil
	return firstErr
}
