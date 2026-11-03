// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"

	"github.com/jfut/prec/internal/config"
	"github.com/jfut/prec/internal/events"
	"github.com/jfut/prec/internal/safefile"
)

// JSONLWriter appends events line by line to a root-owned log file.
type JSONLWriter struct {
	mu            sync.Mutex
	logPath       string
	f             *os.File
	enc           *json.Encoder
	compress      string
	compressLevel int
	gzipWriter    *gzip.Writer
	zstdEncoder   *zstd.Encoder
	zstdBuffer    []byte
	gzipBuffer    bytes.Buffer
	lastSyncAt    time.Time
}

const logSyncInterval = time.Second

func NewJSONLWriter(logPath string, compress string, compressLevel int) (*JSONLWriter, error) {
	f, err := openLogFile(logPath)
	if err != nil {
		return nil, err
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
		w.gzipWriter = gz
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
	if w.f == nil {
		return fmt.Errorf("logger is closed")
	}

	var err error
	switch w.compress {
	case config.CompressNo:
		err = w.enc.Encode(ev)
	case config.CompressGzip:
		err = w.writeGzipEvent(ev)
	case config.CompressZstd:
		err = w.writeZstdEvent(ev)
	default:
		return fmt.Errorf("unsupported compress mode: %s", w.compress)
	}
	if err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	if err := w.syncIfDue(); err != nil {
		return err
	}
	return nil
}

func (w *JSONLWriter) syncIfDue() error {
	now := time.Now()
	if !w.lastSyncAt.IsZero() && now.Sub(w.lastSyncAt) < logSyncInterval {
		return nil
	}
	if err := w.f.Sync(); err != nil {
		return fmt.Errorf("sync log file: %w", err)
	}
	w.lastSyncAt = now
	return nil
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
	if err := oldFile.Sync(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := oldFile.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	w.lastSyncAt = time.Time{}
	return firstErr
}

func (w *JSONLWriter) writeGzipEvent(ev events.CommandEvent) error {
	line, err := marshalJSONL(ev)
	if err != nil {
		return err
	}

	// Append one event per gzip frame to limit damage if corruption occurs mid-stream.
	w.gzipBuffer.Reset()
	gz := w.gzipWriter
	if gz == nil {
		var err error
		gz, err = gzip.NewWriterLevel(&w.gzipBuffer, w.compressLevel)
		if err != nil {
			return fmt.Errorf("init gzip writer: %w", err)
		}
		w.gzipWriter = gz
	} else {
		gz.Reset(&w.gzipBuffer)
	}
	if _, err := gz.Write(line); err != nil {
		gz.Close()
		return fmt.Errorf("gzip write: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("gzip close: %w", err)
	}
	if _, err := w.f.Write(w.gzipBuffer.Bytes()); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	return nil
}

func (w *JSONLWriter) writeZstdEvent(ev events.CommandEvent) error {
	line, err := marshalJSONL(ev)
	if err != nil {
		return err
	}
	compressed := w.zstdEncoder.EncodeAll(line, w.zstdBuffer[:0])
	if _, err := w.f.Write(compressed); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	w.zstdBuffer = compressed[:0]
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
	f, err := openLogFile(w.logPath)
	if err != nil {
		return nil, nil, nil, err
	}

	switch w.compress {
	case config.CompressNo:
		return f, json.NewEncoder(f), nil, nil
	case config.CompressGzip:
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

// openLogFile accepts only a current-user-owned regular file with one link,
// preventing a privileged daemon from redirecting writes to unrelated targets.
func openLogFile(path string) (*os.File, error) {
	f, err := safefile.OpenAppend(path, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	return f, nil
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
	if err := w.f.Sync(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := w.f.Close(); err != nil && firstErr == nil {
		firstErr = err
	}

	w.f = nil
	w.enc = nil
	w.gzipWriter = nil
	w.zstdEncoder = nil
	w.zstdBuffer = nil
	w.gzipBuffer = bytes.Buffer{}
	return firstErr
}
