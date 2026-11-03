// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/klauspost/compress/gzip"

	"github.com/jfut/prec/internal/events"
)

// Limit false magic-byte matches in untrusted compressed input before falling back to a full scan.
const maxCompressedFrameCandidates = 4096

func collectFilteredEvents(logPaths []string, limit int, lf listFilter) ([]events.CommandEvent, error) {
	return collectFilteredEventsWithJoin(logPaths, limit, lf, nil, true)
}

func collectFilteredEventsWithJoin(logPaths []string, limit int, lf listFilter, joinState *commandJoinState, includeCommandEnd bool) ([]events.CommandEvent, error) {
	// Fast path for -n list mode on frame-compressed logs: read only suffix frames instead of full-file decode.
	if fast, ok, err := collectFilteredEventsWithJoinFastTailCompressed(logPaths, limit, lf, joinState, includeCommandEnd); err != nil {
		return nil, err
	} else if ok {
		return fast, nil
	}
	if !includeCommandEnd {
		return collectFilteredEventsStreaming(logPaths, limit, lf)
	}

	raw := make([]events.CommandEvent, 0)
	for _, logPath := range logPaths {
		if err := appendEventsFromLog(logPath, &raw); err != nil {
			return nil, err
		}
	}
	merged := mergeEventsForList(raw, joinState)
	if limit <= 0 {
		mergedLen := len(merged)
		filtered := merged[:0]
		for _, ev := range merged {
			if matchFilter(ev, lf) {
				filtered = append(filtered, ev)
			}
		}
		clear(merged[len(filtered):mergedLen])
		return filtered, nil
	}
	filtered := newEventWindow(limit)
	for _, ev := range merged {
		if matchFilter(ev, lf) {
			filtered.Add(ev)
		}
	}
	return filtered.Events(), nil
}

// collectFilteredEventsStreaming avoids retaining raw and merged copies when
// finalized process fields are not needed by the query or output.
func collectFilteredEventsStreaming(logPaths []string, limit int, lf listFilter) ([]events.CommandEvent, error) {
	filtered := newEventWindow(limit)
	for _, logPath := range logPaths {
		reader, err := openLogReader(logPath)
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 0, 64*1024), maxLogLineLength)
		for scanner.Scan() {
			line := scanner.Bytes()
			// End records cannot affect the start-only view, so skip JSON decoding.
			if bytes.Contains(line, []byte(commandEndRecordTypeMarker)) {
				continue
			}
			var ev events.CommandEvent
			if err := json.Unmarshal(line, &ev); err != nil {
				continue
			}
			merged, keep := mergedEventWithoutCommandEnd(ev)
			if keep && matchFilter(merged, lf) {
				filtered.Add(merged)
			}
		}
		scanErr := scanner.Err()
		closeErr := reader.Close()
		if scanErr != nil {
			return nil, scanErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	return filtered.Events(), nil
}

// eventWindow keeps only the newest matching rows without shifting the whole
// result slice for every event after the requested limit is reached.
type eventWindow struct {
	rows  []events.CommandEvent
	start int
	count int
	limit int
}

func newEventWindow(limit int) *eventWindow {
	if limit < 0 {
		limit = 0
	}
	capacity := 0
	if limit > 0 {
		capacity = min(limit, 256)
	}
	return &eventWindow{rows: make([]events.CommandEvent, 0, capacity), limit: limit}
}

func (w *eventWindow) Add(ev events.CommandEvent) {
	if w.limit == 0 {
		w.rows = append(w.rows, ev)
		return
	}
	if w.count < w.limit {
		w.rows = append(w.rows, ev)
		w.count++
		return
	}
	w.rows[w.start] = ev
	w.start = (w.start + 1) % w.limit
}

func (w *eventWindow) Events() []events.CommandEvent {
	if w.limit == 0 || w.start == 0 {
		return w.rows
	}
	out := make([]events.CommandEvent, w.count)
	for i := range out {
		out[i] = w.rows[(w.start+i)%w.limit]
	}
	return out
}

func collectFilteredEventsWithJoinFastTailCompressed(logPaths []string, limit int, lf listFilter, joinState *commandJoinState, includeCommandEnd bool) ([]events.CommandEvent, bool, error) {
	if limit <= 0 || includeCommandEnd || joinState != nil || len(logPaths) != 1 {
		return nil, false, nil
	}

	logPath := logPaths[0]
	compressionMode, err := detectLogCompression(logPath, "")
	if err != nil {
		return nil, false, err
	}
	if compressionMode != logCompressionZstd && compressionMode != logCompressionGzip {
		return nil, false, nil
	}

	eventsOut, ok, err := collectTailEventsFromCompressedLog(logPath, limit, lf, compressionMode)
	if err != nil {
		// Fall back to full scan if suffix frame decode cannot be used for this file.
		return nil, false, nil
	}
	return eventsOut, ok, nil
}

func collectTailEventsFromCompressedLog(logPath string, limit int, lf listFilter, compressionMode string) ([]events.CommandEvent, bool, error) {
	f, err := os.Open(logPath)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	size := info.Size()
	if size <= 0 {
		return []events.CommandEvent{}, true, nil
	}

	const (
		initialWindowBytes   = int64(4 * 1024 * 1024)
		maxSuffixWindowBytes = int64(64 * 1024 * 1024)
	)
	window := initialWindowBytes
	if window > size {
		window = size
	}

	commandEndMarkerBytes := []byte(commandEndRecordTypeMarker)
	for {
		start := size - window
		decoded, ok, err := decodeCompressedSuffixFromFrameBoundary(f, start, window, compressionMode)
		if err != nil {
			return nil, false, err
		}
		if ok {
			// Nested layers need the recursive reader; the suffix fast path handles one layer.
			if detectCompressionByMagic(bufio.NewReader(bytes.NewReader(decoded))) != logCompressionNone {
				return nil, false, nil
			}
			matchesRev := make([]events.CommandEvent, 0, min(limit, 256))
			lineEnd := len(decoded)
			for i := len(decoded) - 1; i >= -1 && len(matchesRev) < limit; i-- {
				if i >= 0 && decoded[i] != '\n' {
					continue
				}
				line := bytes.TrimSpace(decoded[i+1 : lineEnd])
				lineEnd = i
				if len(line) == 0 {
					continue
				}
				// In fast mode, end is always ignored and does not require JSON decode.
				if bytes.Contains(line, commandEndMarkerBytes) {
					continue
				}

				var ev events.CommandEvent
				if err := json.Unmarshal(line, &ev); err != nil {
					continue
				}
				merged, keep := mergedEventWithoutCommandEnd(ev)
				if !keep {
					continue
				}
				if !matchFilter(merged, lf) {
					continue
				}
				matchesRev = append(matchesRev, merged)
			}

			if len(matchesRev) >= limit || window == size {
				return reverseEvents(matchesRev), true, nil
			}
		}

		if window == size {
			return nil, false, nil
		}
		if window >= maxSuffixWindowBytes {
			return nil, false, nil
		}
		window = minInt64(size, window*2)
	}
}

func decodeCompressedSuffixFromFrameBoundary(f *os.File, start int64, length int64, compressionMode string) ([]byte, bool, error) {
	if length <= 0 {
		return nil, false, nil
	}

	buf := make([]byte, length)
	n, err := f.ReadAt(buf, start)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	buf = buf[:n]
	if len(buf) == 0 {
		return nil, false, nil
	}

	switch compressionMode {
	case logCompressionZstd:
		for _, idx := range findAllBytesIndices(buf, zstdFrameMagic) {
			dec, err := newLogZstdDecoder(bytes.NewReader(buf[idx:]))
			if err != nil {
				continue
			}
			decoded, readErr := io.ReadAll(io.LimitReader(dec, maxLogLineLength+1))
			dec.Close()
			if readErr == nil && len(decoded) > maxLogLineLength {
				return nil, false, fmt.Errorf("compressed suffix expands beyond %d bytes", maxLogLineLength)
			}
			if readErr == nil {
				return decoded, true, nil
			}
		}
	case logCompressionGzip:
		for _, idx := range findAllBytesIndices(buf, gzipFrameMagic) {
			gzReader, err := gzip.NewReader(bytes.NewReader(buf[idx:]))
			if err != nil {
				continue
			}
			decoded, readErr := io.ReadAll(io.LimitReader(gzReader, maxLogLineLength+1))
			closeErr := gzReader.Close()
			if readErr == nil && len(decoded) > maxLogLineLength {
				return nil, false, fmt.Errorf("compressed suffix expands beyond %d bytes", maxLogLineLength)
			}
			if readErr == nil && closeErr == nil {
				return decoded, true, nil
			}
		}
	default:
		return nil, false, fmt.Errorf("unsupported compression mode: %s", compressionMode)
	}
	return nil, false, nil
}

func findAllBytesIndices(src []byte, marker []byte) []int {
	if len(src) == 0 || len(marker) == 0 || len(src) < len(marker) {
		return nil
	}

	indices := make([]int, 0, 32)
	searchStart := 0
	for {
		idx := bytes.Index(src[searchStart:], marker)
		if idx < 0 {
			return indices
		}
		absolute := searchStart + idx
		indices = append(indices, absolute)
		if len(indices) == maxCompressedFrameCandidates {
			return indices
		}
		searchStart = absolute + 1
		if searchStart >= len(src) {
			return indices
		}
	}
}

func reverseEvents(in []events.CommandEvent) []events.CommandEvent {
	out := make([]events.CommandEvent, len(in))
	for i := range in {
		out[len(in)-1-i] = in[i]
	}
	return out
}

func minInt64(a int64, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func appendEventsFromLog(logPath string, dst *[]events.CommandEvent) error {
	reader, err := openLogReader(logPath)
	if err != nil {
		return err
	}

	s := bufio.NewScanner(reader)
	s.Buffer(make([]byte, 0, 64*1024), maxLogLineLength)
	for s.Scan() {
		var ev events.CommandEvent
		if err := json.Unmarshal(s.Bytes(), &ev); err != nil {
			continue
		}
		*dst = append(*dst, ev)
	}
	scanErr := s.Err()
	closeErr := reader.Close()
	if scanErr != nil {
		return scanErr
	}
	return closeErr
}
