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
	"github.com/klauspost/compress/zstd"

	"github.com/jfut/prec/pkg/events"
)

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

	raw := make([]events.CommandEvent, 0)
	for _, logPath := range logPaths {
		if err := appendEventsFromLog(logPath, &raw, includeCommandEnd); err != nil {
			return nil, err
		}
	}
	merged := mergeEventsForList(raw, joinState, includeCommandEnd)
	filteredCapacity := len(merged)
	if limit > 0 && limit < filteredCapacity {
		filteredCapacity = limit
	}
	filtered := make([]events.CommandEvent, 0, filteredCapacity)
	for _, ev := range merged {
		if !matchFilter(ev, lf) {
			continue
		}
		appendWithLimit(&filtered, ev, limit)
	}
	return filtered, nil
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
		initialWindowBytes = int64(4 * 1024 * 1024)
	)
	window := initialWindowBytes
	if window > size {
		window = size
	}

	var dec *zstd.Decoder
	if compressionMode == logCompressionZstd {
		dec, err = zstd.NewReader(nil)
		if err != nil {
			return nil, false, err
		}
		defer dec.Close()
	}

	commandEndMarkerBytes := []byte(commandEndRecordTypeMarker)
	for {
		start := size - window
		decoded, ok, err := decodeCompressedSuffixFromFrameBoundary(f, dec, start, window, compressionMode)
		if err != nil {
			return nil, false, err
		}
		if ok {
			matchesRev := make([]events.CommandEvent, 0, limit)
			lines := bytes.Split(decoded, []byte{'\n'})
			for i := len(lines) - 1; i >= 0 && len(matchesRev) < limit; i-- {
				line := bytes.TrimSpace(lines[i])
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
		window = minInt64(size, window*2)
	}
}

func decodeCompressedSuffixFromFrameBoundary(f *os.File, dec *zstd.Decoder, start int64, length int64, compressionMode string) ([]byte, bool, error) {
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
		if dec == nil {
			return nil, false, errors.New("zstd decoder is not initialized")
		}
		for _, idx := range findAllBytesIndices(buf, zstdFrameMagic) {
			decoded, err := dec.DecodeAll(buf[idx:], nil)
			if err == nil {
				return decoded, true, nil
			}
		}
	case logCompressionGzip:
		for _, idx := range findAllBytesIndices(buf, gzipFrameMagic) {
			gzReader, err := gzip.NewReader(bytes.NewReader(buf[idx:]))
			if err != nil {
				continue
			}
			decoded, readErr := io.ReadAll(gzReader)
			closeErr := gzReader.Close()
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

func appendEventsFromLog(logPath string, dst *[]events.CommandEvent, includeCommandEnd bool) error {
	reader, err := openLogReader(logPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	s := bufio.NewScanner(reader)
	for s.Scan() {
		line := s.Bytes()
		// In fast mode, skip end lines before JSON decode to reduce CPU cost.
		if !includeCommandEnd && bytes.Contains(line, []byte(commandEndRecordTypeMarker)) {
			continue
		}
		var ev events.CommandEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		*dst = append(*dst, ev)
	}
	return s.Err()
}

func appendWithLimit(dst *[]events.CommandEvent, ev events.CommandEvent, limit int) {
	if limit == 0 {
		*dst = append(*dst, ev)
		return
	}
	if len(*dst) < limit {
		*dst = append(*dst, ev)
		return
	}
	copy(*dst, (*dst)[1:])
	(*dst)[len(*dst)-1] = ev
}
