// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jfut/prec/internal/events"
)

func runList(logPaths []string, limit int, lf listFilter, opt outputOptions) int {
	includeCommandEnd := requiresCommandEndProcessing(lf, opt)
	buf, err := collectFilteredEventsWithJoin(logPaths, limit, lf, nil, includeCommandEnd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 1
	}

	formatter := newOutputFormatter(opt)
	if header := formatter.Header(); header != "" {
		fmt.Println(header)
	}
	for _, line := range renderEventsWithFormatter(buf, opt, formatter) {
		fmt.Println(line)
	}
	return 0
}

func runTail(logPath string, compressionHint string, logPaths []string, allLogs bool, n int, lf listFilter, opt outputOptions) int {
	joinState := newCommandJoinState()
	includeCommandEnd := requiresCommandEndProcessing(lf, opt)
	formatter := newOutputFormatter(opt)

	if header := formatter.Header(); header != "" {
		fmt.Println(header)
	}
	initialPaths := []string{logPath}
	if allLogs {
		initialPaths = logPaths
	}
	if err := printLastN(initialPaths, n, lf, joinState, formatter, includeCommandEnd); err != nil {
		fmt.Fprintf(os.Stderr, "tail initial: %v\n", err)
		return 1
	}
	compressionMode, err := detectLogCompression(logPath, compressionHint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "detect log compression: %v\n", err)
		return 1
	}

	if compressionMode == logCompressionNone {
		return runTailPlain(logPath, lf, joinState, formatter, includeCommandEnd)
	}
	return runTailCompressed(logPath, compressionMode, lf, joinState, formatter, includeCommandEnd)
}

func runTailPlain(logPath string, lf listFilter, joinState *commandJoinState, formatter outputFormatter, includeCommandEnd bool) int {
	f, err := os.Open(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open log file: %v\n", err)
		return 1
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		fmt.Fprintf(os.Stderr, "seek end: %v\n", err)
		return 1
	}

	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				nextFile, replaced, err := reopenFollowFileByName(logPath, f)
				if err != nil {
					fmt.Fprintf(os.Stderr, "follow reopen: %v\n", err)
					return 1
				}
				if replaced {
					f = nextFile
					r = bufio.NewReader(f)
					continue
				}
				// If copytruncate shrinks the same inode, rewind and read from the beginning.
				if rewound, err := rewindIfShrunk(f); err != nil {
					fmt.Fprintf(os.Stderr, "follow rewind: %v\n", err)
					return 1
				} else if rewound {
					r = bufio.NewReader(f)
					continue
				}
				time.Sleep(followPollInterval)
				continue
			}
			fmt.Fprintf(os.Stderr, "tail read: %v\n", err)
			return 1
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		emitMergedEventLines(line, lf, joinState, formatter, includeCommandEnd)
	}
}

func runTailCompressed(logPath string, compressionMode string, lf listFilter, joinState *commandJoinState, formatter outputFormatter, includeCommandEnd bool) int {
	f, err := os.Open(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open log file: %v\n", err)
		return 1
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seek end: %v\n", err)
		return 1
	}

	tailReader := newCompressedTailReader()
	defer tailReader.Close()

	const maxChunkSize = 256 * 1024
	buf := make([]byte, maxChunkSize)
	handleLine := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" {
			return
		}
		emitMergedEventLines(line, lf, joinState, formatter, includeCommandEnd)
	}
	if err := tailReader.Reset(compressionMode, handleLine); err != nil {
		fmt.Fprintf(os.Stderr, "reset tail reader: %v\n", err)
		return 1
	}

	for {
		nextFile, replaced, err := reopenFollowFileByName(logPath, f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "follow reopen: %v\n", err)
			return 1
		}
		if replaced {
			f = nextFile
			nextMode, err := detectLogCompression(logPath, compressionMode)
			if err != nil {
				fmt.Fprintf(os.Stderr, "detect log compression: %v\n", err)
				return 1
			}
			if nextMode != logCompressionNone {
				compressionMode = nextMode
			}
			if err := tailReader.Reset(compressionMode, handleLine); err != nil {
				fmt.Fprintf(os.Stderr, "reset tail reader: %v\n", err)
				return 1
			}
			offset = 0
			continue
		}

		if err := tailReader.PollError(); err != nil {
			fmt.Fprintf(os.Stderr, "tail decode: %v\n", err)
			return 1
		}

		st, err := f.Stat()
		if err != nil {
			fmt.Fprintf(os.Stderr, "stat log file: %v\n", err)
			return 1
		}
		size := st.Size()
		if size < offset {
			// If the file shrank by copytruncate, reinitialize the stream and keep following.
			if err := tailReader.Reset(compressionMode, handleLine); err != nil {
				fmt.Fprintf(os.Stderr, "reset tail reader: %v\n", err)
				return 1
			}
			offset = 0
		}

		if size == offset {
			time.Sleep(followPollInterval)
			continue
		}

		remain := size - offset
		for remain > 0 {
			chunk := int64(maxChunkSize)
			if remain < chunk {
				chunk = remain
			}
			n, readErr := f.ReadAt(buf[:chunk], offset)
			if n > 0 {
				if err := tailReader.Feed(buf[:n]); err != nil {
					fmt.Fprintf(os.Stderr, "tail feed: %v\n", err)
					return 1
				}
				offset += int64(n)
				remain -= int64(n)
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					break
				}
				fmt.Fprintf(os.Stderr, "tail read: %v\n", readErr)
				return 1
			}
		}
	}
}

func reopenFollowFileByName(logPath string, current *os.File) (*os.File, bool, error) {
	replaced, err := isReplacedByName(logPath, current)
	if err != nil {
		return nil, false, err
	}
	if !replaced {
		return current, false, nil
	}

	nextFile, err := os.Open(logPath)
	if err != nil {
		// Allow a brief window after rotation where the new file does not exist yet.
		if errors.Is(err, os.ErrNotExist) {
			return current, false, nil
		}
		return nil, false, err
	}
	if err := current.Close(); err != nil {
		nextFile.Close()
		return nil, false, err
	}
	return nextFile, true, nil
}

func isReplacedByName(logPath string, current *os.File) (bool, error) {
	currentInfo, err := current.Stat()
	if err != nil {
		return false, err
	}
	latestInfo, err := os.Stat(logPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return !os.SameFile(currentInfo, latestInfo), nil
}

func rewindIfShrunk(f *os.File) (bool, error) {
	offset, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return false, err
	}
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if info.Size() >= offset {
		return false, nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	return true, nil
}

func printLastN(logPaths []string, n int, lf listFilter, joinState *commandJoinState, formatter outputFormatter, includeCommandEnd bool) error {
	if n == 0 {
		return nil
	}
	buf, err := collectFilteredEventsWithJoin(logPaths, n, lf, joinState, includeCommandEnd)
	if err != nil {
		return err
	}
	for _, ev := range buf {
		fmt.Println(formatter.Format(ev))
	}
	return nil
}

func emitMergedEventLines(line string, lf listFilter, joinState *commandJoinState, formatter outputFormatter, includeCommandEnd bool) {
	// In fast mode, skip end lines before JSON decode to reduce CPU cost.
	if !includeCommandEnd && strings.Contains(line, commandEndRecordTypeMarker) {
		return
	}
	var ev events.CommandEvent
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		return
	}
	for _, merged := range mergeEventsForStreaming(joinState, ev, includeCommandEnd) {
		if !matchFilter(merged, lf) {
			continue
		}
		fmt.Println(formatter.Format(merged))
	}
}
