// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package cli

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type logFileMeta struct {
	path    string
	name    string
	modTime time.Time
}

func resolveLogPaths(logPath string, allLogs bool) ([]string, error) {
	if !allLogs {
		return []string{logPath}, nil
	}

	baseName := filepath.Base(logPath)
	dirPath := filepath.Dir(logPath)
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	files := make([]logFileMeta, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isTargetLogFile(baseName, name) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, logFileMeta{
			path:    filepath.Join(dirPath, name),
			name:    name,
			modTime: info.ModTime(),
		})
	}

	if len(files) == 0 {
		return []string{logPath}, nil
	}

	// Keep list mode stable by sorting in ascending modification time.
	sort.Slice(files, func(i int, j int) bool {
		if files[i].modTime.Equal(files[j].modTime) {
			return files[i].name < files[j].name
		}
		return files[i].modTime.Before(files[j].modTime)
	})

	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.path)
	}
	return paths, nil
}

func isTargetLogFile(baseName string, fileName string) bool {
	if fileName == baseName {
		return true
	}
	if strings.HasPrefix(fileName, baseName+".") {
		return true
	}
	if strings.HasPrefix(fileName, baseName+"-") {
		return true
	}
	return false
}
