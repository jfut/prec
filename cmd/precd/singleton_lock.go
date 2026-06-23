// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

var errPrecdAlreadyRunning = errors.New("precd already running")

// singletonLock holds a process-wide lock file descriptor to prevent duplicate daemons.
type singletonLock struct {
	f *os.File
}

func lockPathFromLogPath(logPath string) string {
	return logPath + ".lock"
}

func acquireSingletonLock(logPath string) (*singletonLock, error) {
	lockPath := lockPathFromLogPath(logPath)
	lockDir := filepath.Dir(lockPath)
	if err := os.MkdirAll(lockDir, 0o750); err != nil {
		return nil, fmt.Errorf("create lock dir: %w", err)
	}

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := f.Chmod(0o640); err != nil {
		f.Close()
		return nil, fmt.Errorf("chmod lock file: %w", err)
	}

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("%w: %s", errPrecdAlreadyRunning, lockPath)
		}
		return nil, fmt.Errorf("acquire lock: %w", err)
	}

	return &singletonLock{f: f}, nil
}

func (l *singletonLock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}

	var firstErr error
	if err := unix.Flock(int(l.f.Fd()), unix.LOCK_UN); err != nil {
		firstErr = err
	}
	if err := l.f.Close(); err != nil && firstErr == nil {
		firstErr = err
	}

	l.f = nil
	return firstErr
}
