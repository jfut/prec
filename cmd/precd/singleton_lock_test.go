// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package main

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestAcquireSingletonLockRejectsSecondInstance(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "prec.log")

	first, err := acquireSingletonLock(logPath)
	if err != nil {
		t.Fatalf("acquire first lock: %v", err)
	}
	defer first.Close()

	second, err := acquireSingletonLock(logPath)
	if second != nil {
		second.Close()
		t.Fatalf("second lock must be nil when lock acquisition fails")
	}
	if !errors.Is(err, errPrecdAlreadyRunning) {
		t.Fatalf("second lock error=%v, want errPrecdAlreadyRunning", err)
	}
}

func TestAcquireSingletonLockAllowsNextAfterClose(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "prec.log")

	first, err := acquireSingletonLock(logPath)
	if err != nil {
		t.Fatalf("acquire first lock: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first lock: %v", err)
	}

	second, err := acquireSingletonLock(logPath)
	if err != nil {
		t.Fatalf("acquire second lock after close: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close second lock: %v", err)
	}
}
