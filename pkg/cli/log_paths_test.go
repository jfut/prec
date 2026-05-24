package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestResolveLogPaths(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	currentLog := filepath.Join(tmpDir, "prec.log")
	rotatedPlain := filepath.Join(tmpDir, "prec.log.1")
	rotatedGzip := filepath.Join(tmpDir, "prec.log.2.gz")
	datedGzip := filepath.Join(tmpDir, "prec.log-20260501.gz")
	unrelated := filepath.Join(tmpDir, "other.log")

	for _, path := range []string{currentLog, rotatedPlain, rotatedGzip, datedGzip, unrelated} {
		if err := os.WriteFile(path, []byte(""), 0644); err != nil {
			t.Fatalf("write file: %v", err)
		}
	}

	base := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(rotatedGzip, base, base); err != nil {
		t.Fatalf("chtimes rotatedGzip: %v", err)
	}
	if err := os.Chtimes(datedGzip, base.Add(1*time.Minute), base.Add(1*time.Minute)); err != nil {
		t.Fatalf("chtimes datedGzip: %v", err)
	}
	if err := os.Chtimes(rotatedPlain, base.Add(2*time.Minute), base.Add(2*time.Minute)); err != nil {
		t.Fatalf("chtimes rotatedPlain: %v", err)
	}
	if err := os.Chtimes(currentLog, base.Add(3*time.Minute), base.Add(3*time.Minute)); err != nil {
		t.Fatalf("chtimes currentLog: %v", err)
	}

	t.Run("single log when allLogs is false", func(t *testing.T) {
		t.Parallel()
		got, err := resolveLogPaths(currentLog, false)
		if err != nil {
			t.Fatalf("resolveLogPaths: %v", err)
		}
		want := []string{currentLog}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got=%v want=%v", got, want)
		}
	})

	t.Run("collect rotated files when allLogs is true", func(t *testing.T) {
		t.Parallel()
		got, err := resolveLogPaths(currentLog, true)
		if err != nil {
			t.Fatalf("resolveLogPaths: %v", err)
		}
		want := []string{rotatedGzip, datedGzip, rotatedPlain, currentLog}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got=%v want=%v", got, want)
		}
	})
}
