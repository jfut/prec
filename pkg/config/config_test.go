// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultWhenMissing(t *testing.T) {
	t.Parallel()

	cfg, err := Load(filepath.Join(t.TempDir(), "missing.conf"))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.LogPath != DefaultLogPath {
		t.Fatalf("unexpected log path: %s", cfg.LogPath)
	}
	if cfg.Compress != CompressZstd {
		t.Fatalf("unexpected compress: %s", cfg.Compress)
	}
	if cfg.CompressLevel != DefaultZstdCompressLevel {
		t.Fatalf("unexpected compress_level: %d", cfg.CompressLevel)
	}
	if cfg.FilterDefault != "allow" {
		t.Fatalf("unexpected filter_default: %s", cfg.FilterDefault)
	}
	if len(cfg.Filter) != 0 {
		t.Fatalf("unexpected filter rules: %+v", cfg.Filter)
	}
	if cfg.LostSamplesAction != LostSamplesActionLog {
		t.Fatalf("unexpected lost_samples_action: %s", cfg.LostSamplesAction)
	}
	if cfg.MaxArgLength != 1024 || cfg.MaxArgs != 128 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadFromTOML(t *testing.T) {
	t.Parallel()

	d := t.TempDir()
	p := filepath.Join(d, "cfg.conf")
	if err := os.WriteFile(p, []byte(`log_path = "/tmp/x.log"
compress = "zstd"
compress_level = 7
filter_default = "deny"
filter = ["-exe~=apt", "+source=user&&uid>=1000"]
user_only = true
lost_samples_action = "stop"
max_arg_length = 100
max_args = 10
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.LogPath != "/tmp/x.log" {
		t.Fatalf("unexpected log path: %s", cfg.LogPath)
	}
	if cfg.Compress != CompressZstd {
		t.Fatalf("unexpected compress: %s", cfg.Compress)
	}
	if cfg.CompressLevel != 7 {
		t.Fatalf("unexpected compress_level: %d", cfg.CompressLevel)
	}
	if cfg.FilterDefault != "deny" {
		t.Fatalf("unexpected filter_default: %s", cfg.FilterDefault)
	}
	if len(cfg.Filter) != 2 {
		t.Fatalf("unexpected filter length: %d", len(cfg.Filter))
	}
	if cfg.Filter[0] != "-exe~=apt" || cfg.Filter[1] != "+source=user&&uid>=1000" {
		t.Fatalf("unexpected filter rules: %+v", cfg.Filter)
	}
	if cfg.LostSamplesAction != LostSamplesActionStop {
		t.Fatalf("unexpected lost_samples_action: %s", cfg.LostSamplesAction)
	}
	if !cfg.UserOnly {
		t.Fatalf("unexpected user_only: %+v", cfg.UserOnly)
	}
	if cfg.MaxArgLength != 100 || cfg.MaxArgs != 10 {
		t.Fatalf("unexpected args config: %+v", cfg)
	}
}

func TestLoadFromEmptyTOML(t *testing.T) {
	t.Parallel()

	d := t.TempDir()
	p := filepath.Join(d, "empty.conf")
	if err := os.WriteFile(p, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.LogPath != DefaultLogPath {
		t.Fatalf("unexpected log path: %s", cfg.LogPath)
	}
	if cfg.Compress != CompressZstd {
		t.Fatalf("unexpected compress: %s", cfg.Compress)
	}
	if cfg.CompressLevel != DefaultZstdCompressLevel {
		t.Fatalf("unexpected compress_level: %d", cfg.CompressLevel)
	}
	if cfg.FilterDefault != "allow" {
		t.Fatalf("unexpected filter_default: %s", cfg.FilterDefault)
	}
	if len(cfg.Filter) != 0 {
		t.Fatalf("unexpected filter rules: %+v", cfg.Filter)
	}
	if cfg.LostSamplesAction != LostSamplesActionLog {
		t.Fatalf("unexpected lost_samples_action: %s", cfg.LostSamplesAction)
	}
	if cfg.UserOnly {
		t.Fatalf("unexpected user_only: %+v", cfg.UserOnly)
	}
	if cfg.MaxArgLength != 1024 || cfg.MaxArgs != 128 {
		t.Fatalf("unexpected args config: %+v", cfg)
	}
}

func TestLoadCompressDefaultsByMode(t *testing.T) {
	t.Parallel()

	d := t.TempDir()
	p := filepath.Join(d, "compress-default.conf")
	if err := os.WriteFile(p, []byte(`compress = "gz"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Compress != CompressGzip {
		t.Fatalf("unexpected compress: %s", cfg.Compress)
	}
	if cfg.CompressLevel != DefaultGzipCompressLevel {
		t.Fatalf("unexpected compress_level: %d", cfg.CompressLevel)
	}
}

func TestLoadRejectInvalidCompress(t *testing.T) {
	t.Parallel()

	d := t.TempDir()
	p := filepath.Join(d, "invalid-compress.conf")
	if err := os.WriteFile(p, []byte(`compress = "brotli"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(p); err == nil {
		t.Fatalf("expected error for invalid compress")
	}
}

func TestLoadRejectInvalidFilterDefault(t *testing.T) {
	t.Parallel()

	d := t.TempDir()
	p := filepath.Join(d, "invalid-filter-default.conf")
	if err := os.WriteFile(p, []byte(`filter_default = "drop"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(p); err == nil {
		t.Fatalf("expected error for invalid filter_default")
	}
}

func TestLoadRejectLegacyFilterKeys(t *testing.T) {
	t.Parallel()

	d := t.TempDir()
	p := filepath.Join(d, "legacy-filter.conf")
	if err := os.WriteFile(p, []byte(`include_uids = [1000]
`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(p); err == nil {
		t.Fatalf("expected error for legacy filter key")
	}
}

func TestLoadRejectInvalidLostSamplesAction(t *testing.T) {
	t.Parallel()

	d := t.TempDir()
	p := filepath.Join(d, "invalid-lost-samples-action.conf")
	if err := os.WriteFile(p, []byte(`lost_samples_action = "panic"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(p); err == nil {
		t.Fatalf("expected error for invalid lost_samples_action")
	}
}

func TestLoadRejectInvalidCompressLevel(t *testing.T) {
	t.Parallel()

	tests := []string{
		`compress = "gz"
compress_level = 11
`,
		`compress = "zstd"
compress_level = 0
`,
	}
	for _, body := range tests {
		body := body
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			d := t.TempDir()
			p := filepath.Join(d, "invalid-level.conf")
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(p); err == nil {
				t.Fatalf("expected error for invalid compress_level")
			}
		})
	}
}
