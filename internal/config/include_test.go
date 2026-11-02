// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadIncludesInOrder(t *testing.T) {
	t.Parallel()

	for _, absolute := range []bool{false, true} {
		t.Run(fmt.Sprintf("absolute=%t", absolute), func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			pattern := "precd.d/*.conf"
			if absolute {
				pattern = filepath.Join(dir, pattern)
			}
			writeConfigFixtures(t, dir, map[string]string{
				"precd.conf": fmt.Sprintf(`include = %q
log_path = "/tmp/main.log"
filter = ["-exe~=apt"]
capture_filter = ["+uid>=1000"]
user_only = true
collect_file_open = true
file_save_dedup_sec = 5
`, pattern),
				"precd.d/20-last.conf": `log_path = "/tmp/last.log"
user_only = false
collect_file_open = false
file_save_dedup_sec = 0
filter = ["+user=nginx"]
capture_filter = ["+comm=php-fpm"]
`,
				"precd.d/10-first.conf": `include = "nested/extra.conf"
log_path = "/tmp/first.log"
collect_file_save = true
filter = ["+user=apache"]
capture_filter = ["+user=apache"]
`,
				"precd.d/nested/extra.conf": `log_path = "/tmp/nested.log"
collect_file_source = "any"
filter = ["-exe~=curl"]
capture_filter = ["+user=nginx"]
`,
				"precd.d/30-empty.conf": `filter = []
capture_filter = []
`,
				"precd.d/ignored.txt": `invalid TOML`,
			})

			cfg, err := Load(filepath.Join(dir, "precd.conf"))
			if err != nil {
				t.Fatalf("Load returned error: %v", err)
			}
			want := Default()
			want.LogPath = "/tmp/last.log"
			want.CollectFileSave = true
			want.CollectFileSource = "any"
			want.FileSaveDedupSec = 0
			want.Filter = []string{"-exe~=apt", "+user=apache", "-exe~=curl", "+user=nginx"}
			want.CaptureFilter = []string{"+uid>=1000", "+user=apache", "+user=nginx", "+comm=php-fpm"}
			if !reflect.DeepEqual(cfg, want) {
				t.Fatalf("config = %+v, want %+v", cfg, want)
			}
		})
	}
}

func TestLoadIncludeWithoutMatches(t *testing.T) {
	t.Parallel()

	for _, pattern := range []string{"", "missing/*.conf", "missing.conf"} {
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeConfigFixtures(t, dir, map[string]string{
				"precd.conf": fmt.Sprintf("include = %q\n", pattern),
			})
			cfg, err := Load(filepath.Join(dir, "precd.conf"))
			if err != nil {
				t.Fatalf("Load returned error: %v", err)
			}
			if !reflect.DeepEqual(cfg, Default()) {
				t.Fatalf("config = %+v, want defaults", cfg)
			}
		})
	}
}

func TestLoadIncludeCompression(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		main      string
		included  string
		wantMode  string
		wantLevel int
	}{
		{name: "mode default", included: `compress = " GZ "`, wantMode: CompressGzip, wantLevel: DefaultGzipCompressLevel},
		{name: "inherited level", main: "compress_level = 7", included: `compress = "gz"`, wantMode: CompressGzip, wantLevel: 7},
		{name: "included level", main: "compress_level = 7", included: "compress = \"gz\"\ncompress_level = 0", wantMode: CompressGzip, wantLevel: 0},
		{name: "level only", included: "compress_level = 9", wantMode: CompressZstd, wantLevel: 9},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeConfigFixtures(t, dir, map[string]string{
				"precd.conf":               "include = \"precd.d/*.conf\"\n" + tt.main,
				"precd.d/10-compress.conf": tt.included,
				"precd.d/20-other.conf":    "max_args = 10",
			})
			cfg, err := Load(filepath.Join(dir, "precd.conf"))
			if err != nil {
				t.Fatalf("Load returned error: %v", err)
			}
			if cfg.Compress != tt.wantMode || cfg.CompressLevel != tt.wantLevel {
				t.Fatalf("compression = %s/%d, want %s/%d", cfg.Compress, cfg.CompressLevel, tt.wantMode, tt.wantLevel)
			}
		})
	}
}

func TestLoadRejectInvalidIncludes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{name: "include type", files: map[string]string{"precd.conf": "include = true"}, want: "parse config"},
		{name: "invalid glob", files: map[string]string{"precd.conf": `include = "["`}, want: "include in config"},
		{name: "syntax", files: map[string]string{"extra.conf": "invalid TOML"}, want: "extra.conf"},
		{name: "legacy key", files: map[string]string{"extra.conf": "include_uids = [1000]"}, want: "include_uids is no longer supported"},
		{name: "validation", files: map[string]string{"extra.conf": "file_save_dedup_sec = -1"}, want: "invalid file_save_dedup_sec"},
		{name: "self cycle", files: map[string]string{"precd.conf": `include = "precd.conf"`}, want: "include cycle"},
		{name: "indirect cycle", files: map[string]string{"extra.conf": `include = "precd.conf"`}, want: "include cycle"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeConfigFixtures(t, dir, map[string]string{"precd.conf": `include = "extra.conf"`})
			writeConfigFixtures(t, dir, tt.files)
			if _, err := Load(filepath.Join(dir, "precd.conf")); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load error = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestLoadRejectUnreadableInclude(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeConfigFixtures(t, dir, map[string]string{"precd.conf": `include = "precd.d"`})
	if err := os.Mkdir(filepath.Join(dir, "precd.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(dir, "precd.conf")); err == nil || !strings.Contains(err.Error(), "read included config") {
		t.Fatalf("Load error = %v, want included-file read error", err)
	}
}

func TestLoadRejectIncludeCycleThroughLinks(t *testing.T) {
	t.Parallel()

	for _, hardLink := range []bool{false, true} {
		t.Run(fmt.Sprintf("hard_link=%t", hardLink), func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeConfigFixtures(t, dir, map[string]string{"precd.conf": `include = "alias.conf"`})
			link := os.Symlink
			if hardLink {
				link = os.Link
			}
			if err := link(filepath.Join(dir, "precd.conf"), filepath.Join(dir, "alias.conf")); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(filepath.Join(dir, "precd.conf")); err == nil || !strings.Contains(err.Error(), "include cycle") {
				t.Fatalf("Load error = %v, want include cycle", err)
			}
		})
	}
}

// writeConfigFixtures creates independent config trees for include resolution tests.
func writeConfigFixtures(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
