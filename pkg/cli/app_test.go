package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/alecthomas/kong"

	"github.com/jfut/prec/pkg/config"
)

func TestValidateModeFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cli     rootCLI
		wantErr bool
	}{
		{
			name:    "invalid output format",
			cli:     rootCLI{Output: "yaml", Limit: 0},
			wantErr: true,
		},
		{
			name:    "query and json output is valid",
			cli:     rootCLI{Query: []string{"uid>=1000"}, Output: outputFormatJSON, Limit: 0},
			wantErr: false,
		},
		{
			name:    "field selection and json output is valid",
			cli:     rootCLI{Fields: "uid", Output: outputFormatJSON, Limit: 0},
			wantErr: false,
		},
		{
			name:    "follow and tree conflict",
			cli:     rootCLI{Follow: true, Tree: true, Limit: 1},
			wantErr: true,
		},
		{
			name:    "invalid limit",
			cli:     rootCLI{Limit: -1},
			wantErr: true,
		},
		{
			name:    "valid default-like options",
			cli:     rootCLI{Limit: 0},
			wantErr: false,
		},
		{
			name:    "json output and follow is valid",
			cli:     rootCLI{Output: outputFormatJSON, Follow: true, Limit: 0},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateModeFlags(tt.cli)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRunVersionOutput(t *testing.T) {
	stdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = writer
	t.Cleanup(func() {
		os.Stdout = stdout
	})

	// Verify that --version prints the exact version metadata line.
	const versionLine = "version=v1.2.3 commit=abc123 date=2026-05-24T00:00:00Z builtBy=goreleaser treeState=clean"
	exitCode := Run([]string{"--version"}, versionLine)

	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	gotBytes, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}

	if exitCode != 0 {
		t.Fatalf("exitCode=%d want=0", exitCode)
	}
	got := string(gotBytes)
	want := versionLine + "\n"
	if got != want {
		t.Fatalf("stdout=%q want=%q", got, want)
	}
}

func TestEffectiveQuerySpecs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cli  rootCLI
		want []string
	}{
		{
			name: "default applies user source filter",
			cli:  rootCLI{},
			want: []string{"source=user"},
		},
		{
			name: "all disables default source filter",
			cli:  rootCLI{AllSources: true},
			want: nil,
		},
		{
			name: "implicit source user is added when query has no source",
			cli:  rootCLI{Query: []string{"uid>=1000"}},
			want: []string{"source=user", "uid>=1000"},
		},
		{
			name: "all keeps explicit query unchanged",
			cli:  rootCLI{AllSources: true, Query: []string{"source=system"}},
			want: []string{"source=system"},
		},
		{
			name: "explicit source query keeps query unchanged",
			cli:  rootCLI{Query: []string{"uid>=1000", "source=system"}},
			want: []string{"uid>=1000", "source=system"},
		},
		{
			name: "source query in and clause keeps query unchanged",
			cli:  rootCLI{Query: []string{"uid>=1000&&source=user"}},
			want: []string{"uid>=1000&&source=user"},
		},
		{
			name: "source query in or expression keeps query unchanged",
			cli:  rootCLI{Query: []string{"uid>=1000||source=system"}},
			want: []string{"uid>=1000||source=system"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := effectiveQuerySpecs(tt.cli)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got=%v want=%v", got, tt.want)
			}
		})
	}
}

func TestRunHelpFieldsFlagHasExplicitLineBreak(t *testing.T) {
	t.Parallel()

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)
	parser, err := kong.New(
		&rootCLI{},
		kong.Name("prec"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{WrapUpperBound: helpWrapUpperBound}),
		kong.Writers(&stdout, &stderr),
	)
	if err != nil {
		t.Fatalf("create parser: %v", err)
	}
	ctx, err := parser.Parse(nil)
	if err != nil {
		t.Fatalf("parse args: %v", err)
	}
	// PrintUsage is used instead of --help parse to avoid kong's os.Exit side effect.
	if err := ctx.PrintUsage(false); err != nil {
		t.Fatalf("print usage: %v", err)
	}

	helpOut, err := io.ReadAll(&stdout)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	got := string(helpOut)

	if !strings.Contains(got, "Supported:\n") {
		t.Fatalf("fields help line break not found in help output:\n%s", got)
	}
	if !strings.Contains(got, "all,timestamp,end_timestamp,event_id") {
		t.Fatalf("fields list not found in help output:\n%s", got)
	}
	// Help formatter inserts indentation after explicit line breaks, so allow spaces.
	if !regexp.MustCompile(`exec_errno,exec_error,lost_samples,\n\s+lost_samples_total`).MatchString(got) {
		t.Fatalf("fields middle line break not found in help output:\n%s", got)
	}
	// Verify help line width is clamped to the configured terminal baseline.
	for _, line := range strings.Split(got, "\n") {
		if len(line) > helpWrapUpperBound {
			t.Fatalf("help line too long: len=%d line=%q", len(line), line)
		}
	}
}

func TestResolveInputLogPath(t *testing.T) {
	t.Parallel()

	t.Run("prefer cli log path when specified", func(t *testing.T) {
		t.Parallel()

		got, err := resolveInputLogPath("/non/existent.conf", "/tmp/custom.log")
		if err != nil {
			t.Fatalf("resolveInputLogPath: %v", err)
		}
		if got != "/tmp/custom.log" {
			t.Fatalf("got=%q want=%q", got, "/tmp/custom.log")
		}
	})

	t.Run("read log path from config when cli path is empty", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "precd.conf")
		want := filepath.Join(tmpDir, "from-config.log")
		cfgBody := "log_path = \"" + want + "\"\n"
		if err := os.WriteFile(cfgPath, []byte(cfgBody), 0644); err != nil {
			t.Fatalf("write config: %v", err)
		}

		got, err := resolveInputLogPath(cfgPath, "")
		if err != nil {
			t.Fatalf("resolveInputLogPath: %v", err)
		}
		if got != want {
			t.Fatalf("got=%q want=%q", got, want)
		}
	})

	t.Run("fallback to default log path when config file is missing", func(t *testing.T) {
		t.Parallel()

		got, err := resolveInputLogPath("/path/that/does/not/exist/precd.conf", "")
		if err != nil {
			t.Fatalf("resolveInputLogPath: %v", err)
		}
		if got != config.DefaultLogPath {
			t.Fatalf("got=%q want=%q", got, config.DefaultLogPath)
		}
	})
}

func TestHasSourceQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		specs []string
		want  bool
	}{
		{
			name:  "no query",
			specs: nil,
			want:  false,
		},
		{
			name:  "query without source",
			specs: []string{"uid>=1000", "user=alice"},
			want:  false,
		},
		{
			name:  "direct source query",
			specs: []string{"source=system"},
			want:  true,
		},
		{
			name:  "source query in and clause",
			specs: []string{"uid>=1000&& source!=system"},
			want:  true,
		},
		{
			name:  "source like query",
			specs: []string{"source~=user"},
			want:  true,
		},
		{
			name:  "source query in or expression",
			specs: []string{"uid>=1000||source=system"},
			want:  true,
		},
		{
			name:  "source query in and operator expression",
			specs: []string{"uid>=1000&&source=user"},
			want:  true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := hasSourceQuery(tt.specs)
			if got != tt.want {
				t.Fatalf("got=%v want=%v", got, tt.want)
			}
		})
	}
}
