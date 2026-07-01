// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kong"

	"github.com/jfut/prec/internal/config"
	"github.com/jfut/prec/internal/query"
)

type listFilter struct {
	compiled              query.Filter
	needsFinalizedCommand bool
}

type outputOptions struct {
	tree     bool
	fullTime bool
	format   string
	fields   []string
}

// rootCLI centralizes flag definitions for prec.
type rootCLI struct {
	Input    string   `name:"input" short:"i" help:"Read log file path (default: /var/log/prec/prec.log)"`
	AllLogs  bool     `name:"all-logs" short:"a" help:"Read current and rotated log files together in list mode and follow initial output"`
	Source   string   `name:"source" short:"s" help:"Select source: user,system,any (default: user)" default:"user"`
	Query    []string `name:"query" short:"q" help:"Filter expression, repeatable. Clause format: key op value, op is = != > >= < <= ~= !~=. Use && for AND, || for OR"`
	Fields   string   `name:"fields" short:"f" help:"Select output fields, comma-separated. Use + to add and - to remove. Supported:\nall,timestamp,end_timestamp,event_id,user,group,\ncommand,uid,gid,auid,session_id,pid,ppid,comm,\nexe,cwd,argv,argc,cgroup,tty,tty_nr,source,\nrecord_type,exit_status,duration_ns,duration,\nexec_errno,exec_error,lost_samples,\nlost_samples_total,parent_comm,parent_exe,\nparent_cmdline,parent_tty,parent_tty_nr"`
	FullTime bool     `name:"full-time" help:"Print full RFC3339Nano timestamp"`
	Limit    int      `name:"limit" short:"n" help:"Max rows in list mode; initial rows before follow in --follow mode (0 means unlimited in list mode and no initial rows in --follow mode)" default:"0"`
	Follow   bool     `name:"follow" short:"F" help:"Follow command events"`
	Tree     bool     `name:"tree" help:"Print command lineage as a tree"`
	Output   string   `name:"output" short:"o" help:"Output format: text,json,csv (default: text)"`
	Version  bool     `name:"version" help:"Show version and build info"`
}

func Run(args []string, version string) int {
	// Keep default values in kong struct tags to centralize CLI defaults.
	cli := rootCLI{}

	parser, err := kong.New(
		&cli,
		kong.Name("prec"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{WrapUpperBound: helpWrapUpperBound}),
		kong.Writers(os.Stdout, os.Stderr),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init parser: %v\n", err)
		return 1
	}

	_, err = parser.Parse(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	if cli.Version {
		fmt.Println(version)
		return 0
	}

	if err := validateModeFlags(cli); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	outputFormat := normalizeOutputFormat(cli.Output)
	selectedFields, err := parseOutputFields(cli.Fields)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	lf, err := buildQueryFilter(effectiveQuerySpecs(cli))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	logPath, compressionHint, err := resolveInputLogSetting(config.DefaultConfigPath, cli.Input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve log path: %v\n", err)
		return 1
	}
	logPaths, err := resolveLogPaths(logPath, cli.AllLogs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve log files: %v\n", err)
		return 1
	}

	if cli.Follow {
		return runTail(logPath, compressionHint, logPaths, cli.AllLogs, cli.Limit, lf, outputOptions{
			tree:     false,
			fullTime: cli.FullTime,
			format:   outputFormat,
			fields:   selectedFields,
		})
	}
	return runList(logPaths, cli.Limit, lf, outputOptions{
		tree:     cli.Tree && outputFormat == outputFormatText,
		fullTime: cli.FullTime,
		format:   outputFormat,
		fields:   selectedFields,
	})
}

func resolveInputLogSetting(configPath string, inputPath string) (string, string, error) {
	if strings.TrimSpace(inputPath) != "" {
		// When -i is set, prefer the CLI input path over daemon config.
		return inputPath, "", nil
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return "", "", err
	}
	return cfg.LogPath, cfg.Compress, nil
}

func resolveInputLogPath(configPath string, inputPath string) (string, error) {
	logPath, _, err := resolveInputLogSetting(configPath, inputPath)
	if err != nil {
		return "", err
	}
	return logPath, nil
}

func effectiveQuerySpecs(cli rootCLI) []string {
	specs := append([]string(nil), cli.Query...)
	switch normalizeSource(cli.Source) {
	case "any":
		return specs
	case "system":
		// Source selection is prepended so non-matching events are rejected early.
		return append([]string{"source=system"}, specs...)
	default:
		// Source selection is prepended so non-matching events are rejected early.
		return append([]string{"source=user"}, specs...)
	}
}

func validateModeFlags(cli rootCLI) error {
	if !isSupportedOutputFormat(normalizeOutputFormat(cli.Output)) {
		return fmt.Errorf("invalid --output value: %s", cli.Output)
	}
	if !isSupportedSource(normalizeSource(cli.Source)) {
		return fmt.Errorf("invalid --source value: %s", cli.Source)
	}
	if cli.Follow && cli.Tree {
		return errors.New("--tree cannot be used with --follow (-F)")
	}
	if cli.Limit < 0 {
		return errors.New("--limit must be 0 or greater")
	}
	return nil
}

func isSupportedOutputFormat(v string) bool {
	switch v {
	case outputFormatText, outputFormatJSON, outputFormatCSV:
		return true
	default:
		return false
	}
}

func normalizeOutputFormat(v string) string {
	if strings.TrimSpace(v) == "" {
		return outputFormatText
	}
	return v
}

func isSupportedSource(v string) bool {
	switch v {
	case "user", "system", "any":
		return true
	default:
		return false
	}
}

func normalizeSource(v string) string {
	if strings.TrimSpace(v) == "" {
		return "user"
	}
	return v
}
