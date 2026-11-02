# prec

[![Tag](https://img.shields.io/github/tag/jfut/prec.svg)](https://github.com/jfut/prec/releases)
[![License](https://img.shields.io/badge/license-Apache%202-blue)](https://github.com/jfut/prec/blob/main/LICENSE)

`prec` is a Linux command execution observability tool where `precd` uses eBPF to continuously collect process execution events as JSON Lines and `prec` lets you quickly search and inspect those records from the CLI.

Implementation note:

- Go packages under `internal/` are private implementation details and are not a supported public import API

## Why use it

- Does not rely on shell history or `LD_PRELOAD`
- Captures external command execution from kernel events
- Stores structured logs with process, user, parent process, and tty context for fast triage
- Logs command execution via `WebShell` on web servers and `OS Command Injection` attacks across various servers
- Logs execution traces of `Local Privilege Escalation: LPE` attacks that are often missing from application logs
- Host-side `precd` also logs commands executed inside `docker`, `runc`, and other containers on the same host
- Supports `audit` workflows with searchable records of who ran what, when, where, and with which result
- Supports `forensic` investigations by reconstructing execution timelines from `proc_start`, `proc_end`, and `proc_fail` records

## Comparison with auditd

`prec` and `auditd` can both observe command execution.

- `prec` is focused on command visibility and quick inspection by humans
- `prec` outputs normalized command-centric records directly
- `prec` focuses on command execution records and includes `exit_status` and `proc_fail`
- `prec` can also be used for forensic investigation by reconstructing execution timelines from structured records

In practice, `prec` is designed for command-focused monitoring and forensic use cases. It can replace parts of `auditd` workflows that only require command execution visibility, and can also be deployed together with `auditd`.

## Scope and limits

- Target is external commands and selected regular file activity
- Shell builtins such as `cd`, `export`, and `alias` are not captured
- File monitoring covers successful write-family operations and, when explicitly bounded by `capture_filter`, read-only opens to regular files
- Broad host auditing needs such as full syscall or network auditing are out of scope

## Recorded fields

Raw log records from `precd`:

- `record_type=proc_start`
- `record_type=proc_end`
- `record_type=proc_fail`
- `record_type=proc_loss`
- `record_type=file_open`
- `record_type=file_save`

Merged `record_type` values from `prec`:

- `record_type=proc_command`
- `record_type=proc_fail`
- `record_type=proc_loss`
- `record_type=file_open`
- `record_type=file_save`

`proc_start` fields:

- `timestamp`, `event_id`
- `uid`, `gid`, `user`, `group`
- `auid`, `session_id`
- `pid`, `ppid`, `comm`, `exe`, `cwd`
- `argv`, `argc`
- `cgroup`, `tty`, `tty_nr`
- `source`
- `parent_comm`, `parent_exe`, `parent_cmdline`, `parent_tty`, `parent_tty_nr`

`proc_end` fields (compact):

- `timestamp` (end time), `event_id`, `pid`
- `duration_ns`
- `exit_status`
- `source`
- unrelated proc_start-only fields are omitted from `proc_end` JSON records

`proc_fail` and `proc_loss` additional fields:

- `proc_fail`: `exec_errno`, `exec_error`
- `proc_loss`: `lost_samples`, `lost_samples_total`

file event additional fields:

- `file_path`, `file_fd`, `file_bytes`, `file_flags`, `file_dev`, `file_ino`

Notes:

- `argv[0]` is normalized to a full path when possible
- `event_id` format is `precd` start time `YYYYMMDDhhmmss` + sequence number
- `auid` and `session_id` are read from `/proc/<pid>/loginuid` and `/proc/<pid>/sessionid`
- `timestamp` is derived from kernel monotonic time and converted to RFC3339Nano in userspace
- `exit_status` is the shell-visible status code range `0-255`
- `proc_start` is written immediately after exec succeeds
- `proc_end` is written when the process exits
- `proc_fail` records are written when `execve` or `execveat` returns an error
- `proc_loss` records are written when the perf ring reports dropped samples
- repeated `proc_loss` notifications are aggregated and logged at most once per second
- file activity is collected from the `openat` and write-family syscall tracepoints such as `write`, `pwrite64`, `writev`, `pwritev`, and `pwritev2`
- file activity collection is disabled by default and starts only when `collect_file_open = true` or `collect_file_save = true` is set in `precd.conf`
- by default, file activity records only `source=user` operations; use `collect_file_source` to switch the target scope
- `file_open` is emitted for successful `openat` calls to regular files with write-capable intent such as `O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`, `O_APPEND`, or `O_EXCL`
- read-only `file_open` records are also emitted when `collect_file_open = true` and a non-empty `capture_filter` is configured; the early filter is required to prevent perf-ring overload
- `file_save` is emitted only when the write-family target is a regular file
- `file_dev` and `file_ino` identify the device and inode observed for the regular-file target
- `precd` self-writes to its own `log_path` are excluded to reduce collector noise
- repeated `file_save` events from the same process to the same file are suppressed within `file_save_dedup_sec` seconds (default: 1)
- `collect_file_scope = "user_visible"` is the default and keeps user-visible files while excluding common hidden app-state paths and deleted temp files
- the log writer syncs data approximately once per second during operation and also syncs during close and log rotation

## Source classification

`source=user` is assigned only when:

- command has an interactive tty (`/dev/pts/*` or `/dev/tty`, or `tty_nr != 0` fallback).
  If child tty data is unavailable, parent tty is used as fallback
- immediate parent process is a shell
- for file events, child processes launched from an interactive user shell are also treated as `user`
- for file events, non-interactive user shell builtins are also treated as `user`
- for file events, VS Code Remote SSH user processes such as `.vscode-server` `node` / extension host are also treated as `user`

Everything else is `source=system`.

## Installation

Install a release package from [Releases](https://github.com/jfut/prec/releases), or use the RPM repository setup below on RHEL-compatible distributions.

Run package installation, manual system installation, and service management commands as root.

For rpm and deb upgrades (for example with `dnf update` or `apt upgrade`), package post-install scripts run `systemctl restart precd.service` automatically.
For rpm and deb uninstall actions, package post-remove scripts run `systemctl stop precd.service` automatically.

### RPM releases with dnf-plugin-anyrepo

Install [dnf-plugin-anyrepo](https://github.com/jfut/dnf-plugin-anyrepo), import the RPM GPG key, add this repository, then install the package with `dnf`.

```bash
rpm --import https://raw.githubusercontent.com/jfut/prec/refs/heads/main/packaging/RPM-GPG-KEY-jfut-github
dnf-anyrepo add https://github.com/jfut/prec
dnf install prec
```

Upgrade the installed package with `dnf`.

```bash
dnf upgrade prec
```

### Downloaded or locally built packages

Use one release package downloaded from [Releases](https://github.com/jfut/prec/releases), or build local package files first:

```bash
just release
```

Install one package with your package manager. For downloaded release packages, replace the `dist/...` path with the downloaded file path.

Use the matching architecture package name (for example, `arm64` or `aarch64` on ARM64 hosts).

```bash
# Debian/Ubuntu
dpkg -i dist/prec_*_amd64.deb

# RHEL/Fedora
rpm -Uvh dist/prec-*.x86_64.rpm

# Alpine
apk add --allow-untrusted dist/prec_*_x86_64.apk

# Arch Linux
pacman -U dist/prec-*-x86_64.pkg.tar.zst
```

Package installs place `/etc/logrotate.d/prec` with a default policy of `daily` and `rotate 7305` (about 20 years of retention).
Adjust the `rotate` value as needed to match your retention policy.

### Manual install from source

Build the binaries first:

```bash
just build
```

Install the binaries:

```bash
install -m 0755 dist/prec /usr/bin/prec
install -m 0755 dist/precd /usr/sbin/precd
```

Install config and service files manually:

```bash
mkdir -p /etc/prec/precd.d
chmod 750 /etc/prec /etc/prec/precd.d
install -m 0640 packaging/precd.conf.example /etc/prec/precd.conf

mkdir -p /var/log/prec
chmod 0750 /var/log/prec

install -m 0640 packaging/systemd/precd.service /usr/lib/systemd/system/
install -m 0640 packaging/logrotate/prec /etc/logrotate.d/prec
```

The installed `/etc/logrotate.d/prec` default is `daily` with `rotate 7305` (about 20 years of retention).
Adjust the `rotate` value as needed to match your retention policy.

### Enable and start precd

```bash
systemctl daemon-reload
systemctl enable precd.service
systemctl start precd.service
systemctl status precd.service
```

## Configuration

Default config path: `/etc/prec/precd.conf`

See: [packaging/precd.conf.example](packaging/precd.conf.example)

Additional configuration files:

```toml
include = "/etc/prec/precd.d/*.conf"
```

- configuration uses TOML, so the include path must be quoted
- `include` accepts a single file path or glob pattern; relative paths are resolved from the including file's directory
- the including file is applied first, then matching files in lexical filename order, regardless of where `include` appears in the file
- included files may also use `include`; nested includes are applied before the next matching file
- later scalar settings override earlier values, including explicit `false` and `0`
- `filter = [...]` and `capture_filter = [...]` in included files append rules in load order instead of overwriting earlier rules; empty arrays add no rules and do not clear earlier rules
- omitted settings retain their previous values; compression defaults and validation are applied after all files are merged
- patterns with no matches are ignored, including nonexistent literal paths
- invalid include patterns, unreadable or malformed included files, and include cycles cause loading to fail
- the packaged configuration enables `/etc/prec/precd.d/*.conf`; restart `precd` after changing configuration

Single-instance behavior:

- `precd` acquires an exclusive `flock` on `<log_path>.lock` at startup
- if the lock is already held, startup fails immediately to prevent duplicate collection

Compression modes:

- `compress = "no"` plain JSONL
- `compress = "gz"` gzip-compressed JSONL stream
- `compress = "zstd"` zstd-compressed JSONL stream (default)

File save dedup:

- `collect_file_open = true` enables `openat` syscall tracing for `file_open`
- with a non-empty `capture_filter`, `collect_file_open = true` also captures matching read-only opens; keep the filter narrow, for example by UID, GID, or `comm`
- `collect_file_save = true` enables write-family syscall tracing and emits `file_save` records
- `collect_file_source = "user"` records only user-originated file activity (default)
- `collect_file_source = "system"` records only system or daemon file activity
- `collect_file_source = "any"` records both user and system file activity
- `collect_file_scope = "user_visible"` records user-visible files and excludes common hidden app-state paths (default)
- `collect_file_scope = "home"` records all files under the user's home directory
- `collect_file_scope = "all"` records all tracked regular-file paths
- `file_save_dedup_sec = 1` suppress repeated `file_save` records for the same `pid` and `file_path` within the configured window
- `file_save_dedup_sec = 0` disables this suppression

Early capture filter:

- `capture_filter` is an optional positive allowlist evaluated in eBPF before events are sent to the perf ring
- `capture_filter = [...]` in an included file adds to the existing allowlist; `capture_filter = []` does not clear it
- rules and `||` terms are ORed; `&&` clauses within a term are ANDed
- every rule must start with `+`; a matching event is captured and a non-matching event is dropped
- supported fields are `uid`, `gid`, `pid`, `user`, `group`, and exact `comm` matches
- `user` and `group` names are resolved to UID/GID when `precd` starts
- numeric fields support `=`, `!=`, `>`, `>=`, `<`, and `<=`; `user`, `group`, and `comm` support `=` and `!=`
- fields that require event data unavailable at the tracepoint, such as `exe`, `argv`, `file_path`, `record_type`, and `source`, are rejected at startup
- `capture_filter` is a coarse prefilter for reducing kernel and perf-ring load; `filter` remains the final user-space filter

Example:

```toml
# Capture events from interactive users and selected web-server workers.
collect_file_open = true
collect_file_source = "any"
capture_filter = [
  "+uid>=1000",
  "+user=apache",
  "+user=nginx",
  "+comm=php-fpm",
]
```

Lost sample actions:

- `lost_samples_action = "log"` write `proc_loss` records (default)
- `lost_samples_action = "ignore"` skip `proc_loss` records
- `lost_samples_action = "stop"` write one `proc_loss` record and stop `precd`

Filter rules:

- `filter_default = "allow" | "deny"` controls events that match no rule
- `filter = ["+query", "-query", ...]` uses ordered first-match evaluation
- `filter = [...]` in an included file appends to existing rules; `filter = []` does not clear them
- rules in the main configuration are evaluated before rules from included files, so an earlier matching rule takes precedence
- each rule must start with `+` allow or `-` deny
- query expression syntax is identical to `prec --query`
- if a rule has no `+` or `-` prefix, `precd` fails to start
- legacy `include_*` and `exclude_*` keys are rejected

## CLI behavior

### Default behavior

- `prec` without options is equivalent to applying `--source user`
- `prec` with `--query` also applies the selected `--source` filter unless `--source any` is specified
- Default output fields are `timestamp user group command`
- Default output fields with `--file-events` are `timestamp user group record_type file_path file_fd file_bytes command`
- human-readable text omits empty optional fields, and JSON omits unavailable file-specific fields from process records
- `prec` joins `proc_start` and `proc_end` by `event_id` and shows one logical `record_type=proc_command`
- file records are hidden by default; use `--file-events` to include them
- file records are not merged and are shown as independent rows when `--file-events` is set
- `--file-events` shows `file_save` records by default; use `--query "record_type=file_open"` when open intent is needed
- `--tree` cannot be used with `--file-events`

### Usage

`precd -h`:

```text
Usage: precd [flags]

Flags:
  -h, --help             Show context-sensitive help.
  -c, --config=STRING    Path to config file (default: /etc/prec/precd.conf)
      --version          Show version and build info
```

`prec -h`:

```text
Usage: prec [flags]

Flags:
  -h, --help               Show context-sensitive help.
  -i, --input=STRING       Read log file path (default: /var/log/prec/prec.log)
  -a, --all-logs           Read current and rotated log files together in list
                           mode and follow initial output
  -s, --source="user"      Select source: user,system,any (default: user)
  -q, --query=QUERY,...    Filter expression, repeatable. Clause format: key op
                           value, op is = != > >= < <= ~= !~=. Use && for AND,
                           || for OR
  -f, --fields=STRING      Select output fields, comma-separated.
                           Use + to add and - to remove. Supported:
                           all,timestamp,end_timestamp,event_id,user,group,
                           command,uid,gid,auid,session_id,pid,ppid,comm,
                           exe,cwd,argv,argc,cgroup,tty,tty_nr,source,
                           record_type,exit_status,duration_ns,duration,
                           exec_errno,exec_error,lost_samples,
                           lost_samples_total,parent_comm,parent_exe,
                           parent_cmdline,parent_tty,parent_tty_nr,
                           file_path,file_fd,file_bytes,file_flags,
                           file_dev,file_ino
      --full-time          Print full RFC3339Nano timestamp
  -n, --limit=0            Max rows in list mode; initial rows before follow in
                           --follow mode (0 means unlimited in list mode and no
                           initial rows in --follow mode)
  -F, --follow             Follow command events
      --file-events        Include file events in CLI output
                           (requires `collect_file_open = true` and/or `collect_file_save = true` in `precd`)
      --tree               Print command lineage as a tree
  -o, --output=STRING      Output format: text,json,csv (default: text)
      --version            Show version and build info
```

### Modes

- list mode: default
- follow mode: `--follow` or `-F`

Follow mode semantics:

- when `proc_start` arrives, `prec` prints a provisional merged row
- `prec` processes `proc_end` only when finalized fields are needed by output or query
  - output fields: `end_timestamp`, `duration_ns`, `duration`, `exit_status`
  - query keys: `end_timestamp`, `duration_ns`, `duration`, `exit_status`
- when `proc_end` is processed, `prec` prints another row for the same `event_id` with finalized values and then releases in-memory join state
- file save records are streamed as-is with `--file-events` and do not require proc_start/proc_end join processing

### Core options

- `-i`, `--input`: read from specified log path instead of config `log_path`
- `-a`, `--all-logs`: include rotated logs in list mode and follow initial backfill
  - gzip and zstd layers are detected from file content and unwrapped recursively, so gzip-compressed rotated zstd logs are included
- `-s`, `--source`: select source (`user`, `system`, `any`)
  - use `any` when `--query` contains custom `source` logic
- `-q`, `--query`: filter expression, repeatable
- `-f`, `--fields`: output fields selection
- `--full-time`: keep RFC3339Nano timestamp text
- `-n`, `--limit`: max rows in list mode, or initial rows before follow
- `--tree`: tree view in text list mode only
- `-o`, `--output`: output format selection (`text`, `json`, `csv`)
- `--version`: print version and build info (`version`, `commit`, `date`, `builtBy`, `treeState`)

### Mode constraints

- Default output mode is text
- `--tree` cannot be used with `--follow`

### Follow with compressed logs

`--follow` works with `compress = "gz"` and `compress = "zstd"` logs.
It tracks log rotation similarly to `tail -F`.

`--all-logs` nuance in follow mode:
- rotated files are used only for initial backfill (`-n`)
- live follow continues on the base log file path

## Query syntax

Syntax:

```text
--query "key op value"
--query "cond1&&cond2||cond3"
```

Operators:

- numeric, timestamp, and duration: `= != > >= < <=`
- string and argv text: `= != ~= !~=`

Rules:

- `&&` is AND operator
- `||` is OR operator
- AND has higher precedence than OR
- repeated `--query` is AND at top level
- `source` value must be `user` or `system`
- `record_type` values in `prec` query match displayed rows: `proc_command`, `proc_fail`, `proc_loss`, `file_open`, or `file_save`
- file `record_type` queries require `--file-events`; otherwise file records are excluded before user queries are applied
- raw log-only record types such as `proc_start` and `proc_end` are joined before filtering and are not accepted as query values
- string match is case-sensitive
- `timestamp` and `end_timestamp` accept RFC3339 or RFC3339Nano
- `duration` accepts `YYYY-MM-DD HH:MM:SS` and means elapsed `year-month-day hour:minute:second`
  - example: `0001-02-03 04:05:06` means 1 year, 2 months, 3 days, 4 hours, 5 minutes, 6 seconds
  - conversion rule is fixed to 1 year = 365 days, 1 month = 30 days
- escaping `&&` and `||` inside values is not supported
- `end_timestamp`, `exit_status`, `duration`, and `duration_ns` conditions match only finalized command rows, not provisional rows

Supported query keys:

- all JSON fields in each event record
- derived keys: `command`, `duration`

Type rules:

- numeric/timestamp/duration typed keys keep strict operators:
  - numeric: `uid`, `gid`, `auid`, `session_id`, `pid`, `ppid`, `argc`, `tty_nr`, `exit_status`, `duration_ns`, `exec_errno`, `lost_samples`, `lost_samples_total`, `parent_tty_nr`, `file_fd`, `file_bytes`, `file_flags`, `file_dev`, `file_ino`
  - timestamp: `timestamp`, `end_timestamp`
  - duration: `duration`
- array key: `argv` is string-matched as joined text
- other keys are treated as string fields and support `= != ~= !~=`

## Output fields with `-f`

Supported fields:

- `all`
- `timestamp`, `end_timestamp`, `event_id`, `user`, `group`, `command`
- `uid`, `gid`, `auid`, `session_id`, `pid`, `ppid`
- `comm`, `exe`, `cwd`, `argv`, `argc`
- `cgroup`, `tty`, `tty_nr`, `source`, `record_type`, `exit_status`, `duration_ns`, `duration`, `exec_errno`, `exec_error`, `lost_samples`, `lost_samples_total`
- `parent_comm`, `parent_exe`, `parent_cmdline`, `parent_tty`, `parent_tty_nr`
- `file_path`, `file_fd`, `file_bytes`, `file_flags`, `file_dev`, `file_ino`

Selection rules:

- no `-f`: default fields
- plain tokens only: explicit mode, output only specified fields in that order
- token with `+` or `-`: start from defaults, then add or remove
- `all` expands to all fields

Examples:

- `-f timestamp,uid,gid,group,command`
- `-f +uid,gid,group,-timestamp,user`
- `-f all,-end_timestamp,event_id,duration_ns,duration,cgroup,tty,tty_nr,source,parent_comm,parent_exe,parent_cmdline,parent_tty,parent_tty_nr,file_path,file_fd,file_bytes,file_flags,file_dev,file_ino`
- `prec -s any --query "record_type=proc_loss" -f timestamp,record_type,lost_samples,lost_samples_total`
- `prec -s any --query "record_type=proc_fail" -f timestamp,auid,session_id,exe,exec_errno,exec_error`
- `prec --file-events -s any --query "record_type=file_open" -f timestamp,user,record_type,file_path,file_fd,file_flags`
- `prec --file-events -s any --query "record_type=file_save&&file_bytes>=4096" -f timestamp,user,record_type,file_path,file_fd,file_bytes`

## Quick examples

Show recent user-origin command executions with default fields.

```bash
prec
```

Follow mode with 10 initial rows, then keep streaming new events.

```bash
prec -F -n 10
```

Follow mode in CSV with all available fields.

```bash
prec -F -n 10 -f all -o csv
```

Follow mode in pretty-printed JSON for pipeline analysis.

```bash
prec -F -n 10 -f all -o json | jq .
```

Filter by UID range, useful to focus on regular users except a specific service account.

```bash
prec -q "uid>=1000&&uid!=1999"
```

Include all sources and show commands run by `user1` or `root`.

```bash
prec -s any -q "user=user1||user=root"
```

Show `curl` executions after a specific time and add duration and exit status.

```bash
prec -q "exe~=curl" --query "timestamp>=2026-01-01T00:00:00+09:00" -f +duration,exit_status
```

Find long-running commands that executed for 10 minutes or more.

```bash
prec -q "duration>=0000-00-00 00:10:00" -f timestamp,end_timestamp,duration,uid,gid,user,group,command
```

Print selected fields with full RFC3339Nano timestamps.

```bash
prec -f timestamp,uid,gid,command --full-time
```

Show both `user` and `system` events.

```bash
prec -s any
```

Show only `system` events.

```bash
prec -s system
```

Monitor commands executed by common web server accounts, which helps detect command execution caused by OS command injection attacks and possible web shell activity.

```bash
prec -s any -q "uid=48 || uid=976 || user=apache || user=nginx"
```

## Development

```bash
just test
just build
just snapshot
```

## Release packaging with goreleaser

Build release artifacts locally:

```bash
just release
```

Generated files are stored in `dist/`:

- tar.gz archives including both `prec` and `precd`
- Linux package `prec` including both `prec` and `precd`: `deb`, `rpm`, `apk`, `archlinux`
- `checksums.txt`

## Release

GitHub Actions signs RPM artifacts with the GPG private key stored in `RPM_SIGNING_KEY`. If the key has a passphrase, store it in `NFPM_PASSPHRASE`.

1. Run `git tag -s vX.Y.Z -m vX.Y.Z`.
2. Run `git push origin vX.Y.Z` and wait for the Release to be created.
3. Edit the created Release.
4. Press the `Generate release notes` button and edit the release notes.
5. Press the `Update release` button.

## License

Apache-2.0

Copyright contributors to the prec project.

## Author

Jun Futagawa (jfut)
