# prec

![Tag](https://img.shields.io/github/tag/jfut/prec.svg)
[![License](https://img.shields.io/badge/license-Apache%202-blue)](https://github.com/jfut/prec/blob/main/LICENSE)

`prec` is a Linux command execution observability tool where `precd` uses eBPF to continuously collect process execution events as JSON Lines and `prec` lets you quickly search and inspect those records from the CLI.

## Why use it

- Does not rely on shell history or `LD_PRELOAD`
- Captures external command execution from kernel events
- Stores structured logs with process, user, parent process, and tty context for fast triage
- Logs command execution via `WebShell` on web servers and `OS Command Injection` attacks across various servers
- Logs execution traces of `Local Privilege Escalation: LPE` attacks that are often missing from application logs
- Host-side `precd` also logs commands executed inside `docker`, `runc`, and other containers on the same host
- Supports `audit` workflows with searchable records of who ran what, when, where, and with which result
- Supports `forensic` investigations by reconstructing execution timelines from `start`, `end`, and `fail` records

## Comparison with auditd

`prec` and `auditd` can both observe command execution.

- `prec` is focused on command visibility and quick inspection by humans
- `prec` outputs normalized command-centric records directly
- `prec` focuses on command execution records and includes `exit_status` and `fail`
- `prec` can also be used for forensic investigation by reconstructing execution timelines from structured records

In practice, `prec` is designed for command-focused monitoring and forensic use cases. It can replace parts of `auditd` workflows that only require command execution visibility, and can also be deployed together with `auditd`.

## Scope and limits

- Target is external commands only
- Shell builtins such as `cd`, `export`, and `alias` are not captured
- Non-exec activities are out of scope unless they invoke external commands
- Broad host auditing needs such as full syscall, file access, or network auditing are out of scope

## Recorded fields

Raw log records from `precd`:

- `record_type=start`
- `record_type=end`
- `record_type=fail`
- `record_type=loss`

`start` fields:

- `timestamp`, `event_id`
- `uid`, `gid`, `user`, `group`
- `auid`, `session_id`
- `pid`, `ppid`, `comm`, `exe`, `cwd`
- `argv`, `argc`
- `cgroup`, `tty`, `tty_nr`
- `source`
- `parent_comm`, `parent_exe`, `parent_cmdline`, `parent_tty`, `parent_tty_nr`

`end` fields (compact):

- `timestamp` (end time), `event_id`, `pid`
- `duration_ns`
- `exit_status`
- `source`
- unrelated start-only fields are omitted from `end` JSON records

`fail` and `loss` additional fields:

- `fail`: `exec_errno`, `exec_error`
- `loss`: `lost_samples`, `lost_samples_total`

Notes:

- `argv[0]` is normalized to a full path when possible
- `event_id` format is `precd` start time `YYYYMMDDhhmmss` + sequence number
- `auid` and `session_id` are read from `/proc/<pid>/loginuid` and `/proc/<pid>/sessionid`
- `timestamp` is derived from kernel monotonic time and converted to RFC3339Nano in userspace
- `exit_status` is the shell-visible status code range `0-255`
- `start` is written immediately after exec succeeds
- `end` is written when the process exits
- `fail` records are written when `execve` or `execveat` returns an error
- `loss` records are written when the perf ring reports dropped samples

## Source classification

`source=user` is assigned only when:

- command has an interactive tty (`/dev/pts/*` or `/dev/tty`, or `tty_nr != 0` fallback).
  If child tty data is unavailable, parent tty is used as fallback
- immediate parent process is a shell

Everything else is `source=system`.

## Installation

`precd` must run as root.

### Manual build and manual install (from source)

Build:

```bash
just build
sudo install -m 0755 dist/prec /usr/bin/prec
sudo install -m 0755 dist/precd /usr/sbin/precd
```

Install config and service files manually:

```bash
sudo mkdir -p /etc/prec
sudo chmod 750 /etc/prec
sudo install -m 0640 packaging/precd.conf.example /etc/prec/precd.conf

sudo mkdir -p /var/log/prec
sudo chmod 0750 /var/log/prec

sudo install -m 0640 packaging/systemd/precd.service /usr/lib/systemd/system/
sudo install -m 0640 packaging/logrotate/prec /etc/logrotate.d/prec
```

### Package-based install

```bash
just release
```

Install one package from `dist/` with your package manager:

Use the matching architecture package name (for example, `arm64` or `aarch64` on ARM64 hosts).

```bash
# Debian/Ubuntu
sudo dpkg -i dist/prec_*_amd64.deb

# RHEL/Fedora
sudo rpm -Uvh dist/prec-*.x86_64.rpm

# Alpine
sudo apk add --allow-untrusted dist/prec_*_x86_64.apk

# Arch Linux
sudo pacman -U dist/prec-*-x86_64.pkg.tar.zst
```

For rpm and deb upgrades (for example with `dnf update` or `apt upgrade`),
package post-install scripts run `systemctl restart precd.service`
automatically.
For rpm and deb uninstall actions, package post-remove scripts run
`systemctl stop precd.service` automatically.

### Enable daemon

```bash
sudo systemctl daemon-reload
sudo systemctl enable precd.service
sudo systemctl start precd.service
sudo systemctl status precd.service
```

## Configuration

Default config path: `/etc/prec/precd.conf`

See: [packaging/precd.conf.example](packaging/precd.conf.example)

Compression modes:

- `compress = "no"` plain JSONL
- `compress = "gz"` gzip-compressed JSONL stream
- `compress = "zstd"` zstd-compressed JSONL stream (default)

Lost sample actions:

- `lost_samples_action = "log"` write `loss` records (default)
- `lost_samples_action = "ignore"` skip `loss` records
- `lost_samples_action = "stop"` write one `loss` record and stop `precd`

Filter rules:

- `filter_default = "allow" | "deny"` controls events that match no rule
- `filter = ["+query", "-query", ...]` uses ordered first-match evaluation
- each rule must start with `+` allow or `-` deny
- query expression syntax is identical to `prec --query`
- if a rule has no `+` or `-` prefix, `precd` fails to start
- legacy `include_*` and `exclude_*` keys are rejected

## CLI behavior

### Default behavior

- `prec` without options is equivalent to applying `--source user`
- `prec` with `--query` also applies the selected `--source` filter unless `--source any` is specified
- Default output fields are `timestamp user group command`
- `prec` joins `start` and `end` by `event_id` and shows one logical `record_type=command`

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
                           parent_cmdline,parent_tty,parent_tty_nr
      --full-time          Print full RFC3339Nano timestamp
  -n, --limit=0            Max rows in list mode; initial rows before follow in
                           --follow mode (0 means unlimited in list mode and no
                           initial rows in --follow mode)
  -F, --follow             Follow command events
      --tree               Print command lineage as a tree
  -o, --output=STRING      Output format: text,json,csv (default: text)
      --version            Show version and build info
```

### Modes

- list mode: default
- follow mode: `--follow` or `-F`

Follow mode semantics:

- when `start` arrives, `prec` prints a provisional merged row
- `prec` processes `end` only when finalized fields are needed by output or query
  - output fields: `end_timestamp`, `duration_ns`, `duration`, `exit_status`
  - query keys: `end_timestamp`, `duration_ns`, `duration`, `exit_status`
- when `end` is processed, `prec` prints another row for the same `event_id` with finalized values and then releases in-memory join state

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
- `source` value in `--query` must be `user` or `system`
- in `prec` merged output, `record_type` is effectively `command`, `fail`, or `loss`
- query parser also accepts `start` and `end` as raw log record types
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
  - numeric: `uid`, `gid`, `auid`, `session_id`, `pid`, `ppid`, `argc`, `tty_nr`, `exit_status`, `duration_ns`, `exec_errno`, `lost_samples`, `lost_samples_total`, `parent_tty_nr`
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

Selection rules:

- no `-f`: default fields
- plain tokens only: explicit mode, output only specified fields in that order
- token with `+` or `-`: start from defaults, then add or remove
- `all` expands to all fields

Examples:

- `-f timestamp,uid,gid,group,command`
- `-f +uid,gid,group,-timestamp,user`
- `-f all,-end_timestamp,event_id,duration_ns,duration,cgroup,tty,tty_nr,source,parent_comm,parent_exe,parent_cmdline,parent_tty,parent_tty_nr`
- `prec -s any --query "record_type=loss" -f timestamp,record_type,lost_samples,lost_samples_total`
- `prec -s any --query "record_type=fail" -f timestamp,auid,session_id,exe,exec_errno,exec_error`

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

1. Edit the `Draft` on the release page.
2. Update the new version `name` and `tag` on the edit page.
3. Check `Set as a pre-release` and press the `Publish release` button.
4. Wait for the build by GitHub Actions to finish.
    - If the build fails due to errors such as download errors of source files, execute `Re-run failed jobs`.
5. Once all release files are automatically uploaded, check `Set as the latest release` and press the `Publish release` button.

## License

Apache-2.0
