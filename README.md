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

Both tools can observe command execution. `prec` provides normalized, command-centric records with `exit_status` and `proc_fail` for quick inspection and timeline reconstruction.

Use `prec` for command-focused monitoring. Use it alongside `auditd` when broader syscall or network auditing is also required.

## Scope and limits

- Target is external commands and selected regular file activity
- Shell builtins such as `cd`, `export`, and `alias` are not captured
- File monitoring covers successful write-family operations and, when explicitly bounded by `capture_filter`, read-only opens to regular files
- Broad host auditing needs such as full syscall or network auditing are out of scope

## Recorded fields

| Raw record (`precd`) | CLI row (`prec`) | Meaning |
| --- | --- | --- |
| `proc_start` + `proc_end` | `proc_command` | Joined by `event_id` |
| `proc_fail` | `proc_fail` | Failed `execve` or `execveat` |
| `proc_loss` | `proc_loss` | Dropped perf-ring samples |
| `file_open` | `file_open` | File opened with tracked intent |
| `file_save` | `file_save` | Successful write-family activity |

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

Additional fields:

| Record | Additional fields |
| --- | --- |
| `proc_fail` | `exec_errno`, `exec_error` |
| `proc_loss` | `lost_samples`, `lost_samples_total` |
| `file_open`, `file_save` | `file_path`, `file_fd`, `file_bytes`, `file_flags`, `file_dev`, `file_ino` |

Collection details:

- `argv[0]` is normalized to a full path when possible. `event_id` is the `precd` start time (`YYYYMMDDhhmmss`) plus a sequence number.
- `timestamp` is converted from kernel monotonic time to RFC3339Nano in userspace. `auid` and `session_id` come from `/proc/<pid>/loginuid` and `/proc/<pid>/sessionid`.
- `proc_start` is written after exec succeeds; `proc_end` when the process exits. `exit_status` uses the shell-visible range `0-255`.
- `proc_loss` notifications are aggregated and logged at most once per second.
- File events are disabled by default. Enable `collect_file_open` and/or `collect_file_save` in `precd.conf`.
- File events are collected from `openat` and write-family syscalls (`write`, `pwrite64`, `writev`, `pwritev`, `pwritev2`). By default, only `source=user` activity is recorded; set `collect_file_source` to change the scope.
- `file_open` records successful opens of regular files with write intent (`O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`, `O_APPEND`, `O_EXCL`). Read-only opens require `collect_file_open = true` and a non-empty `capture_filter` to limit perf-ring load.
- `file_save` records writes to regular files. `file_dev` and `file_ino` identify the target. Writes by `precd` to its own `log_path` are excluded.
- Repeated `file_save` events for the same process and path are suppressed for `file_save_dedup_sec` seconds (default: 1).
- `collect_file_scope = "user_visible"` is the default. It excludes common hidden app-state paths and deleted temporary files.
- The log writer syncs approximately once per second, on close, and during rotation.

## Source classification

| Event | `source=user` condition |
| --- | --- |
| Command | Interactive tty (`/dev/pts/*`, `/dev/tty`, or `tty_nr != 0`) and an immediate shell parent. Parent tty is used when child tty data is unavailable. |
| File activity | Command condition above, child processes launched from an interactive user shell, non-interactive user shell builtins, or VS Code Remote SSH user processes such as `.vscode-server` `node` / extension host. |

All other events are `source=system`.

## Installation

Install a release package from [Releases](https://github.com/jfut/prec/releases), or use the RPM repository setup below on RHEL-compatible distributions.

Run package installation, manual system installation, and service management commands as root.

For rpm and deb upgrades (for example with `dnf update` or `apt upgrade`), package post-install scripts run `systemctl restart precd.service` automatically.
For rpm and deb uninstall actions, package post-remove scripts run `systemctl stop precd.service` automatically.
Both package and manual installs use `/etc/logrotate.d/prec` with `daily` rotation and `rotate 7305` (about 20 years). Adjust `rotate` to suit your retention policy.

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

### Configuration files

Additional files are loaded with:

```toml
include = "/etc/prec/precd.d/*.conf"
```

| Rule | Behavior |
| --- | --- |
| Path | TOML-quoted file path or glob; relative paths use the including file's directory. |
| Order | Main file first, then matches in lexical order. Nested includes are loaded before the next match. |
| Overrides | Later scalar values win, including `false` and `0`. Omitted settings keep their previous values. |
| Rule arrays | `filter` and `capture_filter` arrays append in load order; empty arrays do not clear existing rules. |
| Defaults | Compression defaults and validation are applied after all files are merged. |
| Missing matches | Patterns with no matches, including nonexistent literal paths, are ignored. |
| Errors | Invalid patterns, unreadable or malformed files, and include cycles fail loading. |

The packaged config includes `/etc/prec/precd.d/*.conf`. Restart `precd` after config changes.

### Single-instance and file safety

| Check | Behavior |
| --- | --- |
| Lock | `precd` takes an exclusive `flock` on `<log_path>.lock`; an existing lock makes startup fail. |
| Paths | Log and lock paths cannot contain symlinks. Parent directories must be owned by root or the current user and not writable by others. Root-owned sticky directories are allowed. |
| Targets | Log and lock files must be single-link regular files owned by `precd`. |

### Compression

| `compress` | Format |
| --- | --- |
| `no` | Plain JSONL |
| `gz` | Gzip JSONL stream |
| `zstd` | Zstandard JSONL stream (default) |

### File event settings

| Setting | Behavior |
| --- | --- |
| `collect_file_open = true` | Trace `openat` for `file_open`. With a non-empty `capture_filter`, matching read-only opens are included; keep this filter narrow (for example, by UID, GID, or `comm`). |
| `collect_file_save = true` | Trace write-family syscalls for `file_save`. |
| `collect_file_source` | `user` (default) records user activity; `system` records system/daemon activity; `any` records both. |
| `collect_file_scope` | `user_visible` (default) excludes common hidden app-state paths; `home` limits events to the user's home; `all` includes tracked regular-file paths. |
| `file_save_dedup_sec` | Suppress repeated records for the same `pid` and `file_path` during this window. Default `1`; `0` disables. Must be non-negative and fit in `time.Duration`. |

### Early capture filter

`capture_filter` is an optional eBPF allowlist evaluated before events reach the perf ring. It reduces kernel and ring load; `filter` still applies final user-space filtering.

| Rule | Behavior |
| --- | --- |
| Syntax | Every rule starts with `+`. Rules are ORed; `&&` clauses within a term are ANDed. Matching events are captured once; other events are dropped. |
| Included files | Arrays append; `capture_filter = []` does not clear existing rules. |
| Fields | `uid`, `gid`, `pid`, `user`, `group`, and exact `comm`. Numeric fields support `=`, `!=`, `>`, `>=`, `<`, `<=`; names and `comm` support `=` and `!=`. |
| Unavailable fields | Fields such as `exe`, `argv`, `file_path`, `record_type`, and `source` are rejected at startup. |
| Groups | `gid` and `group` match the process GID; supplementary groups are not checked. |
| Refresh | Names resolve at startup and every `capture_filter_refresh_sec` seconds (default `3600`). The value must be positive and fit in `time.Duration`. Set `21600` for six hours. |
| Account changes | User/group additions, removals, and UID/GID changes take effect at the next refresh. Numeric `uid`/`gid` rules do not change. Restart `precd` to change rules or the refresh interval. |
| Missing names | Missing accounts never match `user=`/`group=` and always match `user!=`/`group!=`. |
| Lookup errors | Errors fail startup. Refresh errors are logged, retain the previous IDs, and retry at the next interval. |
| Process tracking | Matching processes are tracked before samples are sent. Exit status and exit notifications remain available after account changes; tracking ends when the thread-group leader exits. Untracked processes do not bypass the filter. |
| Limits | Up to 4096 distinct user/group names and 1,048,576 tracked processes. Repeated names of the same kind share one entry. If process registration fails, new samples for that process are dropped. |

Each successful name refresh also invalidates cached user/group names and home directories, including cached missing-account results.

The packaged config captures:

- UID or GID `0`, and UID or GID `>=1000` (conditions are independent; `gid=0` also matches non-root UIDs)
- Matching users or groups: `apache`, `nginx`, `php-fpm`, `www-data`, `tomcat`, `jboss`, `app`, `admin`, `www`, `redis`, `git`, `gitlab-www`, `gitlab-runner`, `jenkins`, `grafana`, `zabbix`, `rundeck`

Missing service accounts do not match equality rules. With no config or capture rules, all users are captured.

The packaged `filter` excludes repetitive VS Code Server Extension Host system scans: socket checks (`ls -l /proc/.../fd/...`) and root-process checks (`ps -F -A -l | grep root`).

To capture all users, add this rule to `/etc/prec/precd.d/90-capture-all.conf` and restart `precd`:

```toml
capture_filter = ["+uid>=0"]
```

Example:

```toml
# Capture events from interactive users and selected web-server workers.
collect_file_open = true
collect_file_source = "any"
capture_filter_refresh_sec = 3600
capture_filter = [
  "+uid>=1000",
  "+user=apache",
  "+user=nginx",
  "+comm=php-fpm",
]
```

### Lost sample actions

| Setting | Behavior |
| --- | --- |
| `lost_samples_action = "log"` (default) | Write `proc_loss` records. |
| `lost_samples_action = "ignore"` | Skip `proc_loss` records. |
| `lost_samples_action = "stop"` | Write one `proc_loss` record, then stop `precd`. |

### User-space filter

| Setting | Behavior |
| --- | --- |
| `filter_default` | `allow` or `deny` for events not matched by a rule. |
| `filter` | Ordered first-match rules: `+query` allows, `-query` denies. Syntax matches `prec --query`. |
| Included files | Rules append after main-file rules; empty arrays do not clear rules. Main-file rules are evaluated first. |
| Invalid config | Missing `+`/`-` prefixes and legacy `include_*` / `exclude_*` keys fail startup. |

## CLI behavior

### Default behavior

| Case | Behavior |
| --- | --- |
| Source | Defaults to `user`; `--query` keeps the selected source unless `--source any` is set. |
| Default fields | `timestamp user group command`; with `--file-events`: `timestamp user group record_type file_path file_fd file_bytes command`. |
| Command rows | `proc_start` and `proc_end` are joined by `event_id` into one `proc_command` row. |
| File rows | Hidden by default. `--file-events` shows independent file rows; `file_save` is the default. Query `record_type=file_open` to show open intent. |
| Text / JSON | Text omits empty optional fields; JSON omits unavailable file fields on process rows. |
| Escaping | Text and CSV escape control characters to protect row and terminal structure. |

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
  -n, --limit=0            Max rows in list mode. In follow mode, this sets
                           the number of initial rows before following. A limit
                           of 0 means no limit in list mode and no initial rows
                           in follow mode.
  -F, --follow             Follow command events
      --file-events        Include file events in CLI output
                           (requires `collect_file_open = true` and/or `collect_file_save = true` in `precd`)
      --tree               Print command lineage as a tree
  -o, --output=STRING      Output format: text,json,csv (default: text)
      --version            Show version and build info
```

### Modes

| Mode | Selection |
| --- | --- |
| List | Default |
| Follow | `--follow` or `-F` |

In follow mode:

- `proc_start` prints a provisional row. `proc_end` is read only when output or query needs `end_timestamp`, `duration_ns`, `duration`, or `exit_status`.
- When `proc_end` is read, a finalized row is printed for the same `event_id`, then join state is released.
- `file_save` rows stream independently and do not use the process join.

### Additional CLI details

| Option | Additional behavior |
| --- | --- |
| `--all-logs` | Detects gzip and zstd by content and unwraps nested layers. Skips symlinks and non-regular files. In follow mode, rotated logs are used only for initial backfill; live follow stays on the base path. |
| `--version` | Prints `version`, `commit`, `date`, `builtBy`, and `treeState`. |

### Mode constraints

- Default output is `text`.
- `--tree` requires list mode and cannot be combined with `--file-events`.

### Follow with compressed logs

`--follow` supports `compress = "gz"` and `compress = "zstd"` and follows rotation like `tail -F`.

## Query syntax

Syntax:

```text
--query "key op value"
--query "cond1&&cond2||cond3"
```

| Value type | Operators |
| --- | --- |
| Numeric, timestamp, duration | `= != > >= < <=` |
| String, `argv` text | `= != ~= !~=` |

Rules:

- `&&` means AND; `||` means OR. AND has higher precedence. Repeated `--query` options are ANDed.
- String matches are case-sensitive. Escaping `&&` or `||` inside values is unsupported.
- `source` accepts `user` or `system`.
- Query `record_type` values are displayed rows: `proc_command`, `proc_fail`, `proc_loss`, `file_open`, and `file_save`. File rows require `--file-events`; raw `proc_start` and `proc_end` values are not queryable.
- `timestamp` and `end_timestamp` accept RFC3339 or RFC3339Nano.
- `duration` uses `YYYY-MM-DD HH:MM:SS`; conversion is fixed at 365 days per year and 30 days per month. Example: `0001-02-03 04:05:06` is 1 year, 2 months, 3 days, 4 hours, 5 minutes, and 6 seconds.
- `end_timestamp`, `exit_status`, `duration`, and `duration_ns` match finalized command rows only.

Keys include every field in each record plus derived `command` and `duration`.

| Type | Keys | Match behavior |
| --- | --- | --- |
| Numeric | `uid`, `gid`, `auid`, `session_id`, `pid`, `ppid`, `argc`, `tty_nr`, `exit_status`, `duration_ns`, `exec_errno`, `lost_samples`, `lost_samples_total`, `parent_tty_nr`, `file_fd`, `file_bytes`, `file_flags`, `file_dev`, `file_ino` | Numeric operators |
| Timestamp | `timestamp`, `end_timestamp` | RFC3339 comparison |
| Duration | `duration` | Duration operators |
| Array | `argv` | String-match joined text |
| Other fields | All remaining keys | String operators |

## Output fields with `-f`

| Group | Fields |
| --- | --- |
| All | `all` |
| Identity and time | `timestamp`, `end_timestamp`, `event_id`, `user`, `group`, `uid`, `gid`, `auid`, `session_id` |
| Command | `command`, `pid`, `ppid`, `comm`, `exe`, `cwd`, `argv`, `argc`, `cgroup`, `tty`, `tty_nr`, `source` |
| Result | `record_type`, `exit_status`, `duration_ns`, `duration`, `exec_errno`, `exec_error`, `lost_samples`, `lost_samples_total` |
| Parent | `parent_comm`, `parent_exe`, `parent_cmdline`, `parent_tty`, `parent_tty_nr` |
| File | `file_path`, `file_fd`, `file_bytes`, `file_flags`, `file_dev`, `file_ino` |

| Selection | Behavior |
| --- | --- |
| No `-f` | Use default fields. |
| Plain field names | Output only those fields, in the specified order. |
| `+field` / `-field` | Start with defaults, then add or remove fields. |
| `all` | Expand to all fields. |

Examples:

- Explicit fields: `-f timestamp,uid,gid,group,command`
- Add and remove: `-f +uid,gid,group,-timestamp,user`
- Exclude several fields: `-f all,-end_timestamp,event_id,duration_ns,duration,cgroup,tty,tty_nr,source,parent_comm,parent_exe,parent_cmdline,parent_tty,parent_tty_nr,file_path,file_fd,file_bytes,file_flags,file_dev,file_ino`
- Query failures: `prec -s any --query "record_type=proc_fail" -f timestamp,auid,session_id,exe,exec_errno,exec_error`
- Query file writes: `prec --file-events -s any --query "record_type=file_save&&file_bytes>=4096" -f timestamp,user,record_type,file_path,file_fd,file_bytes`

## Quick examples

| Task | Command |
| --- | --- |
| Recent user commands | `prec` |
| Follow with 10 initial rows | `prec -F -n 10` |
| Follow as CSV | `prec -F -n 10 -f all -o csv` |
| Follow as JSON | `prec -F -n 10 -f all -o json` |
| UID range, excluding one UID | `prec -q "uid>=1000&&uid!=1999"` |
| Commands by a specific user | `prec -s any -q "user=user1"` |
| `curl` after a timestamp, with result fields | `prec -q "exe~=curl" --query "timestamp>=2026-01-01T00:00:00+09:00" -f +duration,exit_status` |
| Commands lasting at least 10 minutes | `prec -q "duration>=0000-00-00 00:10:00" -f timestamp,end_timestamp,duration,uid,gid,user,group,command` |
| Selected fields with full timestamps | `prec -f timestamp,uid,gid,command --full-time` |
| All sources / system only | `prec -s any` / `prec -s system` |
| Commands by Apache | `prec -s any -q "user=apache"` |

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
