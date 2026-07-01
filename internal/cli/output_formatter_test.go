// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/jfut/prec/internal/events"
)

func TestFormatEventSimple(t *testing.T) {
	t.Parallel()

	ev := events.CommandEvent{
		Timestamp: "2026-05-22T22:41:37.715161125+09:00",
		User:      "admin",
		Group:     "admin",
		Argv:      []string{"curl", "https://httpbin.org/ip"},
	}
	got := formatEventSimple(ev, false)
	want := "2026-05-22 22:41:37 admin admin curl https://httpbin.org/ip"
	if got != want {
		t.Fatalf("got=%q want=%q", got, want)
	}
}

func TestFormatEventSimpleFullTime(t *testing.T) {
	t.Parallel()

	ev := events.CommandEvent{
		Timestamp: "2026-05-22T22:41:37.715161125+09:00",
		User:      "admin",
		Group:     "admin",
		Argv:      []string{"curl", "https://httpbin.org/ip"},
	}
	got := formatEventSimple(ev, true)
	want := "2026-05-22T22:41:37.715161125+09:00 admin admin curl https://httpbin.org/ip"
	if got != want {
		t.Fatalf("got=%q want=%q", got, want)
	}
}

func TestRenderEventTree(t *testing.T) {
	t.Parallel()

	base := "2026-05-22T22:48:40."
	in := []events.CommandEvent{
		{
			Timestamp: "2026-05-22T23:05:12.483170858+09:00",
			User:      "admin",
			Group:     "admin",
			UID:       1004,
			PID:       2001,
			PPID:      1000,
			Source:    events.SourceUser,
			Argv:      []string{"/bin/curl", "https://httpbin.org/ip"},
		},
		{
			Timestamp:   base + "544473995+09:00",
			User:        "admin",
			Group:       "admin",
			UID:         1004,
			PID:         2002,
			PPID:        1554996,
			Source:      events.SourceUser,
			ParentTTYNr: 34821,
			Argv:        []string{"/home/admin/.local/share/aquaproj-aqua/bin/go", "test"},
		},
		{
			Timestamp:   base + "545499437+09:00",
			User:        "admin",
			Group:       "admin",
			UID:         1004,
			PID:         2003,
			PPID:        1554996,
			Source:      events.SourceUser,
			ParentTTYNr: 34821,
			Argv:        []string{"/home/admin/local/bin/aqua", "exec", "--", "go", "test"},
		},
		{
			Timestamp:   base + "559744805+09:00",
			User:        "admin",
			Group:       "admin",
			UID:         1004,
			PID:         2004,
			PPID:        1554996,
			Source:      events.SourceUser,
			ParentTTYNr: 34821,
			Argv:        []string{"/home/admin/.local/share/aquaproj-aqua/pkgs/http/golang.org/dl/go1.26.3.linux-amd64.tar.gz/go/bin/go", "test"},
		},
	}

	got := renderEvents(in, outputOptions{tree: true, fullTime: false})
	want := []string{
		"2026-05-22 23:05:12 admin admin /bin/curl https://httpbin.org/ip",
		"2026-05-22 22:48:40 admin admin /home/admin/.local/share/aquaproj-aqua/bin/go test",
		"`- 2026-05-22 22:48:40 admin admin /home/admin/local/bin/aqua exec -- go test",
		"  `- 2026-05-22 22:48:40 admin admin /home/admin/.local/share/aquaproj-aqua/pkgs/http/golang.org/dl/go1.26.3.linux-amd64.tar.gz/go/bin/go test",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestFormatEventForOutputJSON(t *testing.T) {
	t.Parallel()

	ev := events.CommandEvent{
		Timestamp: "2026-05-22T22:41:37.715161125+09:00",
		UID:       1004,
		Source:    events.SourceUser,
		Argv:      []string{"/bin/curl", "https://httpbin.org/ip"},
	}
	got := formatEventForOutput(ev, outputOptions{
		fullTime: false,
		format:   outputFormatJSON,
	})
	if got == "" || got[0] != '{' {
		t.Fatalf("unexpected json output: %q", got)
	}
	if !strings.Contains(got, `"timestamp":"2026-05-22 22:41:37"`) {
		t.Fatalf("unexpected json output: %q", got)
	}
	if !strings.Contains(got, `"user":""`) {
		t.Fatalf("unexpected json output: %q", got)
	}
	if !strings.Contains(got, `"command":"/bin/curl https://httpbin.org/ip"`) {
		t.Fatalf("unexpected json output: %q", got)
	}
	if strings.Contains(got, `"source":"user"`) {
		t.Fatalf("unexpected full json output: %q", got)
	}
}

func TestFormatEventForOutputCSV(t *testing.T) {
	t.Parallel()

	ev := events.CommandEvent{
		Timestamp: "2026-05-22T22:41:37.715161125+09:00",
		UID:       1004,
		GID:       1002,
		User:      "admin",
		Group:     "admin",
		Argv:      []string{"/bin/curl", "https://httpbin.org/ip"},
	}
	got := formatEventForOutput(ev, outputOptions{
		fullTime: false,
		format:   outputFormatCSV,
	})
	if got != "2026-05-22 22:41:37,admin,admin,/bin/curl https://httpbin.org/ip" {
		t.Fatalf("unexpected csv output: %q", got)
	}
}

func TestParseOutputFields(t *testing.T) {
	t.Parallel()

	t.Run("explicit fields only with dedupe", func(t *testing.T) {
		t.Parallel()
		got, err := parseOutputFields("uid,gid,group,uid,user")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"uid", "gid", "group", "user"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got=%v want=%v", got, want)
		}
	})

	t.Run("all expands", func(t *testing.T) {
		t.Parallel()
		got, err := parseOutputFields("all")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) == 0 {
			t.Fatalf("expected expanded fields")
		}
		if got[0] != "timestamp" {
			t.Fatalf("unexpected first field: %v", got[0])
		}
		if got[1] != "user" || got[2] != "group" || got[3] != "command" {
			t.Fatalf("unexpected default field order: %v", got[:4])
		}
	})

	t.Run("mixed add and remove", func(t *testing.T) {
		t.Parallel()
		got, err := parseOutputFields("+uid,gid,-timestamp,user")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"group", "command", "uid", "gid"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got=%v want=%v", got, want)
		}
	})

	t.Run("mixed remove and add", func(t *testing.T) {
		t.Parallel()
		got, err := parseOutputFields("-timestamp,user,+uid,gid")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"group", "command", "uid", "gid"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got=%v want=%v", got, want)
		}
	})

	t.Run("all with remove list", func(t *testing.T) {
		t.Parallel()
		got, err := parseOutputFields("all,-end_timestamp,event_id,duration_ns,duration,cgroup,tty,tty_nr,source,record_type,exit_status,exec_errno,exec_error,lost_samples,lost_samples_total,parent_comm,parent_exe,parent_cmdline,parent_tty,parent_tty_nr,auid,session_id")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{
			"timestamp",
			"user",
			"group",
			"command",
			"uid",
			"gid",
			"pid",
			"ppid",
			"comm",
			"exe",
			"cwd",
			"argv",
			"argc",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got=%v want=%v", got, want)
		}
	})

	t.Run("invalid field", func(t *testing.T) {
		t.Parallel()
		_, err := parseOutputFields("uid,invalid")
		if err == nil {
			t.Fatalf("expected error")
		}
	})

	t.Run("empty field", func(t *testing.T) {
		t.Parallel()
		_, err := parseOutputFields("uid,,gid")
		if err == nil {
			t.Fatalf("expected error")
		}
	})
}

func TestFormatEventForOutputWithExtraFields(t *testing.T) {
	t.Parallel()

	ev := events.CommandEvent{
		Timestamp: "2026-05-22T22:41:37.715161125+09:00",
		UID:       1004,
		GID:       1002,
		User:      "admin",
		Group:     "admin",
		Argv:      []string{"/bin/curl", "https://httpbin.org/ip"},
	}
	got := formatEventForOutput(ev, outputOptions{
		fullTime: false,
		fields:   []string{"uid", "gid", "user"},
	})
	if got != "1004 1002 admin" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestFormatEventForOutputWithAuditAndLossFields(t *testing.T) {
	t.Parallel()

	ev := events.CommandEvent{
		AUID:        uint32Ptr(1000),
		SessionID:   uint32Ptr(44),
		RecordType:  events.RecordTypeLoss,
		LostSamples: int64Ptr(3),
		LostTotal:   int64Ptr(10),
		ExecErrno:   intPtr(2),
		ExecError:   "no such file or directory",
	}
	got := formatEventForOutput(ev, outputOptions{
		fullTime: false,
		fields:   []string{"auid", "session_id", "record_type", "exec_errno", "exec_error", "lost_samples", "lost_samples_total"},
	})
	if got != "1000 44 loss 2 no such file or directory 3 10" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestFormatEventForOutputWithAllDoesNotDuplicateDefaultFields(t *testing.T) {
	t.Parallel()

	fields, err := parseOutputFields("+uid,gid,-timestamp,user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ev := events.CommandEvent{
		Timestamp: "2026-05-22T22:41:37.715161125+09:00",
		UID:       1004,
		GID:       1002,
		User:      "admin",
		Group:     "admin",
		Argv:      []string{"/bin/curl", "https://httpbin.org/ip"},
	}
	got := formatEventForOutput(ev, outputOptions{
		fullTime: false,
		fields:   fields,
	})
	if got != "admin /bin/curl https://httpbin.org/ip 1004 1002" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestResolveStructuredOutputFieldsUsesOutputWhenSpecified(t *testing.T) {
	t.Parallel()

	got := resolveStructuredOutputFields(outputOptions{
		fields: []string{"uid", "gid", "user"},
	})
	want := []string{"uid", "gid", "user"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestRequiresCommandEndProcessing(t *testing.T) {
	t.Parallel()

	noNeed, err := buildQueryFilter([]string{"source=user"})
	if err != nil {
		t.Fatalf("buildQueryFilter(noNeed): %v", err)
	}
	if requiresCommandEndProcessing(noNeed, outputOptions{}) {
		t.Fatalf("default output with source query should not require end")
	}

	needByField := requiresCommandEndProcessing(noNeed, outputOptions{
		fields: []string{"timestamp", "command", "duration"},
	})
	if !needByField {
		t.Fatalf("duration field should require end")
	}

	needByQuery, err := buildQueryFilter([]string{"exit_status=0"})
	if err != nil {
		t.Fatalf("buildQueryFilter(needByQuery): %v", err)
	}
	if !requiresCommandEndProcessing(needByQuery, outputOptions{}) {
		t.Fatalf("exit_status query should require end")
	}
}
