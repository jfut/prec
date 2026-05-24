package cli

import (
	"testing"
	"time"

	"github.com/jfut/prec/pkg/events"
)

func TestBuildQueryFilterValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		specs []string
		event events.CommandEvent
		want  bool
	}{
		{
			name:  "single string equals",
			specs: []string{"user=admin"},
			event: events.CommandEvent{User: "admin"},
			want:  true,
		},
		{
			name:  "single group equals",
			specs: []string{"group=wheel"},
			event: events.CommandEvent{Group: "wheel"},
			want:  true,
		},
		{
			name:  "numeric range with exclude",
			specs: []string{"uid>=1000&&uid!=1500"},
			event: events.CommandEvent{UID: 1400},
			want:  true,
		},
		{
			name:  "numeric range with excluded value",
			specs: []string{"uid>=1000&&uid!=1500"},
			event: events.CommandEvent{UID: 1500},
			want:  false,
		},
		{
			name:  "repeated query flags are and",
			specs: []string{"uid>=1000", "source=user"},
			event: events.CommandEvent{UID: 1001, Source: events.SourceUser},
			want:  true,
		},
		{
			name:  "or expression with two users",
			specs: []string{"user=user1||user=root"},
			event: events.CommandEvent{User: "root"},
			want:  true,
		},
		{
			name:  "and has higher precedence than or",
			specs: []string{"source=user&&user=user1||source=system&&user=root"},
			event: events.CommandEvent{Source: events.SourceSystem, User: "root"},
			want:  true,
		},
		{
			name:  "and expression with spaces",
			specs: []string{"user=root && uid=0"},
			event: events.CommandEvent{User: "root", UID: 0},
			want:  true,
		},
		{
			name:  "repeated flags keep top level and with or expression",
			specs: []string{"user=user1||user=root", "source=user"},
			event: events.CommandEvent{Source: events.SourceSystem, User: "root"},
			want:  false,
		},
		{
			name:  "timestamp compare",
			specs: []string{"timestamp>=2026-05-22T00:00:00+09:00"},
			event: events.CommandEvent{Timestamp: "2026-05-22T12:00:00+09:00"},
			want:  true,
		},
		{
			name:  "command contains",
			specs: []string{"command~=curl"},
			event: events.CommandEvent{Argv: []string{"/bin/curl", "https://example.com"}},
			want:  true,
		},
		{
			name:  "argv not contains",
			specs: []string{"argv!~=token"},
			event: events.CommandEvent{Argv: []string{"/bin/echo", "hello"}},
			want:  true,
		},
		{
			name:  "source value valid",
			specs: []string{"source=system"},
			event: events.CommandEvent{Source: events.SourceSystem},
			want:  true,
		},
		{
			name:  "exit status numeric query",
			specs: []string{"exit_status=4"},
			event: events.CommandEvent{ExitStatus: intPtr(4)},
			want:  true,
		},
		{
			name:  "auid numeric query",
			specs: []string{"auid=1000"},
			event: events.CommandEvent{AUID: uint32Ptr(1000)},
			want:  true,
		},
		{
			name:  "session id numeric query",
			specs: []string{"session_id>=42"},
			event: events.CommandEvent{SessionID: uint32Ptr(100)},
			want:  true,
		},
		{
			name:  "record type string query",
			specs: []string{"record_type=loss"},
			event: events.CommandEvent{RecordType: events.RecordTypeLoss},
			want:  true,
		},
		{
			name:  "record type command start query",
			specs: []string{"record_type=start"},
			event: events.CommandEvent{RecordType: events.RecordTypeStart},
			want:  true,
		},
		{
			name:  "record type command end query",
			specs: []string{"record_type=end"},
			event: events.CommandEvent{RecordType: events.RecordTypeEnd},
			want:  true,
		},
		{
			name:  "record type exec failure query",
			specs: []string{"record_type=fail"},
			event: events.CommandEvent{RecordType: events.RecordTypeFail},
			want:  true,
		},
		{
			name:  "lost samples numeric query",
			specs: []string{"lost_samples=8"},
			event: events.CommandEvent{LostSamples: int64Ptr(8)},
			want:  true,
		},
		{
			name:  "exec errno numeric query",
			specs: []string{"exec_errno=2"},
			event: events.CommandEvent{ExecErrno: intPtr(2)},
			want:  true,
		},
		{
			name:  "exec error string query",
			specs: []string{"exec_error~=file"},
			event: events.CommandEvent{ExecError: "no such file or directory"},
			want:  true,
		},
		{
			name:  "dynamic string field query",
			specs: []string{"parent_exe~=bash"},
			event: events.CommandEvent{ParentExe: "/usr/bin/bash"},
			want:  true,
		},
		{
			name:  "event id equals",
			specs: []string{"event_id=boot-33"},
			event: events.CommandEvent{EventID: "boot-33"},
			want:  true,
		},
		{
			name:  "end timestamp compare",
			specs: []string{"end_timestamp>=2026-05-22T00:00:00Z"},
			event: events.CommandEvent{EndTimestamp: "2026-05-22T01:00:00Z"},
			want:  true,
		},
		{
			name:  "duration formatted query",
			specs: []string{"duration>=0000-00-00 00:00:02"},
			event: events.CommandEvent{DurationNS: int64Ptr(3 * int64(time.Second))},
			want:  true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lf, err := buildQueryFilter(tt.specs)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := matchFilter(tt.event, lf); got != tt.want {
				t.Fatalf("got=%v want=%v", got, tt.want)
			}
		})
	}
}

func TestBuildQueryFilterInvalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		specs []string
	}{
		{name: "empty clause", specs: []string{"uid>=1000&&&&gid=1000"}},
		{name: "invalid key", specs: []string{"username=admin"}},
		{name: "unsupported operator", specs: []string{"uid~=1000"}},
		{name: "missing value", specs: []string{"uid>="}},
		{name: "numeric parse error", specs: []string{"uid=abc"}},
		{name: "timestamp parse error", specs: []string{"timestamp>=not-time"}},
		{name: "duration parse error", specs: []string{"duration>=bad-value"}},
		{name: "dynamic string field with numeric operator", specs: []string{"user>=admin"}},
		{name: "source invalid value", specs: []string{"source=robot"}},
		{name: "record type invalid value", specs: []string{"record_type=robot"}},
		{name: "or empty right side", specs: []string{"user=user1||"}},
		{name: "or empty left side", specs: []string{"||user=root"}},
		{name: "and empty right side", specs: []string{"uid>=1000&&"}},
		{name: "comma is not supported as and", specs: []string{"uid>=1000,uid!=1500"}},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := buildQueryFilter(tt.specs); err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func TestDurationValueFormatAndParse(t *testing.T) {
	t.Parallel()

	ns := int64(3 * int64(time.Second))
	if got := formatDurationValue(&ns); got != "0000-00-00 00:00:03" {
		t.Fatalf("got=%q want=%q", got, "0000-00-00 00:00:03")
	}

	parsed, err := parseDurationValue("0001-02-03 04:05:06")
	if err != nil {
		t.Fatalf("parseDurationValue: %v", err)
	}
	// 1 year(365d) + 2 month(30d each) + 3 day + 4:05:06
	want := int64((365+60+3)*24*60*60+(4*60*60)+(5*60)+6) * int64(time.Second)
	if parsed != want {
		t.Fatalf("parsed=%d want=%d", parsed, want)
	}
}
