package events

import "testing"

func TestClassifyCommandSource(t *testing.T) {
	t.Parallel()

	t.Run("user shell", func(t *testing.T) {
		t.Parallel()
		ev := CommandEvent{TTY: "/dev/pts/0"}
		lineage := []procSnapshot{
			{Comm: "bash", Exe: "/usr/bin/bash"},
			{Comm: "sshd", Exe: "/usr/sbin/sshd"},
		}
		if got := classifyCommandSourceFromLineage(ev, lineage); got != SourceUser {
			t.Fatalf("unexpected source: %s", got)
		}
	})

	t.Run("vscode remote ssh", func(t *testing.T) {
		t.Parallel()
		ev := CommandEvent{TTY: "/dev/pts/1"}
		lineage := []procSnapshot{
			{
				Comm:    "node",
				Exe:     "/home/dev/.vscode-server/bin/xxx/node",
				Cmdline: "/home/dev/.vscode-server/bin/xxx/node ... --connection-token=remotessh --start-server",
			},
			{Comm: "bash", Exe: "/usr/bin/bash"},
		}
		if got := classifyCommandSourceFromLineage(ev, lineage); got != SourceSystem {
			t.Fatalf("unexpected source: %s", got)
		}
	})

	t.Run("no tty is system", func(t *testing.T) {
		t.Parallel()
		ev := CommandEvent{}
		lineage := []procSnapshot{
			{Comm: "bash", Exe: "/usr/bin/bash"},
		}
		if got := classifyCommandSourceFromLineage(ev, lineage); got != SourceSystem {
			t.Fatalf("unexpected source: %s", got)
		}
	})

	t.Run("tty missing but tty_nr non zero is user", func(t *testing.T) {
		t.Parallel()
		ev := CommandEvent{TTYNr: 34823}
		lineage := []procSnapshot{
			{Comm: "bash", Exe: "/usr/bin/bash"},
		}
		if got := classifyCommandSourceFromLineage(ev, lineage); got != SourceUser {
			t.Fatalf("unexpected source: %s", got)
		}
	})

	t.Run("non shell parent is system", func(t *testing.T) {
		t.Parallel()
		ev := CommandEvent{TTY: "/dev/pts/0"}
		lineage := []procSnapshot{
			{Comm: "python", Exe: "/usr/bin/python3"},
		}
		if got := classifyCommandSourceFromLineage(ev, lineage); got != SourceSystem {
			t.Fatalf("unexpected source: %s", got)
		}
	})

	t.Run("dev null tty is system", func(t *testing.T) {
		t.Parallel()
		ev := CommandEvent{TTY: "/dev/null"}
		lineage := []procSnapshot{
			{Comm: "bash", Exe: "/usr/bin/bash"},
		}
		if got := classifyCommandSourceFromLineage(ev, lineage); got != SourceSystem {
			t.Fatalf("unexpected source: %s", got)
		}
	})
}

func TestIsInteractiveTTY(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tty  string
		want bool
	}{
		{name: "pts", tty: "/dev/pts/3", want: true},
		{name: "tty", tty: "/dev/tty", want: true},
		{name: "null", tty: "/dev/null", want: false},
		{name: "empty", tty: "", want: false},
		{name: "pipe", tty: "pipe:[1234]", want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isInteractiveTTY(tt.tty); got != tt.want {
				t.Fatalf("tty=%q got=%v want=%v", tt.tty, got, tt.want)
			}
		})
	}
}
