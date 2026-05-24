package filter

import (
	"testing"

	"github.com/jfut/prec/pkg/config"
	"github.com/jfut/prec/pkg/events"
)

func TestMatcherRulesFirstMatchWins(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		FilterDefault: "deny",
		Filter: []string{
			"-exe~=apt",
			"+source=user&&uid>=1000",
		},
	}
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher returned error: %v", err)
	}

	allowed := events.CommandEvent{UID: 1001, Source: events.SourceUser, Exe: "/usr/bin/curl"}
	if !m.Match(allowed) {
		t.Fatalf("expected allowed event to match")
	}

	deniedByFirstRule := events.CommandEvent{UID: 1001, Source: events.SourceUser, Exe: "/usr/bin/apt"}
	if m.Match(deniedByFirstRule) {
		t.Fatalf("expected deny rule to take precedence")
	}

	deniedByDefault := events.CommandEvent{UID: 900, Source: events.SourceUser, Exe: "/usr/bin/curl"}
	if m.Match(deniedByDefault) {
		t.Fatalf("expected unmatched event to follow filter_default=deny")
	}
}

func TestMatcherDefaultAllow(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		FilterDefault: "allow",
		Filter: []string{
			"-source=system",
		},
	}
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher returned error: %v", err)
	}

	userEvent := events.CommandEvent{Source: events.SourceUser}
	if !m.Match(userEvent) {
		t.Fatalf("expected unmatched user event to match by default")
	}

	systemEvent := events.CommandEvent{Source: events.SourceSystem}
	if m.Match(systemEvent) {
		t.Fatalf("expected system event to be denied by rule")
	}
}

func TestMatcherUserOnlyIsHardRestriction(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		FilterDefault: "allow",
		Filter: []string{
			"+source=system",
		},
		UserOnly: true,
	}
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher returned error: %v", err)
	}

	systemEvent := events.CommandEvent{Source: events.SourceSystem}
	if m.Match(systemEvent) {
		t.Fatalf("expected user_only to deny non-user source")
	}

	userEvent := events.CommandEvent{Source: events.SourceUser}
	if !m.Match(userEvent) {
		t.Fatalf("expected user source to match")
	}
}

func TestMatcherRejectInvalidRule(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		FilterDefault: "allow",
		Filter: []string{
			"uid>=1000",
		},
	}
	if _, err := NewMatcher(cfg); err == nil {
		t.Fatalf("expected invalid rule error")
	}
}
