package filter

import (
	"fmt"
	"strings"

	"github.com/jfut/prec/pkg/config"
	"github.com/jfut/prec/pkg/events"
	"github.com/jfut/prec/pkg/query"
)

type compiledRule struct {
	allow  bool
	filter query.Filter
}

// Matcher decides whether to keep an event based on config rules.
type Matcher struct {
	defaultAllow bool
	rules        []compiledRule
	userOnly     bool
}

func NewMatcher(cfg config.Config) (Matcher, error) {
	rules := make([]compiledRule, 0, len(cfg.Filter))
	for i, raw := range cfg.Filter {
		rule, err := compileRule(raw)
		if err != nil {
			return Matcher{}, fmt.Errorf("invalid filter rule at index %d: %w", i, err)
		}
		rules = append(rules, rule)
	}

	defaultAllow := true
	if cfg.FilterDefault == "deny" {
		defaultAllow = false
	}

	return Matcher{
		defaultAllow: defaultAllow,
		rules:        rules,
		userOnly:     cfg.UserOnly,
	}, nil
}

func compileRule(raw string) (compiledRule, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return compiledRule{}, fmt.Errorf("empty rule")
	}

	prefix := trimmed[0]
	if prefix != '+' && prefix != '-' {
		return compiledRule{}, fmt.Errorf("missing action prefix in %q (must start with '+' or '-')", trimmed)
	}

	expr := strings.TrimSpace(trimmed[1:])
	if expr == "" {
		return compiledRule{}, fmt.Errorf("empty query expression in %q", trimmed)
	}

	compiled, err := query.Build([]string{expr})
	if err != nil {
		return compiledRule{}, err
	}

	return compiledRule{
		allow:  prefix == '+',
		filter: compiled,
	}, nil
}

func (m Matcher) Match(ev events.CommandEvent) bool {
	// Keep user_only as a hard restriction regardless of custom filters.
	if m.userOnly && ev.Source != events.SourceUser {
		return false
	}

	for _, rule := range m.rules {
		if rule.filter.Match(ev) {
			return rule.allow
		}
	}
	return m.defaultAllow
}
