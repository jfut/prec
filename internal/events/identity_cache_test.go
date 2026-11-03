// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package events

import (
	"os/user"
	"testing"
)

func TestIdentityNameCacheRefresh(t *testing.T) {
	t.Parallel()
	var username, groupname string
	userCalls, groupCalls := 0, 0
	cache := newIdentityNameCache(
		func(string) (*user.User, error) {
			userCalls++
			if username == "" {
				return nil, user.UnknownUserIdError(48)
			}
			return &user.User{Username: username}, nil
		},
		func(string) (*user.Group, error) {
			groupCalls++
			if groupname == "" {
				return nil, user.UnknownGroupIdError("82")
			}
			return &user.Group{Name: groupname}, nil
		},
	)
	check := func(wantUser, wantGroup string, calls int) {
		t.Helper()
		if got := cache.user(48); got != wantUser {
			t.Fatalf("user = %q, want %q", got, wantUser)
		}
		if got := cache.group(82); got != wantGroup {
			t.Fatalf("group = %q, want %q", got, wantGroup)
		}
		if userCalls != calls || groupCalls != calls {
			t.Fatalf("lookup calls = %d/%d, want %d each", userCalls, groupCalls, calls)
		}
	}
	check("", "", 1)
	username, groupname = "apache", "apache"
	check("", "", 1) // Negative results expire only at the next refresh.
	cache.clear()
	check("apache", "apache", 2)
	username, groupname = "tomcat", "tomcat"
	check("apache", "apache", 2)
	cache.clear()
	check("tomcat", "tomcat", 3) // Reassigned IDs must not retain the old owner.
	username, groupname = "", ""
	cache.clear()
	check("", "", 4)
}

func TestIdentityNameCacheRefreshDuringLookup(t *testing.T) {
	t.Parallel()
	for _, group := range []bool{false, true} {
		name := "user"
		if group {
			name = "group"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			started := make(chan struct{})
			release := make(chan struct{})
			calls := 0
			lookup := func() string {
				calls++
				if calls == 1 {
					close(started)
					<-release
					return "apache"
				}
				return "tomcat"
			}
			cache := newIdentityNameCache(
				func(string) (*user.User, error) { return &user.User{Username: lookup()}, nil },
				func(string) (*user.Group, error) { return &user.Group{Name: lookup()}, nil },
			)
			read := cache.user
			if group {
				read = cache.group
			}
			result := make(chan string, 1)
			go func() { result <- read(48) }()
			<-started
			cache.clear()
			close(release)
			if got := <-result; got != "apache" {
				t.Fatalf("in-flight lookup = %q, want apache", got)
			}
			if got := read(48); got != "tomcat" {
				t.Fatalf("old lookup repopulated the new cache: %q", got)
			}
		})
	}
}
