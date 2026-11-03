// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package events

import (
	"os/user"
	"strconv"
	"sync"
	"sync/atomic"
)

type identityCacheGeneration struct {
	users  sync.Map
	groups sync.Map
}

type identityNameCache struct {
	lookupUID  func(string) (*user.User, error)
	lookupGID  func(string) (*user.Group, error)
	generation atomic.Pointer[identityCacheGeneration]
}

func newIdentityNameCache(lookupUID func(string) (*user.User, error), lookupGID func(string) (*user.Group, error)) *identityNameCache {
	cache := &identityNameCache{lookupUID: lookupUID, lookupGID: lookupGID}
	cache.clear()
	return cache
}

func (c *identityNameCache) clear() {
	// In-flight lookups may finish after invalidation. Their results stay in the
	// old generation and cannot repopulate the cache used for subsequent events.
	c.generation.Store(new(identityCacheGeneration))
}

func (c *identityNameCache) user(uid uint32) string {
	generation := c.generation.Load()
	if name, ok := generation.users.Load(uid); ok {
		return name.(string)
	}
	name := ""
	if u, err := c.lookupUID(strconv.FormatUint(uint64(uid), 10)); err == nil {
		name = u.Username
	}
	// Negative lookups are cached too, but only until the next refresh.
	generation.users.Store(uid, name)
	return name
}

func (c *identityNameCache) group(gid uint32) string {
	generation := c.generation.Load()
	if name, ok := generation.groups.Load(gid); ok {
		return name.(string)
	}
	name := ""
	if g, err := c.lookupGID(strconv.FormatUint(uint64(gid), 10)); err == nil {
		name = g.Name
	}
	generation.groups.Store(gid, name)
	return name
}

var identityNames = newIdentityNameCache(user.LookupId, user.LookupGroupId)

// InvalidateIdentityCaches makes subsequent events resolve current account names.
func InvalidateIdentityCaches() {
	identityNames.clear()
}
