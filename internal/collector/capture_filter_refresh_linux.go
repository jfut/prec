// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

//go:build linux

package collector

import (
	"errors"
	"fmt"
	"log"
	"math"
	"os/user"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/jfut/prec/internal/events"
)

// captureIdentityRefresher publishes a complete snapshot only after all lookups
// succeed. Transient NSS errors and failed map updates leave the last snapshot intact.
type captureIdentityRefresher struct {
	policy           capturePolicy
	lookupUID        func(string) (uint64, error)
	lookupGID        func(string) (uint64, error)
	update           func([]uint64) error
	current          []uint64
	invalidateCaches func()
}

func (r *captureIdentityRefresher) refresh() error {
	values := make([]uint64, len(r.policy.identities))
	for i, identity := range r.policy.identities {
		lookup := r.lookupUID
		if identity.field == captureFieldGID {
			lookup = r.lookupGID
		}
		value, err := lookup(identity.name)
		if err != nil {
			var unknownUser user.UnknownUserError
			var unknownGroup user.UnknownGroupError
			if !errors.As(err, &unknownUser) && !errors.As(err, &unknownGroup) {
				return err
			}
			// Real UID/GID values are 32-bit. This sentinel never matches equality,
			// and keeps missing-only allowlists from accidentally allowing everyone.
			value = math.MaxUint64
		}
		values[i] = value
	}
	// Clear reverse lookups before accepting events under the new IDs. Even
	// unchanged IDs may have new names, so a successful lookup pass invalidates them.
	if r.invalidateCaches != nil {
		r.invalidateCaches()
	}
	if slices.Equal(values, r.current) {
		return nil
	}
	if err := r.update(values); err != nil {
		return fmt.Errorf("update capture_filter identity map: %w", err)
	}
	r.current = values
	return nil
}

func newCaptureIdentityMap(policy capturePolicy) (*ebpf.Map, *captureIdentityRefresher, error) {
	if len(policy.identities) == 0 {
		return nil, nil, nil
	}
	// Hash updates replace the entire value atomically, so every tracepoint sees
	// either the old or the new snapshot without detaching any eBPF program.
	identities, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "prec_cap_ids",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  uint32(len(policy.identities) * 8),
		MaxEntries: 1,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create capture_filter identity map: %w", err)
	}
	refresher := &captureIdentityRefresher{
		policy:    policy,
		lookupUID: lookupCaptureUID,
		lookupGID: lookupCaptureGID,
		invalidateCaches: func() {
			events.InvalidateIdentityCaches()
			userHomeCaches.Store(new(sync.Map))
		},
		update: func(values []uint64) error {
			return identities.Update(uint32(0), values, ebpf.UpdateAny)
		},
	}
	if err := refresher.refresh(); err != nil {
		_ = identities.Close()
		return nil, nil, err
	}
	return identities, refresher, nil
}

func lookupCaptureUID(name string) (uint64, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("lookup capture_filter user %q: %w", name, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse UID for capture_filter user %q: %w", name, err)
	}
	return uid, nil
}

func lookupCaptureGID(name string) (uint64, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("lookup capture_filter group %q: %w", name, err)
	}
	gid, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse GID for capture_filter group %q: %w", name, err)
	}
	return gid, nil
}

func (r *captureIdentityRefresher) start(stop <-chan struct{}, interval time.Duration) func() {
	ticker := time.NewTicker(interval)
	shutdown := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-shutdown:
				return
			case <-ticker.C:
				if err := r.refresh(); err != nil {
					log.Printf("refresh capture_filter identities failed (keeping previous IDs): %v", err)
				}
			}
		}
	}()
	return func() {
		// Join the worker before closing its eBPF map on every Run return path.
		close(shutdown)
		<-done
	}
}
