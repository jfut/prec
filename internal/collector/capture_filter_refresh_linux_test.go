// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

//go:build linux

package collector

import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/user"
	"slices"
	"testing"
	"time"

	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

func TestCaptureIdentityRefreshChanges(t *testing.T) {
	t.Parallel()
	policy, err := compileCaptureFilter([]string{"+user=tomcat&&group=tomcat", "+user!=tomcat"})
	if err != nil {
		t.Fatal(err)
	}
	var uid, gid uint64
	var userErr, groupErr, updateErr error
	var published []uint64
	writes := 0
	refresher := &captureIdentityRefresher{
		policy:    policy,
		lookupUID: func(string) (uint64, error) { return uid, userErr },
		lookupGID: func(string) (uint64, error) { return gid, groupErr },
		update: func(values []uint64) error {
			writes++
			if updateErr != nil {
				return updateErr
			}
			published = slices.Clone(values)
			return nil
		},
	}
	check := func(want []uint64, wantWrites int, wantErr error) {
		t.Helper()
		if err := refresher.refresh(); !errors.Is(err, wantErr) {
			t.Fatalf("refresh error = %v, want %v", err, wantErr)
		}
		if writes != wantWrites || !slices.Equal(published, want) || !slices.Equal(refresher.current, want) {
			t.Fatalf("published/current/writes = %v/%v/%d, want %v/%v/%d", published, refresher.current, writes, want, want, wantWrites)
		}
	}
	// Missing accounts at startup can later appear, change IDs, and disappear.
	userErr, groupErr = user.UnknownUserError("tomcat"), user.UnknownGroupError("tomcat")
	check([]uint64{math.MaxUint64, math.MaxUint64}, 1, nil)
	uid, gid, userErr, groupErr = 48, 82, nil, nil
	check([]uint64{48, 82}, 2, nil)
	check([]uint64{48, 82}, 2, nil) // Unchanged snapshots do not write to eBPF.
	uid, gid = 848, 882
	check([]uint64{848, 882}, 3, nil)
	userErr, groupErr = user.UnknownUserError("tomcat"), user.UnknownGroupError("tomcat")
	check([]uint64{math.MaxUint64, math.MaxUint64}, 4, nil)

	// A failure after resolving one name must not publish a partial snapshot.
	transient := errors.New("temporary name service failure")
	uid, gid, userErr, groupErr = 100, 200, nil, transient
	check([]uint64{math.MaxUint64, math.MaxUint64}, 4, transient)
	groupErr = nil
	updateErr = errors.New("map update failed")
	check([]uint64{math.MaxUint64, math.MaxUint64}, 5, updateErr)
	updateErr = nil
	check([]uint64{100, 200}, 6, nil) // The failed update must be retried.
	userErr = transient
	check([]uint64{100, 200}, 6, transient)
}

func TestCaptureIdentitySystemLookup(t *testing.T) {
	t.Parallel()
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(current.Gid)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := lookupCaptureUID(current.Username)
	if err != nil || fmt.Sprint(uid) != current.Uid {
		t.Fatalf("lookup UID = %d, %v, want %s", uid, err, current.Uid)
	}
	gid, err := lookupCaptureGID(group.Name)
	if err != nil || fmt.Sprint(gid) != current.Gid {
		t.Fatalf("lookup GID = %d, %v, want %s", gid, err, current.Gid)
	}
}

func TestCaptureIdentityRefreshInvalidatesCachesBeforePublish(t *testing.T) {
	t.Parallel()
	policy, err := compileCaptureFilter([]string{"+user=tomcat"})
	if err != nil {
		t.Fatal(err)
	}
	uid := uint64(48)
	var lookupErr error
	var steps []string
	refresher := &captureIdentityRefresher{
		policy:           policy,
		lookupUID:        func(string) (uint64, error) { return uid, lookupErr },
		invalidateCaches: func() { steps = append(steps, "invalidate") },
		update: func([]uint64) error {
			steps = append(steps, "publish")
			return nil
		},
	}
	check := func(want []string, wantErr error) {
		t.Helper()
		steps = nil
		if err := refresher.refresh(); !errors.Is(err, wantErr) {
			t.Fatalf("refresh error = %v, want %v", err, wantErr)
		}
		if !slices.Equal(steps, want) {
			t.Fatalf("refresh steps = %v, want %v", steps, want)
		}
	}
	check([]string{"invalidate", "publish"}, nil)
	check([]string{"invalidate"}, nil) // Renames can occur without a numeric ID change.
	uid = 49
	check([]string{"invalidate", "publish"}, nil)
	lookupErr = errors.New("name service unavailable")
	check(nil, lookupErr) // A failed resolution pass does not publish partial changes.
}

func TestCaptureIdentityRefreshWorker(t *testing.T) {
	t.Parallel()
	for _, viaStop := range []bool{false, true} {
		t.Run(fmt.Sprintf("viaStop=%t", viaStop), func(t *testing.T) {
			t.Parallel()
			policy, err := compileCaptureFilter([]string{"+user=tomcat"})
			if err != nil {
				t.Fatal(err)
			}
			updated := make(chan struct{}, 1)
			refresher := &captureIdentityRefresher{
				policy:    policy,
				lookupUID: func(string) (uint64, error) { return 48, nil },
				update: func([]uint64) error {
					updated <- struct{}{}
					return nil
				},
			}
			stop := make(chan struct{})
			cleanup := refresher.start(stop, time.Millisecond)
			select {
			case <-updated:
			case <-time.After(time.Second):
				cleanup()
				t.Fatal("periodic refresh did not run")
			}
			if viaStop {
				close(stop)
			}
			cleanup()
			if !slices.Equal(refresher.current, []uint64{48}) {
				t.Fatalf("worker did not publish the resolved UID: %v", refresher.current)
			}
		})
	}
}

func TestCaptureIdentityMapKernel(t *testing.T) {
	// Exercise the actual guard and shared map. Ordinary unprivileged test runs
	// skip this check; a host with BPF capabilities can run it without tracepoints.
	policy, err := compileCaptureFilter([]string{"+user=tomcat&&group=tomcat"})
	if err != nil {
		t.Fatal(err)
	}
	identities, refresher, err := newCaptureIdentityMap(policy)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("eBPF unavailable: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = identities.Close() }()
	policy.identitiesMapFD = identities.FD()
	processes, err := newCaptureProcessMap()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = processes.Close() }()
	policy.processes = processes
	instructions := appendCaptureTraceBody(startCaptureTraceInstructions(policy), asm.Instructions{
		asm.Mov.Imm(asm.R0, 1),
		asm.Return(),
	}, policy)
	program := newCaptureTestProgram(t, instructions,
		uint64(os.Getuid())|uint64(os.Getgid())<<32,
		uint64(os.Getpid())|uint64(os.Getpid())<<32)
	var uid, gid uint64
	var userErr, groupErr error
	refresher.lookupUID = func(string) (uint64, error) { return uid, userErr }
	refresher.lookupGID = func(string) (uint64, error) { return gid, groupErr }
	check := func(want uint32) {
		t.Helper()
		if err := refresher.refresh(); err != nil {
			t.Fatal(err)
		}
		got, _, err := program.Test(make([]byte, 64))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("guard returned %d, want %d (UID/GID snapshot: %v)", got, want, refresher.current)
		}
	}
	uid, gid = uint64(os.Getuid()), uint64(os.Getgid())
	userErr, groupErr = user.UnknownUserError("tomcat"), user.UnknownGroupError("tomcat")
	check(0)
	userErr, groupErr = nil, nil
	check(1) // Creating the named accounts enables capture without reloading the program.
	uid++
	check(0) // Reassignment removes the old UID immediately after map publication.
	uid--
	gid++
	check(0)
	gid--
	check(1)
	userErr = user.UnknownUserError("tomcat")
	check(0)
}
