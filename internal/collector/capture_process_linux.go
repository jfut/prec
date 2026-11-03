// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

//go:build linux

package collector

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

const (
	captureProcessKeyOffset    = captureIdentityKeyOffset - 4
	captureProcessValueOffset  = captureProcessKeyOffset - 4
	captureProcessTrackedLabel = "prec_capture_process_tracked"
	captureProcessMax          = 1 << 20
)

func newCaptureProcessMap() (*ebpf.Map, error) {
	processes, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "prec_cap_procs",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: captureProcessMax,
		Flags:      unix.BPF_F_NO_PREALLOC,
	})
	if err != nil {
		return nil, fmt.Errorf("create capture_filter process map: %w", err)
	}
	return processes, nil
}

func (p capturePolicy) trackProcessInstructions() asm.Instructions {
	// Register before emitting any sample: a short-lived task may exit before
	// userspace reads its start or file event. Entries survive identity refreshes.
	return asm.Instructions{
		asm.FnGetCurrentPidTgid.Call(),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, captureProcessKeyOffset, asm.R0, asm.Word),
		asm.LoadMapPtr(asm.R1, p.processes.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, captureProcessKeyOffset),
		asm.FnMapLookupElem.Call(),
		asm.JNE.Imm(asm.R0, 0, captureProcessTrackedLabel),
		asm.StoreImm(asm.RFP, captureProcessValueOffset, 1, asm.Word),
		asm.LoadMapPtr(asm.R1, p.processes.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, captureProcessKeyOffset),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, captureProcessValueOffset),
		asm.Mov.Imm(asm.R4, int32(ebpf.UpdateNoExist)),
		asm.FnMapUpdateElem.Call(),
		asm.JEq.Imm(asm.R0, 0, captureProcessTrackedLabel),
		// Another thread may have registered the same process concurrently.
		asm.JNE.Imm(asm.R0, -int32(unix.EEXIST), captureFilterDropLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(captureProcessTrackedLabel),
	}
}

func startCaptureExitInstructions(policy capturePolicy, cleanup bool) asm.Instructions {
	instructions := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}
	if policy.empty() {
		return instructions
	}
	// Exit/status events follow the tracked TGID, never the current UID/GID
	// allowlist. Tasks retain their kernel credentials after account changes.
	instructions = append(instructions,
		asm.FnGetCurrentPidTgid.Call(),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, captureProcessKeyOffset, asm.R0, asm.Word),
		asm.LoadMapPtr(asm.R1, policy.processes.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, captureProcessKeyOffset),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, captureFilterDropLabel),
	)
	if cleanup {
		instructions = append(instructions,
			asm.Mov.Reg(asm.R8, asm.R7),
			asm.RSh.Imm(asm.R8, 32),
			asm.LSh.Imm(asm.R7, 32),
			asm.RSh.Imm(asm.R7, 32),
			// A non-leader thread must not remove the shared process entry.
			asm.JNE.Reg(asm.R7, asm.R8, captureFilterAllowLabel),
			asm.LoadMapPtr(asm.R1, policy.processes.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, captureProcessKeyOffset),
			asm.FnMapDeleteElem.Call(),
		)
	}
	return append(instructions,
		asm.Ja.Label(captureFilterAllowLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(captureFilterDropLabel),
		asm.Return(),
	)
}
