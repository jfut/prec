// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

//go:build linux

package collector

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const (
	captureFilterAllowLabel  = "prec_capture_filter_allow"
	captureFilterDropLabel   = "prec_capture_filter_drop"
	captureFilterCommOffset  = perfSampleStackStart - 16
	captureIdentityKeyOffset = captureFilterCommOffset - 4
	// Map-value offsets in eBPF loads are signed 16-bit byte offsets.
	captureIdentityMax = 4096
)

type captureField uint8

const (
	captureFieldUID captureField = iota
	captureFieldGID
	captureFieldPID
	captureFieldComm
)

type captureClause struct {
	field         captureField
	op            string
	value         uint64
	text          string
	identityIndex int
}

type captureRule []captureClause

type captureIdentity struct {
	field captureField
	name  string
}

type capturePolicy struct {
	rules           []captureRule
	hasComm         bool
	identities      []captureIdentity
	identitiesMapFD int
	processes       *ebpf.Map
}

func (p capturePolicy) empty() bool {
	return len(p.rules) == 0
}

func compileCaptureFilter(rawRules []string) (capturePolicy, error) {
	policy := capturePolicy{}
	identityIndexes := make(map[captureIdentity]int)
	for ruleIndex, raw := range rawRules {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return capturePolicy{}, fmt.Errorf("capture_filter rule %d is empty", ruleIndex)
		}
		if trimmed[0] != '+' {
			return capturePolicy{}, fmt.Errorf("capture_filter rule %d must start with +", ruleIndex)
		}
		expr := strings.TrimSpace(trimmed[1:])
		if expr == "" {
			return capturePolicy{}, fmt.Errorf("capture_filter rule %d has an empty expression", ruleIndex)
		}

		orTerms, err := splitCaptureExpression(expr, "||")
		if err != nil {
			return capturePolicy{}, fmt.Errorf("capture_filter rule %d: %w", ruleIndex, err)
		}
		for termIndex, term := range orTerms {
			clauses, err := splitCaptureExpression(term, "&&")
			if err != nil {
				return capturePolicy{}, fmt.Errorf("capture_filter rule %d term %d: %w", ruleIndex, termIndex, err)
			}
			compiled := make(captureRule, 0, len(clauses))
			for clauseIndex, clause := range clauses {
				parsed, err := parseCaptureClause(clause)
				if err != nil {
					return capturePolicy{}, fmt.Errorf("capture_filter rule %d term %d clause %d: %w", ruleIndex, termIndex, clauseIndex, err)
				}
				if parsed.field == captureFieldComm {
					policy.hasComm = true
				} else if parsed.text != "" {
					identity := captureIdentity{field: parsed.field, name: parsed.text}
					index, ok := identityIndexes[identity]
					if !ok {
						if len(policy.identities) == captureIdentityMax {
							return capturePolicy{}, fmt.Errorf("capture_filter has too many user/group names (maximum %d)", captureIdentityMax)
						}
						index = len(policy.identities)
						identityIndexes[identity] = index
						policy.identities = append(policy.identities, identity)
					}
					parsed.identityIndex = index
				}
				compiled = append(compiled, parsed)
			}
			policy.rules = append(policy.rules, compiled)
		}
	}
	return policy, nil
}

func splitCaptureExpression(raw string, delimiter string) ([]string, error) {
	parts := strings.Split(raw, delimiter)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			return nil, fmt.Errorf("empty clause in %q", raw)
		}
		out = append(out, trimmed)
	}
	return out, nil
}

func parseCaptureClause(raw string) (captureClause, error) {
	operators := []string{"!=", ">=", "<=", "=", ">", "<", "~=", "!~="}
	operator := ""
	position := -1
	for _, candidate := range operators {
		if index := strings.Index(raw, candidate); index > 0 {
			operator = candidate
			position = index
			break
		}
	}
	if operator == "" {
		return captureClause{}, fmt.Errorf("invalid clause %q", raw)
	}
	key := strings.TrimSpace(raw[:position])
	value := strings.TrimSpace(raw[position+len(operator):])
	if value == "" {
		return captureClause{}, fmt.Errorf("empty value for %s", key)
	}

	switch key {
	case "uid", "gid", "pid":
		if !isCaptureNumericOperator(operator) {
			return captureClause{}, fmt.Errorf("operator %s is not supported for %s", operator, key)
		}
		number, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return captureClause{}, fmt.Errorf("invalid %s value %q: %w", key, value, err)
		}
		return captureClause{field: captureFieldForKey(key), op: operator, value: number}, nil
	case "user", "group":
		if operator != "=" && operator != "!=" {
			return captureClause{}, fmt.Errorf("operator %s is not supported for %s", operator, key)
		}
		field := captureFieldUID
		if key == "group" {
			field = captureFieldGID
		}
		// Keep names separate from numeric rules so their IDs can change at runtime.
		return captureClause{field: field, op: operator, text: value}, nil
	case "comm":
		if operator != "=" && operator != "!=" {
			return captureClause{}, fmt.Errorf("operator %s is not supported for comm; use exact match", operator)
		}
		if len(value) > 15 {
			return captureClause{}, fmt.Errorf("comm value %q is longer than the kernel limit of 15 characters", value)
		}
		return captureClause{field: captureFieldComm, op: operator, text: value}, nil
	default:
		return captureClause{}, fmt.Errorf("field %s cannot be evaluated before perf ring delivery", key)
	}
}

func captureFieldForKey(key string) captureField {
	switch key {
	case "gid":
		return captureFieldGID
	case "pid":
		return captureFieldPID
	default:
		return captureFieldUID
	}
}

func isCaptureNumericOperator(op string) bool {
	switch op {
	case "=", "!=", ">", ">=", "<", "<=":
		return true
	default:
		return false
	}
}

func startCaptureTraceInstructions(policy capturePolicy) asm.Instructions {
	instructions := asm.Instructions{
		// Preserve tracepoint context before capture_filter calls overwrite helper registers.
		asm.Mov.Reg(asm.R6, asm.R1),
	}
	if policy.empty() {
		return instructions
	}
	instructions = append(instructions, policy.guardInstructions()...)
	return instructions
}

func appendCaptureTraceBody(instructions asm.Instructions, body asm.Instructions, policy capturePolicy) asm.Instructions {
	if !policy.empty() {
		tracking := policy.trackProcessInstructions()
		tracking[0] = tracking[0].WithSymbol(captureFilterAllowLabel)
		instructions = append(instructions, tracking...)
		return append(instructions, body...)
	}
	return appendCaptureExitBody(instructions, body, policy)
}

func appendCaptureExitBody(instructions asm.Instructions, body asm.Instructions, policy capturePolicy) asm.Instructions {
	if !policy.empty() && len(body) > 0 {
		body[0] = body[0].WithSymbol(captureFilterAllowLabel)
	}
	return append(instructions, body...)
}

func (p capturePolicy) guardInstructions() asm.Instructions {
	instructions := asm.Instructions{}
	if p.hasComm {
		instructions = append(instructions,
			asm.Mov.Imm(asm.R0, 0),
			asm.StoreMem(asm.RFP, captureFilterCommOffset, asm.R0, asm.DWord),
			asm.StoreMem(asm.RFP, captureFilterCommOffset+8, asm.R0, asm.DWord),
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, captureFilterCommOffset),
			asm.Mov.Imm(asm.R2, 16),
			asm.FnGetCurrentComm.Call(),
		)
	}
	instructions = append(instructions,
		asm.FnGetCurrentUidGid.Call(),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.FnGetCurrentPidTgid.Call(),
		asm.Mov.Reg(asm.R8, asm.R0),
	)
	if len(p.identities) > 0 {
		// One hash value holds an immutable ID snapshot for all named clauses.
		// Look it up after the other helpers so R5 remains valid through the guard.
		instructions = append(instructions,
			asm.StoreImm(asm.RFP, captureIdentityKeyOffset, 0, asm.Word),
			asm.LoadMapPtr(asm.R1, p.identitiesMapFD),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, captureIdentityKeyOffset),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, captureFilterDropLabel),
			asm.Mov.Reg(asm.R5, asm.R0),
		)
	}

	for ruleIndex, rule := range p.rules {
		nextRuleLabel := fmt.Sprintf("prec_capture_filter_next_rule_%d", ruleIndex)
		for clauseIndex, clause := range rule {
			instructions = append(instructions, p.clauseInstructions(clause, nextRuleLabel, ruleIndex, clauseIndex)...)
		}
		instructions = append(instructions, asm.Ja.Label(captureFilterAllowLabel))
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol(nextRuleLabel))
	}
	instructions = append(instructions,
		asm.Ja.Label(captureFilterDropLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(captureFilterDropLabel),
		asm.Return(),
	)
	return instructions
}

func (p capturePolicy) clauseInstructions(clause captureClause, falseLabel string, ruleIndex int, clauseIndex int) asm.Instructions {
	if clause.field == captureFieldComm {
		return p.commClauseInstructions(clause, falseLabel, ruleIndex, clauseIndex)
	}

	instructions := captureFieldValueInstructions(clause.field)
	if clause.text != "" {
		instructions = append(instructions, asm.LoadMem(asm.R0, asm.R5, int16(clause.identityIndex*8), asm.DWord))
	} else {
		instructions = append(instructions, asm.LoadImm(asm.R0, int64(clause.value), asm.DWord))
	}
	switch clause.op {
	case "=":
		instructions = append(instructions, asm.JNE.Reg(asm.R9, asm.R0, falseLabel))
	case "!=":
		instructions = append(instructions, asm.JEq.Reg(asm.R9, asm.R0, falseLabel))
	case ">":
		instructions = append(instructions, asm.JLE.Reg(asm.R9, asm.R0, falseLabel))
	case ">=":
		instructions = append(instructions, asm.JLT.Reg(asm.R9, asm.R0, falseLabel))
	case "<":
		instructions = append(instructions, asm.JGE.Reg(asm.R9, asm.R0, falseLabel))
	case "<=":
		instructions = append(instructions, asm.JGT.Reg(asm.R9, asm.R0, falseLabel))
	}
	return instructions
}

func captureFieldValueInstructions(field captureField) asm.Instructions {
	switch field {
	case captureFieldGID:
		return asm.Instructions{
			asm.Mov.Reg(asm.R9, asm.R7),
			asm.RSh.Imm(asm.R9, 32),
		}
	case captureFieldPID:
		return asm.Instructions{
			asm.Mov.Reg(asm.R9, asm.R8),
			asm.RSh.Imm(asm.R9, 32),
		}
	default:
		return asm.Instructions{
			asm.Mov.Reg(asm.R9, asm.R7),
			// FnGetCurrentUidGid packs UID in the low 32 bits and GID in the high 32 bits.
			asm.LSh.Imm(asm.R9, 32),
			asm.RSh.Imm(asm.R9, 32),
		}
	}
}

func (p capturePolicy) commClauseInstructions(clause captureClause, falseLabel string, ruleIndex int, clauseIndex int) asm.Instructions {
	var expected [16]byte
	copy(expected[:], clause.text)
	first := int64(binary.LittleEndian.Uint64(expected[:8]))
	second := int64(binary.LittleEndian.Uint64(expected[8:]))
	firstPassLabel := fmt.Sprintf("prec_capture_filter_comm_pass_%d_%d", ruleIndex, clauseIndex)

	instructions := asm.Instructions{
		asm.LoadMem(asm.R9, asm.RFP, captureFilterCommOffset, asm.DWord),
		asm.LoadImm(asm.R0, first, asm.DWord),
	}
	if clause.op == "=" {
		instructions = append(instructions, asm.JNE.Reg(asm.R9, asm.R0, falseLabel))
		instructions = append(instructions,
			asm.LoadMem(asm.R9, asm.RFP, captureFilterCommOffset+8, asm.DWord),
			asm.LoadImm(asm.R0, second, asm.DWord),
			asm.JNE.Reg(asm.R9, asm.R0, falseLabel),
		)
		return instructions
	}

	instructions = append(instructions, asm.JNE.Reg(asm.R9, asm.R0, firstPassLabel))
	instructions = append(instructions,
		asm.LoadMem(asm.R9, asm.RFP, captureFilterCommOffset+8, asm.DWord),
		asm.LoadImm(asm.R0, second, asm.DWord),
		asm.JEq.Reg(asm.R9, asm.R0, falseLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(firstPassLabel),
	)
	return instructions
}
