// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package netfilter helps the sentry interact with netstack's netfilter
// capabilities.
package netfilter

import (
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/binary"
	"gvisor.googlesource.com/gvisor/pkg/sentry/inet"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/iptables"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
)

const errorTargetName = "ERROR"

type metadata struct {
	HookEntry  [linux.NF_INET_NUMHOOKS]uint32
	Underflow  [linux.NF_INET_NUMHOOKS]uint32
	NumEntries uint32
	Size       uint32
}

// GetInfo returns information about iptables.
func GetInfo(t *kernel.Task, ep tcpip.Endpoint, outPtr usermem.Addr) (linux.IPTGetinfo, *syserr.Error) {
	// Read in the struct and table name.
	var info linux.IPTGetinfo
	if _, err := t.CopyIn(outPtr, &info); err != nil {
		return info, syserr.FromError(err)
	}

	// Find the appropriate table.
	stack := inet.StackFromContext(t)
	ipt, err := stack.IPTables()
	if err != nil {
		return info, syserr.FromError(err)
	}
	table, ok := ipt.Tables[info.TableName()]
	if !ok {
		return info, syserr.ErrInvalidArgument
	}

	// Get the hooks that apply to this table.
	validHooks, netstackErr := table.ValidHooks()
	if err != nil {
		return info, syserr.TranslateNetstackError(netstackErr)
	}
	info.ValidHooks = validHooks

	// Grab the metadata struct, which is used to store information (e.g.
	// the number of entries) that applies to the user's encoding of
	// iptables, but not netstack's.
	metadata, ok := table.Metadata().(metadata)
	if !ok {
		panic(fmt.Sprintf("Unknown metadata type found: %T", table.Metadata()))
	}

	// Set values from metadata.
	info.HookEntry = metadata.HookEntry
	info.Underflow = metadata.Underflow
	info.NumEntries = metadata.NumEntries
	info.Size = metadata.Size

	return info, nil
}

// GetEntries returns netstack's iptables rules encoded for the iptables tool.
func GetEntries(t *kernel.Task, ep tcpip.Endpoint, outPtr usermem.Addr, outLen int) (linux.KernelIPTGetEntries, *syserr.Error) {
	// Read in the struct and table name.
	var userEntries linux.IPTGetEntries
	if _, err := t.CopyIn(outPtr, &userEntries); err != nil {
		return linux.KernelIPTGetEntries{}, syserr.FromError(err)
	}

	// Find the appropriate table.
	stack := inet.StackFromContext(t)
	ipt, err := stack.IPTables()
	if err != nil {
		return linux.KernelIPTGetEntries{}, syserr.FromError(err)
	}
	table, ok := ipt.Tables[userEntries.TableName()]
	if !ok {
		return linux.KernelIPTGetEntries{}, syserr.ErrInvalidArgument
	}

	// Convert netstack's iptables rules to something that the iptables
	// tool can understand.
	entries, _ := convertNetstackToBinary(userEntries.TableName(), table)
	if binary.Size(entries) > uintptr(outLen) {
		return linux.KernelIPTGetEntries{}, syserr.ErrInvalidArgument
	}

	return entries, nil
}

// FillDefaultIPTables sets stack's IPTables to the default tables and
// populates them with metadata.
func FillDefaultIPTables(stack *stack.Stack) error {
	ipt := iptables.DefaultTables()

	// In order to fill in the metadata, we have to translate ipt from its
	// netstack format to Linux's giant-binary-blob format.
	for name, table := range ipt.Tables {
		_, metadata := convertNetstackToBinary(name, table)
		table.SetMetadata(metadata)
	}

	stack.SetIPTables(ipt)

	return nil
}

// convertNetstackToBinary converts the iptables as stored in netstack to the
// format expected by the iptables tool. Linux stores each table as a binary
// blob that can only be traversed by parsing a bit, reading some offsets,
// jumping to those offsets, parsing again, etc. This makes the code here
// pretty hairy - sorry!
//
// This function panics upon error, since it should be impossible to store
// iptables that produce an error when translated to the Linux binary format.
func convertNetstackToBinary(name string, table *iptables.Table) (linux.KernelIPTGetEntries, metadata) {
	// Return values.
	var entries linux.KernelIPTGetEntries
	var meta metadata

	// The table name has to fit in the struct.
	if linux.XT_TABLE_MAXNAMELEN < len(name) {
		panic(fmt.Sprintf("table named %s is longer than max length %d", name, linux.XT_TABLE_MAXNAMELEN))
	}
	copy(entries.Name[:], name)

	// Deal with the built in chains first (INPUT, OUTPUT, etc.). Each of
	// these chains ends with an unconditional policy entry.
	for hook := iptables.Prerouting; hook < iptables.NumHooks; hook++ {
		chain, ok := table.BuiltinChains[hook]
		if !ok {
			// This table doesn't support this hook.
			continue
		}

		// Sanity check.
		if len(chain.Rules) < 1 {
			panic("each iptables chain needs at least 1 rule")
		}

		for ruleIdx, rule := range chain.Rules {
			// If this is the first rule of a builtin chain, set
			// the metadata hook entry point.
			if ruleIdx == 0 {
				meta.HookEntry[hook] = entries.Size
			}

			// Each rule corresponds to an entry.
			entry := linux.KernelIPTEntry{
				NextOffset:   linux.SizeOfIPTEntry,
				TargetOffset: linux.SizeOfIPTEntry,
			}

			for _, matcher := range rule.Matchers {
				// Serialize the matcher and add it to the
				// entry.
				serialized := marshalMatcher(matcher)
				entry.Elems = append(entry.Elems, serialized...)
				entry.NextOffset += uint16(len(serialized))
				entry.TargetOffset += uint16(len(serialized))
			}

			// Serialize and append the target.
			serialized := marshalTarget(rule.Target)
			entry.Elems = append(entry.Elems, serialized...)
			entry.NextOffset += uint16(len(serialized))

			// The underflow rule is the last rule in the chain,
			// and is an unconditional rule (i.e. it matches any
			// packet). This is enforced when saving iptables.
			if ruleIdx == len(chain.Rules)-1 {
				meta.Underflow[hook] = entries.Size
			}

			entries.Size += uint32(entry.NextOffset)
			entries.Entrytable = append(entries.Entrytable, entry)
			meta.NumEntries++
		}

	}

	// TODO(gvisor.dev/issue/170): Deal with the user chains here. Each of
	// these starts with an error node holding the chain's name and ends
	// with an unconditional return.

	// Lastly, each table ends with an unconditional error target rule as
	// its final entry.
	errorEntry := linux.KernelIPTEntry{
		NextOffset:   linux.SizeOfIPTEntry,
		TargetOffset: linux.SizeOfIPTEntry,
	}
	var errorTarget linux.XTErrorTarget
	errorTarget.Target.TargetSize = linux.SizeOfXTErrorTarget
	copy(errorTarget.ErrorName[:], errorTargetName)
	copy(errorTarget.Target.Name[:], errorTargetName)

	// Serialize and add it to the list of entries.
	errorTargetBuf := make([]byte, 0, linux.SizeOfXTErrorTarget)
	serializedErrorTarget := binary.Marshal(errorTargetBuf, usermem.ByteOrder, errorTarget)
	errorEntry.Elems = append(errorEntry.Elems, serializedErrorTarget...)
	errorEntry.NextOffset += uint16(len(serializedErrorTarget))

	entries.Size += uint32(errorEntry.NextOffset)
	entries.Entrytable = append(entries.Entrytable, errorEntry)
	meta.NumEntries++
	meta.Size = entries.Size

	return entries, meta
}

func marshalMatcher(matcher iptables.Matcher) []byte {
	switch matcher.(type) {
	}

	panic(fmt.Errorf("unknown matcher: %T", matcher))
}

func marshalTarget(target iptables.Target) []byte {
	switch target.(type) {
	case iptables.UnconditionalAcceptTarget:
		return marshalUnconditionalAcceptTarget()
	}

	panic(fmt.Errorf("unknown target: %T", target))
}

func marshalUnconditionalAcceptTarget() []byte {
	// The target's name will be the empty string.
	target := linux.XTStandardTarget{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTStandardTarget,
		},
		Verdict: translateStandardVerdict(iptables.Accept),
	}

	ret := make([]byte, 0, linux.SizeOfXTStandardTarget)
	return binary.Marshal(ret, usermem.ByteOrder, target)
}

// I swear I'm not crazy, this is just how it works.
func translateStandardVerdict(verdict iptables.Verdict) int32 {
	switch verdict {
	case iptables.Accept:
		return -linux.NF_ACCEPT - 1
	case iptables.Drop:
		return -linux.NF_DROP - 1
	case iptables.Queue:
		return -linux.NF_QUEUE - 1
	case iptables.Return:
		return linux.NF_RETURN
	case iptables.Jump:
		// TODO(gvisor.dev/issue/170): Support Jump.
		panic("Jump isn't supported yet")
	}
	panic(fmt.Sprintf("unknown standard verdict: %d", verdict))
}
