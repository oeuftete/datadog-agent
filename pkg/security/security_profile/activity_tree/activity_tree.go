// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package activity_tree

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/DataDog/datadog-go/v5/statsd"
	"golang.org/x/sys/unix"

	"github.com/DataDog/datadog-agent/pkg/security/resolvers"
	"github.com/DataDog/datadog-agent/pkg/security/resolvers/process"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
)

// NodeDroppedReason is used to list the reasons to drop a node
type NodeDroppedReason string

var (
	eventTypeReason       NodeDroppedReason = "event_type"
	invalidRootNodeReason NodeDroppedReason = "invalid_root_node"
	bindFamilyReason      NodeDroppedReason = "bind_family"
	brokenEventReason     NodeDroppedReason = "broken_event"
	allDropReasons                          = []NodeDroppedReason{
		eventTypeReason,
		invalidRootNodeReason,
		bindFamilyReason,
		brokenEventReason,
	}
)

var (
	// ErrBrokenLineage is returned when the given process don't have a full lineage
	ErrBrokenLineage = errors.New("broken lineage")
	// ErrContainerIDNotEqual is returnet when the given process don't have the same container ID as the tree
	ErrContainerIDNotEqual = errors.New("ContainerIDs are different")
	// ErrNotValidRootNode is returned when trying to insert a process with an invalide root node
	ErrNotValidRootNode = errors.New("root node not valid")
)

// NodeGenerationType is used to indicate if a node was generated by a runtime or snapshot event
// IMPORTANT: IT MUST STAY IN SYNC WITH `adproto.GenerationType`
type NodeGenerationType byte

const (
	// Unknown is a node that was added at an unknown time
	Unknown NodeGenerationType = 0
	// Runtime is a node that was added at runtime
	Runtime NodeGenerationType = 1
	// Snapshot is a node that was added during the snapshot
	Snapshot NodeGenerationType = 2
	// ProfileDrift is a node that was added because of a drift from a security profile
	ProfileDrift NodeGenerationType = 3
	// WorkloadWarmup is a node that was added of a drift in a warming up profile
	WorkloadWarmup NodeGenerationType = 4
	// MaxNodeGenerationType is the maximum node type
	MaxNodeGenerationType NodeGenerationType = 4
)

func (genType NodeGenerationType) String() string {
	switch genType {
	case Runtime:
		return "runtime"
	case Snapshot:
		return "snapshot"
	case ProfileDrift:
		return "profile_drift"
	case WorkloadWarmup:
		return "workload_warmup"
	default:
		return "unknown"
	}
}

// ActivityTreeOwner is used to communicate with the owner of the activity tree
type ActivityTreeOwner interface {
	MatchesSelector(entry *model.ProcessCacheEntry) bool
	IsEventTypeValid(evtType model.EventType) bool
	NewProcessNodeCallback(p *ProcessNode)
}

type cookieSelector struct {
	execTime int64
	cookie   uint32
}

func (cs *cookieSelector) isSet() bool {
	return cs.execTime != 0 && cs.cookie != 0
}

// ActivityTree contains a process tree and its activities. This structure has no locks.
type ActivityTree struct {
	Stats *ActivityTreeStats

	treeType          string
	differentiateArgs bool
	DNSMatchMaxDepth  int

	validator    ActivityTreeOwner
	pathsReducer *PathsReducer

	CookieToProcessNode map[cookieSelector]*ProcessNode
	ProcessNodes        []*ProcessNode `json:"-"`

	// top level lists used to summarize the content of the tree
	DNSNames     *utils.StringKeys
	SyscallsMask map[int]int
}

// NewActivityTree returns a new ActivityTree instance
func NewActivityTree(validator ActivityTreeOwner, pathsReducer *PathsReducer, treeType string) *ActivityTree {
	at := &ActivityTree{
		treeType:            treeType,
		validator:           validator,
		pathsReducer:        pathsReducer,
		Stats:               NewActivityTreeNodeStats(),
		CookieToProcessNode: make(map[cookieSelector]*ProcessNode),
		SyscallsMask:        make(map[int]int),
		DNSNames:            utils.NewStringKeys(nil),
	}
	return at
}

// ComputeSyscallsList computes the top level list of syscalls
func (at *ActivityTree) ComputeSyscallsList() []uint32 {
	output := make([]uint32, 0, len(at.SyscallsMask))
	for key := range at.SyscallsMask {
		output = append(output, uint32(key))
	}
	sort.Slice(output, func(i, j int) bool {
		return output[i] < output[j]
	})
	return output
}

// ComputeActivityTreeStats computes the initial counts of the activity tree stats
func (at *ActivityTree) ComputeActivityTreeStats() {
	pnodes := at.ProcessNodes
	var fnodes []*FileNode

	for len(pnodes) > 0 {
		node := pnodes[0]

		at.Stats.ProcessNodes += 1
		pnodes = append(pnodes, node.Children...)

		at.Stats.DNSNodes += int64(len(node.DNSNames))
		at.Stats.SocketNodes += int64(len(node.Sockets))

		for _, f := range node.Files {
			fnodes = append(fnodes, f)
		}

		pnodes = pnodes[1:]
	}

	for len(fnodes) > 0 {
		node := fnodes[0]

		if node.File != nil {
			at.Stats.FileNodes += 1
		}

		for _, f := range node.Children {
			fnodes = append(fnodes, f)
		}

		fnodes = fnodes[1:]
	}
}

// IsEmpty returns true if the tree is empty
func (at *ActivityTree) IsEmpty() bool {
	return len(at.ProcessNodes) == 0
}

// nolint: unused
func (at *ActivityTree) Debug(w io.Writer) {
	for _, root := range at.ProcessNodes {
		root.debug(w, "")
	}
}

// ScrubProcessArgsEnvs scrubs and retains process args and envs
func (at *ActivityTree) ScrubProcessArgsEnvs(resolver *process.Resolver) {
	// iterate through all the process nodes
	openList := make([]*ProcessNode, len(at.ProcessNodes))
	copy(openList, at.ProcessNodes)

	for len(openList) != 0 {
		current := openList[len(openList)-1]
		current.scrubAndReleaseArgsEnvs(resolver)
		openList = append(openList[:len(openList)-1], current.Children...)
	}
}

// DifferentiateArgs enables the args differentiation feature
func (at *ActivityTree) DifferentiateArgs() {
	at.differentiateArgs = true
}

// isEventValid evaluates if the provided event is valid
func (at *ActivityTree) isEventValid(event *model.Event, dryRun bool) (bool, error) {
	// check event type
	if !at.validator.IsEventTypeValid(event.GetEventType()) {
		if !dryRun {
			at.Stats.droppedCount[event.GetEventType()][eventTypeReason].Inc()
		}
		return false, fmt.Errorf("event type not valid: %s", event.GetEventType())
	}

	// event specific filtering
	switch event.GetEventType() {
	case model.BindEventType:
		// ignore non IPv4 / IPv6 bind events for now
		if event.Bind.AddrFamily != unix.AF_INET && event.Bind.AddrFamily != unix.AF_INET6 {
			if !dryRun {
				at.Stats.droppedCount[model.BindEventType][bindFamilyReason].Inc()
			}
			return false, fmt.Errorf("invalid bind family")
		}
	}
	return true, nil
}

// Insert inserts the event in the activity tree
func (at *ActivityTree) Insert(event *model.Event, generationType NodeGenerationType, resolvers *resolvers.Resolvers) (bool, error) {
	newEntry, err := at.insert(event, false, generationType, resolvers)
	if newEntry {
		// this doesn't count the exec events which are counted separately
		at.Stats.addedCount[event.GetEventType()][generationType].Inc()
	}
	return newEntry, err
}

// Contains looks up the event in the activity tree
func (at *ActivityTree) Contains(event *model.Event, generationType NodeGenerationType, resolvers *resolvers.Resolvers) (bool, error) {
	newEntry, err := at.insert(event, true, generationType, resolvers)
	return !newEntry, err
}

// insert inserts the event in the activity tree, returns true if the event generated a new entry in the tree
func (at *ActivityTree) insert(event *model.Event, dryRun bool, generationType NodeGenerationType, resolvers *resolvers.Resolvers) (bool, error) {
	// sanity check
	if generationType == Unknown || generationType > MaxNodeGenerationType {
		return false, fmt.Errorf("invalid generation type: %v", generationType)
	}

	// check if this event type is traced
	if valid, err := at.isEventValid(event, dryRun); !valid || err != nil {
		return false, fmt.Errorf("invalid event: %s", err)
	}

	node, newProcessNode, err := at.CreateProcessNode(event.ProcessCacheEntry, nil, generationType, dryRun, resolvers)
	if err != nil {
		return false, err
	}
	if newProcessNode && dryRun {
		return true, nil
	}
	if node == nil {
		// a process node couldn't be found or created for this event, ignore it
		return false, errors.New("a process node couldn't be found or created for this event")
	}

	// resolve fields
	event.ResolveFieldsForAD()

	// ignore events with an error
	if event.Error != nil {
		at.Stats.droppedCount[event.GetEventType()][brokenEventReason].Inc()
		return false, event.Error
	}

	// the count of processed events is the count of events that matched the activity dump selector = the events for
	// which we successfully found a process activity node
	at.Stats.processedCount[event.GetEventType()].Inc()

	// insert the event based on its type
	switch event.GetEventType() {
	case model.ExecEventType:
		// tag the matched rules if any
		node.MatchedRules = model.AppendMatchedRule(node.MatchedRules, event.Rules)
		return newProcessNode, nil
	case model.FileOpenEventType:
		return node.InsertFileEvent(&event.Open.File, event, generationType, at.Stats, dryRun, at.pathsReducer, resolvers), nil
	case model.DNSEventType:
		return node.InsertDNSEvent(event, generationType, at.Stats, at.DNSNames, dryRun, at.DNSMatchMaxDepth), nil
	case model.BindEventType:
		return node.InsertBindEvent(event, generationType, at.Stats, dryRun), nil
	case model.SyscallsEventType:
		return node.InsertSyscalls(event, at.SyscallsMask), nil
	case model.ExitEventType:
		// Update the exit time of the process (this is purely informative, do not rely on timestamps to detect
		// execed children)
		node.Process.ExitTime = event.Timestamp
	}

	return false, nil
}

func isContainerRuntimePrefix(basename string) bool {
	return strings.HasPrefix(basename, "runc") || strings.HasPrefix(basename, "containerd-shim")
}

// isValidRootNode evaluates if the provided process entry is allowed to become a root node of an Activity Dump
func isValidRootNode(entry *model.ProcessContext) bool {
	// an ancestor is required
	ancestor := GetNextAncestorBinaryOrArgv0(entry)
	if ancestor == nil {
		return false
	}

	if entry.FileEvent.IsFileless() {
		// a fileless node is a valid root node only if not having runc as parent
		// ex: runc -> exec(fileless) -> init.sh; exec(fileless) is not a valid root node
		return !(isContainerRuntimePrefix(ancestor.FileEvent.BasenameStr) || isContainerRuntimePrefix(entry.FileEvent.BasenameStr))
	}

	// container runtime prefixes are not valid root nodes
	return !isContainerRuntimePrefix(entry.FileEvent.BasenameStr)
}

// GetNextAncestorBinaryOrArgv0 returns the first ancestor with a different binary, or a different argv0 in the case of busybox processes
func GetNextAncestorBinaryOrArgv0(entry *model.ProcessContext) *model.ProcessCacheEntry {
	if entry == nil {
		return nil
	}
	current := entry
	ancestor := entry.Ancestor
	for ancestor != nil {
		if ancestor.FileEvent.Inode == 0 {
			return nil
		}
		if current.FileEvent.Inode != ancestor.FileEvent.Inode {
			return ancestor
		}
		if process.IsBusybox(current.FileEvent.PathnameStr) && process.IsBusybox(ancestor.FileEvent.PathnameStr) {
			currentArgv0, _ := process.GetProcessArgv0(&current.Process)
			if len(currentArgv0) == 0 {
				return nil
			}
			ancestorArgv0, _ := process.GetProcessArgv0(&ancestor.Process)
			if len(ancestorArgv0) == 0 {
				return nil
			}
			if currentArgv0 != ancestorArgv0 {
				return ancestor
			}
		}
		current = &ancestor.ProcessContext
		ancestor = ancestor.Ancestor
	}
	return nil
}

func eventHaveValidCookie(entry *model.ProcessCacheEntry) bool {
	return !entry.ExecTime.IsZero() && entry.Cookie != 0
}

// CreateProcessNode finds or a create a new process activity node in the activity dump if the entry
// matches the activity dump selector.
func (at *ActivityTree) CreateProcessNode(entry *model.ProcessCacheEntry, branch []*model.ProcessCacheEntry, generationType NodeGenerationType, dryRun bool, resolvers *resolvers.Resolvers) (node *ProcessNode, newProcessNode bool, err error) {
	if entry == nil {
		return nil, false, nil
	}

	if !entry.HasCompleteLineage() {
		return nil, false, ErrBrokenLineage
	}

	// look for a ProcessActivityNode by process cookie
	cs := cookieSelector{}
	if eventHaveValidCookie(entry) {
		cs = cookieSelector{
			execTime: entry.ExecTime.UnixNano(),
			cookie:   entry.Cookie,
		}
		var found bool
		node, found = at.CookieToProcessNode[cs]
		if found {
			return node, false, nil
		}
	}

	defer func() {
		// if a node was found, and if the entry has a valid cookie, insert a cookie shortcut
		if cs.isSet() && node != nil {
			at.CookieToProcessNode[cs] = node
		}
	}()

	branch = append([]*model.ProcessCacheEntry{entry}, branch...)

	// find or create a ProcessActivityNode for the parent of the input ProcessCacheEntry. If the parent is a fork entry,
	// jump immediately to the next ancestor.
	parentNode, newProcessNode, err := at.CreateProcessNode(GetNextAncestorBinaryOrArgv0(&entry.ProcessContext), branch, Snapshot, dryRun, resolvers)
	if err == nil && newProcessNode && dryRun {
		// Explanation of (newProcessNode && dryRun): when dryRun is on, we can return as soon as we
		// see something new in the tree.
		return parentNode, newProcessNode, err
	}

	// if parentNode is nil, the parent of the current node is out of tree (either because the parent is null, or it
	// doesn't match the dump tags).
	if parentNode == nil {

		// since the parent of the current entry wasn't inserted, we need to know if the current entry needs to be inserted.
		if !at.validator.MatchesSelector(entry) {
			return nil, false, ErrContainerIDNotEqual
		}

		// go through the root nodes and check if one of them matches the input ProcessCacheEntry:
		if branchRoot, newChildNode := at.findBranchInChildrenNodes(&at.ProcessNodes, branch, dryRun, generationType, resolvers); branchRoot != nil {
			return branchRoot, newChildNode, nil
		}

		// we're about to add a root process node, make sure this root node passes the root node sanitizer
		if !isValidRootNode(&entry.ProcessContext) {
			return nil, false, ErrNotValidRootNode
		}

		// if it doesn't, create a new ProcessActivityNode for the input ProcessCacheEntry
		if !dryRun {
			node = NewProcessNode(entry, generationType, resolvers)
			// insert in the list of root entries
			at.ProcessNodes = append(at.ProcessNodes, node)
			at.Stats.ProcessNodes++
		}

	} else {
		// if parentNode wasn't nil, then (at least) the parent is part of the activity dump. This means that we need
		// to add the current entry no matter if it matches the selector or not. Go through the root children of the
		// parent node and check if one of them matches the input ProcessCacheEntry.
		branchRoot, newChildNode := at.findBranchInChildrenNodes(&parentNode.Children, branch, dryRun, generationType, resolvers)
		if branchRoot != nil {
			return branchRoot, newChildNode || newProcessNode, nil
		}

		// we haven't found anything, create a new ProcessActivityNode for the input processCacheEntry
		if !dryRun {
			node = NewProcessNode(entry, generationType, resolvers)
			// insert in the list of children
			parentNode.Children = append(parentNode.Children, node)
			at.Stats.ProcessNodes++
		}
	}

	// count new entry
	if !dryRun {
		at.Stats.addedCount[model.ExecEventType][generationType].Inc()
		// propagate the entry matching process cache entry
		at.validator.NewProcessNodeCallback(node)
	}

	return node, true, nil
}

// findBranchInChildrenNodes looks for the provided branch in the list of children. Returns the node that matches the
// first node of the branch and true if a new entry was inserted.
func (at *ActivityTree) findBranchInChildrenNodes(tree *[]*ProcessNode, branch []*model.ProcessCacheEntry, dryRun bool, generationType NodeGenerationType, resolvers *resolvers.Resolvers) (*ProcessNode, bool) {
	for i, branchCursor := range branch {

		// look for branchCursor in the tree
		treeNodeToRebase, treeNodeToRebaseIndex := at.findProcessCacheEntryInChildrenNodes(tree, branchCursor)

		// if found, append the input process sequence and rebase the tree
		if treeNodeToRebase != nil {
			// if this is the first iteration, we've just identified a direct match without looking for execs, return now
			if i == 0 {
				return treeNodeToRebase, false
			}

			// we're about to rebase part of the tree, exit early if this is a dry run
			if dryRun {
				return nil, true
			}

			// here is the current state of the tree:
			//   parentNode (owner of tree) -> treeNodeToRebase -> [...] -> an existing node that matched children[i]
			// here is what we want:
			//   parentNode (owner of tree) -> children[0] -> children[i-1] -> treeNodeToRebase

			// start by appending the entry
			newNodesRoot := NewProcessNode(branch[0], generationType, resolvers)
			*tree = append(*tree, newNodesRoot)
			at.Stats.ProcessNodes++
			at.Stats.addedCount[model.ExecEventType][generationType].Inc()

			// now add the children
			childrenCursor := newNodesRoot
			for _, eventExecChildTmp := range branch[1:i] {
				n := NewProcessNode(eventExecChildTmp, generationType, resolvers)
				childrenCursor.Children = append(childrenCursor.Children, n)
				at.Stats.ProcessNodes++
				at.Stats.addedCount[model.ExecEventType][generationType].Inc()

				childrenCursor = n
			}

			// attach the head of  to the last newly inserted child
			childrenCursor.Children = append(childrenCursor.Children, (*tree)[treeNodeToRebaseIndex])
			// rebase the tree, break the link between parent and treeNodeToRebase
			*tree = append((*tree)[0:treeNodeToRebaseIndex], (*tree)[treeNodeToRebaseIndex+1:]...)

			// now that the tree is ready, call the validator on the first node
			at.validator.NewProcessNodeCallback(newNodesRoot)

			// we need to return the node that matched `entry`
			return newNodesRoot, true
		} else {
			// We didn't find the current entry anywhere, has it execed into something else ? (i.e. are we missing something
			// in the profile ?)
			if i+1 < len(branch) {
				if branch[i+1].IsExecChild() {
					continue
				}
			}

			// if we're here, we've either reached the end of the list of children, or the next child wasn't
			// directly exec-ed
			break
		}
	}
	return nil, false
}

// findProcessCacheEntryInChildrenNodes looks for the provided entry in the list of process nodes, returns the node (if
// found) and the index of the top level child that lead to the node (if found) and its index (or -1 if not found).
func (at *ActivityTree) findProcessCacheEntryInChildrenNodes(tree *[]*ProcessNode, entry *model.ProcessCacheEntry) (*ProcessNode, int) {
	for i, child := range *tree {
		if child.Matches(&entry.Process, at.differentiateArgs) {
			return child, i
		}

		// has the parent execed into one of its own children ?
		if execChild := at.findProcessCacheEntryInChildExecedNodes(child, entry); execChild != nil {
			return execChild, i
		}
	}
	return nil, -1
}

// findProcessCacheEntryInChildExecedNodes look for entry in the execed nodes of child
func (at *ActivityTree) findProcessCacheEntryInChildExecedNodes(child *ProcessNode, entry *model.ProcessCacheEntry) *ProcessNode {
	// children is used to iterate over the tree below child
	execChildren := []*ProcessNode{child}

	for len(execChildren) > 0 {
		cursor := execChildren[0]
		execChildren = execChildren[1:]

		// look for an execed child
		for _, node := range cursor.Children {
			if node.IsExecChild {
				// there should always be only one
				execChildren = append(execChildren, node)
			}
		}

		if len(execChildren) == 0 {
			break
		}

		// does this execed child match the entry ?
		if execChildren[0].Matches(&entry.Process, at.differentiateArgs) {
			return execChildren[0]
		}
	}

	// not found
	return nil
}

func (at *ActivityTree) FindMatchingRootNodes(arg0 string) []*ProcessNode {
	var res []*ProcessNode
	for _, node := range at.ProcessNodes {
		if node.Process.Argv0 == arg0 {
			res = append(res, node)
		}
	}
	return res
}

// Snapshot uses procfs to snapshot the nodes of the tree
func (at *ActivityTree) Snapshot(newEvent func() *model.Event) {
	for _, pn := range at.ProcessNodes {
		pn.snapshot(at.validator, at.Stats, newEvent, at.pathsReducer)
		// iterate slowly
		time.Sleep(50 * time.Millisecond)
	}
}

// SendStats sends the tree statistics
func (at *ActivityTree) SendStats(client statsd.ClientInterface) error {
	return at.Stats.SendStats(client, at.treeType)
}
