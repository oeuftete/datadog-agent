// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build shared

package tests

import (
	"fmt"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/security/security_profile/activity_tree"
	"github.com/DataDog/datadog-agent/pkg/security/security_profile/dump"
	"github.com/DataDog/datadog-agent/pkg/security/tests/shared"
	"github.com/stretchr/testify/assert"
)

type AgentInterface struct {
	name string
}

func NewAgentInterface() shared.Shared[activity_tree.ActivityTree] {
	return &AgentInterface{name: "foo"}
}

func (ai *AgentInterface) CreateEmptyTree() *activity_tree.ActivityTree {
	dump := dump.NewEmptyActivityDump(nil)
	// TODO
	return dump.ActivityTree
}

func (ai *AgentInterface) MergeTrees(tree1, tree2 *activity_tree.ActivityTree) *activity_tree.ActivityTree {
	dump := dump.NewEmptyActivityDump(nil)
	return dump.ActivityTree
}

func (ai *AgentInterface) InsertEvent(event string /*json?*/, tree *activity_tree.ActivityTree) bool {
	// TODO
	return true
}

func (ai *AgentInterface) MatchesTrees(tree *activity_tree.ActivityTree, output []*shared.ActivityTreeRepresentation) bool {
	// TODO
	return true
}

func TestShared(t *testing.T) {
	fmt.Printf("TestShared\n")
	ai := NewAgentInterface()

	for _, test := range shared.SharedTestSuite {
		fmt.Printf("test: %s\n", test.Name)
		tree := ai.CreateEmptyTree()
		assert.Equal(t, true, ai.InsertEvent(test.Input, tree))
		assert.Equal(t, true, ai.MatchesTrees(tree, test.Output))
	}

}
