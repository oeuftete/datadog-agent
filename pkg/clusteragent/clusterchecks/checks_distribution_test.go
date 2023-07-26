// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build clusterchecks

package clusterchecks

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddToLeastBusy(t *testing.T) {
	tests := []struct {
		name              string
		existingNodes     []string
		existingChecks    map[string]CheckStatus
		preferredNode     string
		expectedPlacement string
	}{
		{
			name:          "standard case",
			existingNodes: []string{"node1", "node2", "node3"},
			existingChecks: map[string]CheckStatus{
				"check1": {busyness: 3, node: "node1"},
				"check2": {busyness: 1, node: "node2"},
				"check3": {busyness: 2, node: "node3"},
			},
			preferredNode:     "",
			expectedPlacement: "node2",
		},
		{
			name:          "2 least busy nodes. Add to preferred",
			existingNodes: []string{"node1", "node2", "node3"},
			existingChecks: map[string]CheckStatus{
				"check1": {busyness: 3, node: "node1"},
				"check2": {busyness: 1, node: "node2"},
				"check3": {busyness: 1, node: "node3"},
			},
			preferredNode:     "node2",
			expectedPlacement: "node2",
		},
		{
			name:          "2 least busy nodes. Add to the one with less checks",
			existingNodes: []string{"node1", "node2", "node3"},
			existingChecks: map[string]CheckStatus{
				"check1": {busyness: 3, node: "node1"},
				"check2": {busyness: 2, node: "node2"},
				"check3": {busyness: 1, node: "node3"},
				"check4": {busyness: 1, node: "node3"},
			},
			preferredNode:     "",
			expectedPlacement: "node2",
		},
		{
			name:          "only one node",
			existingNodes: []string{"node1"},
			existingChecks: map[string]CheckStatus{
				"check1": {busyness: 3, node: "node1"},
			},
			preferredNode:     "",
			expectedPlacement: "node1",
		},
		{
			name:              "no nodes",
			existingNodes:     []string{},
			existingChecks:    map[string]CheckStatus{},
			preferredNode:     "",
			expectedPlacement: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			distribution := newChecksDistribution(test.existingNodes)

			for checkID, checkStatus := range test.existingChecks {
				distribution.addCheck(checkID, checkStatus.busyness, checkStatus.node)
			}

			distribution.addToLeastBusy("newCheck", 10, test.preferredNode)

			assert.Equal(t, test.expectedPlacement, distribution.nodeForCheck("newCheck"))
		})
	}
}

func TestAddCheck(t *testing.T) {
	distribution := newChecksDistribution([]string{"node1"})

	distribution.addCheck("check1", 3, "node1")
	assert.Equal(t, "node1", distribution.nodeForCheck("check1"))
	assert.Equal(t, 3, distribution.busynessForCheck("check1"))
}

func TestChecksSortedByBusyness(t *testing.T) {
	distribution := newChecksDistribution([]string{"node1", "node2", "node3"})

	distribution.addCheck("check1", 3, "node1")
	distribution.addCheck("check2", 1, "node1")
	distribution.addCheck("check3", 4, "node2")
	distribution.addCheck("check4", 2, "node3")

	assert.Equal(t, []string{"check3", "check1", "check4", "check2"}, distribution.checksSortedByBusyness())
}

func TestBusynessStdDev(t *testing.T) {
	// Define node1 with busyness of 3, node2 with 5, node3 with 8, and node4 with 0
	distribution := newChecksDistribution([]string{"node1", "node2", "node3", "node4"})
	distribution.addCheck("check1", 1, "node1")
	distribution.addCheck("check2", 2, "node1")
	distribution.addCheck("check3", 5, "node2")
	distribution.addCheck("check4", 8, "node3")

	// The avg busyness is (3+5+8+0)/4 = 4
	// The variance is ((3-4)^2 + (5-4)^2 + (8-4)^2)/3 + (0-4)^2= 34/4 = 8.5
	// The stddev is sqrt(8.5) = 2.91
	assert.InDelta(t, 2.91, distribution.busynessStdDev(), 0.05)
}
