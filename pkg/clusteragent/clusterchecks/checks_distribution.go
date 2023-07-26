// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build clusterchecks

package clusterchecks

import (
	"math"
	"sort"
)

type CheckStatus struct {
	busyness int
	node     string
}

type NodeStatus struct {
	busyness  int
	numChecks int
}

// checksDistribution represents the placement of cluster checks across the
// different nodes of a cluster
type checksDistribution struct {
	checks map[string]*CheckStatus
	nodes  map[string]*NodeStatus
}

func newChecksDistribution(nodeNames []string) checksDistribution {
	nodes := map[string]*NodeStatus{}
	for _, nodeName := range nodeNames {
		nodes[nodeName] = &NodeStatus{
			busyness:  0,
			numChecks: 0,
		}
	}

	return checksDistribution{
		checks: map[string]*CheckStatus{},
		nodes:  nodes,
	}
}

func (distribution *checksDistribution) leastBusyNode(preferredNode string) string {
	leastBusyNode := ""
	minBusyness := 0
	numChecksLeastBusyNode := 0

	for nodeName, nodeStatus := range distribution.nodes {
		nodeBusyness := nodeStatus.busyness
		nodeNumChecks := nodeStatus.numChecks

		selectNode := leastBusyNode == "" ||
			nodeBusyness < minBusyness ||
			nodeBusyness == minBusyness && nodeName == preferredNode ||
			nodeBusyness == minBusyness && nodeNumChecks < numChecksLeastBusyNode

		if selectNode {
			leastBusyNode = nodeName
			minBusyness = nodeBusyness
			numChecksLeastBusyNode = nodeNumChecks
		}
	}

	return leastBusyNode
}

// Note: if there are several nodes with the same busyness and preferredNode is among them, add the check to it.
func (distribution *checksDistribution) addToLeastBusy(checkID string, checkBusyness int, preferredNode string) {
	leastBusy := distribution.leastBusyNode(preferredNode)
	if leastBusy == "" {
		return
	}

	distribution.addCheck(checkID, checkBusyness, leastBusy)
}

func (distribution *checksDistribution) addCheck(checkID string, checkBusyness int, node string) {
	distribution.checks[checkID] = &CheckStatus{
		busyness: checkBusyness,
		node:     node,
	}

	nodeInfo, nodeExists := distribution.nodes[node]
	if nodeExists {
		nodeInfo.busyness += checkBusyness
		nodeInfo.numChecks += 1
	} else {
		distribution.nodes[node] = &NodeStatus{
			busyness:  checkBusyness,
			numChecks: 1,
		}
	}
}

func (distribution *checksDistribution) nodeNames() []string {
	var res []string

	for nodeName := range distribution.nodes {
		res = append(res, nodeName)
	}

	return res
}

func (distribution *checksDistribution) nodeForCheck(checkID string) string {
	if checkInfo, found := distribution.checks[checkID]; found {
		return checkInfo.node
	}

	return ""
}

func (distribution *checksDistribution) busynessForCheck(checkID string) int {
	if checkInfo, found := distribution.checks[checkID]; found {
		return checkInfo.busyness
	}

	return 0
}

func (distribution *checksDistribution) checksSortedByBusyness() []string {
	var checks []struct {
		checkID  string
		busyness int
	}

	for checkID, checkStatus := range distribution.checks {
		checks = append(checks, struct {
			checkID  string
			busyness int
		}{
			checkID:  checkID,
			busyness: checkStatus.busyness,
		})
	}

	sort.Slice(checks, func(i, j int) bool {
		return checks[i].busyness > checks[j].busyness
	})

	var res []string
	for _, check := range checks {
		res = append(res, check.checkID)
	}
	return res
}

func (distribution *checksDistribution) busynessStdDev() float64 {
	totalBusyness := 0
	for _, nodeStatus := range distribution.nodes {
		totalBusyness += nodeStatus.busyness
	}

	meanBusyness := float64(totalBusyness) / float64(len(distribution.nodes))

	sumSquaredDeviations := 0.0
	for _, nodeStatus := range distribution.nodes {
		sumSquaredDeviations += math.Pow(float64(nodeStatus.busyness)-meanBusyness, 2)
	}

	variance := sumSquaredDeviations / float64(len(distribution.nodes))

	return math.Sqrt(variance)
}
