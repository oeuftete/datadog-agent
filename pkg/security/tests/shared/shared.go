// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build shared

package shared

//
// INTERFACE
//

type ActivityTreeRepresentation struct {
	Name   string
	Childs []ActivityTreeRepresentation
}

type Shared[T any] interface {
	CreateEmptyTree() *T
	MergeTrees(tree1 *T, tree2 *T) *T
	InsertEvent(event string /*json?*/, tree *T) bool
	MatchesTrees(tree *T, output []*ActivityTreeRepresentation) bool
}

//
// TESTS DEFINITION
//

/*
   test definitions should be of three kinds:
   - merge trees: tree + tree == tree
   - insert nodes: tree + node == tree
   - detect anomalies: tree + event == true|false
*/

// INSERT NODES TESTS

type SharedTest struct {
	Name   string
	Input  string // JSON
	Output []*ActivityTreeRepresentation
}

var SharedTestSuite = []SharedTest{
	{
		Name:  "test1",
		Input: "fake imput", // activity tree OR anomaly event
		Output: []*ActivityTreeRepresentation{
			{
				Name: "systemd",
				Childs: []ActivityTreeRepresentation{
					{
						Name: "foo",
						Childs: []ActivityTreeRepresentation{
							{
								Name: "bar",
							},
						},
					},
				},
			},
		},
	},
}
