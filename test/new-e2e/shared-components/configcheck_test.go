// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package testinfradefinition

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/DataDog/datadog-agent/test/new-e2e/utils/e2e"
	"github.com/DataDog/test-infra-definitions/components/datadog/agentparams"
	"github.com/stretchr/testify/assert"
)

type agentSuite struct {
	e2e.Suite[e2e.AgentEnv]
}

func TestAgentConfigCheckSuite(t *testing.T) {
	e2e.Run(t, &agentSuite{}, e2e.AgentStackDef(nil))
}

/*
 */

type CheckConfigOutput struct {
	CheckName  string
	Filepath   string
	InstanceId string
	Settings   string
}

func MatchCheckToTemplate(checkname, input string) (*CheckConfigOutput, error) {
	regexTemplate := fmt.Sprintf("=== %s check ===\n", checkname) +
		"Configuration provider: file\n" +
		"Configuration source: (?P<filepath>.*)\n" +
		"Config for instance ID: (?P<instance>.*)\n" +
		"(?P<settings>(?:[^~]*\n)+)" + // non-capturing group to get all settings
		"~\n" +
		"==="
	re := regexp.MustCompile(regexTemplate)
	matches := re.FindStringSubmatch(input)

	// without a match, SubexpIndex lookups panic with range errors
	if len(matches) == 0 {
		return nil, fmt.Errorf("regexp: no matches for %s check", checkname)
	}

	filepathIndex := re.SubexpIndex("filepath")
	instanceIndex := re.SubexpIndex("instance")
	settingsIndex := re.SubexpIndex("settings")

	return &CheckConfigOutput{
		CheckName:  checkname,
		Filepath:   matches[filepathIndex],
		InstanceId: matches[instanceIndex],
		Settings:   fmt.Sprintf("%s", matches[settingsIndex:]), // format to string for assertion
	}, nil
}

func (v *agentSuite) TestMatchToTemplateHelper() {
	sampleCheck := `=== uptime check ===
Configuration provider: file
Configuration source: file:/etc/datadog-agent/conf.d/uptime.d/conf.yaml.default
Config for instance ID: uptime:c72f390abdefdf1a
key: value
path: http://example.com/foo
~
===

=== npt check ===
Configuration provider: file
Configuration source: file:/etc/datadog-agent/conf.d/npt.d/conf.yaml.default
Config for instance ID: npt:c72f390abdefdf1a
{}
~
===`

	result, err := MatchCheckToTemplate("uptime", sampleCheck)
	assert.NoError(v.T(), err)

	assert.Contains(v.T(), result.CheckName, "uptime")
	assert.Contains(v.T(), result.Filepath, "file:/etc/datadog-agent/conf.d/uptime.d/conf.yaml.default")
	assert.Contains(v.T(), result.InstanceId, "uptime:c72f390abdefdf1a")
	assert.Contains(v.T(), result.Settings, "key: value")
	assert.Contains(v.T(), result.Settings, "path: http://example.com/foo")
	assert.NotContains(v.T(), result.Settings, "{}")
}

// cpu, disk, file_handle, io, load, memory, network, ntp, uptime
func (v *agentSuite) TestDefaultInstalledChecks() {
	v.UpdateEnv(e2e.AgentStackDef(nil))

	testChecks := []CheckConfigOutput{
		CheckConfigOutput{
			CheckName:  "cpu",
			Filepath:   "file:/etc/datadog-agent/conf.d/cpu.d/conf.yaml.default",
			InstanceId: "cpu:",
			Settings:   "{}",
		},
		CheckConfigOutput{
			CheckName:  "disk",
			Filepath:   "file:/etc/datadog-agent/conf.d/disk.d/conf.yaml.default",
			InstanceId: "disk:",
			Settings:   "use_mount: false",
		},
		CheckConfigOutput{
			CheckName:  "file_handle",
			Filepath:   "file:/etc/datadog-agent/conf.d/file_handle.d/conf.yaml.default",
			InstanceId: "file_handle:",
			Settings:   "{}",
		},
		CheckConfigOutput{
			CheckName:  "io",
			Filepath:   "file:/etc/datadog-agent/conf.d/io.d/conf.yaml.default",
			InstanceId: "io:",
			Settings:   "{}",
		},
		CheckConfigOutput{
			CheckName:  "load",
			Filepath:   "file:/etc/datadog-agent/conf.d/load.d/conf.yaml.default",
			InstanceId: "load:",
			Settings:   "{}",
		},
		CheckConfigOutput{
			CheckName:  "memory",
			Filepath:   "file:/etc/datadog-agent/conf.d/memory.d/conf.yaml.default",
			InstanceId: "memory:",
			Settings:   "{}",
		},
		CheckConfigOutput{
			CheckName:  "network",
			Filepath:   "file:/etc/datadog-agent/conf.d/network.d/conf.yaml.default",
			InstanceId: "network:",
			Settings:   "{}",
		},
		CheckConfigOutput{
			CheckName:  "ntp",
			Filepath:   "file:/etc/datadog-agent/conf.d/ntp.d/conf.yaml.default",
			InstanceId: "ntp:",
			Settings:   "{}",
		},
		CheckConfigOutput{
			CheckName:  "uptime",
			Filepath:   "file:/etc/datadog-agent/conf.d/uptime.d/conf.yaml.default",
			InstanceId: "uptime:",
			Settings:   "{}",
		},
	}

	output := v.Env().Agent.ConfigCheck()
	fmt.Println(output)

	for _, testCheck := range testChecks {
		v.T().Run(fmt.Sprintf("default - %s test", testCheck.CheckName), func(t *testing.T) {
			result, err := MatchCheckToTemplate(testCheck.CheckName, output)
			assert.NoError(t, err)
			assert.Contains(t, result.Filepath, testCheck.Filepath)
			assert.Contains(t, result.InstanceId, testCheck.InstanceId)
			assert.Contains(t, result.Settings, testCheck.Settings)
		})
	}
}

func (v *agentSuite) TestWithBadConfigCheck() {
	config := `instances:
	- name: bad yaml formatting via tab
`
	integration := agentparams.WithIntegration("http_check.d", config)
	v.UpdateEnv(e2e.AgentStackDef(nil, integration))

	output := v.Env().Agent.ConfigCheck()
	fmt.Println(output)

	assert.Contains(v.T(), output, "http_check: yaml: line 2: found character that cannot start any token")
}

func (v *agentSuite) TestWithAddedIntegrationsCheck() {
	config := `instances:
  - name: My First Service
    url: http://some.url.example.com
`
	integration := agentparams.WithIntegration("http_check.d", config)
	v.UpdateEnv(e2e.AgentStackDef(nil, integration))

	output := v.Env().Agent.ConfigCheck()
	fmt.Println(output)

	result, err := MatchCheckToTemplate("http_check", output)
	assert.NoError(v.T(), err)
	assert.Contains(v.T(), result.Filepath, "file:/etc/datadog-agent/conf.d/http_check.d/conf.yaml")
	assert.Contains(v.T(), result.InstanceId, "http_check:")
	assert.Contains(v.T(), result.Settings, "name: My First Service")
	assert.Contains(v.T(), result.Settings, "url: http://some.url.example.com")
}
