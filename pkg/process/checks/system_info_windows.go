// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package checks

import (
	"fmt"

	"github.com/DataDog/datadog-agent/pkg/gohai/cpu"
	"github.com/DataDog/datadog-agent/pkg/gohai/platform"

	"github.com/DataDog/datadog-agent/pkg/util/winutil"

	model "github.com/DataDog/agent-payload/v5/process"
)

// CollectSystemInfo collects a set of system-level information that will not
// change until a restart. This bit of information should be passed along with
// the process messages.
func CollectSystemInfo() (*model.SystemInfo, error) {
	hi := platform.CollectInfo()
	cpuInfo := cpu.CollectInfo()
	mi, err := winutil.VirtualMemory()
	if err != nil {
		return nil, err
	}
	physCount, err := cpuInfo.CPUPkgs.Value()
	if err != nil {
		return nil, fmt.Errorf("gohai cpuInfo.CPUPkgs: %w", err)
	}

	// logicalcount will be the total number of logical processors on the system
	// i.e. physCount * coreCount * 1 if not HT CPU
	//      physCount * coreCount * 2 if an HT CPU.
	logicalCount, _ := cpuInfo.CPULogicalProcessors.Value()

	// shouldn't be possible, as `cpuInfo.CPUPkgs.Value()` should return an error in this case
	// but double check before risking a divide by zero
	if physCount == 0 {
		return nil, fmt.Errorf("Returned zero physical processors")
	}
	logicalCountPerPhys := logicalCount / physCount
	clockSpeed, _ := cpuInfo.Mhz.Value()
	l2Cache, _ := cpuInfo.CacheSizeL2Bytes.Value()
	cpus := make([]*model.CPUInfo, 0)
	vendor, _ := cpuInfo.VendorID.Value()
	family, _ := cpuInfo.Family.Value()
	modelName, _ := cpuInfo.Model.Value()
	for i := uint64(0); i < physCount; i++ {
		cpus = append(cpus, &model.CPUInfo{
			Number:     int32(i),
			Vendor:     vendor,
			Family:     family,
			Model:      modelName,
			PhysicalId: "",
			CoreId:     "",
			Cores:      int32(logicalCountPerPhys),
			Mhz:        int64(clockSpeed),
			CacheSize:  int32(l2Cache),
		})
	}

	kernelName, _ := hi.KernelName.Value()
	osName, _ := hi.OS.Value()
	platformFamily, _ := hi.Family.Value()
	kernelRelease, _ := hi.KernelRelease.Value()
	m := &model.SystemInfo{
		Uuid: "",
		Os: &model.OSInfo{
			Name:          kernelName,
			Platform:      osName,
			Family:        platformFamily,
			Version:       kernelRelease,
			KernelVersion: "",
		},
		Cpus:        cpus,
		TotalMemory: int64(mi.Total),
	}
	return m, nil
}
