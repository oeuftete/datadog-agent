// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Portions of this code are taken from the gopsutil project
// https://github.com/shirou/gopsutil .  This code is licensed under the New BSD License
// copyright WAKAYAMA Shirou, and the gopsutil contributors

package host

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/w32"
	"golang.org/x/sys/windows"

	hostMetadataUtils "github.com/DataDog/datadog-agent/comp/metadata/host/utils"
	"github.com/DataDog/datadog-agent/pkg/gohai/cpu"
	"github.com/DataDog/datadog-agent/pkg/gohai/platform"
	"github.com/DataDog/datadog-agent/pkg/metadata/common"
	"github.com/DataDog/datadog-agent/pkg/metadata/inventories"
	"github.com/DataDog/datadog-agent/pkg/util/cache"
	"github.com/DataDog/datadog-agent/pkg/util/winutil"
)

// Set the OS to "win32" instead of the runtime.GOOS of "windows" for the in app icon
const osName = "win32"

// Collect at init time
var cpuInfo []hostMetadataUtils.InfoStat

// InitHostMetadata initializes necessary CPU info
func InitHostMetadata() error {
	var err error
	info := hostMetadataUtils.GetInformation()
	cpuInfo = append(cpuInfo, *info)

	return err
}

func getSystemStats() *systemStats {
	var stats *systemStats
	key := buildKey("systemStats")
	if x, found := cache.Cache.Get(key); found {
		stats = x.(*systemStats)
	} else {
		cpuInfo := cpu.CollectInfo()
		cores := cpuInfo.CPUCores.ValueOrDefault()
		c32 := int32(cores)
		modelName := cpuInfo.ModelName.ValueOrDefault()

		stats = &systemStats{
			Machine:   runtime.GOARCH,
			Platform:  runtime.GOOS,
			Processor: modelName,
			CPUCores:  c32,
			Pythonv:   strings.Split(GetPythonVersion(), " ")[0],
		}

		// fill the platform dependent bits of info
		hostInfo := hostMetadataUtils.GetInformation()
		stats.Winver = osVersion{hostInfo.Platform, hostInfo.PlatformVersion}
		cache.Cache.Set(key, stats, cache.NoExpiration)

		hostVersion := strings.Trim(hostInfo.Platform+" "+hostInfo.PlatformVersion, " ")
		inventories.SetHostMetadata(inventories.HostOSVersion, hostVersion)
	}

	return stats
}
