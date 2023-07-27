// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !windows

package utils

import (
	"github.com/shirou/gopsutil/v3/host"

	"github.com/DataDog/datadog-agent/pkg/util/cache"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// GetInformation just returns an InfoStat object, we need some additional information that's not
func GetInformation() *host.InfoStat {
	info, _ := cache.Get[*host.InfoStat](
		cacheKey,
		func() (*host.InfoStat, error) {
			info, err := host.Info()
			if err != nil {
				log.Errorf("failed to retrieve host info: %s", err)
				return &host.InfoStat{}, err
			}
			return info, err
		})
	return info
}
