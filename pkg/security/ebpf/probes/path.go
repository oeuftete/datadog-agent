// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package probes

import manager "github.com/DataDog/ebpf-manager"

// getDentryResolverTailCallRoutes is the list of routes used during the dentry resolution process
func getPathResolverTailCallRoutes() []manager.TailCallRoute {
	routes := []manager.TailCallRoute{
		// path resolver entrypoint
		//  - kprobe
		{
			ProgArrayName: "path_resolver_kprobe_progs",
			Key:           0,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_path_resolver_entrypoint",
			},
		},
		//  - tracepoint
		{
			ProgArrayName: "path_resolver_tracepoint_progs",
			Key:           0,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "tracepoint_path_resolver_entrypoint",
			},
		},
		// path resolver loop
		//  - kprobe
		{
			ProgArrayName: "path_resolver_kprobe_progs",
			Key:           1,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_path_resolver_loop",
			},
		},
		//  - tracepoint
		{
			ProgArrayName: "path_resolver_tracepoint_progs",
			Key:           1,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "tracepoint_path_resolver_loop",
			},
		},
		// exec - executable path callback
		//  - kprobe only
		{
			ProgArrayName: "path_resolver_kprobe_progs",
			Key:           2,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_handle_executable_path_cb",
			},
		},
		// exec - interpreter path callback
		//  - kprobe only
		{
			ProgArrayName: "path_resolver_kprobe_progs",
			Key:           3,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_handle_interpreter_path_cb",
			},
		},
		// mount - mountpoint path callback
		//  - kprobe
		{
			ProgArrayName: "path_resolver_kprobe_progs",
			Key:           4,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_dr_mount_callback",
			},
		},
		//  - tracepoint
		{
			ProgArrayName: "path_resolver_tracepoint_progs",
			Key:           2,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "tracepoint_dr_mount_callback",
			},
		},
		// unshare_mntns - mountpoint path callback
		//  - kprobe only
		{
			ProgArrayName: "path_resolver_kprobe_progs",
			Key:           5,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_dr_unshare_mntns_stage_one_callback",
			},
		},
	}

	return routes
}
