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
		// open callback
		//  - kprobe
		{
			ProgArrayName: "path_resolver_kprobe_progs",
			Key:           2,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_dr_open_callback",
			},
		},
		//  - tracepoint
		{
			ProgArrayName: "path_resolver_tracepoint_progs",
			Key:           2,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "tracepoint_dr_open_callback",
			},
		},
		// mkdir callback
		//  - kprobe
		{
			ProgArrayName: "path_resolver_kprobe_progs",
			Key:           3,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_dr_mkdir_callback",
			},
		},
		//  - tracepoint
		{
			ProgArrayName: "path_resolver_tracepoint_progs",
			Key:           3,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "tracepoint_dr_mkdir_callback",
			},
		},
		// mount callback
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
			Key:           4,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "tracepoint_dr_mount_callback",
			},
		},
		// link dst callback
		//  - kprobe
		{
			ProgArrayName: "path_resolver_kprobe_progs",
			Key:           5,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_dr_link_dst_callback",
			},
		},
		//  - tracepoint
		{
			ProgArrayName: "path_resolver_tracepoint_progs",
			Key:           5,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "tracepoint_dr_link_dst_callback",
			},
		},
		// rename dst callback
		//  - kprobe
		{
			ProgArrayName: "path_resolver_kprobe_progs",
			Key:           6,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_dr_rename_callback",
			},
		},
		//  - tracepoint
		{
			ProgArrayName: "path_resolver_tracepoint_progs",
			Key:           6,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "tracepoint_dr_rename_callback",
			},
		},
		// exec - executable callback
		//  - kprobe only
		{
			ProgArrayName: "path_resolver_kprobe_progs",
			Key:           7,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_handle_executable_path_cb",
			},
		},
		// exec - interpreter callback
		//  - kprobe only
		{
			ProgArrayName: "path_resolver_kprobe_progs",
			Key:           8,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_handle_interpreter_path_cb",
			},
		},
		// link src callback
		//  - kprobe only
		{
			ProgArrayName: "path_resolver_kprobe_progs",
			Key:           9,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_dr_link_src_callback",
			},
		},
		// rename src callback
		//  - kprobe only
		{
			ProgArrayName: "path_resolver_kprobe_progs",
			Key:           10,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_dr_rename_src_callback",
			},
		},
		// rmdir callback
		//  - kprobe only
		{
			ProgArrayName: "path_resolver_kprobe_progs",
			Key:           11,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_dr_security_inode_rmdir_callback",
			},
		},
		// selinux callback
		//  - kprobe only
		{
			ProgArrayName: "path_resolver_kprobe_progs",
			Key:           12,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_dr_selinux_callback",
			},
		},
	}

	return routes
}
