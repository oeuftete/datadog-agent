// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021-present Datadog, Inc.
//go:build windows
// +build windows

package probe

/*
#cgo LDFLAGS: -l dbgeng -static
#include "crashdump.h"
*/
import "C"
import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type logCallbackContext struct {
	loglines       []string
	hasSeenRetAddr bool
	unfinished     string
}

const maxscan = int(200)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

const (
	bugcheckCodePrefix     = "Bugcheck code"
	debugSessionTimePrefix = "Debug session time"
)

//export logLineCallback
func logLineCallback(voidctx C.PVOID, str C.PCSTR) {
	var ctx *logCallbackContext
	ctx = (*logCallbackContext)(unsafe.Pointer(uintptr(voidctx)))
	line := C.GoString(str)
	if !strings.Contains(line, "\n") {
		ctx.unfinished = ctx.unfinished + line
		return
	}
	if len(ctx.unfinished) != 0 {
		line = ctx.unfinished + line
		ctx.unfinished = ""
	}
	lines := strings.Split(line, "\n")
	start := int(0)
	if !ctx.hasSeenRetAddr {
		for idx, l := range lines {
			if strings.HasPrefix(l, bugcheckCodePrefix) {
				ctx.loglines = append(ctx.loglines, l)
				return
			}
			if strings.HasPrefix(l, debugSessionTimePrefix) {
				ctx.loglines = append(ctx.loglines, l)
				return
			}
			if strings.HasPrefix(l, "RetAddr") {
				ctx.hasSeenRetAddr = true
				start = idx
			}
		}
		if !ctx.hasSeenRetAddr {
			return
		}

	}
	ctx.loglines = append(ctx.loglines, lines[start:]...)
}
func parseCrashDump(wcs *WinCrashStatus) {
	var ctx logCallbackContext
	var extendedError uint32

	err := C.readCrashDump(C.CString(wcs.FileName), unsafe.Pointer(&ctx), (*C.long)(unsafe.Pointer(&extendedError)))

	if err != C.RCD_NONE {
		wcs.Success = false
		wcs.ErrString = fmt.Sprintf("Failed to load crash dump file %d %x", int(err), extendedError)
		log.Errorf("Failed to open crash dump %s: %d %x", wcs.FileName, int(err), extendedError)
		return
	}

	if len(ctx.loglines) < 2 {
		wcs.ErrString = fmt.Sprintf("Invalid crash dump file %s", wcs.FileName)
		wcs.Success = false
		return
	}

	end := min(len(ctx.loglines)-1, maxscan)
	for _, line := range ctx.loglines[:end] {
		// skip lines that start with RetAddr, that's just the header
		if strings.HasPrefix(line, debugSessionTimePrefix) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				wcs.DateString = strings.TrimSpace(parts[1])
			}
			continue
		}

		if strings.HasPrefix(line, bugcheckCodePrefix) {
			codeAsString := strings.TrimSpace(line[len(bugcheckCodePrefix)+1:])
			wcs.BugCheck = codeAsString
			continue
		}
		if strings.HasPrefix(line, "RetAddr") {
			continue
		}
		if strings.HasPrefix(line, "Unable to") { // "Unable to load image, which is ok
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			continue
		}
		callsite := strings.TrimSpace(parts[2])
		if strings.HasPrefix(callsite, "nt!") {
			// we're still in ntoskernel, keep looking
			continue
		}
		wcs.Offender = callsite
		break
	}
	wcs.Success = true
	return
}
