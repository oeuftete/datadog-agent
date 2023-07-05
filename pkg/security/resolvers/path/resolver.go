// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package path

import (
	"errors"
	"fmt"
	"hash"
	"hash/fnv"
	"math"
	"path"
	"strings"
	"syscall"

	"github.com/DataDog/datadog-go/v5/statsd"
	"go.uber.org/atomic"

	"github.com/DataDog/datadog-agent/pkg/security/metrics"
	"github.com/DataDog/datadog-agent/pkg/security/probe/managerhelper"
	"github.com/DataDog/datadog-agent/pkg/security/resolvers/dentry"
	"github.com/DataDog/datadog-agent/pkg/security/resolvers/mount"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
	manager "github.com/DataDog/ebpf-manager"
	"golang.org/x/sys/unix"
)

type ResolverInterface interface {
	ResolveBasename(e *model.FileFields) string
	ResolveFileFieldsPath(e *model.FileFields, pidCtx *model.PIDContext, ctrCtx *model.ContainerContext) (string, error)
	SetMountRoot(ev *model.Event, e *model.Mount) error
	ResolveMountRoot(ev *model.Event, e *model.Mount) (string, error)
	SetMountPoint(ev *model.Event, e *model.Mount) error
	ResolveMountPoint(ev *model.Event, e *model.Mount) (string, error)
	SendStats() error
	Start(*manager.Manager) error
	Close() error
}

// NoResolver returns an empty resolver
type NoResolver struct {
}

// ResolveBasename resolves an inode/mount ID pair to a file basename
func (n *NoResolver) ResolveBasename(e *model.FileFields) string {
	return ""
}

// ResolveFileFieldsPath resolves an inode/mount ID pair to a full path
func (n *NoResolver) ResolveFileFieldsPath(e *model.FileFields, pidCtx *model.PIDContext, ctrCtx *model.ContainerContext) (string, error) {
	return "", nil
}

// SetMountRoot set the mount point information
func (n *NoResolver) SetMountRoot(ev *model.Event, e *model.Mount) error {
	return nil
}

// ResolveMountRoot resolves the mountpoint to a full path
func (n *NoResolver) ResolveMountRoot(ev *model.Event, e *model.Mount) (string, error) {
	return "", nil
}

// SetMountPoint set the mount point information
func (n *NoResolver) SetMountPoint(ev *model.Event, e *model.Mount) error {
	return nil
}

// ResolveMountPoint resolves the mountpoint to a full path
func (n *NoResolver) ResolveMountPoint(ev *model.Event, e *model.Mount) (string, error) {
	return "", nil
}

func (n *NoResolver) SendStats() error {
	return nil
}

func (n *NoResolver) Start(m *manager.Manager) error {
	return nil
}

func (n *NoResolver) Close() error {
	return nil
}

// Resolver describes a resolvers for path and file names
type Resolver struct {
	dentryResolver *dentry.Resolver
	mountResolver  *mount.Resolver
}

// NewResolver returns a new path resolver
func NewResolver(dentryResolver *dentry.Resolver, mountResolver *mount.Resolver) *Resolver {
	return &Resolver{dentryResolver: dentryResolver, mountResolver: mountResolver}
}

// // ResolveBasename resolves an inode/mount ID pair to a file basename
// func (r *Resolver) ResolveBasename(e *model.FileFields) string {
// 	return r.dentryResolver.ResolveName(e.MountID, e.Inode, e.PathID)
// }

// // ResolveFileFieldsPath resolves an inode/mount ID pair to a full path
// func (r *Resolver) ResolveFileFieldsPath(e *model.FileFields, pidCtx *model.PIDContext, ctrCtx *model.ContainerContext) (string, error) {
// 	pathStr, err := r.dentryResolver.Resolve(e.MountID, e.Inode, e.PathID, !e.HasHardLinks())
// 	if err != nil {
// 		return pathStr, &ErrPathResolution{Err: err}
// 	}

// 	if e.IsFileless() {
// 		return pathStr, nil
// 	}

// 	mountPath, err := r.mountResolver.ResolveMountPath(e.MountID, pidCtx.Pid, ctrCtx.ID)
// 	if err != nil {
// 		if _, err := r.mountResolver.IsMountIDValid(e.MountID); errors.Is(err, mount.ErrMountKernelID) {
// 			return pathStr, &ErrPathResolutionNotCritical{Err: fmt.Errorf("mount ID(%d) invalid: %w", e.MountID, err)}
// 		}
// 		return pathStr, &ErrPathResolution{Err: err}
// 	}

// 	rootPath, err := r.mountResolver.ResolveMountRoot(e.MountID, pidCtx.Pid, ctrCtx.ID)
// 	if err != nil {
// 		if _, err := r.mountResolver.IsMountIDValid(e.MountID); errors.Is(err, mount.ErrMountKernelID) {
// 			return pathStr, &ErrPathResolutionNotCritical{Err: fmt.Errorf("mount ID(%d) invalid: %w", e.MountID, err)}
// 		}
// 		return pathStr, &ErrPathResolution{Err: err}
// 	}
// 	// This aims to handle bind mounts
// 	if strings.HasPrefix(pathStr, rootPath) && rootPath != "/" {
// 		pathStr = strings.Replace(pathStr, rootPath, "", 1)
// 	}

// 	if mountPath != "/" {
// 		pathStr = mountPath + pathStr
// 	}

// 	return pathStr, nil
// }

// // SetMountRoot set the mount point information
// func (r *Resolver) SetMountRoot(ev *model.Event, e *model.Mount) error {
// 	var err error
// 	e.RootStr, err = r.dentryResolver.Resolve(e.RootMountID, e.RootInode, 0, true)
// 	if err != nil {
// 		return &ErrPathResolutionNotCritical{Err: err}
// 	}
// 	return nil
// }

// // ResolveMountRoot resolves the mountpoint to a full path
// func (r *Resolver) ResolveMountRoot(ev *model.Event, e *model.Mount) (string, error) {
// 	if len(e.RootStr) == 0 {
// 		if err := r.SetMountRoot(ev, e); err != nil {
// 			return "", err
// 		}
// 	}
// 	return e.RootStr, nil
// }

// // SetMountPoint set the mount point information
// func (r *Resolver) SetMountPoint(ev *model.Event, e *model.Mount) error {
// 	var err error
// 	e.MountPointStr, err = r.dentryResolver.Resolve(e.ParentMountID, e.ParentInode, 0, true)
// 	if err != nil {
// 		return &ErrPathResolutionNotCritical{Err: err}
// 	}
// 	return nil
// }

// // ResolveMountPoint resolves the mountpoint to a full path
// func (r *Resolver) ResolveMountPoint(ev *model.Event, e *model.Mount) (string, error) {
// 	if len(e.MountPointStr) == 0 {
// 		if err := r.SetMountPoint(ev, e); err != nil {
// 			return "", err
// 		}
// 	}
// 	return e.MountPointStr, nil
// }

// func (r *Resolver) Start(m *manager.Manager) error {
// 	return nil
// }

// func (r *Resolver) Close() error {
// 	return nil
// }

type pathResolutionFailureCause uint8

const (
	unknown pathResolutionFailureCause = iota
	truncated
	zeroLength
	tooBig
	outOfBounds
	invalidCPU
	hashMismatch
	max
)

var pathResolutionFailureCauses = [...]string{
	"unknown",
	"truncated",
	"zero_length",
	"too_big",
	"out_of_bounds",
	"invalid_cpu",
	"hash_mismatch",
}

func (cause pathResolutionFailureCause) String() string {
	return pathResolutionFailureCauses[cause]
}

const PathRingBuffersSize = uint64(131072)

// Resolver describes a resolvers for path and file names
type PathRingsResolver struct {
	mountResolver   *mount.Resolver
	statsdClient    statsd.ClientInterface
	fnv1a           hash.Hash64
	numCPU          uint64
	pathRings       []byte
	failureCounters [max]atomic.Int64
	successCounter  atomic.Int64
}

// NewResolver returns a new path resolver
func NewPathRingsResolver(mountResolver *mount.Resolver, statsdClient statsd.ClientInterface) *PathRingsResolver {
	return &PathRingsResolver{
		mountResolver: mountResolver,
		statsdClient:  statsdClient,
		fnv1a:         fnv.New64a(),
	}
}

func (pr *PathRingsResolver) resolvePath(ref *model.PathRingBufferRef) (string, error) {
	if ref.Length == math.MaxUint64 {
		pr.failureCounters[truncated].Inc()
		return "", errTruncatedPath
	}

	if ref.Length == 0 {
		pr.failureCounters[zeroLength].Inc()
		return "", fmt.Errorf("path ref length is 0")
	}

	if ref.Length > PathRingBuffersSize {
		pr.failureCounters[tooBig].Inc()
		return "", fmt.Errorf("path ref length exceeds ring buffer size: %d", ref.Length)
	}

	if ref.ReadCursor > PathRingBuffersSize {
		pr.failureCounters[outOfBounds].Inc()
		return "", fmt.Errorf("path ref read cursor is out-of-bounds: %d", ref.ReadCursor)
	}

	if ref.CPU >= uint32(pr.numCPU) {
		pr.failureCounters[invalidCPU].Inc()
		return "", fmt.Errorf("path ref CPU number is invalid: %d", ref.CPU)
	}

	var pathStr string
	ringBufferOffset := uint64(uint64(ref.CPU) * PathRingBuffersSize)
	if ref.ReadCursor+ref.Length > PathRingBuffersSize {
		firstPart := model.NullTerminatedString(pr.pathRings[ringBufferOffset+ref.ReadCursor : ringBufferOffset+PathRingBuffersSize])
		remaining := ref.Length - (PathRingBuffersSize - ref.ReadCursor)
		secondPart := model.NullTerminatedString(pr.pathRings[ringBufferOffset : ringBufferOffset+remaining])
		pathStr = firstPart + secondPart
	} else {
		pathStr = model.NullTerminatedString(pr.pathRings[ringBufferOffset+ref.ReadCursor : ringBufferOffset+ref.ReadCursor+ref.Length])
	}

	pr.fnv1a.Reset()
	pr.fnv1a.Write([]byte(pathStr))
	hash := pr.fnv1a.Sum64()
	if ref.Hash != hash {
		pr.failureCounters[hashMismatch].Inc()
		return "", fmt.Errorf("path ref hash mismatch (expected %d, got %d)", ref.Hash, hash)
	}

	if pathStr != "/" {
		pathStr = strings.TrimSuffix(pathStr, "/")
		pathParts := strings.Split(pathStr, "/")
		pathStr = dentry.ComputeFilenameFromParts(pathParts)
	}

	pr.successCounter.Inc()

	return pathStr, nil
}

func (pr *PathRingsResolver) ResolveBasename(e *model.FileFields) string {
	resolvedPath, err := pr.resolvePath(&e.PathRef)
	if err != nil {
		return ""
	}
	return path.Base(resolvedPath)
}

func (pr *PathRingsResolver) ResolveFileFieldsPath(e *model.FileFields, pidCtx *model.PIDContext, ctrCtx *model.ContainerContext) (string, error) {
	pathStr, err := pr.resolvePath(&e.PathRef)
	if err != nil {
		return pathStr, &ErrPathResolution{Err: err}
	}

	if e.IsFileless() {
		return pathStr, nil
	}

	mountPath, err := pr.mountResolver.ResolveMountPath(e.MountID, pidCtx.Pid, ctrCtx.ID)
	if err != nil {
		if _, err := pr.mountResolver.IsMountIDValid(e.MountID); errors.Is(err, mount.ErrMountKernelID) {
			return pathStr, &ErrPathResolutionNotCritical{Err: fmt.Errorf("mount ID(%d) invalid: %w", e.MountID, err)}
		}
		return pathStr, &ErrPathResolution{Err: err}
	}

	// This aims to handle bind mounts
	rootPath, err := pr.mountResolver.ResolveMountRoot(e.MountID, pidCtx.Pid, ctrCtx.ID)
	if err != nil {
		if _, err := pr.mountResolver.IsMountIDValid(e.MountID); errors.Is(err, mount.ErrMountKernelID) {
			return pathStr, &ErrPathResolutionNotCritical{Err: fmt.Errorf("mount ID(%d) invalid: %w", e.MountID, err)}
		}
		return pathStr, &ErrPathResolution{Err: err}
	}
	if strings.HasPrefix(pathStr, rootPath) && rootPath != "/" {
		pathStr = strings.Replace(pathStr, rootPath, "", 1)
	}

	if mountPath != "/" {
		pathStr = mountPath + pathStr
	}

	return pathStr, nil
}

// SetMountRoot set the mount point information
func (pr *PathRingsResolver) SetMountRoot(ev *model.Event, e *model.Mount) error {
	var err error
	e.RootStr, err = pr.resolvePath(&e.RootStrPathRef)
	if err != nil {
		return &ErrPathResolutionNotCritical{Err: err}
	}
	return nil
}

// ResolveMountRoot resolves the mountpoint to a full path
func (pr *PathRingsResolver) ResolveMountRoot(ev *model.Event, e *model.Mount) (string, error) {
	if len(e.RootStr) == 0 {
		if err := pr.SetMountRoot(ev, e); err != nil {
			return "", err
		}
	}
	return e.RootStr, nil
}

// SetMountPoint set the mount point information
func (pr *PathRingsResolver) SetMountPoint(ev *model.Event, e *model.Mount) error {
	var err error
	e.MountPointStr, err = pr.resolvePath(&e.MountPointPathRef)
	if err != nil {
		return &ErrPathResolutionNotCritical{Err: err}
	}
	return nil
}

// ResolveMountPoint resolves the mountpoint to a full path
func (r *PathRingsResolver) ResolveMountPoint(ev *model.Event, e *model.Mount) (string, error) {
	if len(e.MountPointStr) == 0 {
		if err := r.SetMountPoint(ev, e); err != nil {
			return "", err
		}
	}
	return e.MountPointStr, nil
}

func (pr *PathRingsResolver) Start(m *manager.Manager) error {
	if pr.pathRings != nil {
		return fmt.Errorf("path resolver already started")
	}

	numCPU, err := utils.NumCPU()
	if err != nil {
		return err
	}
	pr.numCPU = uint64(numCPU)

	pathRingsMap, err := managerhelper.Map(m, "pr_ringbufs")
	if err != nil {
		return err
	}

	pathRings, err := syscall.Mmap(pathRingsMap.FD(), 0, int(pr.numCPU*PathRingBuffersSize), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil || pathRings == nil {
		return fmt.Errorf("failed to mmap pr_ringbufs map: %w", err)
	}
	pr.pathRings = pathRings

	return nil
}

func (pr *PathRingsResolver) Close() error {
	return unix.Munmap(pr.pathRings)
}

func (pr *PathRingsResolver) SendStats() error {
	for cause, counter := range pr.failureCounters {
		if cause > 0 {
			val := counter.Swap(0)
			if val > 0 {
				tags := []string{fmt.Sprintf("cause:%s", pathResolutionFailureCause(cause).String())}
				_ = pr.statsdClient.Count(metrics.MetricPathResolutionFailure, val, tags, 1.0)
			}
		}
	}

	val := pr.successCounter.Swap(0)
	if val > 0 {
		_ = pr.statsdClient.Count(metrics.MetricPathResolutionSuccess, val, []string{}, 1.0)
	}

	return nil
}
