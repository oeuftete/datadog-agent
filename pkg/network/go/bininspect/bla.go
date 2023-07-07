//go:build linux_bpf

package bininspect

import (
	"fmt"
	"github.com/go-delve/delve/pkg/goversion"
)

// GetWriteParams gets the parameter metadata (positions/types) for crypto/tls.(*Conn).Write
func GetWriteParams(version goversion.GoVersion, goarch string) ([]ParameterMetadata, error) {
	switch goarch {
	case "amd64":
		if version.AfterOrEqual(goversion.GoVersion{Major: 1, Minor: 17, Rev: 0}) {
			return []ParameterMetadata{{TotalSize: 8, Kind: 0x16, Pieces: []ParameterPiece{{Size: 0, InReg: true, StackOffset: 0, Register: 0}}}, {TotalSize: 24, Kind: 0x17, Pieces: []ParameterPiece{{Size: 8, InReg: true, StackOffset: 0, Register: 3}, {Size: 8, InReg: true, StackOffset: 0, Register: 2}, {Size: 8, InReg: true, StackOffset: 0, Register: 5}}}}, nil
		}
		if version.AfterOrEqual(goversion.GoVersion{Major: 1, Minor: 13, Rev: 0}) {
			return []ParameterMetadata{{TotalSize: 8, Kind: 0x16, Pieces: []ParameterPiece{{Size: 8, InReg: false, StackOffset: 8, Register: 0}}}, {TotalSize: 24, Kind: 0x17, Pieces: []ParameterPiece{{Size: 8, InReg: false, StackOffset: 16, Register: 0}, {Size: 8, InReg: false, StackOffset: 24, Register: 0}, {Size: 8, InReg: false, StackOffset: 32, Register: 0}}}}, nil
		}
		return nil, fmt.Errorf("unsupported version go%d.%d.%d (min supported: go%d.%d.%d)", version.Major, version.Minor, version.Rev, 1, 13, 0)
	case "arm64":
		if version.AfterOrEqual(goversion.GoVersion{Major: 1, Minor: 18, Rev: 0}) {
			return []ParameterMetadata{{TotalSize: 8, Kind: 0x16, Pieces: []ParameterPiece{{Size: 0, InReg: true, StackOffset: 0, Register: 0}}}, {TotalSize: 24, Kind: 0x17, Pieces: []ParameterPiece{{Size: 8, InReg: true, StackOffset: 0, Register: 1}, {Size: 8, InReg: true, StackOffset: 0, Register: 2}, {Size: 8, InReg: true, StackOffset: 0, Register: 3}}}}, nil
		}
		if version.AfterOrEqual(goversion.GoVersion{Major: 1, Minor: 13, Rev: 0}) {
			return []ParameterMetadata{{TotalSize: 8, Kind: 0x16, Pieces: []ParameterPiece{{Size: 8, InReg: false, StackOffset: 16, Register: 0}}}, {TotalSize: 24, Kind: 0x17, Pieces: []ParameterPiece{{Size: 8, InReg: false, StackOffset: 24, Register: 0}, {Size: 8, InReg: false, StackOffset: 32, Register: 0}, {Size: 8, InReg: false, StackOffset: 40, Register: 0}}}}, nil
		}
		return nil, fmt.Errorf("unsupported version go%d.%d.%d (min supported: go%d.%d.%d)", version.Major, version.Minor, version.Rev, 1, 13, 0)
	default:
		return nil, fmt.Errorf("unsupported architecture %q", goarch)
	}
}

// GetReadParams gets the parameter metadata (positions/types) for crypto/tls.(*Conn).Read
func GetReadParams(version goversion.GoVersion, goarch string) ([]ParameterMetadata, error) {
	switch goarch {
	case "amd64":
		if version.AfterOrEqual(goversion.GoVersion{Major: 1, Minor: 18, Rev: 0}) {
			return []ParameterMetadata{{TotalSize: 8, Kind: 0x16, Pieces: []ParameterPiece{{Size: 0, InReg: true, StackOffset: 0, Register: 0}}}, {TotalSize: 24, Kind: 0x17, Pieces: []ParameterPiece{{Size: 8, InReg: true, StackOffset: 0, Register: 3}, {Size: 8, InReg: true, StackOffset: 0, Register: 2}, {Size: 8, InReg: true, StackOffset: 0, Register: 5}}}}, nil
		}
		if version.AfterOrEqual(goversion.GoVersion{Major: 1, Minor: 17, Rev: 0}) {
			return []ParameterMetadata{{TotalSize: 8, Kind: 0x16, Pieces: []ParameterPiece{{Size: 0, InReg: true, StackOffset: 0, Register: 0}}}, {TotalSize: 24, Kind: 0x17, Pieces: []ParameterPiece{{Size: 8, InReg: true, StackOffset: 0, Register: 3}, {Size: 8, InReg: false, StackOffset: 24, Register: 0}, {Size: 8, InReg: true, StackOffset: 0, Register: 5}}}}, nil
		}
		if version.AfterOrEqual(goversion.GoVersion{Major: 1, Minor: 16, Rev: 0}) {
			return []ParameterMetadata{{TotalSize: 8, Kind: 0x16, Pieces: []ParameterPiece{{Size: 8, InReg: false, StackOffset: 8, Register: 0}}}, {TotalSize: 24, Kind: 0x17, Pieces: []ParameterPiece{}}}, nil
		}
		if version.AfterOrEqual(goversion.GoVersion{Major: 1, Minor: 13, Rev: 0}) {
			return []ParameterMetadata{{TotalSize: 8, Kind: 0x16, Pieces: []ParameterPiece{{Size: 8, InReg: false, StackOffset: 8, Register: 0}}}, {TotalSize: 24, Kind: 0x17, Pieces: []ParameterPiece{{Size: 8, InReg: false, StackOffset: 16, Register: 0}, {Size: 8, InReg: false, StackOffset: 24, Register: 0}}}}, nil
		}
		return nil, fmt.Errorf("unsupported version go%d.%d.%d (min supported: go%d.%d.%d)", version.Major, version.Minor, version.Rev, 1, 13, 0)
	case "arm64":
		if version.AfterOrEqual(goversion.GoVersion{Major: 1, Minor: 18, Rev: 0}) {
			return []ParameterMetadata{{TotalSize: 8, Kind: 0x16, Pieces: []ParameterPiece{{Size: 0, InReg: true, StackOffset: 0, Register: 0}}}, {TotalSize: 24, Kind: 0x17, Pieces: []ParameterPiece{{Size: 8, InReg: true, StackOffset: 0, Register: 1}, {Size: 8, InReg: true, StackOffset: 0, Register: 2}, {Size: 8, InReg: true, StackOffset: 0, Register: 3}}}}, nil
		}
		if version.AfterOrEqual(goversion.GoVersion{Major: 1, Minor: 17, Rev: 0}) {
			return []ParameterMetadata{{TotalSize: 8, Kind: 0x16, Pieces: []ParameterPiece{{Size: 8, InReg: false, StackOffset: 16, Register: 0}}}, {TotalSize: 24, Kind: 0x17, Pieces: []ParameterPiece{{Size: 8, InReg: false, StackOffset: 24, Register: 0}, {Size: 8, InReg: false, StackOffset: 32, Register: 0}}}}, nil
		}
		if version.AfterOrEqual(goversion.GoVersion{Major: 1, Minor: 16, Rev: 0}) {
			return []ParameterMetadata{{TotalSize: 8, Kind: 0x16, Pieces: []ParameterPiece{{Size: 8, InReg: false, StackOffset: 16, Register: 0}}}, {TotalSize: 24, Kind: 0x17, Pieces: []ParameterPiece{}}}, nil
		}
		if version.AfterOrEqual(goversion.GoVersion{Major: 1, Minor: 13, Rev: 0}) {
			return []ParameterMetadata{{TotalSize: 8, Kind: 0x16, Pieces: []ParameterPiece{{Size: 8, InReg: false, StackOffset: 16, Register: 0}}}, {TotalSize: 24, Kind: 0x17, Pieces: []ParameterPiece{{Size: 8, InReg: false, StackOffset: 24, Register: 0}, {Size: 8, InReg: false, StackOffset: 32, Register: 0}}}}, nil
		}
		return nil, fmt.Errorf("unsupported version go%d.%d.%d (min supported: go%d.%d.%d)", version.Major, version.Minor, version.Rev, 1, 13, 0)
	default:
		return nil, fmt.Errorf("unsupported architecture %q", goarch)
	}
}

// GetCloseParams gets the parameter metadata (positions/types) for crypto/tls.(*Conn).Close
func GetCloseParams(version goversion.GoVersion, goarch string) ([]ParameterMetadata, error) {
	switch goarch {
	case "amd64":
		if version.AfterOrEqual(goversion.GoVersion{Major: 1, Minor: 17, Rev: 0}) {
			return []ParameterMetadata{{TotalSize: 8, Kind: 0x16, Pieces: []ParameterPiece{{Size: 0, InReg: true, StackOffset: 0, Register: 0}}}}, nil
		}
		if version.AfterOrEqual(goversion.GoVersion{Major: 1, Minor: 13, Rev: 0}) {
			return []ParameterMetadata{{TotalSize: 8, Kind: 0x16, Pieces: []ParameterPiece{{Size: 8, InReg: false, StackOffset: 8, Register: 0}}}}, nil
		}
		return nil, fmt.Errorf("unsupported version go%d.%d.%d (min supported: go%d.%d.%d)", version.Major, version.Minor, version.Rev, 1, 13, 0)
	case "arm64":
		if version.AfterOrEqual(goversion.GoVersion{Major: 1, Minor: 18, Rev: 0}) {
			return []ParameterMetadata{{TotalSize: 8, Kind: 0x16, Pieces: []ParameterPiece{{Size: 0, InReg: true, StackOffset: 0, Register: 0}}}}, nil
		}
		if version.AfterOrEqual(goversion.GoVersion{Major: 1, Minor: 13, Rev: 0}) {
			return []ParameterMetadata{{TotalSize: 8, Kind: 0x16, Pieces: []ParameterPiece{{Size: 8, InReg: false, StackOffset: 16, Register: 0}}}}, nil
		}
		return nil, fmt.Errorf("unsupported version go%d.%d.%d (min supported: go%d.%d.%d)", version.Major, version.Minor, version.Rev, 1, 13, 0)
	default:
		return nil, fmt.Errorf("unsupported architecture %q", goarch)
	}
}
