//go:build !linux

package sockmark

import "syscall"

// control is a no-op on non-Linux platforms — SO_MARK does not exist
// there. Control only invokes this when mark is non-zero, so the only
// callers reaching here are dev/test builds on macOS or Windows where
// fwmark-based router bypass is not applicable anyway.
func control(_ uint32) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return nil
	}
}
