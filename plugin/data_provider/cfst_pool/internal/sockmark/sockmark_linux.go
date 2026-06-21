//go:build linux

package sockmark

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// control applies SO_MARK=mark to the socket behind c. Called only when
// mark is non-zero (Control short-circuits the zero case).
func control(mark uint32) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		}); err != nil {
			return err
		}
		return serr
	}
}
