package sockmark_test

import (
	"net"
	"syscall"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/cfst_pool/internal/sockmark"
)

// Control's zero-mark fast path lets callers leave net.Dialer.Control
// unset, so the per-dial callback is skipped entirely.
func TestControl_ZeroMarkReturnsNil(t *testing.T) {
	if sockmark.Control(0) != nil {
		t.Fatal("Control(0) returned non-nil; caller cannot leave net.Dialer.Control unset")
	}
}

// A non-zero mark must return a function that:
//   - has the net.Dialer.Control signature (compile-time checked below)
//   - does not error when actually invoked on a real dial (on Linux this
//     exercises the setsockopt path; on non-Linux it is a no-op)
func TestControl_NonZeroMarkSmoke(t *testing.T) {
	fn := sockmark.Control(0x1)
	if fn == nil {
		t.Fatal("Control(0x1) returned nil, expected a function")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Close()
	}()

	d := &net.Dialer{Control: fn}
	conn, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial with Control: %v", err)
	}
	conn.Close()
}

// Compile-time check: Control matches net.Dialer.Control's signature.
var _ func(network, address string, c syscall.RawConn) error = sockmark.Control(1)
