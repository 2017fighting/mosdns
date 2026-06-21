package sockmark_test

import (
	"errors"
	"net"
	"strings"
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
//   - wires through to the dialer so a real dial invokes it. On Linux this
//     exercises the setsockopt(SO_MARK) path, which requires CAP_NET_ADMIN;
//     unprivileged environments (CI runners, dev shells) lack it and the
//     kernel returns EPERM. That still proves the wiring is correct — only
//     the privilege is missing — so EPERM is tolerated as a skip, the same
//     tolerance the tcping/downspeed FWMark probes apply. On non-Linux
//     (macOS dev) Control is a no-op, so the dial must succeed outright.
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
		// EPERM means the Control hook fired and reached setsockopt(SO_MARK),
		// but the kernel rejected it for lack of CAP_NET_ADMIN (CI runners,
		// unprivileged dev shells). The wiring is correct; only the privilege
		// is missing, so skip rather than fail — same tolerance the
		// tcping/downspeed FWMark probes apply.
		if errors.Is(err, syscall.EPERM) || strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("SO_MARK failed (no CAP_NET_ADMIN); wiring is correct: %v", err)
		}
		t.Fatalf("dial with Control: %v", err)
	}
	conn.Close()
}

// Compile-time check: Control matches net.Dialer.Control's signature.
var _ func(network, address string, c syscall.RawConn) error = sockmark.Control(1)
