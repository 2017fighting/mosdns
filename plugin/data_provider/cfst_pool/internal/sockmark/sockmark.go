// Package sockmark exposes a net.Dialer.Control hook that applies the
// Linux SO_MARK socket option to cfst_pool's probe sockets.
//
// Router deployments commonly run a global proxy policy that intercepts
// outbound traffic. Without a fwmark exemption, cfst_pool's TCP and HTTP
// probes would be measured through the proxy, defeating the point of the
// speed test. Setting SO_MARK on the probe sockets lets the operator
// write an ip-rule/iptables exemption for that mark so the probes flow
// over the direct path.
//
// A zero mark is treated as "no marking" and Control returns nil so that
// net.Dialer skips the per-dial callback entirely. On non-Linux platforms
// the returned function is a no-op (SO_MARK is Linux-only); this keeps
// the package compilable on macOS for development without weakening the
// production Linux build.
package sockmark

import "syscall"

// Control returns a net.Dialer.Control hook that applies SO_MARK=mark to
// the underlying socket on Linux. A zero mark returns nil, signalling the
// caller to leave net.Dialer.Control unset and skip the per-dial callback.
func Control(mark uint32) func(network, address string, c syscall.RawConn) error {
	if mark == 0 {
		return nil
	}
	return control(mark)
}
