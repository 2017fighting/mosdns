package downspeed

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestProbe_SuccessReturnsBytesPerSecond(t *testing.T) {
	// 1MB payload, served instantly. Speed should be > 0.
	payload := strings.Repeat("x", 1<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	p := Probe{
		Timeout:    2 * time.Second,
		HTTPS:      false,
		Port:       0,
		DownloadMB: 1,
	}
	// Extract port from srv.URL for dialing
	dialIP := "127.0.0.1"
	r := p.Probe(context.Background(), dialIP, srv.URL, netip.MustParseAddr("127.0.0.1"))
	if r.Err != nil {
		t.Fatalf("unexpected error: %v", r.Err)
	}
	if r.BytesPerSec <= 0 {
		t.Errorf("expected positive BytesPerSec, got %v", r.BytesPerSec)
	}
}

func TestProbe_UnreachableFails(t *testing.T) {
	p := Probe{
		Timeout:    100 * time.Millisecond,
		HTTPS:      true,
		Port:       1,
		DownloadMB: 1,
	}
	r := p.Probe(context.Background(), "127.0.0.1", "https://127.0.0.1:1/x", netip.MustParseAddr("127.0.0.1"))
	if r.Err == nil {
		t.Errorf("expected error for unreachable host, got nil")
	}
}

func TestProbe_AbortsOnTimeout(t *testing.T) {
	// Server that stalls forever; probe must respect Timeout.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	p := Probe{
		Timeout:    100 * time.Millisecond,
		HTTPS:      false,
		Port:       0,
		DownloadMB: 1,
	}
	r := p.Probe(context.Background(), "127.0.0.1", srv.URL, netip.MustParseAddr("127.0.0.1"))
	if r.Err == nil {
		t.Errorf("expected timeout error, got nil (BytesPerSec=%v)", r.BytesPerSec)
	}
}

// TestProbe_StreamingTimeoutReportsSpeed reproduces the real-world failure
// for which the read loop was fixed: a speed-test endpoint that STREAMS a
// payload larger than the probe can finish within Timeout. The probe must
// treat the inevitable mid-stream timeout as the NORMAL end of the test and
// report the throughput measured so far — NOT as a "read body" error.
//
// This mirrors cfst's downloadHandler, which breaks on a non-EOF read error
// and returns its accumulated EWMA. Discarding the IP here is what emptied
// the pool even when fast IPs (cfst reference measured 27 MB/s on a
// neighboring 104.17.x address) were downloading fine.
func TestProbe_StreamingTimeoutReportsSpeed(t *testing.T) {
	// Stream 64KB chunks forever. Loopback drains them fast, so totalRead
	// is comfortably > 0 long before the 300ms timeout cuts the request.
	chunk := make([]byte, 64*1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, _ := w.(http.Flusher)
		for {
			if _, err := w.Write(chunk); err != nil {
				return // client gone
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	defer srv.Close()

	p := Probe{
		Timeout: 300 * time.Millisecond,
		HTTPS:   false,
	}
	r := p.Probe(context.Background(), "127.0.0.1", srv.URL, netip.MustParseAddr("127.0.0.1"))
	if r.Err != nil {
		t.Fatalf("streaming timeout after data must not be an error, got: %v", r.Err)
	}
	if r.BytesPerSec <= 0 {
		t.Fatalf("expected positive BytesPerSec after partial stream, got %v", r.BytesPerSec)
	}
}

// TestProbe_FWMarkExercisesControl verifies that a non-zero FWMark wires
// through to the dialer's Control hook. On Linux SO_MARK requires
// CAP_NET_ADMIN; without it the kernel returns EPERM, which we tolerate
// (skip) since the wiring itself is correct. On macOS the Control hook is
// a no-op so the probe must succeed end-to-end.
func TestProbe_FWMarkExercisesControl(t *testing.T) {
	payload := strings.Repeat("x", 1<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	p := Probe{
		Timeout:    2 * time.Second,
		HTTPS:      false,
		Port:       0,
		DownloadMB: 1,
		FWMark:     0x1,
	}
	r := p.Probe(context.Background(), "127.0.0.1", srv.URL, netip.MustParseAddr("127.0.0.1"))
	if r.Err != nil {
		if errors.Is(r.Err, syscall.EPERM) || strings.Contains(r.Err.Error(), "operation not permitted") {
			t.Skipf("SO_MARK failed (no CAP_NET_ADMIN); wiring is correct: %v", r.Err)
		}
		t.Fatalf("unexpected error: %v", r.Err)
	}
}

// connCountListener wraps a net.Listener, counting open server-side connections
// so a test can assert the client closed its connection rather than parking it
// in an idle keep-alive pool.
type connCountListener struct {
	net.Listener
	mu   sync.Mutex
	live int
}

func (l *connCountListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return c, err
	}
	l.mu.Lock()
	l.live++
	l.mu.Unlock()
	return &countedConn{Conn: c, parent: l}, nil
}

func (l *connCountListener) liveCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.live
}

func (l *connCountListener) decrement() {
	l.mu.Lock()
	l.live--
	l.mu.Unlock()
}

type countedConn struct {
	net.Conn
	parent *connCountListener
}

func (c *countedConn) Close() error {
	err := c.Conn.Close()
	c.parent.decrement()
	return err
}

// TestProbe_ClosesConnectionAfterProbe asserts the probe does NOT leak an
// idle keep-alive connection: after Probe returns, the server-side connection
// count must drop back to 0. Before DisableKeepAlives this fails because the
// per-call Transport parks the connection in an idle pool that lingers until GC.
func TestProbe_ClosesConnectionAfterProbe(t *testing.T) {
	payload := strings.Repeat("x", 1<<20)

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	listener := &connCountListener{Listener: inner}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	// Replace httptest's default listener with our counting one, closing the
	// unused default to avoid an FD leak. Start() builds srv.URL from
	// srv.Listener.Addr(), so srv.URL reflects the counting listener's port.
	orig := srv.Listener
	srv.Listener = listener
	orig.Close()
	srv.Start()
	defer srv.Close()

	p := Probe{
		Timeout:    2 * time.Second,
		HTTPS:      false,
		Port:       0,
		DownloadMB: 1,
	}
	dialIP := "127.0.0.1"
	r := p.Probe(context.Background(), dialIP, srv.URL, netip.MustParseAddr("127.0.0.1"))
	if r.Err != nil {
		t.Fatalf("unexpected error: %v", r.Err)
	}

	// The client-side close propagates to the server side asynchronously; poll
	// briefly rather than asserting synchronously to avoid flakiness.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if listener.liveCount() == 0 {
			return // pass
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected 0 live connections after probe, got %d (idle connection leaked)",
		listener.liveCount())
}
