package downspeed

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
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
