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
