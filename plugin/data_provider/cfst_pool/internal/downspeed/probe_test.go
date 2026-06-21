package downspeed

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
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
	r := p.Probe(dialIP, srv.URL, netip.MustParseAddr("127.0.0.1"))
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
	r := p.Probe("127.0.0.1", "https://127.0.0.1:1/x", netip.MustParseAddr("127.0.0.1"))
	if r.Err == nil {
		t.Errorf("expected error for unreachable host, got nil")
	}
}

func TestProbe_AbortsOnTimeout(t *testing.T) {
	// Server that stalls forever; probe must respect Timeout.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer srv.Close()

	p := Probe{
		Timeout:    100 * time.Millisecond,
		HTTPS:      false,
		Port:       0,
		DownloadMB: 1,
	}
	r := p.Probe("127.0.0.1", srv.URL, netip.MustParseAddr("127.0.0.1"))
	if r.Err == nil {
		t.Errorf("expected timeout error, got nil (BytesPerSec=%v)", r.BytesPerSec)
	}
}
