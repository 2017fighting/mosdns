package runner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRun_HappyPath_ProducesFastIPSet(t *testing.T) {
	payload := strings.Repeat("x", 256*1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	port := uint16(srv.Listener.Addr().(*net.TCPAddr).Port)

	r := Runner{
		CIDRs:           []string{"127.0.0.1/32"},
		Port:            port,
		PingTimes:       1,
		Routines:        1,
		TCPTimeout:      500 * time.Millisecond,
		HTTPS:           false,
		DownloadURL:     srv.URL,
		DownloadTimeout: 1 * time.Second,
		TopN:            1,
		Seed:            42,
		SampleCount:     1,
	}

	set, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// 127.0.0.1/32 guarantees the sampler picks 127.0.0.1
	if len(set.IPv4) == 0 {
		t.Fatalf("expected at least 1 IPv4 from 127.0.0.1/32, got 0")
	}
	if len(set.IPv4) != 1 {
		t.Errorf("expected exactly 1 IPv4 (TopN=1), got %d: %v", len(set.IPv4), set.IPv4)
	}
	if !set.IPv4[0].IsLoopback() {
		t.Errorf("expected loopback, got %v", set.IPv4[0])
	}
}

// TestRun_CIDRExcludesApplied verifies Runner.CIDRExcludes is wired into the
// sampler: when the only candidate is excluded, it must NOT reach the probe
// (the set stays empty / Run reports no samples). Without wiring, the
// reachable loopback server would still produce an IP.
func TestRun_CIDRExcludesApplied(t *testing.T) {
	payload := strings.Repeat("x", 64*1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	port := uint16(srv.Listener.Addr().(*net.TCPAddr).Port)

	r := Runner{
		CIDRs:           []string{"127.0.0.1/32"},
		CIDRExcludes:    []string{"127.0.0.1/32"},
		Port:            port,
		PingTimes:       1,
		Routines:        1,
		TCPTimeout:      500 * time.Millisecond,
		HTTPS:           false,
		DownloadURL:     srv.URL,
		DownloadTimeout: 1 * time.Second,
		TopN:            1,
		Seed:            42,
		SampleCount:     1,
	}
	set, err := r.Run(context.Background())
	if err == nil && len(set.IPv4) > 0 {
		t.Fatalf("CIDRExcludes must drop the only candidate, but got IPv4=%v", set.IPv4)
	}
}

func TestRun_NoCIDRsErrors(t *testing.T) {
	r := Runner{
		DownloadURL: "http://example.com",
	}
	_, err := r.Run(context.Background())
	if err == nil {
		t.Fatal("expected error for no CIDRs")
	}
}
