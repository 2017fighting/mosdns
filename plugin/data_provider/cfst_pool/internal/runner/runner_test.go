package runner

import (
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

	set, err := r.Run()
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

func TestRun_NoCIDRsErrors(t *testing.T) {
	r := Runner{
		DownloadURL: "http://example.com",
	}
	_, err := r.Run()
	if err == nil {
		t.Fatal("expected error for no CIDRs")
	}
}
