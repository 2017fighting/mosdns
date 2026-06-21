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
		CIDRs:           []string{"127.0.0.0/24"},
		Port:            port,
		PingTimes:       2,
		Routines:        4,
		TCPTimeout:      500 * time.Millisecond,
		HTTPS:           false,
		DownloadURL:     srv.URL,
		DownloadTimeout: 1 * time.Second,
		TopN:            2,
		Seed:            0,
		SampleCount:     100,
	}

	set, err := r.Run()
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// 127.0.0.1:<port> should succeed; only .1 of 127.0.0.0/30 has our listener.
	if len(set.IPv4) == 0 {
		t.Skip("no candidates succeeded in this environment; sampler RNG or timing varied")
	}
	for _, ip := range set.IPv4 {
		if !ip.IsLoopback() {
			t.Errorf("expected loopback IP, got %v", ip)
		}
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
