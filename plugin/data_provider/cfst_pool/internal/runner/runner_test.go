package runner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

// TestRun_SampleModeCFST_RoutesToEnumerate verifies that SampleMode="cfst"
// routes IPv4 sampling through cidrsample.EnumerateIPv4 (full /24 walk)
// instead of the random subset. With 127.0.0.1/32 — which EnumerateIPv4
// returns verbatim via its /32 special-case — the loopback server is still
// reached, so the pipeline produces the same loopback result as the
// default-mode happy path. (EnumerateIPv4's multi-/24 coverage is pinned
// directly in cidrsample/enumerate_test.go; this test only confirms routing.)
func TestRun_SampleModeCFST_RoutesToEnumerate(t *testing.T) {
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
		SampleMode:      SampleModeCFST,
	}

	set, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(set.IPv4) != 1 {
		t.Fatalf("expected exactly 1 IPv4 (TopN=1), got %d: %v", len(set.IPv4), set.IPv4)
	}
	if !set.IPv4[0].IsLoopback() {
		t.Errorf("expected loopback, got %v", set.IPv4[0])
	}
}

func TestMergePrevious_EmptyPreviousIsPassthrough(t *testing.T) {
	fresh := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	out, added := mergePrevious(fresh, nil)
	if added != 0 {
		t.Errorf("added = %d, want 0", added)
	}
	if len(out) != 1 || out[0] != fresh[0] {
		t.Errorf("out = %v, want %v unchanged", out, fresh)
	}
}

func TestMergePrevious_AppendsNewAddrsAndCounts(t *testing.T) {
	fresh := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	prev := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"), // dup → skipped
		netip.MustParseAddr("1.1.1.2"), // new → added
		netip.MustParseAddr("1.1.1.3"), // new → added
	}
	out, added := mergePrevious(fresh, prev)
	if added != 2 {
		t.Fatalf("added = %d, want 2", added)
	}
	if len(out) != 3 {
		t.Fatalf("len(out) = %d, want 3", len(out))
	}
	// Order: fresh first, then appended previous in order.
	want := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("1.1.1.2"),
		netip.MustParseAddr("1.1.1.3"),
	}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("out[%d] = %v, want %v", i, out[i], want[i])
		}
	}
}

func TestMergePrevious_FamilyGuardDropsCrossFamily(t *testing.T) {
	// Fresh is v4; a v6 previous addr must be skipped, not dialed on the v4 pool.
	fresh := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	prev := []netip.Addr{
		netip.MustParseAddr("2606:4700::1"), // cross-family → skipped
		netip.MustParseAddr("1.1.1.2"),      // same family → added
	}
	out, added := mergePrevious(fresh, prev)
	if added != 1 {
		t.Fatalf("added = %d, want 1 (cross-family skipped)", added)
	}
	for _, a := range out {
		if a.Is6() {
			t.Errorf("v6 addr %v leaked into v4 pool", a)
		}
	}
}

func TestMergePrevious_FreshEmptyInfersFamilyFromPrevious(t *testing.T) {
	// No fresh sample; family taken from previous. v6 previous all kept.
	prev := []netip.Addr{
		netip.MustParseAddr("2606:4700::1"),
		netip.MustParseAddr("2606:4700::2"),
	}
	out, added := mergePrevious(nil, prev)
	if added != 2 {
		t.Fatalf("added = %d, want 2", added)
	}
	if len(out) != 2 {
		t.Fatalf("len(out) = %d, want 2", len(out))
	}
}

func TestMergePrevious_BothEmptyReturnsNil(t *testing.T) {
	out, added := mergePrevious(nil, nil)
	if added != 0 || out != nil {
		t.Errorf("out = %v added = %d, want nil/0", out, added)
	}
}
