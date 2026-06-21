package cfst_pool

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/cfst_pool/internal/cachefile"
)

func TestInitCacheLoadFail(t *testing.T) {
	// Test: cache exists, first scan fails, should use cache
	tmpDir := t.TempDir()
	cachePath := tmpDir + "/cache.json"

	// Pre-populate cache with test IPs
	cacheData := cachefile.Data{
		Version:     1,
		RefreshedAt: time.Now().UTC(),
		IPv4:        []string{"1.1.1.1", "1.0.0.1"},
		IPv6:        []string{},
	}
	if err := cachefile.Save(cachePath, cacheData); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	// Create args with invalid URL (will fail scan)
	argsYAML := fmt.Sprintf(`
download_url: http://invalid.invalid
cache_file: %s
sample_count: 10
ping_times: 1
download_seconds: 1
top_n: 1
cidrs:
  - 192.0.2.0/24
refresh_interval: 1
`, cachePath)

	args, err := ParseArgs([]byte(argsYAML))
	if err != nil {
		t.Fatalf("parse args: %v", err)
	}

	plugins := make(map[string]any)
	m := coremain.NewTestMosdnsWithPlugins(plugins)
	bp := coremain.NewBP("test_cache_fail", m)

	// Init should succeed despite scan failure (cache exists)
	pluginAny, err := Init(bp, &args)
	if err != nil {
		t.Fatalf("Init should succeed with cache: %v", err)
	}

	plugin := pluginAny.(*Plugin)
	defer plugin.Close()

	// GetFastIPs should return cached IPs
	set := plugin.GetFastIPs()
	if len(set.IPv4) != 2 {
		t.Errorf("Expected 2 cached IPv4, got %d", len(set.IPv4))
	}
}

func TestInitAsyncSucceedsWithoutCache(t *testing.T) {
	// Async contract: Init must not block on the first scan and must not
	// fail mosdns startup just because the scan cannot reach the URL.
	// Without a cache, GetFastIPs returns an empty snapshot until the
	// background scan populates the set.
	argsYAML := `
download_url: http://invalid.invalid
sample_count: 10
ping_times: 1
download_seconds: 1
top_n: 1
cidrs:
  - 192.0.2.0/24
refresh_interval: 1
`

	args, err := ParseArgs([]byte(argsYAML))
	if err != nil {
		t.Fatalf("parse args: %v", err)
	}

	plugins := make(map[string]any)
	m := coremain.NewTestMosdnsWithPlugins(plugins)
	bp := coremain.NewBP("test_async_no_cache", m)

	// Init must return well before a 1-second scan could finish.
	start := time.Now()
	pluginAny, err := Init(bp, &args)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Init must succeed asynchronously: %v", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("Init blocked for %v; expected to return without waiting for scan", elapsed)
	}

	plugin := pluginAny.(*Plugin)
	defer plugin.Close()

	// Snapshot may be empty (scan hasn't completed or failed). Either way
	// it must be safe to read.
	_ = plugin.GetFastIPs()
}

func TestPluginImplementsFastIPProvider(t *testing.T) {
	// Test that Plugin implements FastIPProvider
	var _ data_provider.FastIPProvider = (*Plugin)(nil)
}

func TestCloseIdempotent(t *testing.T) {
	// Create a minimal plugin with mocked data
	p := &Plugin{
		args:   Args{},
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	// Start a mock refresh loop that closes doneCh when stopped
	go func() {
		<-p.stopCh
		close(p.doneCh)
	}()
	// Store a non-nil set
	set := data_provider.FastIPSet{IPv4: []netip.Addr{}}
	p.current.Store(&set)

	// First Close
	if err := p.Close(); err != nil {
		t.Errorf("First Close failed: %v", err)
	}
	// Verify doneCh is closed
	select {
	case <-p.doneCh:
		// Expected
	default:
		t.Error("doneCh not closed after Close")
	}
	// Second Close should not panic
	if err := p.Close(); err != nil {
		t.Errorf("Second Close failed (not idempotent): %v", err)
	}
}

func TestGetFastIPsConcurrency(t *testing.T) {
	// Test that GetFastIPs is safe for concurrent reads
	// Create a plugin with mocked data
	p := &Plugin{
		args:   Args{},
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	// Start a mock goroutine so Close() doesn't block
	go func() {
		<-p.stopCh
		close(p.doneCh)
	}()
	// Store a non-nil set
	set := data_provider.FastIPSet{IPv4: []netip.Addr{}}
	p.current.Store(&set)
	defer p.Close()

	// Spawn many goroutines reading GetFastIPs concurrently
	done := make(chan struct{}, 100)
	for i := 0; i < 100; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				set := p.GetFastIPs()
				// Should never panic or return nil
				if set.IPv4 == nil {
					panic("IPv4 set is nil")
				}
			}
		}()
	}

	// Wait for all goroutines to finish
	timeout := time.After(5 * time.Second)
	for i := 0; i < 100; i++ {
		select {
		case <-done:
		case <-timeout:
			t.Fatal("Timeout waiting for goroutines")
		}
	}
}

// TestCloseAbortsInFlightScan reproduces the slow-shutdown bug: when mosdns
// closes the plugin while a refresh scan is mid-flight (inside the HTTP
// download probe), Close() must not wait for the scan's full DownloadTimeout
// to elapse. Before ctx propagation, it blocked for ~10s here.
func TestCloseAbortsInFlightScan(t *testing.T) {
	// Server that stalls until the test tears it down. The scan will reach
	// this handler after the (instant) loopback TCP probe and park here.
	stallCh := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-stallCh:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(stallCh)

	// Parse the httptest port so we can point cfst_pool's Port arg at the
	// real listener (Port=0 in args defaults to 443, which is not where the
	// test server lives).
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse srv.URL: %v", err)
	}
	var srvPort uint16
	if _, err := fmt.Sscanf(u.Port(), "%d", &srvPort); err != nil {
		t.Fatalf("parse srv port: %v", err)
	}

	args := Args{
		DownloadURL:     srv.URL,
		SampleCount:     1,
		DownloadSeconds: 10,
		DownloadTimeout: 10,
		Port:            srvPort,
		PingTimes:       1,
		TopN:            1,
		CIDRs:           []string{"127.0.0.1/32"},
		RefreshInterval: 3600,
	}
	args.applyDefaults()

	plugins := make(map[string]any)
	m := coremain.NewTestMosdnsWithPlugins(plugins)
	bp := coremain.NewBP("test_close_abort", m)

	pluginAny, err := Init(bp, &args)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	plugin := pluginAny.(*Plugin)

	// Give the cold-start scan time to reach the download probe. The TCP
	// ping to 127.0.0.1 completes in <1ms; 300ms is ample headroom.
	time.Sleep(300 * time.Millisecond)

	// Close must abort the in-flight scan via context cancellation and
	// return promptly. Before the fix this blocked for the full 10s
	// DownloadTimeout.
	start := time.Now()
	if err := plugin.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Errorf("Close took %v; expected <1s once ctx cancel propagates", elapsed)
	}
}
