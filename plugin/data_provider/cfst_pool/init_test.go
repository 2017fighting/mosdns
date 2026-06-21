package cfst_pool

import (
	"fmt"
	"net/netip"
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

func TestInitNoCacheFail(t *testing.T) {
	// Test: no cache, first scan fails, should return error
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
	bp := coremain.NewBP("test_no_cache_fail", m)

	// Init should fail
	_, err = Init(bp, &args)
	if err == nil {
		t.Error("Init should fail when no cache and scan fails")
	}
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
