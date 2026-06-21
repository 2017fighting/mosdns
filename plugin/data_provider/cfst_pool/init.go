package cfst_pool

import (
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/cfst_pool/internal/cachefile"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/cfst_pool/internal/cidrsample"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/cfst_pool/internal/runner"
	"go.uber.org/zap"
)

const PluginType = "cfst_pool"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

// Init is the mosdns data_provider init function.
//
// Signature matches coremain.NewPluginFunc: func(bp *BP, args any) (any, error).
//
// High-level behavior:
//   - Parse args.
//   - If CacheFile set and exists, load it into current atomic pointer.
//   - Run first scan synchronously.
//   -   - If first scan fails AND cache was loaded, log warning and keep cache.
//   -   - If first scan fails AND no cache, return error.
//   -   - Otherwise store scan result, persist to cache.
//   - Start background refresh loop (ticker).
//   - Start SIGUSR1 handler.
//   - Return *Plugin.
func Init(bp *coremain.BP, args any) (any, error) {
	a, ok := args.(*Args)
	if !ok {
		return nil, fmt.Errorf("cfst_pool: args is not *Args")
	}

	// Build CIDR list
	cidrs := a.CIDRs
	if len(cidrs) == 0 {
		cidrs = cidrsample.CloudflareIPv4CIDRs
		if a.IPv6 {
			cidrs = append(cidrs, cidrsample.CloudflareIPv6CIDRs...)
		}
	}

	// Build runner
	r := runner.Runner{
		CIDRs:           cidrs,
		Port:            a.Port,
		IPv6:            a.IPv6,
		PingTimes:       a.PingTimes,
		Routines:        a.Routines,
		TCPTimeout:      time.Second,
		HTTPS:           strings.HasPrefix(a.DownloadURL, "https://"),
		DownloadURL:     a.DownloadURL,
		DownloadTimeout: a.DownloadTimeout,
		TopN:            a.TopN,
		Seed:            a.Seed,
		SampleCount:     a.SampleCount,
	}

	p := &Plugin{
		args:   *a,
		runner: r,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}

	// Load cache if configured and exists
	haveCache := false
	if a.CacheFile != "" {
		if data, err := cachefile.Load(a.CacheFile); err == nil {
			set := convertCacheToSet(data)
			p.current.Store(&set)
			haveCache = true
			bp.L().Info("cfst_pool: loaded cache",
				zap.String("file", a.CacheFile),
				zap.Int("ipv4", len(set.IPv4)),
				zap.Int("ipv6", len(set.IPv6)))
		}
	}

	// Cold start: run first scan synchronously
	set, err := p.runner.Run()
	if err != nil {
		if haveCache {
			bp.L().Warn("cfst_pool: cold start scan failed, using cache", zap.Error(err))
		} else {
			return nil, fmt.Errorf("cfst_pool: cold start scan failed (no cache): %w", err)
		}
	} else {
		// Non-zero speed contract: if entire scan returns empty, keep last set (or cache)
		if len(set.IPv4) == 0 && len(set.IPv6) == 0 {
			if p.current.Load() != nil {
				bp.L().Warn("cfst_pool: cold start produced empty set, keeping cache")
			} else {
				return nil, fmt.Errorf("cfst_pool: cold start produced empty set (no cache to fall back)")
			}
		} else {
			p.current.Store(&set)
			p.persist(bp)
			bp.L().Info("cfst_pool: cold start complete",
				zap.Int("ipv4", len(set.IPv4)),
				zap.Int("ipv6", len(set.IPv6)))
		}
	}

	// Start background refresh loop
	go p.refreshLoop(bp)

	// Start SIGUSR1 handler
	go p.signalHandler(bp)

	return p, nil
}

func (p *Plugin) refreshLoop(bp *coremain.BP) {
	defer close(p.doneCh)
	ticker := time.NewTicker(p.args.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.refresh(bp)
		}
	}
}

func (p *Plugin) signalHandler(bp *coremain.BP) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	defer signal.Stop(ch)
	for {
		select {
		case <-p.stopCh:
			return
		case <-ch:
			bp.L().Info("cfst_pool: SIGUSR1 received, refreshing")
			p.refresh(bp)
		}
	}
}

func (p *Plugin) refresh(bp *coremain.BP) {
	set, err := p.runner.Run()
	if err != nil {
		bp.L().Warn("cfst_pool: refresh failed, keeping last set", zap.Error(err))
		return
	}
	// Non-zero speed contract: if entire scan returns empty, keep last set.
	if len(set.IPv4) == 0 && len(set.IPv6) == 0 {
		if p.current.Load() != nil {
			bp.L().Warn("cfst_pool: refresh produced empty set, keeping last")
			return
		}
	}
	p.current.Store(&set)
	p.persist(bp)
	bp.L().Info("cfst_pool: refresh complete",
		zap.Int("ipv4", len(set.IPv4)),
		zap.Int("ipv6", len(set.IPv6)))
}

func (p *Plugin) persist(bp *coremain.BP) {
	if p.args.CacheFile == "" {
		return
	}
	set := p.current.Load()
	if set == nil {
		return
	}
	data := cachefile.Data{
		Version:     1,
		RefreshedAt: time.Now().UTC(),
		IPv4:        addrsToStrings(set.IPv4),
		IPv6:        addrsToStrings(set.IPv6),
	}
	if err := cachefile.Save(p.args.CacheFile, data); err != nil {
		bp.L().Warn("cfst_pool: cache save failed", zap.Error(err))
	}
}

func convertCacheToSet(d cachefile.Data) data_provider.FastIPSet {
	s := d.ToFastIPSet()
	return data_provider.FastIPSet{IPv4: s.IPv4, IPv6: s.IPv6}
}

func addrsToStrings(addrs []netip.Addr) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out
}
