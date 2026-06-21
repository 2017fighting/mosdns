package cfst_pool

import (
	"context"
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
//   - If CacheFile set and exists, load it synchronously into the atomic
//     pointer (fast file I/O; no network).
//   - Start the background refresh loop. The first scan runs immediately
//     inside the loop — Init does NOT block on it. This lets mosdns bind
//     its UDP/TCP servers right away while the scan runs in the background.
//   - Start SIGUSR1 handler.
//   - Return *Plugin.
//
// Async contract: Init never fails because of a scan failure. If no cache
// is loaded, GetFastIPs returns an empty FastIPSet until the background
// scan populates the pointer.
func Init(bp *coremain.BP, args any) (any, error) {
	a, ok := args.(*Args)
	if !ok {
		return nil, fmt.Errorf("cfst_pool: args is not *Args")
	}

	// Apply defaults. mosdns core decodes plugin args via mapstructure's
	// WeakDecode, which bypasses ParseArgs — so we must apply defaults here.
	a.applyDefaults()

	// Build CIDR list
	cidrs := a.CIDRs
	if len(cidrs) == 0 {
		cidrs = cidrsample.CloudflareIPv4CIDRs
		if a.IPv6 {
			cidrs = append(cidrs, cidrsample.CloudflareIPv6CIDRs...)
		}
	}

	// Build runner. Duration fields in Args are int seconds; convert at use.
	// Log wires bp.L() so the operator can see per-stage diagnostics when
	// a refresh produces an empty set — without it, the silent pipeline
	// gives no clue which stage (sample/TCP/download) dropped candidates.
	r := runner.Runner{
		CIDRs:           cidrs,
		CIDRExcludes:    a.CIDRExcludes,
		Port:            a.Port,
		IPv6:            a.IPv6,
		PingTimes:       a.PingTimes,
		Routines:        a.Routines,
		TCPTimeout:      time.Second,
		HTTPS:           strings.HasPrefix(a.DownloadURL, "https://"),
		DownloadURL:     a.DownloadURL,
		DownloadTimeout: time.Duration(a.DownloadTimeout) * time.Second,
		TopN:            a.TopN,
		Seed:            a.Seed,
		SampleCount:     a.SampleCount,
		SampleMode:      a.SampleMode,
		FWMark:          a.FWMark,
		Log:             bp.L(),
	}

	p := &Plugin{
		args:   *a,
		runner: r,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}

	// Load cache if configured and exists. This is the only synchronous I/O
	// before returning — it is a local file read and runs in microseconds.
	// On a hit, callers see the cached set immediately; on a miss, callers
	// see an empty set until the background scan completes.
	if a.CacheFile != "" {
		if data, err := cachefile.Load(a.CacheFile); err == nil {
			set := convertCacheToSet(data)
			p.current.Store(&set)
			bp.L().Info("cfst_pool: loaded cache",
				zap.String("file", a.CacheFile),
				zap.Int("ipv4", len(set.IPv4)),
				zap.Int("ipv6", len(set.IPv6)))
		}
	} else {
		bp.L().Info("cfst_pool: no cache configured; serving empty set until first scan completes")
	}

	// Start background refresh loop. The loop performs the first scan
	// immediately on entry, then ticks on RefreshInterval.
	go p.refreshLoop(bp)

	// Start SIGUSR1 handler
	go p.signalHandler(bp)

	return p, nil
}

func (p *Plugin) refreshLoop(bp *coremain.BP) {
	defer close(p.doneCh)

	// ctx lives for the lifetime of the loop. Canceling it aborts any
	// in-flight scan promptly (TCP dials and HTTP downloads honor ctx),
	// so Close() does not have to wait for a multi-minute scan to finish.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Fan stopCh out to ctx cancellation. The companion goroutine exits
	// as soon as either side fires.
	go func() {
		select {
		case <-p.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	// Immediate cold-start scan. Runs in the background so mosdns can bind
	// UDP/TCP ports without waiting for it. Failure is logged and retried
	// on the next tick; the last good set (or cache) is preserved.
	p.refresh(ctx, bp)

	ticker := time.NewTicker(time.Duration(p.args.RefreshInterval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.refresh(ctx, bp)
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
			// Operator-initiated rescans use background ctx; if shutdown
			// arrives mid-rescan, Close() does not block on this goroutine
			// because signalHandler does not own doneCh. The refresh simply
			// runs to completion and its result lands in p.current.
			p.refresh(context.Background(), bp)
		}
	}
}

func (p *Plugin) refresh(ctx context.Context, bp *coremain.BP) {
	set, err := p.runner.Run(ctx)
	if err != nil {
		if ctx.Err() != nil {
			// Cancellation (typically shutdown) — don't warn at default
			// level; this is expected during Close.
			bp.L().Debug("cfst_pool: refresh aborted", zap.Error(err))
		} else {
			bp.L().Warn("cfst_pool: refresh failed, keeping last set", zap.Error(err))
		}
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
