// Package runner orchestrates the cfst pipeline:
// sample CIDRs → TCP probe → HTTP download → score → FastIPSet.
package runner

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"time"

	"go.uber.org/zap"

	dp "github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/cfst_pool/internal/cidrsample"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/cfst_pool/internal/downspeed"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/cfst_pool/internal/scorer"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/cfst_pool/internal/tcping"
)

const (
	defaultTCPTimeout      = time.Second
	defaultDownloadTimeout = 10 * time.Second

	// SampleModeCFST selects CloudflareSpeedTest's default IPv4 sampling —
	// walk every /24 and take one random IP per /24 — instead of drawing a
	// fixed-size random subset. See cidrsample.EnumerateIPv4.
	SampleModeCFST = "cfst"
)

// Runner is a one-shot pipeline execution.
type Runner struct {
	// CIDRs is the candidate pool. Required.
	CIDRs []string
	// CIDRExcludes are prefixes sampled candidates must NOT fall inside.
	// nil (default) → apply cidrsample.CloudflareWARPExcludes (WARP/gateway
	// blocks that pass TCP but don't serve proxied customer domains).
	// An empty slice disables exclusion; a non-empty slice replaces the
	// default.
	CIDRExcludes []string
	// Port is the TCP port to probe (443 typical). Required.
	Port uint16
	// IPv6 enables IPv6 sampling. Defaults to IPv4 only.
	IPv6 bool

	// TCP probe config
	PingTimes  int
	Routines   int
	TCPTimeout time.Duration

	// Download probe config
	HTTPS           bool
	DownloadURL     string
	DownloadTimeout time.Duration

	// Selection
	TopN int

	// Sampler seed for reproducibility
	Seed int64

	// SampleCount: how many IPs to draw per family before probing.
	SampleCount int

	// SampleMode selects the IPv4 sampling strategy. "" or "random" (default)
	// draws SampleCount IPs, at most one per /24; SampleModeCFST ("cfst")
	// mirrors CloudflareSpeedTest's default walk over every /24 for full
	// coverage (~5900 candidates on the built-in list). IPv6 always samples
	// randomly regardless — an IPv6 /32 cannot be enumerated.
	SampleMode string

	// FWMark is applied to every probe socket via SO_MARK on Linux.
	// Zero leaves sockets unmarked. Used to bypass router-level proxies
	// that would invalidate the measurement.
	FWMark uint32

	// Log receives per-stage diagnostics. Nil → discard (test path).
	// Production wires bp.L() so the operator sees where the pipeline
	// drops candidates when an empty FastIPSet would otherwise be a mystery.
	Log *zap.Logger
}

// logger returns the configured logger or a no-op sink so the runner stays
// safe to call from tests that never set Log.
func (r Runner) logger() *zap.Logger {
	if r.Log == nil {
		return zap.NewNop()
	}
	return r.Log
}

// Run executes the pipeline and returns the selected IPs.
//
// The ctx argument is propagated into both probes (TCP ping and HTTP
// download) so the caller can abort an in-flight scan early — primarily
// used by the plugin's shutdown path so mosdns's Close is not held hostage
// to a multi-minute scan running to completion.
//
// Stage-level counts are logged at Info so the operator can see exactly
// which stage drops candidates when the final set is smaller than expected
// (or empty). Per-IP probe failures are logged at Debug to avoid spamming
// the default-level log stream when hundreds of candidates fail.
func (r Runner) Run(ctx context.Context) (dp.FastIPSet, error) {
	log := r.logger()

	if len(r.CIDRs) == 0 {
		return dp.FastIPSet{}, fmt.Errorf("no CIDRs configured")
	}
	if r.DownloadURL == "" {
		return dp.FastIPSet{}, fmt.Errorf("no download URL configured")
	}

	sampler := cidrsample.New(r.Seed)

	// Resolve excluded prefixes: omit the field to get the built-in WARP/
	// gateway block (passes TCP but doesn't serve proxied domains), set it
	// to [] to disable, or set it to a custom list to replace the default.
	rawExcludes := r.CIDRExcludes
	if rawExcludes == nil {
		rawExcludes = cidrsample.CloudflareWARPExcludes
	}
	for _, c := range rawExcludes {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			log.Warn("cfst_pool: ignoring invalid cidr_excludes entry",
				zap.String("cidr", c), zap.Error(err))
			continue
		}
		sampler.Excludes = append(sampler.Excludes, pfx.Masked())
	}

	v4CIDRs, v6CIDRs := splitCIDRsByFamily(r.CIDRs)

	sampleCount := r.SampleCount
	if sampleCount <= 0 {
		sampleCount = 100
	}

	sampleMode := r.SampleMode
	if sampleMode != SampleModeCFST {
		sampleMode = "random"
	}

	topN := r.TopN
	if topN <= 0 {
		topN = 10
	}

	log.Info("cfst_pool: scan starting",
		zap.Int("cidrs_total", len(r.CIDRs)),
		zap.Int("v4_cidrs", len(v4CIDRs)),
		zap.Int("v6_cidrs", len(v6CIDRs)),
		zap.Int("cidr_excludes", len(sampler.Excludes)),
		zap.Bool("ipv6_enabled", r.IPv6),
		zap.Uint16("port", r.Port),
		zap.String("sample_mode", sampleMode),
		zap.Int("sample_count", sampleCount),
		zap.Int("top_n", topN),
		zap.String("download_url", r.DownloadURL),
	)

	var v4Addrs, v6Addrs []netip.Addr
	var err error
	if len(v4CIDRs) > 0 {
		// cfst mode walks every /24 (full coverage, ~5900 candidates on the
		// built-in list); otherwise draw a fixed-size random subset. IPv6
		// always samples randomly below — a /32 cannot be enumerated.
		if sampleMode == SampleModeCFST {
			v4Addrs, err = sampler.EnumerateIPv4(v4CIDRs)
		} else {
			v4Addrs, err = sampler.SampleIPv4(v4CIDRs, sampleCount)
		}
		if err != nil {
			return dp.FastIPSet{}, fmt.Errorf("sample IPv4: %w", err)
		}
	}
	if r.IPv6 && len(v6CIDRs) > 0 {
		v6Addrs, err = sampler.SampleIPv6(v6CIDRs, sampleCount)
		if err != nil {
			return dp.FastIPSet{}, fmt.Errorf("sample IPv6: %w", err)
		}
	}

	log.Info("cfst_pool: sampled candidates",
		zap.Int("v4", len(v4Addrs)),
		zap.Int("v6", len(v6Addrs)),
	)

	if err := ctx.Err(); err != nil {
		return dp.FastIPSet{}, fmt.Errorf("runner: %w", err)
	}

	tcpTimeout := r.TCPTimeout
	if tcpTimeout <= 0 {
		tcpTimeout = defaultTCPTimeout
	}
	tcp := tcping.Probe{
		PingTimes: r.PingTimes,
		Routines:  r.Routines,
		Timeout:   tcpTimeout,
		Port:      r.Port,
		FWMark:    r.FWMark,
	}
	v4Reach := tcp.Probe(ctx, v4Addrs)
	v6Reach := tcp.Probe(ctx, v6Addrs)

	logTCPStats(log, "v4", v4Addrs, v4Reach)
	if r.IPv6 {
		logTCPStats(log, "v6", v6Addrs, v6Reach)
	}

	if err := ctx.Err(); err != nil {
		return dp.FastIPSet{}, fmt.Errorf("runner: %w", err)
	}

	dlTimeout := r.DownloadTimeout
	if dlTimeout <= 0 {
		dlTimeout = defaultDownloadTimeout
	}
	dl := downspeed.Probe{
		Timeout: dlTimeout,
		HTTPS:   r.HTTPS,
		Port:    r.Port,
		FWMark:  r.FWMark,
	}

	// Probe only topN candidates by TCP latency, matching cfst's TestCount.
	// Sequential probing (inside probeDownloads) avoids tripping Cloudflare's
	// edge WAF, which 429s parallel requests from a single source.
	v4Candidates := probeDownloads(ctx, dl, v4Reach, r.DownloadURL, topN, "v4", log)
	var v6Candidates []scorer.Candidate
	if r.IPv6 {
		v6Candidates = probeDownloads(ctx, dl, v6Reach, r.DownloadURL, topN, "v6", log)
	}

	set := dp.FastIPSet{}
	for _, c := range scorer.SelectTopN(v4Candidates, topN) {
		set.IPv4 = append(set.IPv4, c.Addr)
	}
	if r.IPv6 {
		for _, c := range scorer.SelectTopN(v6Candidates, topN) {
			set.IPv6 = append(set.IPv6, c.Addr)
		}
	}

	log.Info("cfst_pool: scan complete",
		zap.Int("v4_selected", len(set.IPv4)),
		zap.Int("v6_selected", len(set.IPv6)),
	)
	return set, nil
}

// logTCPStats reports TCP probe aggregate outcomes per family. When every
// sampled IP failed, surfacing the first error explains WHY the set is
// empty (e.g. all dials refused → upstream port closed / firewall).
func logTCPStats(log *zap.Logger, family string, sampled []netip.Addr, reach []tcping.Result) {
	reachable := 0
	var firstErr error
	rtts := make([]time.Duration, 0, len(reach))
	for _, res := range reach {
		if res.Err == nil && res.AvgRTT > 0 {
			reachable++
			rtts = append(rtts, res.AvgRTT)
			continue
		}
		if firstErr == nil && res.Err != nil {
			firstErr = res.Err
		}
	}
	log.Info("cfst_pool: tcp probe complete",
		zap.String("family", family),
		zap.Int("sampled", len(sampled)),
		zap.Int("reachable", reachable),
		zap.NamedError("first_err", firstErr),
	)
	// RTT distribution at Debug — ONE line, not one-per-IP, so it stays
	// readable when thousands of IPs are reachable. Min/p50/max is enough
	// to tell whether the reachable set is uniformly fast or split between
	// a fast core and a sluggish tail (the tail then loses the download
	// stage). Per-IP RTT was deliberately dropped: it flooded Debug.
	if len(rtts) > 0 {
		slices.Sort(rtts)
		log.Debug("cfst_pool: tcp probe rtt stats",
			zap.String("family", family),
			zap.Int("reachable", len(rtts)),
			zap.Duration("min", rtts[0]),
			zap.Duration("p50", rtts[len(rtts)/2]),
			zap.Duration("max", rtts[len(rtts)-1]),
		)
	}
}

func splitCIDRsByFamily(cidrs []string) (v4, v6 []string) {
	for _, c := range cidrs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			continue
		}
		if pfx.Addr().Is4() {
			v4 = append(v4, c)
		} else {
			v6 = append(v6, c)
		}
	}
	return v4, v6
}

// probeDownloads picks the top `maxProbes` TCP-reachable IPs (by lowest
// AvgRTT), then probes them for download throughput SEQUENTIALLY.
//
// Sequential is deliberate: Cloudflare's edge WAF rate-limits parallel
// requests from a single source IP to speed.cloudflare.com and 429s them.
// cfst itself probes one IP at a time and gets 200 OK; we replicate that.
// Probing N IPs at T seconds each costs N*T wall-clock — acceptable for a
// background refresh that runs hourly.
//
// The ctx is checked between each sequential probe so a canceled scan
// (e.g. plugin shutdown) does not wait behind the remaining N-1 downloads.
//
// log and family are used to emit per-stage outcome stats. Each per-IP
// download result (success throughput and failure) is logged at Debug; the
// aggregate (success/total + sample err) is logged at Info so the operator
// can see at a glance whether the download stage is what emptied the
// candidate pool.
func probeDownloads(ctx context.Context, dl downspeed.Probe, reach []tcping.Result, downloadURL string, maxProbes int, family string, log *zap.Logger) []scorer.Candidate {
	filtered := make([]tcping.Result, 0, len(reach))
	for _, res := range reach {
		if res.Err == nil && res.AvgRTT > 0 {
			filtered = append(filtered, res)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].AvgRTT < filtered[j].AvgRTT
	})
	if len(filtered) > maxProbes {
		filtered = filtered[:maxProbes]
	}

	candidates := make([]scorer.Candidate, 0, len(filtered))
	var firstErr error
	for _, res := range filtered {
		if err := ctx.Err(); err != nil {
			log.Info("cfst_pool: download probe aborted",
				zap.String("family", family),
				zap.Int("probed", len(candidates)),
				zap.Int("remaining", len(filtered)-len(candidates)),
				zap.NamedError("err", err),
			)
			break
		}
		dlResult := dl.Probe(ctx, res.Addr.String(), downloadURL, res.Addr)
		if dlResult.Err != nil {
			if firstErr == nil {
				firstErr = dlResult.Err
			}
			log.Debug("cfst_pool: download probe failed",
				zap.String("family", family),
				zap.Stringer("addr", res.Addr),
				zap.Error(dlResult.Err),
			)
			continue
		}
		if dlResult.BytesPerSec <= 0 {
			if firstErr == nil {
				firstErr = fmt.Errorf("bytes_per_sec=%g", dlResult.BytesPerSec)
			}
			log.Debug("cfst_pool: download probe returned zero throughput",
				zap.String("family", family),
				zap.Stringer("addr", res.Addr),
				zap.Float64("bytes_per_sec", dlResult.BytesPerSec),
			)
			continue
		}
		candidates = append(candidates, scorer.Candidate{
			Addr:        res.Addr,
			AvgRTT:      res.AvgRTT,
			BytesPerSec: dlResult.BytesPerSec,
		})
		log.Debug("cfst_pool: download probe result",
			zap.String("family", family),
			zap.Stringer("addr", res.Addr),
			zap.Float64("bytes_per_sec", dlResult.BytesPerSec),
			zap.Duration("avg_rtt", res.AvgRTT),
		)
	}
	log.Info("cfst_pool: download probe complete",
		zap.String("family", family),
		zap.Int("tcp_reachable", len(filtered)),
		zap.Int("download_ok", len(candidates)),
		zap.NamedError("first_err", firstErr),
	)
	return candidates
}

// mergePrevious folds previous addrs into the fresh candidate pool, returning
// the merged slice and the number of previous addrs actually added. A previous
// addr is appended only if it is not already present in fresh (dedup) and
// matches the pool's family.
//
// The expected family is taken from the first addr in fresh, or — when fresh
// is empty — the first addr in previous. Both inputs are single-family by
// construction (v4 pools come from v4 CIDRs; the caller passes Previous.IPv4
// and Previous.IPv6 separately, already split), so this is well-defined. When
// both are empty the result is (nil, 0).
//
// This lets the previously-elected IPs re-enter the next scan as candidates so
// a still-good IP is not dropped merely because the random sampler did not
// re-draw it this round.
func mergePrevious(fresh, previous []netip.Addr) ([]netip.Addr, int) {
	if len(previous) == 0 {
		return fresh, 0
	}
	wantV6 := false
	switch {
	case len(fresh) > 0:
		wantV6 = fresh[0].Is6()
	default:
		wantV6 = previous[0].Is6()
	}
	seen := make(map[netip.Addr]struct{}, len(fresh)+len(previous))
	for _, a := range fresh {
		seen[a] = struct{}{}
	}
	out := fresh
	added := 0
	for _, a := range previous {
		if a.Is6() != wantV6 {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
		added++
	}
	return out, added
}
