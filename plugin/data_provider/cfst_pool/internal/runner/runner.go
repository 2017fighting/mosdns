// Package runner orchestrates the cfst pipeline:
// sample CIDRs → TCP probe → HTTP download → score → FastIPSet.
package runner

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/cfst_pool/internal/cidrsample"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/cfst_pool/internal/downspeed"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/cfst_pool/internal/scorer"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/cfst_pool/internal/tcping"
	dp "github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
)

const (
	defaultTCPTimeout      = time.Second
	defaultDownloadTimeout = 10 * time.Second
)

// Runner is a one-shot pipeline execution.
type Runner struct {
	// CIDRs is the candidate pool. Required.
	CIDRs []string
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

	// FWMark is applied to every probe socket via SO_MARK on Linux.
	// Zero leaves sockets unmarked. Used to bypass router-level proxies
	// that would invalidate the measurement.
	FWMark uint32
}

// Run executes the pipeline and returns the selected IPs.
//
// The ctx argument is propagated into both probes (TCP ping and HTTP
// download) so the caller can abort an in-flight scan early — primarily
// used by the plugin's shutdown path so mosdns's Close is not held hostage
// to a multi-minute scan running to completion.
func (r Runner) Run(ctx context.Context) (dp.FastIPSet, error) {
	if len(r.CIDRs) == 0 {
		return dp.FastIPSet{}, fmt.Errorf("no CIDRs configured")
	}
	if r.DownloadURL == "" {
		return dp.FastIPSet{}, fmt.Errorf("no download URL configured")
	}

	sampler := cidrsample.New(r.Seed)
	v4CIDRs, v6CIDRs := splitCIDRsByFamily(r.CIDRs)

	sampleCount := r.SampleCount
	if sampleCount <= 0 {
		sampleCount = 100
	}

	var v4Addrs, v6Addrs []netip.Addr
	var err error
	if len(v4CIDRs) > 0 {
		v4Addrs, err = sampler.SampleIPv4(v4CIDRs, sampleCount)
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

	topN := r.TopN
	if topN <= 0 {
		topN = 10
	}

	// Probe only topN candidates by TCP latency, matching cfst's TestCount.
	// Sequential probing (inside probeDownloads) avoids tripping Cloudflare's
	// edge WAF, which 429s parallel requests from a single source.
	v4Candidates := probeDownloads(ctx, dl, v4Reach, r.DownloadURL, topN)
	var v6Candidates []scorer.Candidate
	if r.IPv6 {
		v6Candidates = probeDownloads(ctx, dl, v6Reach, r.DownloadURL, topN)
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
	return set, nil
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
func probeDownloads(ctx context.Context, dl downspeed.Probe, reach []tcping.Result, downloadURL string, maxProbes int) []scorer.Candidate {
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
	for _, res := range filtered {
		if err := ctx.Err(); err != nil {
			break
		}
		dlResult := dl.Probe(ctx, res.Addr.String(), downloadURL, res.Addr)
		if dlResult.Err != nil || dlResult.BytesPerSec <= 0 {
			continue
		}
		candidates = append(candidates, scorer.Candidate{
			Addr:        res.Addr,
			AvgRTT:      res.AvgRTT,
			BytesPerSec: dlResult.BytesPerSec,
		})
	}
	return candidates
}
