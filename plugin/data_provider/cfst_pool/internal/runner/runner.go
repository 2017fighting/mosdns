// Package runner orchestrates the cfst pipeline:
// sample CIDRs → TCP probe → HTTP download → score → FastIPSet.
package runner

import (
	"fmt"
	"net/netip"
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
}

// Run executes the pipeline and returns the selected IPs.
func (r Runner) Run() (dp.FastIPSet, error) {
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

	tcpTimeout := r.TCPTimeout
	if tcpTimeout <= 0 {
		tcpTimeout = defaultTCPTimeout
	}
	tcp := tcping.Probe{
		PingTimes: r.PingTimes,
		Routines:  r.Routines,
		Timeout:   tcpTimeout,
		Port:      r.Port,
	}
	v4Reach := tcp.Probe(v4Addrs)
	v6Reach := tcp.Probe(v6Addrs)

	dlTimeout := r.DownloadTimeout
	if dlTimeout <= 0 {
		dlTimeout = defaultDownloadTimeout
	}
	dl := downspeed.Probe{
		Timeout: dlTimeout,
		HTTPS:   r.HTTPS,
		Port:    r.Port,
	}

	v4Candidates := make([]scorer.Candidate, 0, len(v4Reach))
	for _, res := range v4Reach {
		if res.Err != nil || res.AvgRTT <= 0 {
			continue
		}
		dlResult := dl.Probe(res.Addr.String(), r.DownloadURL, res.Addr)
		if dlResult.Err != nil {
			continue
		}
		v4Candidates = append(v4Candidates, scorer.Candidate{
			Addr:        res.Addr,
			AvgRTT:      res.AvgRTT,
			BytesPerSec: dlResult.BytesPerSec,
		})
	}

	var v6Candidates []scorer.Candidate
	for _, res := range v6Reach {
		if res.Err != nil || res.AvgRTT <= 0 {
			continue
		}
		dlResult := dl.Probe(res.Addr.String(), r.DownloadURL, res.Addr)
		if dlResult.Err != nil {
			continue
		}
		v6Candidates = append(v6Candidates, scorer.Candidate{
			Addr:        res.Addr,
			AvgRTT:      res.AvgRTT,
			BytesPerSec: dlResult.BytesPerSec,
		})
	}

	topN := r.TopN
	if topN <= 0 {
		topN = 10
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
