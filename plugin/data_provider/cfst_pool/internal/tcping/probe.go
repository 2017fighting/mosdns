// Package tcping probes TCP connect latency for a batch of IPs.
package tcping

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/cfst_pool/internal/sockmark"
)

// Result is the latency measurement for one IP.
type Result struct {
	Addr   netip.Addr
	Err    error
	AvgRTT time.Duration
}

// Probe runs TCP connect probes against a list of IPs.
type Probe struct {
	// PingTimes is the number of TCP connect attempts per IP. cfst default is 4.
	PingTimes int
	// Routines bounds concurrency. cfst default is 200.
	Routines int
	// Timeout per connect attempt. cfst default is 1s.
	Timeout time.Duration
	// Port is the TCP port to probe (e.g. 443).
	Port uint16
	// FWMark is applied to each probe socket via SO_MARK on Linux. Zero
	// leaves the socket unmarked. Used to bypass router-level proxies
	// that would invalidate the measurement.
	FWMark uint32
}

// Probe returns one Result per input addr, in input order. Unreachable IPs
// have a non-nil Err and zero AvgRTT.
//
// Safe for concurrent use by multiple goroutines only if each goroutine has
// its own Probe value; the method itself does not mutate Probe state.
func (p Probe) Probe(addrs []netip.Addr) []Result {
	if len(addrs) == 0 {
		return nil
	}
	if p.PingTimes <= 0 {
		p.PingTimes = 4
	}
	if p.Routines <= 0 {
		p.Routines = 200
	}
	if p.Timeout <= 0 {
		p.Timeout = time.Second
	}

	results := make([]Result, len(addrs))
	sem := make(chan struct{}, p.Routines)
	var wg sync.WaitGroup

	for i, addr := range addrs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, addr netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()

			results[i] = p.probeOne(addr)
		}(i, addr)
	}
	wg.Wait()
	return results
}

func (p Probe) probeOne(addr netip.Addr) Result {
	var sumRTT time.Duration
	var lastErr error
	successes := 0
	ap := netip.AddrPortFrom(addr, p.Port)
	// Dialer (vs net.DialTimeout) so we can install a Control hook that
	// applies SO_MARK before connect(). FWMark=0 → Control returns nil →
	// net.Dialer skips the callback, zero overhead on the unmarked path.
	dialer := &net.Dialer{
		Timeout:  p.Timeout,
		Control:  sockmark.Control(p.FWMark),
	}
	for i := 0; i < p.PingTimes; i++ {
		start := time.Now()
		conn, err := dialer.Dial("tcp", ap.String())
		elapsed := time.Since(start)
		if err != nil {
			lastErr = err
			continue
		}
		conn.Close()
		sumRTT += elapsed
		successes++
	}
	r := Result{Addr: addr}
	if successes == 0 {
		r.Err = lastErr
		return r
	}
	r.AvgRTT = sumRTT / time.Duration(successes)
	return r
}
