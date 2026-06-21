// Package downspeed measures HTTP download throughput against a single IP.
package downspeed

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/VividCortex/ewma"

	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/cfst_pool/internal/sockmark"
)

// Result is the download measurement for one IP.
type Result struct {
	Addr        netip.Addr
	Err         error
	BytesPerSec float64
}

// Probe downloads a test file through a specific IP and measures throughput.
type Probe struct {
	// Timeout bounds the full download. cfst default is 10s.
	Timeout time.Duration
	// HTTPS selects scheme. cfst default is true (https://).
	HTTPS bool
	// Port is used when constructing the dial address. 0 means default (443/80).
	Port uint16
	// DownloadMB is informational only — we read until Timeout elapses.
	DownloadMB int
	// FWMark is applied to the dial socket via SO_MARK on Linux. Zero
	// leaves the socket unmarked. Used to bypass router-level proxies
	// that would invalidate the throughput measurement.
	FWMark uint32
}

// Probe measures throughput for one IP against testURL (whose Host is rewritten
// to the dial IP).
//
// The parent ctx bounds the probe alongside the probe's own Timeout: whichever
// fires first (parent cancel or Timeout deadline) aborts the in-flight HTTP
// request via context cancellation. This lets the runner abort a long download
// promptly when the plugin is shutting down.
func (p Probe) Probe(ctx context.Context, dialIP string, testURL string, addr netip.Addr) Result {
	if p.Timeout <= 0 {
		p.Timeout = 10 * time.Second
	}
	r := Result{Addr: addr}

	parsedURL, err := url.Parse(testURL)
	if err != nil {
		r.Err = fmt.Errorf("parse URL: %w", err)
		return r
	}

	dialer := &net.Dialer{
		Control: sockmark.Control(p.FWMark),
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			port := p.Port
			if port == 0 {
				// Use port from URL if not explicitly set
				if parsedURL.Port() != "" {
					// Parse port from URL (for testing with httptest)
					_, err := fmt.Sscanf(parsedURL.Port(), "%d", &port)
					if err != nil {
						port = 80
					}
				} else {
					// Default ports for production URLs
					if p.HTTPS {
						port = 443
					} else {
						port = 80
					}
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(dialIP, fmt.Sprintf("%d", port)))
		},
	}

	// Timeout enforcement: http.Client.Timeout bounds the full request (dial +
	// TLS + headers + body read) and triggers a context cancellation that
	// aborts the body Read below. The loop's time.Since(start) check is a
	// belt-and-suspenders guard for cases where Read returns tiny chunks
	// faster than the goroutine scheduler yields to the context cancellation.
	client := &http.Client{
		Transport: transport,
		Timeout:   p.Timeout,
	}

	// Derive the request ctx from the caller-supplied ctx so a parent
	// cancellation (e.g. plugin shutdown) aborts the in-flight download
	// promptly instead of waiting for Timeout to elapse.
	reqCtx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, testURL, nil)
	if err != nil {
		r.Err = fmt.Errorf("build request: %w", err)
		return r
	}
	// Match cfst's User-Agent. Without it, Cloudflare's edge WAF 429s the
	// speed.cloudflare.com endpoint aggressively when many IPs are probed
	// in quick succession.
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		r.Err = fmt.Errorf("do request: %w", err)
		return r
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		r.Err = fmt.Errorf("status %d", resp.StatusCode)
		return r
	}

	e := ewma.NewMovingAverage()
	const tickInterval = 200 * time.Millisecond
	start := time.Now()
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	var totalRead int64
	buf := make([]byte, 32*1024)
readLoop:
	for {
		select {
		case <-ticker.C:
			elapsed := time.Since(start).Seconds()
			if elapsed > 0 {
				instant := float64(totalRead) / elapsed
				e.Add(instant)
				r.BytesPerSec = e.Value() / (p.Timeout.Seconds() / 120)
			}
		case <-reqCtx.Done():
			// Parent cancellation or Timeout deadline fired while not
			// blocked in Read. Fall through to the final EWMA computation
			// below, reporting whatever throughput was measured. Only a
			// probe that never received a payload byte is a real failure.
			break readLoop
		default:
		}
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			totalRead += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			// A non-EOF read error is the NORMAL end of a streaming speed
			// test: the payload is larger than fits in Timeout, so
			// client.Timeout / reqCtx fires mid-stream and Read returns
			// "context deadline exceeded" (or a reset on a flaky link).
			// cfst's downloadHandler breaks here and returns its accumulated
			// EWMA; we do the same, failing only when not a single payload
			// byte arrived — a genuine connect/TLS/empty-body failure, not
			// a normal cutoff. Treating the cutoff as an error is what
			// emptied the pool even for fast IPs that were mid-download.
			if totalRead == 0 {
				r.Err = fmt.Errorf("read body: %w", readErr)
				return r
			}
			break
		}
		if time.Since(start) >= p.Timeout {
			break
		}
	}

	elapsed := time.Since(start).Seconds()
	if elapsed > 0 {
		instant := float64(totalRead) / elapsed
		e.Add(instant)
		r.BytesPerSec = e.Value() / (p.Timeout.Seconds() / 120)
	}
	return r
}
