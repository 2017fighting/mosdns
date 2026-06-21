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
}

// Probe measures throughput for one IP against testURL (whose Host is rewritten
// to the dial IP).
func (p Probe) Probe(dialIP string, testURL string, addr netip.Addr) Result {
	if p.Timeout <= 0 {
		p.Timeout = 10 * time.Second
	}
	r := Result{Addr: addr}

	parsedURL, err := url.Parse(testURL)
	if err != nil {
		r.Err = fmt.Errorf("parse URL: %w", err)
		return r
	}

	dialer := &net.Dialer{Timeout: p.Timeout}
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
	client := &http.Client{
		Transport: transport,
		Timeout:   p.Timeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		r.Err = fmt.Errorf("build request: %w", err)
		return r
	}

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
	for {
		select {
		case <-ticker.C:
			elapsed := time.Since(start).Seconds()
			if elapsed > 0 {
				instant := float64(totalRead) / elapsed
				e.Add(instant)
				r.BytesPerSec = e.Value() / (p.Timeout.Seconds() / 120)
			}
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
			r.Err = fmt.Errorf("read body: %w", readErr)
			return r
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
