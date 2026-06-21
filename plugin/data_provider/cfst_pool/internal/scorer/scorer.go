// Package scorer ranks and selects the fastest IPs from candidates.
package scorer

import (
	"net/netip"
	"sort"
	"time"
)

// Candidate is a fully-measured IP ready for ranking.
type Candidate struct {
	Addr        netip.Addr
	AvgRTT      time.Duration
	BytesPerSec float64
}

// SelectTopN returns the top `n` candidates ranked by BytesPerSec descending.
// IPs with BytesPerSec == 0 are excluded (non-zero speed contract).
// If fewer than n candidates have non-zero speed, returns all that do.
func SelectTopN(candidates []Candidate, n int) []Candidate {
	if n <= 0 || len(candidates) == 0 {
		return nil
	}
	qualified := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		if c.BytesPerSec > 0 {
			qualified = append(qualified, c)
		}
	}
	if len(qualified) == 0 {
		return nil
	}
	sort.SliceStable(qualified, func(i, j int) bool {
		return qualified[i].BytesPerSec > qualified[j].BytesPerSec
	})
	if n > len(qualified) {
		n = len(qualified)
	}
	return qualified[:n]
}
