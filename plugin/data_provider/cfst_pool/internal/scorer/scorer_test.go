package scorer

import (
	"net/netip"
	"testing"
	"time"
)

func TestSelectTopN_IPv4_NonZeroSpeedContract(t *testing.T) {
	candidates := []Candidate{
		{Addr: netip.MustParseAddr("1.1.1.1"), AvgRTT: 10 * time.Millisecond, BytesPerSec: 1000},
		{Addr: netip.MustParseAddr("1.1.1.2"), AvgRTT: 20 * time.Millisecond, BytesPerSec: 5000}, // fastest
		{Addr: netip.MustParseAddr("1.1.1.3"), AvgRTT: 15 * time.Millisecond, BytesPerSec: 2000},
		{Addr: netip.MustParseAddr("1.1.1.4"), AvgRTT: 5 * time.Millisecond, BytesPerSec: 0}, // dropped
	}
	got := SelectTopN(candidates, 2)
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
	if got[0].Addr != netip.MustParseAddr("1.1.1.2") {
		t.Errorf("expected fastest first, got %v", got[0].Addr)
	}
	if got[1].Addr != netip.MustParseAddr("1.1.1.3") {
		t.Errorf("expected second-fastest, got %v", got[1].Addr)
	}
}

func TestSelectTopN_FewerCandidatesThanN(t *testing.T) {
	candidates := []Candidate{
		{Addr: netip.MustParseAddr("1.1.1.1"), BytesPerSec: 1000},
	}
	got := SelectTopN(candidates, 5)
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
}

func TestSelectTopN_AllZeroSpeed(t *testing.T) {
	candidates := []Candidate{
		{Addr: netip.MustParseAddr("1.1.1.1"), BytesPerSec: 0},
		{Addr: netip.MustParseAddr("1.1.1.2"), BytesPerSec: 0},
	}
	got := SelectTopN(candidates, 3)
	if len(got) != 0 {
		t.Fatalf("non-zero speed contract: want 0, got %d", len(got))
	}
}

func TestSelectTopN_StableOrderForTies(t *testing.T) {
	candidates := []Candidate{
		{Addr: netip.MustParseAddr("1.1.1.1"), BytesPerSec: 1000},
		{Addr: netip.MustParseAddr("1.1.1.2"), BytesPerSec: 1000},
	}
	got := SelectTopN(candidates, 2)
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
}
