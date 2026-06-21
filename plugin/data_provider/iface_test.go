package data_provider

import (
	"net/netip"
	"testing"
)

func TestFastIPSet_EmptyAndFilled(t *testing.T) {
	var empty FastIPSet
	if len(empty.IPv4) != 0 || len(empty.IPv6) != 0 {
		t.Fatalf("zero value FastIPSet must have empty slices, got v4=%v v6=%v", empty.IPv4, empty.IPv6)
	}

	filled := FastIPSet{
		IPv4: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		IPv6: []netip.Addr{netip.MustParseAddr("2606:4700::1")},
	}
	if len(filled.IPv4) != 1 || filled.IPv4[0].String() != "1.1.1.1" {
		t.Fatalf("unexpected IPv4: %v", filled.IPv4)
	}
	if len(filled.IPv6) != 1 || filled.IPv6[0].String() != "2606:4700::1" {
		t.Fatalf("unexpected IPv6: %v", filled.IPv6)
	}
}

type stubFastIPProvider struct{ set FastIPSet }

func (s stubFastIPProvider) GetFastIPs() FastIPSet { return s.set }

func TestFastIPProvider_InterfaceConformance(t *testing.T) {
	var _ FastIPProvider = stubFastIPProvider{}
}
