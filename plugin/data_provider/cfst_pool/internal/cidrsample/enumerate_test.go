package cidrsample

import (
	"net/netip"
	"testing"
)

// EnumerateIPv4 reproduces CloudflareSpeedTest's default (TestAll=false) IPv4
// sampling: walk EVERY /24 in the CIDRs and take one random IP per /24. These
// tests pin that behavior so it cannot silently drift back toward the
// fixed-size random subset of SampleIPv4.

func TestEnumerateIPv4_SingleHost(t *testing.T) {
	// /32 is degenerate: cfst returns it verbatim (no randomization), so
	// 10.0.0.5/32 must yield exactly [10.0.0.5].
	s := New(42)
	got, err := s.EnumerateIPv4([]string{"10.0.0.5/32"})
	if err != nil {
		t.Fatalf("EnumerateIPv4: %v", err)
	}
	if len(got) != 1 || got[0] != netip.MustParseAddr("10.0.0.5") {
		t.Fatalf("want [10.0.0.5], got %v", got)
	}
}

func TestEnumerateIPv4_Slash22FourBlocks(t *testing.T) {
	// 10.0.0.0/22 spans 4 /24s; cfst walks each one and picks one IP per /24.
	s := New(42)
	got, err := s.EnumerateIPv4([]string{"10.0.0.0/22"})
	if err != nil {
		t.Fatalf("EnumerateIPv4: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 IPs (one per /24 in a /22), got %d", len(got))
	}
	want := map[string]bool{
		"10.0.0.0/24": false, "10.0.1.0/24": false,
		"10.0.2.0/24": false, "10.0.3.0/24": false,
	}
	for _, ip := range got {
		sp, _ := ip.Prefix(24)
		k := sp.String()
		seen, ok := want[k]
		if !ok {
			t.Errorf("IP %s landed in unexpected /24 %s", ip, k)
		}
		if seen {
			t.Errorf("/24 %s covered twice", k)
		}
		want[k] = true
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("missing expected /24 %s", k)
		}
	}
}

func TestEnumerateIPv4_Slash13AllBlocks(t *testing.T) {
	// 104.16.0.0/13 spans 2^(24-13) = 2048 /24s. Every /24 must be covered
	// exactly once (cfst's deterministic walk), each contributing one IP.
	s := New(7)
	got, err := s.EnumerateIPv4([]string{"104.16.0.0/13"})
	if err != nil {
		t.Fatalf("EnumerateIPv4: %v", err)
	}
	if len(got) != 2048 {
		t.Fatalf("want 2048 IPs, got %d", len(got))
	}
	seen := make(map[string]struct{}, len(got))
	for _, ip := range got {
		sp, _ := ip.Prefix(24)
		k := sp.String()
		if _, dup := seen[k]; dup {
			t.Fatalf("duplicate /24 %s — enumeration must cover each /24 once", k)
		}
		seen[k] = struct{}{}
	}
}

func TestEnumerateIPv4_ExcludesPrefix(t *testing.T) {
	// 10.0.0.0/16 = 256 /24s; exclude the lower /17 (128 /24s). cfst-mode
	// enumeration must skip every excluded /24, leaving exactly 128 IPs,
	// all in the upper half.
	s := New(42)
	s.Excludes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/17")}
	got, err := s.EnumerateIPv4([]string{"10.0.0.0/16"})
	if err != nil {
		t.Fatalf("EnumerateIPv4: %v", err)
	}
	if len(got) != 128 {
		t.Fatalf("want 128 IPs after excluding a /17 from a /16, got %d", len(got))
	}
	ex := s.Excludes[0]
	for _, ip := range got {
		if ex.Contains(ip) {
			t.Errorf("enumerated IP %s falls in excluded %s", ip, ex)
		}
	}
}

func TestEnumerateIPv4_DeterministicSeed(t *testing.T) {
	a, err := New(7).EnumerateIPv4([]string{"104.16.0.0/13"})
	if err != nil {
		t.Fatalf("EnumerateIPv4 a: %v", err)
	}
	b, err := New(7).EnumerateIPv4([]string{"104.16.0.0/13"})
	if err != nil {
		t.Fatalf("EnumerateIPv4 b: %v", err)
	}
	if len(a) != len(b) {
		t.Fatalf("lengths differ: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("seed 7 diverged at index %d: %s vs %s", i, a[i], b[i])
		}
	}
}

func TestEnumerateIPv4_InvalidCIDR(t *testing.T) {
	s := New(1)
	if _, err := s.EnumerateIPv4([]string{"not-a-cidr"}); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestEnumerateIPv4_EmptyInput(t *testing.T) {
	s := New(1)
	got, err := s.EnumerateIPv4(nil)
	if err != nil {
		t.Fatalf("empty input should not error: %v", err)
	}
	if got != nil {
		t.Fatalf("empty input should return nil, got %v", got)
	}
}

func TestEnumerateIPv4_AllExcludedErrors(t *testing.T) {
	// When every candidate is excluded, enumeration yields nothing and must
	// surface an error (mirrors SampleIPv4's contract) instead of a silent
	// empty slice the runner would mistake for success.
	s := New(1)
	s.Excludes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	if _, err := s.EnumerateIPv4([]string{"10.0.0.0/24"}); err == nil {
		t.Fatal("expected error when every enumerated IP is excluded")
	}
}

func TestEnumerateIPv4_CloudflareListFullCoverage(t *testing.T) {
	// The built-in Cloudflare list expands to thousands of /24s; cfst-mode
	// must cover them all (this is the "same as upstream" property the
	// feature exists for). Assert a large count plus per-/24 uniqueness
	// rather than an exact number, which would couple the test to the list.
	s := New(1)
	got, err := s.EnumerateIPv4(CloudflareIPv4CIDRs)
	if err != nil {
		t.Fatalf("EnumerateIPv4 Cloudflare: %v", err)
	}
	if len(got) <= 1000 {
		t.Fatalf("cfst-mode must cover far more /24s than random sampling; got only %d", len(got))
	}
	seen := make(map[string]struct{}, len(got))
	for _, ip := range got {
		sp, _ := ip.Prefix(24)
		k := sp.String()
		if _, dup := seen[k]; dup {
			t.Fatalf("duplicate /24 %s in Cloudflare enumeration", k)
		}
		seen[k] = struct{}{}
	}
}
