package cidrsample

import (
	"net/netip"
	"testing"
)

func TestCloudflareCIDRs_ParseAndNonEmpty(t *testing.T) {
	if len(CloudflareIPv4CIDRs) == 0 {
		t.Fatal("CloudflareIPv4CIDRs must not be empty")
	}
	if len(CloudflareIPv6CIDRs) == 0 {
		t.Fatal("CloudflareIPv6CIDRs must not be empty")
	}

	for _, c := range CloudflareIPv4CIDRs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			t.Errorf("invalid IPv4 CIDR %q: %v", c, err)
			continue
		}
		if pfx.Addr().Is6() {
			t.Errorf("CIDR %q parsed as IPv6, expected IPv4", c)
		}
	}

	for _, c := range CloudflareIPv6CIDRs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			t.Errorf("invalid IPv6 CIDR %q: %v", c, err)
			continue
		}
		if pfx.Addr().Is4() {
			t.Errorf("CIDR %q parsed as IPv4, expected IPv6", c)
		}
	}
}

func TestSampler_IPv4OnePerSlash24(t *testing.T) {
	s := New(42)
	got, err := s.SampleIPv4([]string{"104.16.0.0/13"}, 100)
	if err != nil {
		t.Fatalf("SampleIPv4: %v", err)
	}
	if len(got) != 100 {
		t.Fatalf("want 100 IPs, got %d", len(got))
	}

	seen := make(map[string]struct{}, len(got))
	for _, ip := range got {
		pfx, _ := ip.Prefix(24)
		key := pfx.String()
		if _, dup := seen[key]; dup {
			t.Fatalf("duplicate /24 %s in sample", key)
		}
		seen[key] = struct{}{}
	}
}

func TestSampler_IPv6RandomFill(t *testing.T) {
	s := New(42)
	got, err := s.SampleIPv6([]string{"2606:4700::/32"}, 50)
	if err != nil {
		t.Fatalf("SampleIPv6: %v", err)
	}
	if len(got) != 50 {
		t.Fatalf("want 50 IPs, got %d", len(got))
	}
	for _, ip := range got {
		if !ip.Is6() || ip.Is4In6() {
			t.Errorf("got non-IPv6: %v", ip)
		}
	}
}

func TestSampler_DeterministicSeed(t *testing.T) {
	a, _ := New(7).SampleIPv4(CloudflareIPv4CIDRs, 10)
	b, _ := New(7).SampleIPv4(CloudflareIPv4CIDRs, 10)
	if len(a) != len(b) {
		t.Fatalf("lengths differ")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("seed 7 produced different sequences at index %d: %s vs %s", i, a[i], b[i])
		}
	}
}

func TestSampler_MoreSamplesThanCIDRsAllows(t *testing.T) {
	// 104.16.0.0/13 has 2^(24-13) = 2048 /24s, so 1500 fits.
	// This tests that we can handle larger sample counts without hitting maxAttempts.
	s := New(1)
	got, err := s.SampleIPv4([]string{"104.16.0.0/13"}, 1500)
	if err != nil {
		t.Fatalf("SampleIPv4 large: %v", err)
	}
	if len(got) != 1500 {
		t.Fatalf("want 1500, got %d", len(got))
	}
}

func TestSampler_InvalidCIDR(t *testing.T) {
	s := New(1)
	_, err := s.SampleIPv4([]string{"not-a-cidr"}, 1)
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

// TestSampler_IPv4ExcludesPrefix verifies sampled candidates never fall in an
// excluded prefix. The WARP/gateway blocks (e.g. 162.159.192.0/18) pass TCP-443
// but don't serve proxied customer domains — presenting a *.cloudflareclient.com
// cert — so they must be filtered out before wasting download-probe slots.
func TestSampler_IPv4ExcludesPrefix(t *testing.T) {
	// Sample a /16 but exclude its lower half (/17). Without filtering,
	// ~half the samples land in the excluded range, so this reliably
	// catches a missing exclude check (0.5^100 ≈ 0 chance of false green).
	s := New(42)
	s.Excludes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/17")}
	got, err := s.SampleIPv4([]string{"10.0.0.0/16"}, 100)
	if err != nil {
		t.Fatalf("SampleIPv4: %v", err)
	}
	if len(got) != 100 {
		t.Fatalf("want 100 IPs, got %d", len(got))
	}
	for _, ip := range got {
		if s.Excludes[0].Contains(ip) {
			t.Errorf("sampled IP %s falls in excluded prefix %s", ip, s.Excludes[0])
		}
	}
}

// TestCloudflareWARPExcludes_Parse ensures the built-in WARP exclude list is
// syntactically valid and covers a known WARP endpoint (engage.cloudflareclient.com
// resolves inside 162.159.192.0/24) plus the masque cert IP observed in the wild.
func TestCloudflareWARPExcludes_Parse(t *testing.T) {
	if len(CloudflareWARPExcludes) == 0 {
		t.Fatal("CloudflareWARPExcludes must not be empty")
	}
	coversEngage := false
	coversObserved := false
	observed := netip.MustParseAddr("162.159.199.159")
	for _, c := range CloudflareWARPExcludes {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			t.Errorf("invalid WARP exclude CIDR %q: %v", c, err)
			continue
		}
		if pfx.Contains(netip.MustParseAddr("162.159.192.1")) {
			coversEngage = true
		}
		if pfx.Contains(observed) {
			coversObserved = true
		}
	}
	if !coversEngage {
		t.Error("WARP excludes do not cover engage.cloudflareclient.com (162.159.192.1)")
	}
	if !coversObserved {
		t.Error("WARP excludes do not cover observed masque cert IP 162.159.199.159")
	}
}
