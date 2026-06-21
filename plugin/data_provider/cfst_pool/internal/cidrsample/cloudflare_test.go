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
