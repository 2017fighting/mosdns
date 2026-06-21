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
