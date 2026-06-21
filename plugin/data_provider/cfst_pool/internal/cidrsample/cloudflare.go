// Package cidrsample picks candidate IPs from a CIDR list.
package cidrsample

// CloudflareIPv4CIDRs is the list of IPv4 CIDRs announced by Cloudflare.
// Source: https://www.cloudflare.com/ips/ — coarse ranges for broad sampling.
// Note: cfst ships its own more granular list (ip.txt with 25 IPv4 + 100 IPv6 /48 prefixes).
var CloudflareIPv4CIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

// CloudflareIPv6CIDRs is the list of IPv6 CIDRs announced by Cloudflare.
var CloudflareIPv6CIDRs = []string{
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

// CloudflareWARPExcludes are IPv4 prefixes that terminate TLS with a
// *.cloudflareclient.com certificate and do NOT serve proxied customer
// domains. They pass a TCP-443 connect probe but fail the download probe
// (cert mismatch / reset), wasting candidate slots and occasionally tipping
// an already-thin pool to empty.
//
// 162.159.192.0/18 covers the consumer WARP client block
// (engage.cloudflareclient.com → 162.159.192.1, per Cloudflare's firewall
// docs) and the masque/gateway addresses observed in the wild
// (e.g. 162.159.199.159 presenting masque.cloudflareclient.com).
//
// Applied by default by the runner. Override via Args.CIDRExcludes; set to
// an empty list to disable exclusion entirely.
var CloudflareWARPExcludes = []string{
	"162.159.192.0/18",
}
