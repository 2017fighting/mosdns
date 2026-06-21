// Package cfst_pool is a mosdns data_provider plugin that runs the cfst
// (CloudflareSpeedTest) pipeline in-process and exposes the fastest IPs.
package cfst_pool

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Args is the plugin's YAML config shape.
//
// It mirrors the user's cfst CLI invocation:
//
//	cfst -dn 5 -dt 5 -n 100 -url https://cfst.raenzo.com/test
//
// mapping:
//
//	-n    → sample_count
//	-dn   → download_seconds
//	-dt   → download_timeout
//	-url  → download_url
//
// Duration fields (download_seconds, download_timeout, refresh_interval) are
// expressed as integer SECONDS, not Go time.Duration strings. mosdns core
// decodes plugin args via mapstructure with WeaklyTypedInput, which would
// silently turn a bare YAML int into nanoseconds when the target field is
// time.Duration (so `download_timeout: 5` becomes 5ns, breaking every
// probe). Using int seconds sidesteps that footgun.
type Args struct {
	// DownloadSeconds is the time budget per download probe. cfst -dn. Default 10.
	DownloadSeconds int `yaml:"download_seconds"`
	// DownloadTimeout bounds a single download attempt, in seconds. cfst -dt. Default = DownloadSeconds.
	DownloadTimeout int `yaml:"download_timeout"`
	// SampleCount is the number of IPs to draw per family. cfst -n. Default 100.
	// Ignored for IPv4 when sample_mode is "cfst" (full /24 coverage).
	SampleCount int `yaml:"sample_count"`
	// SampleMode selects the IPv4 sampling strategy. "" or "random" (default)
	// draws SampleCount IPs at most one per /24; "cfst" mirrors
	// CloudflareSpeedTest's default walk over every /24 for full coverage
	// (~5900 candidates on the built-in list). IPv6 always samples randomly.
	SampleMode string `yaml:"sample_mode"`
	// DownloadURL is the test file URL. Required.
	DownloadURL string `yaml:"download_url"`
	// Port is the TCP port to probe. Default 443.
	Port uint16 `yaml:"port"`
	// PingTimes is TCP probes per IP. Default 4.
	PingTimes int `yaml:"ping_times"`
	// Routines bounds concurrency. Default 200.
	Routines int `yaml:"routines"`
	// TopN is how many IPs per family to retain. Default 10.
	TopN int `yaml:"top_n"`
	// RefreshInterval is the background rescan period, in seconds. Default
	// 21600 (6h): cfst-mode scans test ~5900 IPs and are heavier than the
	// random subset, so the default is sized for that. Set lower for random
	// mode if you want fresher results.
	RefreshInterval int `yaml:"refresh_interval"`
	// CacheFile is the on-disk persistence path. Default empty (no persistence).
	CacheFile string `yaml:"cache_file"`
	// IPv6 enables IPv6 sampling. Default false.
	IPv6 bool `yaml:"ipv6"`
	// Seed is the sampler RNG seed. Default 1 (cfst uses time-based; we prefer
	// deterministic for reproducibility).
	Seed int64 `yaml:"seed"`
	// CIDRs overrides the built-in Cloudflare list. Empty = use built-ins.
	CIDRs []string `yaml:"cidrs"`
	// CIDRExcludes are prefixes to exclude from sampling. Omit (nil) to get
	// the built-in WARP/gateway block (recommended; those ranges pass TCP
	// but don't serve proxied customer domains); set to [] to disable; or
	// list your own to replace the default.
	CIDRExcludes []string `yaml:"cidr_excludes"`
	// FWMark is the Linux SO_MARK value applied to every probe socket
	// (both TCP ping and HTTP download). Non-zero lets an operator write
	// an ip-rule/iptables exemption on a router with a global proxy so
	// the speed-test traffic bypasses the proxy — measuring it through
	// the proxy would defeat the entire point of cfst. Zero (default)
	// leaves the socket unmarked. No-op on non-Linux.
	FWMark uint32 `yaml:"fwmark"`
}

// applyDefaults fills in zero-valued fields with the documented defaults.
// Called by ParseArgs (test path) and Init (production path, since mosdns
// core's WeakDecode bypasses ParseArgs).
func (a *Args) applyDefaults() {
	if a.SampleCount <= 0 {
		a.SampleCount = 100
	}
	if a.DownloadSeconds <= 0 {
		a.DownloadSeconds = 10
	}
	if a.DownloadTimeout <= 0 {
		a.DownloadTimeout = a.DownloadSeconds
	}
	if a.Port == 0 {
		a.Port = 443
	}
	if a.PingTimes <= 0 {
		a.PingTimes = 4
	}
	if a.Routines <= 0 {
		a.Routines = 200
	}
	if a.TopN <= 0 {
		a.TopN = 10
	}
	if a.SampleMode == "" {
		a.SampleMode = "random"
	}
	if a.RefreshInterval <= 0 {
		a.RefreshInterval = 21600 // 6h
	}
	if a.Seed == 0 {
		a.Seed = 1
	}
}

// ParseArgs deserializes YAML and applies defaults.
func ParseArgs(b []byte) (Args, error) {
	var a Args
	if err := yaml.Unmarshal(b, &a); err != nil {
		return Args{}, fmt.Errorf("parse cfst_pool args: %w", err)
	}
	if a.DownloadURL == "" {
		return Args{}, fmt.Errorf("cfst_pool: download_url is required")
	}
	a.applyDefaults()
	return a, nil
}
