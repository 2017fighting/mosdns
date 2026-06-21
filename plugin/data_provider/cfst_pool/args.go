// Package cfst_pool is a mosdns data_provider plugin that runs the cfst
// (CloudflareSpeedTest) pipeline in-process and exposes the fastest IPs.
package cfst_pool

import (
	"fmt"
	"time"

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
type Args struct {
	// DownloadSeconds is the time budget per download probe. cfst -dn. Default 10.
	DownloadSeconds int `yaml:"download_seconds"`
	// DownloadTimeout bounds a single download attempt. cfst -dt. Default 10s.
	DownloadTimeout time.Duration `yaml:"download_timeout"`
	// SampleCount is the number of IPs to draw per family. cfst -n. Default 100.
	SampleCount int `yaml:"sample_count"`
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
	// RefreshInterval is the background rescan period. Default 1h.
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	// CacheFile is the on-disk persistence path. Default empty (no persistence).
	CacheFile string `yaml:"cache_file"`
	// IPv6 enables IPv6 sampling. Default false.
	IPv6 bool `yaml:"ipv6"`
	// Seed is the sampler RNG seed. Default 1 (cfst uses time-based; we prefer
	// deterministic for reproducibility).
	Seed int64 `yaml:"seed"`
	// CIDRs overrides the built-in Cloudflare list. Empty = use built-ins.
	CIDRs []string `yaml:"cidrs"`
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
	if a.SampleCount <= 0 {
		a.SampleCount = 100
	}
	if a.DownloadSeconds <= 0 {
		a.DownloadSeconds = 10
	}
	if a.DownloadTimeout <= 0 {
		a.DownloadTimeout = time.Duration(a.DownloadSeconds) * time.Second
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
	if a.RefreshInterval <= 0 {
		a.RefreshInterval = time.Hour
	}
	if a.Seed == 0 {
		a.Seed = 1
	}
	return a, nil
}
