// Package cachefile persists cfst_pool results to a JSON file.
package cachefile

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// Data is the JSON shape of the on-disk cache. Sample:
//
//	{
//	  "version": 1,
//	  "refreshed_at": "2026-06-21T12:34:56Z",
//	  "ipv4": ["104.16.1.1", "104.16.2.2"],
//	  "ipv6": ["2606:4700::1", "2606:4700::2"]
//	}
type Data struct {
	Version     int       `json:"version"`
	RefreshedAt time.Time `json:"refreshed_at"`
	IPv4        []string  `json:"ipv4"`
	IPv6        []string  `json:"ipv6"`
}

// Load reads the cache file. Returns an error if the file is missing or
// corrupt — callers must handle this (e.g. by triggering a fresh scan).
func Load(path string) (Data, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Data{}, fmt.Errorf("read cache %s: %w", path, err)
	}
	var d Data
	if err := json.Unmarshal(b, &d); err != nil {
		return Data{}, fmt.Errorf("parse cache %s: %w", path, err)
	}
	return d, nil
}

// Save writes data atomically: write to temp file in same dir, then rename.
// The temp file lives next to the target so the rename is guaranteed to be
// on the same filesystem.
func Save(path string, data Data) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".cfst-cache-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}

	if _, err := tmp.Write(b); err != nil {
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename temp→%s: %w", path, err)
	}
	return nil
}

// ToFastIPSet converts the string-form cache into a FastIPSet of netip.Addr.
// Invalid IPs are skipped silently — they shouldn't happen, but we don't
// trust the on-disk format to be perfectly clean.
func (d Data) ToFastIPSet() FastIPSet {
	var set FastIPSet
	for _, s := range d.IPv4 {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if ip.Is4() {
			set.IPv4 = append(set.IPv4, ip)
		}
	}
	for _, s := range d.IPv6 {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if ip.Is6() {
			set.IPv6 = append(set.IPv6, ip)
		}
	}
	return set
}

// FastIPSet is re-declared here to avoid an import cycle between cachefile
// and the top-level data_provider package. The plugin converts between them
// at the boundary. (Alternative: move FastIPSet into its own package; deferred
// per YAGNI until a second consumer appears.)
type FastIPSet struct {
	IPv4 []netip.Addr
	IPv6 []netip.Addr
}
