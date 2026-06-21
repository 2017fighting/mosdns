package cfst_pool

import (
	"testing"
)

func TestArgs_Parse_HappyPath(t *testing.T) {
	yaml := `
download_seconds: 5
download_timeout: 5
sample_count: 100
download_url: https://cfst.raenzo.com/test
port: 443
ping_times: 4
routines: 200
top_n: 10
refresh_interval: 3600
cache_file: /var/lib/mosdns/cfst.json
ipv6: false
seed: 42
`
	a, err := ParseArgs([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if a.DownloadSeconds != 5 {
		t.Errorf("DownloadSeconds: want 5, got %d", a.DownloadSeconds)
	}
	if a.DownloadTimeout != 5 {
		t.Errorf("DownloadTimeout: want 5, got %d", a.DownloadTimeout)
	}
	if a.SampleCount != 100 {
		t.Errorf("SampleCount: want 100, got %d", a.SampleCount)
	}
	if a.DownloadURL != "https://cfst.raenzo.com/test" {
		t.Errorf("DownloadURL: want https://cfst.raenzo.com/test, got %s", a.DownloadURL)
	}
	if a.Port != 443 {
		t.Errorf("Port: want 443, got %d", a.Port)
	}
	if a.TopN != 10 {
		t.Errorf("TopN: want 10, got %d", a.TopN)
	}
	if a.RefreshInterval != 3600 {
		t.Errorf("RefreshInterval: want 3600, got %d", a.RefreshInterval)
	}
	if a.IPv6 {
		t.Errorf("IPv6: want false, got true")
	}
}

func TestArgs_DefaultsWhenOmitted(t *testing.T) {
	yaml := `
download_url: https://cfst.raenzo.com/test
`
	a, err := ParseArgs([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if a.SampleCount == 0 {
		t.Errorf("SampleCount should default, got 0")
	}
	if a.Port == 0 {
		t.Errorf("Port should default, got 0")
	}
}

func TestArgs_RequiredFieldsMissing(t *testing.T) {
	yaml := `sample_count: 100`
	_, err := ParseArgs([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing download_url")
	}
}

func TestArgs_FWMarkParses(t *testing.T) {
	yaml := `
download_url: https://cfst.raenzo.com/test
fwmark: 0x1
`
	a, err := ParseArgs([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if a.FWMark != 1 {
		t.Errorf("FWMark: want 1, got %d", a.FWMark)
	}
}

func TestArgs_FWMarkDefaultsToZero(t *testing.T) {
	yaml := `
download_url: https://cfst.raenzo.com/test
`
	a, err := ParseArgs([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if a.FWMark != 0 {
		t.Errorf("FWMark: want 0 when omitted, got %d", a.FWMark)
	}
}
