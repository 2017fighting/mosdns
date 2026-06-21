package cachefile

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	in := Data{
		Version:     1,
		RefreshedAt: time.Date(2026, 6, 21, 12, 34, 56, 0, time.UTC),
		IPv4:        []string{"104.16.1.1", "104.16.2.2"},
		IPv6:        []string{"2606:4700::1"},
	}
	if err := Save(path, in); err != nil {
		t.Fatalf("Save: %v", err)
	}

	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if out.Version != in.Version {
		t.Errorf("Version: want %d, got %d", in.Version, out.Version)
	}
	if !out.RefreshedAt.Equal(in.RefreshedAt) {
		t.Errorf("RefreshedAt: want %v, got %v", in.RefreshedAt, out.RefreshedAt)
	}
	if len(out.IPv4) != 2 || out.IPv4[0] != "104.16.1.1" {
		t.Errorf("IPv4 mismatch: %v", out.IPv4)
	}
	if len(out.IPv6) != 1 || out.IPv6[0] != "2606:4700::1" {
		t.Errorf("IPv6 mismatch: %v", out.IPv6)
	}
}

func TestSave_AtomicOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	if err := Save(path, Data{Version: 1, IPv4: []string{"1.1.1.1"}}); err != nil {
		t.Fatalf("Save v1: %v", err)
	}
	if err := Save(path, Data{Version: 2, IPv4: []string{"2.2.2.2"}}); err != nil {
		t.Fatalf("Save v2: %v", err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if out.Version != 2 {
		t.Errorf("expected v2 after overwrite, got %d", out.Version)
	}

	matches, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(matches) != 0 {
		t.Errorf("leftover temp files: %v", matches)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestToFastIPSet_Conversion(t *testing.T) {
	d := Data{
		IPv4: []string{"1.1.1.1", "1.1.1.2"},
		IPv6: []string{"2606:4700::1"},
	}
	set := d.ToFastIPSet()
	if len(set.IPv4) != 2 || set.IPv4[0] != netip.MustParseAddr("1.1.1.1") {
		t.Errorf("IPv4 conversion wrong: %v", set.IPv4)
	}
	if len(set.IPv6) != 1 || set.IPv6[0] != netip.MustParseAddr("2606:4700::1") {
		t.Errorf("IPv6 conversion wrong: %v", set.IPv6)
	}
}

func TestLoad_CorruptFileFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for corrupt file")
	}
}
