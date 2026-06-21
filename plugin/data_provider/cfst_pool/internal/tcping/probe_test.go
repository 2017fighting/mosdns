package tcping

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestProbe_ReachableHostRTT(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	p := Probe{
		PingTimes: 3,
		Routines:  4,
		Timeout:   500 * time.Millisecond,
		Port:      port,
	}
	results := p.Probe([]netip.Addr{netip.MustParseAddr("127.0.0.1")})

	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Addr != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("unexpected addr: %v", r.Addr)
	}
	if r.Err != nil {
		t.Errorf("unexpected error: %v", r.Err)
	}
	if r.AvgRTT <= 0 {
		t.Errorf("expected positive RTT, got %v", r.AvgRTT)
	}
}

func TestProbe_UnreachableHostFails(t *testing.T) {
	// 127.0.0.1:1 typically refuses — connection refused.
	p := Probe{
		PingTimes: 2,
		Routines:  2,
		Timeout:   200 * time.Millisecond,
		Port:      1,
	}
	results := p.Probe([]netip.Addr{netip.MustParseAddr("127.0.0.1")})
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Err == nil {
		t.Errorf("expected error for unreachable port, got nil (RTT=%v)", results[0].AvgRTT)
	}
}

func TestProbe_ConcurrencyBounded(t *testing.T) {
	// Spin up 10 listeners and verify all 10 are probed successfully even with Routines=3.
	lns := make([]net.Listener, 10)
	addrs := make([]netip.Addr, 10)
	for i := range lns {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen %d: %v", i, err)
		}
		lns[i] = ln
		addrs[i] = netip.MustParseAddr(ln.Addr().(*net.TCPAddr).IP.String())
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}
	defer func() {
		for _, ln := range lns {
			ln.Close()
		}
	}()

	p := Probe{
		PingTimes: 1,
		Routines:  3,
		Timeout:   500 * time.Millisecond,
		Port:      uint16(lns[0].Addr().(*net.TCPAddr).Port),
	}
	results := p.Probe(addrs)
	if len(results) != 10 {
		t.Fatalf("want 10 results, got %d", len(results))
	}
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("unexpected error for %v: %v", r.Addr, r.Err)
		}
	}
}
