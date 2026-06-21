package lpush

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func TestNewLPush(t *testing.T) {
	tests := []struct {
		name    string
		ips     []string
		wantErr bool
		wantV4  int
		wantV6  int
	}{
		{name: "single ipv4", ips: []string{"10.0.0.1"}, wantV4: 1},
		{name: "single ipv6", ips: []string{"::1"}, wantV6: 1},
		{name: "mixed", ips: []string{"10.0.0.1", "::1", "10.0.0.2"}, wantV4: 2, wantV6: 1},
		{name: "empty", ips: []string{}, wantV4: 0, wantV6: 0},
		{name: "invalid", ips: []string{"not-an-ip"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := NewLPush(tt.ips)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(b.ipv4) != tt.wantV4 {
				t.Errorf("ipv4 count: got %d, want %d", len(b.ipv4), tt.wantV4)
			}
			if len(b.ipv6) != tt.wantV6 {
				t.Errorf("ipv6 count: got %d, want %d", len(b.ipv6), tt.wantV6)
			}
		})
	}
}

func TestLPush_Response(t *testing.T) {
	b, err := NewLPush([]string{"10.0.0.1", "::1"})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("A query returns A records", func(t *testing.T) {
		q := new(dns.Msg)
		q.SetQuestion("example.", dns.TypeA)
		r := b.Response(q)
		if r == nil {
			t.Fatal("expected response, got nil")
		}
		if len(r.Answer) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(r.Answer))
		}
		a, ok := r.Answer[0].(*dns.A)
		if !ok {
			t.Fatalf("expected *dns.A, got %T", r.Answer[0])
		}
		if !a.A.Equal(net.ParseIP("10.0.0.1")) {
			t.Errorf("expected 10.0.0.1, got %s", a.A)
		}
	})

	t.Run("AAAA query returns AAAA records", func(t *testing.T) {
		q := new(dns.Msg)
		q.SetQuestion("example.", dns.TypeAAAA)
		r := b.Response(q)
		if r == nil {
			t.Fatal("expected response, got nil")
		}
		if len(r.Answer) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(r.Answer))
		}
		aaaa, ok := r.Answer[0].(*dns.AAAA)
		if !ok {
			t.Fatalf("expected *dns.AAAA, got %T", r.Answer[0])
		}
		if !aaaa.AAAA.Equal(net.ParseIP("::1")) {
			t.Errorf("expected ::1, got %s", aaaa.AAAA)
		}
	})

	t.Run("wrong qtype returns nil", func(t *testing.T) {
		q := new(dns.Msg)
		q.SetQuestion("example.", dns.TypeTXT)
		if r := b.Response(q); r != nil {
			t.Fatalf("expected nil, got %v", r)
		}
	})

	t.Run("multiple questions returns nil", func(t *testing.T) {
		q := new(dns.Msg)
		q.Question = []dns.Question{
			{Name: "example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			{Name: "example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		}
		if r := b.Response(q); r != nil {
			t.Fatalf("expected nil, got %v", r)
		}
	})

	t.Run("A query with only ipv6 configured returns nil", func(t *testing.T) {
		b2, _ := NewLPush([]string{"::1"})
		q := new(dns.Msg)
		q.SetQuestion("example.", dns.TypeA)
		if r := b2.Response(q); r != nil {
			t.Fatalf("expected nil, got %v", r)
		}
	})
}

func TestLPush_Exec_NoExistingResponse(t *testing.T) {
	b, err := NewLPush([]string{"10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}

	q := new(dns.Msg)
	q.SetQuestion("example.", dns.TypeA)
	qCtx := query_context.NewContext(q)

	if err := b.Exec(context.Background(), qCtx); err != nil {
		t.Fatal(err)
	}

	r := qCtx.R()
	if r == nil {
		t.Fatal("expected response, got nil")
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(r.Answer))
	}
	a := r.Answer[0].(*dns.A)
	if !a.A.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("expected 10.0.0.1, got %s", a.A)
	}
}

func TestLPush_Exec_PrependToExisting(t *testing.T) {
	b, err := NewLPush([]string{"10.0.0.1", "::1"})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("prepend to A response", func(t *testing.T) {
		q := new(dns.Msg)
		q.SetQuestion("example.", dns.TypeA)

		r := new(dns.Msg)
		r.SetReply(q)
		originalRR := &dns.A{
			Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.168.1.1"),
		}
		r.Answer = append(r.Answer, originalRR)

		qCtx := query_context.NewContext(q)
		qCtx.SetResponse(r)

		if err := b.Exec(context.Background(), qCtx); err != nil {
			t.Fatal(err)
		}

		resp := qCtx.R()
		if len(resp.Answer) != 2 {
			t.Fatalf("expected 2 answers, got %d", len(resp.Answer))
		}

		// First record should be the lpush IP
		a, ok := resp.Answer[0].(*dns.A)
		if !ok {
			t.Fatalf("expected *dns.A at position 0, got %T", resp.Answer[0])
		}
		if !a.A.Equal(net.ParseIP("10.0.0.1")) {
			t.Errorf("expected 10.0.0.1 at position 0, got %s", a.A)
		}

		// Second record should be the original
		orig, ok := resp.Answer[1].(*dns.A)
		if !ok {
			t.Fatalf("expected *dns.A at position 1, got %T", resp.Answer[1])
		}
		if !orig.A.Equal(net.ParseIP("192.168.1.1")) {
			t.Errorf("expected 192.168.1.1 at position 1, got %s", orig.A)
		}
	})

	t.Run("prepend to AAAA response", func(t *testing.T) {
		q := new(dns.Msg)
		q.SetQuestion("example.", dns.TypeAAAA)

		r := new(dns.Msg)
		r.SetReply(q)
		originalRR := &dns.AAAA{
			Hdr:  dns.RR_Header{Name: "example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP("::2"),
		}
		r.Answer = append(r.Answer, originalRR)

		qCtx := query_context.NewContext(q)
		qCtx.SetResponse(r)

		if err := b.Exec(context.Background(), qCtx); err != nil {
			t.Fatal(err)
		}

		resp := qCtx.R()
		if len(resp.Answer) != 2 {
			t.Fatalf("expected 2 answers, got %d", len(resp.Answer))
		}

		aaaa, ok := resp.Answer[0].(*dns.AAAA)
		if !ok {
			t.Fatalf("expected *dns.AAAA at position 0, got %T", resp.Answer[0])
		}
		if !aaaa.AAAA.Equal(net.ParseIP("::1")) {
			t.Errorf("expected ::1 at position 0, got %s", aaaa.AAAA)
		}
	})

	t.Run("prepend to response with multiple existing records", func(t *testing.T) {
		b2, _ := NewLPush([]string{"10.0.0.1", "10.0.0.2"})
		q := new(dns.Msg)
		q.SetQuestion("example.", dns.TypeA)

		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = append(r.Answer,
			&dns.A{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.168.1.1")},
			&dns.A{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.168.1.2")},
		)

		qCtx := query_context.NewContext(q)
		qCtx.SetResponse(r)

		if err := b2.Exec(context.Background(), qCtx); err != nil {
			t.Fatal(err)
		}

		resp := qCtx.R()
		if len(resp.Answer) != 4 {
			t.Fatalf("expected 4 answers, got %d", len(resp.Answer))
		}

		// First two should be lpush IPs
		a0 := resp.Answer[0].(*dns.A)
		if !a0.A.Equal(net.ParseIP("10.0.0.1")) {
			t.Errorf("expected 10.0.0.1 at position 0, got %s", a0.A)
		}
		a1 := resp.Answer[1].(*dns.A)
		if !a1.A.Equal(net.ParseIP("10.0.0.2")) {
			t.Errorf("expected 10.0.0.2 at position 1, got %s", a1.A)
		}
	})
}

func TestLPush_Exec_ResponseReturnsNil(t *testing.T) {
	// Configure only IPv4, but send an AAAA query with an existing response.
	// Response() returns nil, so Exec should leave the context unchanged.
	b, err := NewLPush([]string{"10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}

	q := new(dns.Msg)
	q.SetQuestion("example.", dns.TypeAAAA)

	r := new(dns.Msg)
	r.SetReply(q)
	qCtx := query_context.NewContext(q)
	qCtx.SetResponse(r)

	if err := b.Exec(context.Background(), qCtx); err != nil {
		t.Fatal(err)
	}

	// Response should still be the original (unchanged)
	resp := qCtx.R()
	if len(resp.Answer) != 0 {
		t.Fatalf("expected 0 answers, got %d", len(resp.Answer))
	}
}

func TestLPush_QuickSetup(t *testing.T) {
	v, err := QuickSetup(nil, "10.0.0.1 ::1")
	if err != nil {
		t.Fatal(err)
	}
	b, ok := v.(*LPush)
	if !ok {
		t.Fatalf("expected *LPush, got %T", v)
	}
	if len(b.ipv4) != 1 || len(b.ipv6) != 1 {
		t.Fatalf("expected 1 ipv4 and 1 ipv6, got %d ipv4 and %d ipv6", len(b.ipv4), len(b.ipv6))
	}

	_, err = QuickSetup(nil, "bad-ip")
	if err == nil {
		t.Fatal("expected error for invalid IP, got nil")
	}
}

// stubFastIPProvider implements data_provider.FastIPProvider for testing.
type stubFastIPProvider struct {
	ipv4 []netip.Addr
	ipv6 []netip.Addr
}

func (s *stubFastIPProvider) GetFastIPs() data_provider.FastIPSet {
	return data_provider.FastIPSet{
		IPv4: s.ipv4,
		IPv6: s.ipv6,
	}
}

func TestLPush_DynamicMode(t *testing.T) {
	// Create a stub provider returning known IPs.
	stubProv := &stubFastIPProvider{
		ipv4: []netip.Addr{netip.MustParseAddr("9.9.9.9")},
		ipv6: []netip.Addr{netip.MustParseAddr("2001:db8::1")},
	}

	// Register it in a test mosdns instance.
	plugins := map[string]any{
		"stub_provider": stubProv,
	}
	m := coremain.NewTestMosdnsWithPlugins(plugins)
	bq := sequence.NewBQ(m, zap.NewNop())

	t.Run("dynamic mode looks up provider", func(t *testing.T) {
		v, err := QuickSetup(bq, "$stub_provider")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		b, ok := v.(*LPush)
		if !ok {
			t.Fatalf("expected *LPush, got %T", v)
		}
		if b.provider == nil {
			t.Fatal("provider should be set in dynamic mode")
		}
		if b.provider != stubProv {
			t.Error("provider should be the stub instance")
		}
	})

	t.Run("dynamic mode unknown tag fails", func(t *testing.T) {
		_, err := QuickSetup(bq, "$nope")
		if err == nil {
			t.Fatal("expected error for unknown tag, got nil")
		}
	})

	t.Run("dynamic mode empty tag fails", func(t *testing.T) {
		_, err := QuickSetup(bq, "$")
		if err == nil {
			t.Fatal("expected error for empty tag, got nil")
		}
	})

	t.Run("dynamic mode wrong type fails", func(t *testing.T) {
		// Register a non-FastIPProvider plugin.
		plugins2 := map[string]any{
			"wrong_plugin": "not a provider",
		}
		m2 := coremain.NewTestMosdnsWithPlugins(plugins2)
		bq2 := sequence.NewBQ(m2, zap.NewNop())

		_, err := QuickSetup(bq2, "$wrong_plugin")
		if err == nil {
			t.Fatal("expected error for wrong type, got nil")
		}
	})

	t.Run("Response uses provider IPs in dynamic mode", func(t *testing.T) {
		v, err := QuickSetup(bq, "$stub_provider")
		if err != nil {
			t.Fatal(err)
		}
		b := v.(*LPush)

		// Test A query.
		q := new(dns.Msg)
		q.SetQuestion("example.", dns.TypeA)
		r := b.Response(q)
		if r == nil {
			t.Fatal("expected response, got nil")
		}
		if len(r.Answer) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(r.Answer))
		}
		a, ok := r.Answer[0].(*dns.A)
		if !ok {
			t.Fatalf("expected *dns.A, got %T", r.Answer[0])
		}
		if !a.A.Equal(net.ParseIP("9.9.9.9")) {
			t.Errorf("expected 9.9.9.9, got %s", a.A)
		}

		// Test AAAA query.
		q6 := new(dns.Msg)
		q6.SetQuestion("example.", dns.TypeAAAA)
		r6 := b.Response(q6)
		if r6 == nil {
			t.Fatal("expected response, got nil")
		}
		if len(r6.Answer) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(r6.Answer))
		}
		aaaa, ok := r6.Answer[0].(*dns.AAAA)
		if !ok {
			t.Fatalf("expected *dns.AAAA, got %T", r6.Answer[0])
		}
		if !aaaa.AAAA.Equal(net.ParseIP("2001:db8::1")) {
			t.Errorf("expected 2001:db8::1, got %s", aaaa.AAAA)
		}
	})

	t.Run("dynamic mode Exec works correctly", func(t *testing.T) {
		v, err := QuickSetup(bq, "$stub_provider")
		if err != nil {
			t.Fatal(err)
		}
		b := v.(*LPush)

		q := new(dns.Msg)
		q.SetQuestion("example.", dns.TypeA)
		qCtx := query_context.NewContext(q)

		if err := b.Exec(context.Background(), qCtx); err != nil {
			t.Fatal(err)
		}

		r := qCtx.R()
		if r == nil {
			t.Fatal("expected response, got nil")
		}
		if len(r.Answer) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(r.Answer))
		}
		a := r.Answer[0].(*dns.A)
		if !a.A.Equal(net.ParseIP("9.9.9.9")) {
			t.Errorf("expected 9.9.9.9, got %s", a.A)
		}
	})

	t.Run("literal mode preserves existing behavior", func(t *testing.T) {
		v, err := QuickSetup(bq, "1.1.1.1")
		if err != nil {
			t.Fatal(err)
		}
		b, ok := v.(*LPush)
		if !ok {
			t.Fatalf("expected *LPush, got %T", v)
		}
		if len(b.ipv4) != 1 {
			t.Fatalf("expected 1 ipv4, got %d", len(b.ipv4))
		}
		expectedIP := netip.MustParseAddr("1.1.1.1")
		if b.ipv4[0] != expectedIP {
			t.Errorf("expected 1.1.1.1, got %s", b.ipv4[0])
		}
		if b.provider != nil {
			t.Error("provider should be nil in literal mode")
		}
	})
}
