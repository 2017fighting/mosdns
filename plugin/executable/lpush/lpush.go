/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package lpush

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

const PluginType = "lpush"

const tagPrefix = "$"

func init() {
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

var _ sequence.Executable = (*LPush)(nil)

type LPush struct {
	ipv4 []netip.Addr
	ipv6 []netip.Addr

	// provider is set in dynamic mode ($tag). When non-nil, Exec/Response
	// pull live IPs from it instead of using the static slices.
	provider data_provider.FastIPProvider
}

// QuickSetup format: either literal IPs ("1.1.1.1 1.0.0.1") OR "$tag" referencing
// a FastIPProvider plugin.
func QuickSetup(bq sequence.BQ, s string) (any, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, tagPrefix) {
		return newDynamicLPush(bq, strings.TrimSpace(strings.TrimPrefix(s, tagPrefix)))
	}
	return NewLPush(strings.Fields(s))
}

// NewLPush creates a new LPush with given literal ips.
func NewLPush(ips []string) (*LPush, error) {
	b := &LPush{}
	for _, s := range ips {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("invalid addr %s, %w", s, err)
		}
		if addr.Is4() {
			b.ipv4 = append(b.ipv4, addr)
		} else {
			b.ipv6 = append(b.ipv6, addr)
		}
	}
	return b, nil
}

// newDynamicLPush looks up a FastIPProvider plugin by tag.
func newDynamicLPush(bq sequence.BQ, tag string) (*LPush, error) {
	if tag == "" {
		return nil, fmt.Errorf("lpush: empty plugin tag after %q", tagPrefix)
	}
	p := bq.M().GetPlugin(tag)
	if p == nil {
		return nil, fmt.Errorf("lpush: plugin %q not found", tag)
	}
	prov, ok := p.(data_provider.FastIPProvider)
	if !ok {
		return nil, fmt.Errorf("lpush: plugin %q does not implement FastIPProvider (got %T)", tag, p)
	}
	return &LPush{provider: prov}, nil
}

// currentIPv4 / currentIPv6 unify access between literal and dynamic modes.
func (b *LPush) currentIPv4() []netip.Addr {
	if b.provider != nil {
		return b.provider.GetFastIPs().IPv4
	}
	return b.ipv4
}

func (b *LPush) currentIPv6() []netip.Addr {
	if b.provider != nil {
		return b.provider.GetFastIPs().IPv6
	}
	return b.ipv6
}

// Exec implements sequence.Executable. Behavior preserved from existing code,
// except it pulls from currentIPv4/currentIPv6 so dynamic mode works.
func (b *LPush) Exec(_ context.Context, qCtx *query_context.Context) error {
	r := b.Response(qCtx.Q())
	if r == nil {
		return nil
	}

	if existing := qCtx.R(); existing != nil {
		newAns := make([]dns.RR, len(r.Answer), len(r.Answer)+len(existing.Answer))
		copy(newAns, r.Answer)
		newAns = append(newAns, existing.Answer...)
		existing.Answer = newAns
	} else {
		qCtx.SetResponse(r)
	}
	return nil
}

// Response returns a response with given ips if query has corresponding qtypes.
// Uses currentIPv4/currentIPv6 so dynamic mode is transparent.
func (b *LPush) Response(q *dns.Msg) *dns.Msg {
	if len(q.Question) != 1 {
		return nil
	}

	qName := q.Question[0].Name
	qtype := q.Question[0].Qtype
	ipv4 := b.currentIPv4()
	ipv6 := b.currentIPv6()

	switch {
	case qtype == dns.TypeA && len(ipv4) > 0:
		r := new(dns.Msg)
		r.SetReply(q)
		for _, addr := range ipv4 {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   qName,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: addr.AsSlice(),
			}
			r.Answer = append(r.Answer, rr)
		}
		return r

	case qtype == dns.TypeAAAA && len(ipv6) > 0:
		r := new(dns.Msg)
		r.SetReply(q)
		for _, addr := range ipv6 {
			rr := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   qName,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: addr.AsSlice(),
			}
			r.Answer = append(r.Answer, rr)
		}
		return r
	}
	return nil
}
