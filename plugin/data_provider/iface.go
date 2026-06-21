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

package data_provider

import (
	"net/netip"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
)

type DomainMatcherProvider interface {
	GetDomainMatcher() domain.Matcher[struct{}]
}

type IPMatcherProvider interface {
	GetIPMatcher() netlist.Matcher
}

// FastIPSet is a snapshot of the currently selected "fast" IPs, partitioned
// by address family. Values are frozen at read time; callers must not mutate.
type FastIPSet struct {
	IPv4 []netip.Addr
	IPv6 []netip.Addr
}

// FastIPProvider exposes the most recent fast-IP snapshot. Implementations
// must be safe for concurrent reads.
type FastIPProvider interface {
	GetFastIPs() FastIPSet
}
