package cidrsample

import (
	"fmt"
	"math/rand"
	"net/netip"
)

// Sampler picks candidate IPs from a list of CIDRs. A fixed seed produces a
// deterministic sequence, which keeps tests reproducible.
//
// Not safe for concurrent use. The internal *rand.Rand is not goroutine-safe;
// callers must invoke SampleIPv4/SampleIPv6 from a single goroutine or provide
// external synchronization.
type Sampler struct {
	rng *rand.Rand
	// Excludes are prefixes sampled candidates must NOT fall inside. Used to
	// drop WARP/gateway blocks that pass a TCP probe but don't serve proxied
	// customer domains. Empty (default) disables filtering.
	Excludes []netip.Prefix
}

// New returns a Sampler seeded with seed. Same seed → same sequence.
func New(seed int64) *Sampler {
	return &Sampler{rng: rand.New(rand.NewSource(seed))}
}

// isExcluded reports whether ip falls inside any Excludes prefix.
func (s *Sampler) isExcluded(ip netip.Addr) bool {
	for _, ex := range s.Excludes {
		if ex.Contains(ip) {
			return true
		}
	}
	return false
}

// SampleIPv4 picks up to count IPs from cidrs, at most one per /24. cfst uses
// this strategy so multiple candidates in the same /24 don't bias results.
func (s *Sampler) SampleIPv4(cidrs []string, count int) ([]netip.Addr, error) {
	if count <= 0 {
		return nil, nil
	}
	used := make(map[string]struct{}, count)
	out := make([]netip.Addr, 0, count)
	var attempts int
	maxAttempts := count * 50
	for len(out) < count && attempts < maxAttempts {
		attempts++
		ip, err := s.pickRandomIPv4(cidrs)
		if err != nil {
			return nil, err
		}
		pfx, err := ip.Prefix(24)
		if err != nil {
			continue
		}
		key := pfx.String()
		if _, dup := used[key]; dup {
			continue
		}
		if s.isExcluded(ip) {
			continue
		}
		used[key] = struct{}{}
		out = append(out, ip)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no IPv4 samples produced from %d CIDRs after %d attempts", len(cidrs), attempts)
	}
	return out, nil
}

// SampleIPv6 picks count IPs uniformly across cidrs. /64 grouping is too
// sparse for IPv6, so we just random-fill.
func (s *Sampler) SampleIPv6(cidrs []string, count int) ([]netip.Addr, error) {
	if count <= 0 {
		return nil, nil
	}
	out := make([]netip.Addr, 0, count)
	for i := 0; i < count; i++ {
		ip, err := s.pickRandomIPv6(cidrs)
		if err != nil {
			return nil, err
		}
		// Re-roll excluded picks. Excludes are tiny vs the IPv6 space, so a
		// handful of retries is always enough; if exhausted we accept the
		// last pick rather than failing the whole sample.
		for attempt := 0; attempt < 50 && s.isExcluded(ip); attempt++ {
			ip, err = s.pickRandomIPv6(cidrs)
			if err != nil {
				return nil, err
			}
		}
		out = append(out, ip)
	}
	return out, nil
}

// EnumerateIPv4 mirrors CloudflareSpeedTest's default (TestAll=false) IPv4
// sampling: it walks EVERY /24 contained in cidrs and picks one random host
// address per /24, giving full /24 coverage. For the built-in Cloudflare list
// this yields ~5900 candidates vs. SampleIPv4's fixed subset. A /32 collapses
// to its single host (returned verbatim, matching cfst). Excludes drop whole
// candidate picks; a fully-excluded input errors rather than returning empty.
//
// Use this when the caller wants cfst's "same as upstream" coverage. The
// runner selects it via SampleMode == "cfst"; SampleIPv4 remains the default.
func (s *Sampler) EnumerateIPv4(cidrs []string) ([]netip.Addr, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{})
	out := make([]netip.Addr, 0)
	for _, c := range cidrs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("parse CIDR %q: %w", c, err)
		}
		pfx = pfx.Masked()

		// /32 is a degenerate single host: return it verbatim, no
		// randomization (cfst's chooseIPv4 special-cases /32 the same way).
		if pfx.Bits() == 32 {
			ip := pfx.Addr()
			if s.isExcluded(ip) {
				continue
			}
			key := ip.String()
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, ip)
			continue
		}

		forEachIPv4Slash24(pfx, func(sp netip.Prefix) {
			key := sp.String()
			if _, dup := seen[key]; dup {
				return
			}
			ip := randomAddrInPrefixV4(sp, s.rng)
			if s.isExcluded(ip) {
				return
			}
			seen[key] = struct{}{}
			out = append(out, ip)
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no IPv4 addresses enumerated from %d CIDRs after excludes", len(cidrs))
	}
	return out, nil
}

// forEachIPv4Slash24 invokes fn once for every /24 prefix contained in pfx,
// which must be a masked IPv4 prefix with bits <= 24. It reproduces cfst's
// chooseIPv4 walk: the third octet steps through every value in range so each
// /24 is visited exactly once (e.g. a /13 yields 2048 blocks, a /22 yields 4).
func forEachIPv4Slash24(pfx netip.Prefix, fn func(netip.Prefix)) {
	b := pfx.Addr().As4()
	blocks := 1 << (24 - pfx.Bits())
	for i := 0; i < blocks; i++ {
		sp, _ := netip.AddrFrom4(b).Prefix(24)
		fn(sp)
		// Advance to the next /24 by incrementing the third octet, carrying
		// into the upper octets — identical to cfst's firstIP[14]++ walk.
		b[2]++
		if b[2] == 0 {
			b[1]++
			if b[1] == 0 {
				b[0]++
			}
		}
	}
}

func (s *Sampler) pickRandomIPv4(cidrs []string) (netip.Addr, error) {
	pfx, err := s.randomPrefix(cidrs)
	if err != nil {
		return netip.Addr{}, err
	}
	return randomAddrInPrefixV4(pfx, s.rng), nil
}

func (s *Sampler) pickRandomIPv6(cidrs []string) (netip.Addr, error) {
	pfx, err := s.randomPrefix(cidrs)
	if err != nil {
		return netip.Addr{}, err
	}
	return randomAddrInPrefixV6(pfx, s.rng), nil
}

func (s *Sampler) randomPrefix(cidrs []string) (netip.Prefix, error) {
	if len(cidrs) == 0 {
		return netip.Prefix{}, fmt.Errorf("no CIDRs provided")
	}
	pick := cidrs[s.rng.Intn(len(cidrs))]
	pfx, err := netip.ParsePrefix(pick)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse CIDR %q: %w", pick, err)
	}
	return pfx.Masked(), nil
}

func randomAddrInPrefixV4(pfx netip.Prefix, rng *rand.Rand) netip.Addr {
	bits := pfx.Bits()
	hostBits := 32 - bits
	base := uint32(pfx.Addr().As4()[0])<<24 |
		uint32(pfx.Addr().As4()[1])<<16 |
		uint32(pfx.Addr().As4()[2])<<8 |
		uint32(pfx.Addr().As4()[3])

	var offset uint32
	if hostBits > 0 {
		if hostBits < 32 {
			offset = rng.Uint32() & ((1 << hostBits) - 1)
		} else {
			offset = rng.Uint32()
		}
	}
	full := base | offset
	b := [4]byte{byte(full >> 24), byte(full >> 16), byte(full >> 8), byte(full)}
	return netip.AddrFrom4(b)
}

func randomAddrInPrefixV6(pfx netip.Prefix, rng *rand.Rand) netip.Addr {
	bits := pfx.Bits()
	addr := pfx.Addr().As16()
	// preserve the prefix bits, randomize the rest
	for i := bits / 8; i < 16; i++ {
		addr[i] = byte(rng.Intn(256))
	}
	// if bits isn't byte-aligned, mask the partial byte
	if rem := bits % 8; rem != 0 {
		idx := bits / 8
		mask := byte(0xFF << (8 - rem))
		addr[idx] = (addr[idx] & mask) | (byte(rng.Intn(256)) & ^mask)
	}
	return netip.AddrFrom16(addr)
}
