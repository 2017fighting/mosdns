package cidrsample

import (
	"fmt"
	"math/rand"
	"net/netip"
)

// Sampler picks candidate IPs from a list of CIDRs. A fixed seed produces a
// deterministic sequence, which keeps tests reproducible.
type Sampler struct {
	rng *rand.Rand
}

// New returns a Sampler seeded with seed. Same seed → same sequence.
func New(seed int64) *Sampler {
	return &Sampler{rng: rand.New(rand.NewSource(seed))}
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
		out = append(out, ip)
	}
	return out, nil
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
