package nowhere

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

// dialAuto is the only non-literal value accepted by the dial parameters. An
// empty value means the same thing, following the mihomo schema convention for
// optional strings.
const dialAuto = "auto"

var (
	errDialFamilyConflict = errors.New("target address family conflicts with dial")
	errDialNoAddr         = errors.New("no target address matches the configured address family")
)

// DialPolicy is the outbound source-address policy. It mirrors the Rust
// reference common::dial::DialPolicy: either a single legacy source that also
// restricts the address family, or the dual-stack form where each family gets
// its own source and the family follows the resolved target. The zero value is
// the automatic policy — no source binding and no family restriction.
type DialPolicy struct {
	legacy netip.Addr
	v4     netip.Addr
	v6     netip.Addr
	dual   bool
}

// ParseDialPolicy validates the dial/dial4/dial6 parameters the way the Rust
// DialPolicy::from_query does. The legacy single-source form is mutually
// exclusive with the dual-stack pair; dial4 must be an IPv4 literal, dial6 an
// IPv6 literal that is not IPv4-mapped, and 0.0.0.0/:: are accepted as
// wildcards. A nowhere surface exposes only the dual-stack pair, so its legacy
// value is empty.
func ParseDialPolicy(dial, dial4, dial6 string) (DialPolicy, error) {
	if dial != "" && (dial4 != "" || dial6 != "") {
		return DialPolicy{}, errors.New("dial and dial4/dial6 are mutually exclusive")
	}
	if dial4 == "" && dial6 == "" {
		return parseLegacyDialPolicy(dial)
	}
	var policy DialPolicy
	policy.dual = true
	if dial4 != "" && dial4 != dialAuto {
		addr, err := netip.ParseAddr(dial4)
		if err != nil || !addr.Is4() {
			return DialPolicy{}, errors.New("dial4 must be auto or an IPv4 literal")
		}
		policy.v4 = addr
	}
	if dial6 != "" && dial6 != dialAuto {
		addr, err := netip.ParseAddr(dial6)
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return DialPolicy{}, errors.New("dial6 must be auto or an IPv6 literal")
		}
		if addr.Is4In6() {
			return DialPolicy{}, errors.New("dial6 must not be an IPv4-mapped IPv6 address")
		}
		policy.v6 = addr
	}
	return policy, nil
}

func parseLegacyDialPolicy(dial string) (DialPolicy, error) {
	if dial == "" || dial == dialAuto {
		return DialPolicy{}, nil
	}
	addr, err := netip.ParseAddr(dial)
	if err != nil {
		return DialPolicy{}, errors.New("dial must be auto or an IP literal")
	}
	return DialPolicy{legacy: addr.Unmap()}, nil
}

// Configured reports whether a source address is pinned. When it is not, the
// binder defers to the plain mihomo dialer and preserves default behavior.
func (p DialPolicy) Configured() bool {
	if p.dual {
		return p.v4.IsValid() || p.v6.IsValid()
	}
	return p.legacy.IsValid()
}

// Accepts reports whether the target's address family is permitted. Only the
// legacy single-source form restricts the family.
func (p DialPolicy) Accepts(target netip.Addr) bool {
	if !p.dual && p.legacy.IsValid() {
		return p.legacy.Is4() == target.Is4()
	}
	return true
}

// SourceFor returns the outbound source for a target of the given family. An
// invalid result lets the kernel choose. The legacy policy fails when the
// target family conflicts with its single pinned source.
func (p DialPolicy) SourceFor(target netip.Addr) (netip.Addr, error) {
	if !p.Accepts(target) {
		return netip.Addr{}, errDialFamilyConflict
	}
	if p.dual {
		if target.Is4() {
			return p.v4, nil
		}
		return p.v6, nil
	}
	return p.legacy, nil
}

// SourceBoundDialer applies a DialPolicy to the outbound connections the
// nowhere integration owns, layered on the mihomo dialer so
// interface/routing-mark/TFO policy still applies. It satisfies both the
// nowhere TLS/TCP dialer and the QUIC packet dialer interfaces. A policy that
// pins no source delegates every call unchanged.
type SourceBoundDialer struct {
	policy DialPolicy
	inner  C.Dialer
}

// NewSourceBoundDialer wraps a host dialer with the Nowhere source-address
// policy.
func NewSourceBoundDialer(policy DialPolicy, inner C.Dialer) SourceBoundDialer {
	return SourceBoundDialer{policy: policy, inner: inner}
}

// composable reports whether the source policy can be layered on the host
// dialer. A host dialer that is not a plain mihomo dialer (a chained
// dialer-proxy) owns its own socket policy, so the nowhere source policy does
// not apply to it.
func (d SourceBoundDialer) composable() bool {
	_, ok := d.inner.(dialer.Dialer)
	return ok
}

// DialContext implements the nowhere TLS/TCP dialer. Every resolved candidate
// is tried with its own family-correct source; a failed bind moves on to the
// next candidate and never silently falls back to an automatic source.
func (d SourceBoundDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !d.policy.Configured() || !d.composable() {
		return d.inner.DialContext(ctx, network, address)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	candidates, err := d.candidates(ctx, host)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, target := range candidates {
		source, err := d.policy.SourceFor(target)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		conn, err := d.dialBound(ctx, network, target, port, source)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		return conn, nil
	}
	return nil, errors.Join(errs...)
}

// ListenPacket implements the QUIC packet dialer. The QUIC carrier binds a
// wildcard UDP socket and lets the kernel pick the source; a pinned source is
// expressed as the bind address instead, matching the Rust connect_udp_addr
// contract.
func (d SourceBoundDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	if !d.policy.Configured() || !d.composable() {
		return d.inner.ListenPacket(ctx, network, address, rAddrPort)
	}
	target := rAddrPort.Addr().Unmap()
	if !target.IsValid() {
		return d.inner.ListenPacket(ctx, network, address, rAddrPort)
	}
	source, err := d.policy.SourceFor(target)
	if err != nil {
		return nil, err
	}
	if !source.IsValid() {
		return d.inner.ListenPacket(ctx, network, address, rAddrPort)
	}
	return d.inner.ListenPacket(ctx, familyNetwork(network, source), net.JoinHostPort(source.String(), "0"), rAddrPort)
}

// candidates resolves host to the addresses the policy permits. An IP literal
// is returned directly without touching the resolver.
func (d SourceBoundDialer) candidates(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if !d.policy.Accepts(addr) {
			return nil, errDialFamilyConflict
		}
		return []netip.Addr{addr}, nil
	}
	// The mihomo dialer resolves a proxy-server host with this same resolver.
	addrs, err := resolver.LookupIPWithResolver(ctx, host, resolver.ProxyServerHostResolver)
	if err != nil {
		return nil, err
	}
	accepted := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		if d.policy.Accepts(addr.Unmap()) {
			accepted = append(accepted, addr.Unmap())
		}
	}
	if len(accepted) == 0 {
		return nil, errDialNoAddr
	}
	return accepted, nil
}

// dialBound hands a single resolved candidate to the mihomo dialer with a
// *net.Dialer that binds the source, so the host's interface, routing mark,
// TFO and MPTCP policy still applies.
func (d SourceBoundDialer) dialBound(ctx context.Context, network string, target netip.Addr, port string, source netip.Addr) (net.Conn, error) {
	address := net.JoinHostPort(target.String(), port)
	if !source.IsValid() {
		return d.inner.DialContext(ctx, network, address)
	}
	var local net.Addr = &net.TCPAddr{IP: source.AsSlice()}
	if strings.HasPrefix(network, "udp") {
		local = &net.UDPAddr{IP: source.AsSlice()}
	}
	return dialer.DialContext(ctx, familyNetwork(network, source), address,
		append(d.dialOptions(), dialer.WithNetDialer(&net.Dialer{LocalAddr: local}))...)
}

// dialOptions recovers the host dialer options so a source-bound dial still
// honours the interface, routing mark, TFO and MPTCP policy of the hop.
func (d SourceBoundDialer) dialOptions() []dialer.Option {
	if inner, ok := d.inner.(dialer.Dialer); ok {
		return []dialer.Option{dialer.WithOption(inner.Opt)}
	}
	return nil
}

// familyNetwork pins the network to the source address family so the bind
// cannot fail on a family mismatch.
func familyNetwork(network string, source netip.Addr) string {
	family := "4"
	if !source.Is4() {
		family = "6"
	}
	switch {
	case strings.HasPrefix(network, "tcp"):
		return "tcp" + family
	case strings.HasPrefix(network, "udp"):
		return "udp" + family
	default:
		return network
	}
}
