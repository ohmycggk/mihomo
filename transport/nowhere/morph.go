package nowhere

import (
	"context"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/transport/nowhere/core/carrier/morph"
	"github.com/metacubex/mihomo/transport/tuic/common"
)

// MorphSharedKey returns the hop password as a Morph key when enabled.
// An empty result leaves the TCP/QUIC carriers as bare TLS/QUIC (morph=0).
func MorphSharedKey(enabled bool, password string) []byte {
	if !enabled || password == "" {
		return nil
	}
	return []byte(password)
}

// WrapMorphPacketConn XOR-transforms every UDP datagram below QUIC. The
// client side seals under udp c2s and opens under udp s2c; the server side
// uses the reverse pairing.
func WrapMorphPacketConn(pc net.PacketConn, password string, client bool) net.PacketConn {
	if pc == nil || password == "" {
		return pc
	}
	return morph.WrapPacketConn(pc, morph.Derive([]byte(password)), client)
}

// WrapMorphPacketDialer wraps every packet socket the QUIC client opens.
func WrapMorphPacketDialer(d common.PacketDialer, password string) common.PacketDialer {
	if d == nil || password == "" {
		return d
	}
	return morphPacketDialer{inner: d, keys: morph.Derive([]byte(password))}
}

type morphPacketDialer struct {
	inner common.PacketDialer
	keys  morph.Keys
}

func (d morphPacketDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	pc, err := d.inner.ListenPacket(ctx, network, address, rAddrPort)
	if err != nil {
		return nil, err
	}
	return morph.WrapPacketConn(pc, d.keys, true), nil
}
