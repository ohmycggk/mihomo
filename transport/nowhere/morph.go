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

// WrapMorphPacketConn XOR-transforms every UDP datagram below QUIC.
func WrapMorphPacketConn(pc net.PacketConn, password string) net.PacketConn {
	if pc == nil || password == "" {
		return pc
	}
	return morph.WrapPacketConn(pc, morph.Derive([]byte(password)).UDP)
}

// WrapMorphPacketDialer wraps every packet socket the QUIC client opens.
func WrapMorphPacketDialer(d common.PacketDialer, password string) common.PacketDialer {
	if d == nil || password == "" {
		return d
	}
	return morphPacketDialer{inner: d, key: morph.Derive([]byte(password)).UDP}
}

type morphPacketDialer struct {
	inner common.PacketDialer
	key   [32]byte
}

func (d morphPacketDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	pc, err := d.inner.ListenPacket(ctx, network, address, rAddrPort)
	if err != nil {
		return nil, err
	}
	return morph.WrapPacketConn(pc, d.key), nil
}
