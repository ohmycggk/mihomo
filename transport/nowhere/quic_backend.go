package nowhere

import (
	"context"
	"net"

	nquic "github.com/ohmycggk/nowhere-go/carrier/quic"

	quicpkg "github.com/metacubex/mihomo/transport/nowhere/carrier/quic"
)

// QuicBackend adapts Mihomo's physical QUIC transport primitives to nowhere-go.
type QuicBackend struct {
	cfg    *quicpkg.QUICConfig
	client *quicpkg.Client
}

func NewBackend(cfg *quicpkg.QUICConfig) *QuicBackend {
	if cfg == nil {
		return &QuicBackend{}
	}
	configCopy := *cfg
	return &QuicBackend{cfg: &configCopy, client: quicpkg.NewClient(&configCopy)}
}

func (b *QuicBackend) AcquireSession(ctx context.Context) (nquic.Session, error) {
	if b == nil || b.client == nil {
		return nil, net.ErrClosed
	}
	return b.client.AcquireSession(ctx)
}

func (b *QuicBackend) InvalidateSession(session nquic.Session) {
	if b == nil || b.client == nil || session == nil {
		return
	}
	if concrete, ok := session.(*quicpkg.Session); ok {
		b.client.InvalidateSession(concrete)
	}
}

func (b *QuicBackend) Close() error {
	if b == nil || b.client == nil {
		return nil
	}
	return b.client.Close()
}

var (
	_ nquic.Backend = (*QuicBackend)(nil)
	_ nquic.Session = (*quicpkg.Session)(nil)
)
