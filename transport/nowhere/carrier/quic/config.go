package quic

import (
	"context"
	"time"

	"github.com/metacubex/mihomo/transport/tuic/common"
	"github.com/ohmycggk/nowhere-go/diagnostic"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

const defaultIdleCloseDelay = 120 * time.Second

// QUICConfig holds per-proxy QUIC/TLS settings.
type QUICConfig struct {
	Addr           string
	ServerName     string
	TLSConfig      *tls.Config
	QUICConfig     *quic.Config
	Dialer         common.PacketDialer
	Congestion     string
	CWND           int
	IdleCloseDelay time.Duration
	// DialBackoffInitial / DialBackoffMax control portal session establish backoff.
	DialBackoffInitial time.Duration
	DialBackoffMax     time.Duration
	// PrepareTLS runs on a per-dial TLSConfig clone (e.g. ECH resolution).
	PrepareTLS func(ctx context.Context, tlsConfig *tls.Config) error
	Observer   diagnostic.Observer
}
