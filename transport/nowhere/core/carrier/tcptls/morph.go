package tcptls

import (
	"net"

	"github.com/metacubex/mihomo/transport/nowhere/core/carrier/morph"
)

func wrapMorphClient(cfg *Config, conn net.Conn) (net.Conn, error) {
	if cfg == nil || cfg.morph == nil {
		return conn, nil
	}
	wrapped, err := morph.WrapTCPClient(conn, *cfg.morph)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return wrapped, nil
}
