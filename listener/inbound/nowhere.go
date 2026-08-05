package inbound

import (
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/nowhere"
	"github.com/metacubex/mihomo/log"
)

type NowhereOption struct {
	BaseOption
	Password             string   `inbound:"password"`
	Certificate          string   `inbound:"certificate,omitempty"`
	PrivateKey           string   `inbound:"private-key,omitempty"`
	EchKey               string   `inbound:"ech-key,omitempty"`
	ALPN                 []string `inbound:"alpn,omitempty"`
	CongestionController string   `inbound:"congestion-controller,omitempty"`
	CWND                 int      `inbound:"cwnd,omitempty"`
}

func (o NowhereOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Nowhere struct {
	*Base
	config *NowhereOption
	l      *nowhere.Server
	ts     LC.NowhereServer
}

func NewNowhere(options *NowhereOption) (*Nowhere, error) {
	if options.Password == "" {
		return nil, fmt.Errorf("nowhere %s: missing password", options.Name())
	}
	// wire.NewCredentials bound, matching the Rust oracle's u8 limit
	if len(options.Password) > 255 {
		return nil, fmt.Errorf("nowhere %s: password exceeds 255 bytes", options.Name())
	}
	if (options.Certificate == "") != (options.PrivateKey == "") {
		return nil, fmt.Errorf("nowhere %s: certificate and private-key must be set together (omit both for an in-memory self-signed certificate)", options.Name())
	}
	// One-ALPN profile, mirroring the outbound's normalizeNowhereALPN: an
	// omitted field uses the default supplied by ParseListener ("now/1").
	if options.ALPN != nil {
		if len(options.ALPN) != 1 {
			return nil, fmt.Errorf("nowhere %s: alpn must contain exactly one value", options.Name())
		}
		if length := len(options.ALPN[0]); length == 0 || length > 255 {
			return nil, fmt.Errorf("nowhere %s: invalid alpn length %d", options.Name(), length)
		}
	}
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Nowhere{
		Base:   base,
		config: options,
		ts: LC.NowhereServer{
			Enable:               true,
			Listen:               base.RawAddress(),
			Password:             options.Password,
			Certificate:          options.Certificate,
			PrivateKey:           options.PrivateKey,
			EchKey:               options.EchKey,
			ALPN:                 options.ALPN,
			CongestionController: options.CongestionController,
			CWND:                 options.CWND,
		},
	}, nil
}

// Config implements constant.InboundListener
func (n *Nowhere) Config() C.InboundConfig {
	return n.config
}

// Address implements constant.InboundListener
func (n *Nowhere) Address() string {
	var addrList []string
	if n.l != nil {
		addrList = n.l.AddrList()
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (n *Nowhere) Listen(tunnel C.Tunnel) error {
	var err error
	n.l, err = nowhere.New(n.ts, n.ListenConfig(), tunnel, n.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("Nowhere[%s] proxy listening at: %s", n.Name(), n.Address())
	return nil
}

// Close implements constant.InboundListener
func (n *Nowhere) Close() error {
	return n.l.Close()
}

var _ C.InboundListener = (*Nowhere)(nil)
