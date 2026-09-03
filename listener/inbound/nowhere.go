package inbound

import (
	"fmt"
	"net/netip"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/nowhere"
	"github.com/metacubex/mihomo/log"
	nwtransport "github.com/metacubex/mihomo/transport/nowhere"
)

type NowhereOption struct {
	BaseOption
	Password             string             `inbound:"password"`
	Certificate          string             `inbound:"certificate,omitempty"`
	PrivateKey           string             `inbound:"private-key,omitempty"`
	EchKey               string             `inbound:"ech-key,omitempty"`
	ALPN                 []string           `inbound:"alpn,omitempty"`
	CongestionController string             `inbound:"congestion-controller,omitempty"`
	CWND                 int                `inbound:"cwnd,omitempty"`
	Next                 *NowhereNextOption `inbound:"next,omitempty"`
}

// NowhereNextOption is the next-hop Portal for native Portal chaining
// (Nowhere 1.7+): when set, the listener forwards every inbound flow to
// another Nowhere Portal instead of the tunnel. Validation mirrors the
// outbound's carrier/mux/pool rules (adapter/outbound/nowhere.go).
type NowhereNextOption struct {
	Server   string `inbound:"server"`
	Port     int    `inbound:"port"`
	Password string `inbound:"password"`
	// Up and Down independently select the carrier towards the next Portal
	// ("tcp", "udp", or "mix"). Each defaults to "udp" and they must be set
	// together. mix is a Nowhere 1.8.3 client policy resolved per flow.
	Up   string `inbound:"up,omitempty"`
	Down string `inbound:"down,omitempty"`
	// Mux selects dedicated TLS lanes (0, default) or marked Mux shards (1)
	// towards the next Portal. udp/udp&mux=1 canonicalizes to 0.
	Mux *int `inbound:"mux,omitempty"`
	// Pool is the warm TLS/TCP connection count, only meaningful for dedicated
	// (mux=0) tcp/tcp (default 5 there, 0 otherwise; max tcptls.MaxPoolSize).
	Pool *int `inbound:"pool,omitempty"`
	// MixFallbackTimeout is the mix primary-route budget in seconds. Omitted/0
	// uses the library default (1s).
	MixFallbackTimeout *int `inbound:"mix-fallback-timeout,omitempty"`
	// SNI overrides the TLS server name used towards the next Portal. Empty or
	// the literal "none" disables certificate verification (a domain server is
	// still sent as ClientHello SNI); an explicit DNS name enables chain+name
	// verification.
	SNI string `inbound:"sni,omitempty"`
	// Pin is the next Portal's leaf-certificate SHA-256 (lowercase hex). When
	// set (non-empty, non-"none") it overrides SNI/chain verification, like
	// the outbound's pin.
	Pin string `inbound:"pin,omitempty"`
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
	if err := validateNowhereNext(options.Name(), options.Next); err != nil {
		return nil, err
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
			Next:                 nowhereNextConfig(options.Next),
		},
	}, nil
}

// validateNowhereNext checks the next-hop Portal section, mirroring the
// outbound's carrier/pool/pin rules (adapter/outbound/nowhere.go).
func validateNowhereNext(name string, next *NowhereNextOption) error {
	if next == nil {
		return nil
	}
	if next.Server == "" {
		return fmt.Errorf("nowhere %s: next: missing server", name)
	}
	// Rust parses the port as u16.
	if next.Port <= 0 || next.Port > 65535 {
		return fmt.Errorf("nowhere %s: next: invalid port %d", name, next.Port)
	}
	if next.Password == "" {
		return fmt.Errorf("nowhere %s: next: missing password", name)
	}
	// wire.NewCredentials bound, matching the Rust oracle's u8 limit
	if len(next.Password) > 255 {
		return fmt.Errorf("nowhere %s: next: password exceeds 255 bytes", name)
	}
	if _, err := nwtransport.ResolveRoutePolicy(nwtransport.RouteInputs{
		Prefix:             fmt.Sprintf("nowhere %s: next", name),
		Up:                 next.Up,
		Down:               next.Down,
		Pool:               next.Pool,
		Mux:                next.Mux,
		MixFallbackTimeout: next.MixFallbackTimeout,
		Warn: func(format string, args ...any) {
			log.Warnln("[Nowhere](%s) next "+format, append([]any{name}, args...)...)
		},
	}); err != nil {
		return err
	}
	// Rust contract (vector/config.rs): the literal "none" is an alias for an
	// omitted sni/pin.
	if sni := normalizeNowhereNone(next.SNI); sni != "" && !validNowhereSNI(sni) {
		return fmt.Errorf("nowhere %s: next: sni must be an ASCII DNS name", name)
	}
	if pin := normalizeNowhereNone(next.Pin); pin != "" {
		if _, err := nwtransport.ParseCertificatePin(pin); err != nil {
			return fmt.Errorf("nowhere %s: next: %w", name, err)
		}
	}
	return nil
}

// normalizeNowhereNone maps the Rust "none" sentinel for sni/pin onto the
// empty value, which the listener config treats as unset.
func normalizeNowhereNone(value string) string {
	if value == "none" {
		return ""
	}
	return value
}

// validNowhereSNI mirrors the Rust sni rule (vector/config.rs): an explicit
// sni must be an ASCII DNS name — at most 253 bytes, no ':'/'['/']', and not
// an IP literal.
func validNowhereSNI(sni string) bool {
	if len(sni) > 253 || strings.ContainsAny(sni, ":[]") {
		return false
	}
	for i := 0; i < len(sni); i++ {
		if sni[i] > 0x7f {
			return false
		}
	}
	if _, err := netip.ParseAddr(sni); err == nil {
		return false
	}
	return true
}

// nowhereNextConfig maps the inbound next option onto the listener server
// config; nil stays nil (direct tunnel upstream). sni/pin are normalized so
// NowhereNext stores the effective values ("none" means unset).
func nowhereNextConfig(o *NowhereNextOption) *LC.NowhereNext {
	if o == nil {
		return nil
	}
	return &LC.NowhereNext{
		Server:             o.Server,
		Port:               o.Port,
		Password:           o.Password,
		Up:                 o.Up,
		Down:               o.Down,
		Mux:                o.Mux,
		Pool:               o.Pool,
		MixFallbackTimeout: o.MixFallbackTimeout,
		SNI:                normalizeNowhereNone(o.SNI),
		Pin:                normalizeNowhereNone(o.Pin),
	}
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
