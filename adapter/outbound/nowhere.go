package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/nowhere"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

// Nowhere is the Nowhere v1 proxy outbound. It speaks the protocol defined by
// Nowhere/docs/protocol.md and supports the full client carrier matrix: the
// upload and download carriers may each independently be TLS/TCP or QUIC/UDP,
// yielding four combinations (tcp/tcp, tcp/udp, udp/tcp, udp/udp) for both TCP
// relay and UDP traffic. Symmetric combinations (up==down) use the direct fast
// path; asymmetric combinations are paired by the Portal on a shared session
// id and flow id. See docs in transport/nowhere for the wire format.
type Nowhere struct {
	*Base
	option *NowhereOption

	bundle carrierBundle
}

// carrierBundle is the subset of *nowhere.CarrierBundle used by the outbound.
// It exists so tests can substitute a recording fake.
type carrierBundle interface {
	OpenTCP(ctx context.Context, target nowhere.Target) (net.Conn, error)
	OpenUDPAsync(ctx context.Context, target nowhere.Target) (net.PacketConn, error)
	Close() error
}

// NowhereOption is the proxy map for a nowhere outbound.
type NowhereOption struct {
	BasicOption
	Name   string `proxy:"name"`
	Server string `proxy:"server"`
	Port   int    `proxy:"port"`
	// Password is the shared key used to authenticate to the Portal. It is the
	// canonical field name (matching trojan/anytls/tuic).
	Password string `proxy:"password,omitempty"`
	// Up and Down independently select the upload and download carrier
	// ("tcp" for TLS/TCP or "udp" for QUIC/UDP). Each defaults to "udp" and
	// they must be set together.
	Up   string `proxy:"up,omitempty"`
	Down string `proxy:"down,omitempty"`
	// Pool is the warm TLS/TCP connection count (0..256), only meaningful for the
	// tcp/tcp matrix. A nil/omitted value defaults to 5 for tcp/tcp and 0 for
	// every matrix containing UDP. An explicit 0 disables the warm pool (every
	// flow opens a fresh connection), mirroring the Anywhere client.
	//
	// Diagnostics: pool=0 is equivalent to disabling preconnect — every flow
	// dials its own carrier, which is the cleanest signal when troubleshooting
	// concurrent-speedtest anomalies (each flow must own a distinct carrier_id
	// in the [Nowhere] [carrier] debug log). Compare pool=0 vs pool=5 to isolate
	// warm-pool behavior from per-flow carrier behavior.
	Pool *int `proxy:"pool,omitempty"`
	// PrewarmOnStart fills the warm TLS/TCP pool at outbound start (tcp/tcp only).
	// Default false keeps first-business-dial-then-replenish behavior.
	PrewarmOnStart bool `proxy:"prewarm-on-start,omitempty"`
	// MaxConcurrentDials caps in-flight physical TLS/TCP dials per outbound.
	// Omitted/0 uses the shared-core default (16).
	MaxConcurrentDials *int `proxy:"max-concurrent-dials,omitempty"`
	// WarmBackoffInitial is the first warm-prepare retry delay in seconds after
	// failure. Omitted/0 uses 1s.
	WarmBackoffInitial *int `proxy:"warm-backoff-initial,omitempty"`
	// WarmBackoffMax caps warm-prepare exponential backoff in seconds.
	// Omitted/0 uses 30s.
	WarmBackoffMax *int `proxy:"warm-backoff-max,omitempty"`

	ALPN           []string `proxy:"alpn,omitempty"`
	SNI            string   `proxy:"sni,omitempty"`
	SkipCertVerify bool     `proxy:"skip-cert-verify,omitempty"`
	Fingerprint    string   `proxy:"fingerprint,omitempty"`
	// Pin is the Nowhere leaf-certificate SHA-256 (lowercase hex). When set it
	// overrides SNI/chain verification for both TCP and QUIC carriers.
	Pin               string     `proxy:"pin,omitempty"`
	Certificate       string     `proxy:"certificate,omitempty"`
	PrivateKey        string     `proxy:"private-key,omitempty"`
	ClientFingerprint string     `proxy:"client-fingerprint,omitempty"`
	ECHOpts           ECHOptions `proxy:"ech-opts,omitempty"`

	CongestionController string `proxy:"congestion-controller,omitempty"`
	CWND                 int    `proxy:"cwnd,omitempty"`

	UDP bool `proxy:"udp,omitempty"`
}

// DialContext implements C.ProxyAdapter.
func (n *Nowhere) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	target, err := n.destination(metadata)
	if err != nil {
		return nil, err
	}
	conn, err := n.bundle.OpenTCP(ctx, target)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, n), nil
}

// ListenPacketContext implements C.ProxyAdapter. Domain targets are passed to
// the Portal unresolved: no local DNS resolution happens here.
func (n *Nowhere) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	target, err := n.destination(metadata)
	if err != nil {
		return nil, err
	}
	pc, err := n.bundle.OpenUDPAsync(ctx, target)
	if err != nil {
		return nil, err
	}
	return NewPacketConn(N.NewThreadSafePacketConn(pc), n), nil
}

// SupportUOT implements C.ProxyAdapter. The bundle exposes UoT whenever TCP is
// part of the carrier matrix (downlink or uplink).
func (n *Nowhere) SupportUOT() bool {
	return n.option.Up == "tcp" || n.option.Down == "tcp"
}

// ProxyInfo implements C.ProxyAdapter.
func (n *Nowhere) ProxyInfo() C.ProxyInfo {
	info := n.Base.ProxyInfo()
	info.DialerProxy = n.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter.
func (n *Nowhere) Close() error {
	if n.bundle != nil {
		return n.bundle.Close()
	}
	return nil
}

// destination converts Mihomo metadata to the typed Nowhere target. A
// non-IP-literal Host always wins over an already-resolved DstIP so the
// original domain reaches the Portal as a Domain Target; the Portal resolves
// it. Wire-level validation (empty/oversized domain, non-ASCII, zero port,
// embedded port, bracketed IPv6) lives in nowhere-go's wire constructors and
// is intentionally not duplicated here.
func (n *Nowhere) destination(metadata *C.Metadata) (nowhere.Target, error) {
	if metadata == nil {
		return nowhere.Target{}, errors.New("nowhere: nil destination metadata")
	}
	if metadata.Host != "" {
		if address, err := netip.ParseAddr(metadata.Host); err == nil {
			return nowhere.NewIPTarget(address.Unmap(), metadata.DstPort)
		}
		return nowhere.NewDomainTarget(metadata.Host, metadata.DstPort)
	}
	if metadata.DstIP.IsValid() {
		return nowhere.NewIPTarget(metadata.DstIP.Unmap(), metadata.DstPort)
	}
	return nowhere.Target{}, errors.New("nowhere: empty destination")
}

// NewNowhere builds a Nowhere outbound from its option map.
func NewNowhere(option NowhereOption) (*Nowhere, error) {
	if option.Password == "" {
		return nil, fmt.Errorf("nowhere %s: missing password", option.Name)
	}
	if option.Port <= 0 {
		return nil, fmt.Errorf("nowhere %s: invalid port %d", option.Name, option.Port)
	}
	up, down, err := option.resolveCarriers()
	if err != nil {
		return nil, err
	}
	option.Up = up
	option.Down = down
	// Pool defaults: tcp/tcp -> 5 (warm pool on); any matrix containing UDP ->
	// 0 (warm pool only applies to TLS/TCP and only the symmetric tcp/tcp
	// matrix keeps lanes warm). An explicit 0 disables warming.
	poolSize := 0
	if up == "tcp" && down == "tcp" {
		if option.Pool == nil {
			poolSize = nowhere.DefaultPoolSize
		} else if *option.Pool < 0 {
			return nil, fmt.Errorf("nowhere %s: invalid pool %d (must be >= 0)", option.Name, *option.Pool)
		} else if *option.Pool > nowhere.MaxPoolSize {
			log.Warnln("[Nowhere](%s) pool %d exceeds maximum %d; using %d", option.Name, *option.Pool, nowhere.MaxPoolSize, nowhere.MaxPoolSize)
			poolSize = nowhere.MaxPoolSize
		} else {
			poolSize = *option.Pool
		}
	} else if option.Pool != nil && *option.Pool != 0 {
		// Rust v1.7 only parses pool for tcp/tcp, so values that would be
		// invalid for a TCP pool are ignored for every matrix containing UDP.
		log.Warnln("[Nowhere](%s) pool is only effective for tcp/tcp; ignoring configured value %d", option.Name, *option.Pool)
	}
	if option.ClientFingerprint != "" && (up == "udp" || down == "udp") {
		log.Warnln("[Nowhere](%s) client-fingerprint applies only to TLS/TCP carrier; QUIC uses the standard TLS ClientHello", option.Name)
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	serverName := option.Server
	if option.SNI != "" {
		serverName = option.SNI
	}

	credentials, err := nowhere.NewCredentials(option.Password)
	if err != nil {
		return nil, err
	}

	echConfig, err := option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}

	alpn, err := normalizeNowhereALPN(option.ALPN)
	if err != nil {
		return nil, fmt.Errorf("nowhere %s: %w", option.Name, err)
	}
	// Normalize the pin before it is copied into effectiveTLS: empty or "none"
	// disables pinning (Rust contract), a real pin is validated here so a bad
	// value fails at construction instead of the first dial.
	pin, err := nowhere.ParseCertificatePin(option.Pin)
	if err != nil {
		return nil, fmt.Errorf("nowhere %s: %w", option.Name, err)
	}
	option.Pin = pin
	if option.Pin != "" && option.Fingerprint != "" && option.Fingerprint != option.Pin {
		log.Warnln("[Nowhere](%s) pin overrides fingerprint for leaf-certificate pinning", option.Name)
	}
	eff := newEffectiveTLS(option, serverName, alpn, echConfig)
	var tlsConfig *tls.Config
	if up == "udp" || down == "udp" {
		tlsConfig, err = eff.quicTLSConfig()
		if err != nil {
			return nil, err
		}
	}

	n := &Nowhere{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Nowhere,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	n.dialer = option.NewDialer(n.DialOptions())

	quicConfig := &quic.Config{
		EnableDatagrams:                true,
		Allow0RTT:                      false,
		KeepAlivePeriod:                0,
		MaxIdleTimeout:                 120 * time.Second,
		MaxIncomingStreams:             -1,
		MaxIncomingUniStreams:          -1,
		InitialStreamReceiveWindow:     nowhere.RecommendedStreamReceiveWindow,
		MaxStreamReceiveWindow:         nowhere.RecommendedStreamReceiveWindow,
		InitialConnectionReceiveWindow: nowhere.RecommendedConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     nowhere.RecommendedConnectionReceiveWindow,
		// Send window / DATAGRAM buffer (32 MiB / 4 MiB) are not exposed by
		// metacubex/quic-go Config; recv windows above mirror Vector 1.5.2.
	}
	quicCfg := &nowhere.QUICConfig{
		Addr:       addr,
		ServerName: serverName,
		TLSConfig:  tlsConfig,
		QUICConfig: quicConfig,
		Dialer:     n.dialer, // C.Dialer is structurally identical to common.PacketDialer
		Congestion: orDefault(option.CongestionController, "bbr"),
		CWND:       orInt(option.CWND, 32),
		Observer:   nowhere.MihomoObserver{},
		// Apply ECH on every QUIC dial, the same way hysteria2/tuic do inside
		// their QuicDialer wrapper. echConfig.ClientHandle mutates the config,
		// so the transport clones TLSConfig before calling this.
		PrepareTLS: func(ctx context.Context, cfg *tls.Config) error {
			return echConfig.ClientHandle(ctx, cfg)
		},
	}
	var tcpCfg *nowhere.TCPConfig
	if up == "tcp" || down == "tcp" {
		var tlsDialer nowhere.TLSDialer = &vmessTLSDialer{cfg: eff.tcpTLSConfig()}
		if option.Pin != "" {
			tlsDialer = &pinTLSDialer{cfg: eff.tcpTLSConfig(), pin: option.Pin}
		}
		tcpCfg, err = nowhere.NewTCPConfig(nowhere.TCPOptions{
			Address:            addr,
			ConnectAddress:     addr, // direct dialer resolves the host; chained proxies go via dialer
			Dialer:             n.dialer,
			TLSDialer:          tlsDialer,
			Observer:           nowhere.MihomoObserver{},
			MaxConcurrentDials: derefInt(option.MaxConcurrentDials),
			WarmBackoffInitial: secondsPtr(option.WarmBackoffInitial),
			WarmBackoffMax:     secondsPtr(option.WarmBackoffMax),
		})
		if err != nil {
			return nil, err
		}
	}
	bundleCfg := nowhere.BundleOptions{
		TCP: tcpCfg, Credentials: credentials, ALPN: alpn, Observer: nowhere.MihomoObserver{},
		PoolSize: poolSize, PrewarmOnStart: option.PrewarmOnStart,
		Up: nowhereCarrier(up), Down: nowhereCarrier(down),
	}
	if up == "udp" || down == "udp" {
		bundleCfg.QUIC = nowhere.NewQuicBackend(quicCfg)
	}
	bundle, err := nowhere.NewCarrierBundle(bundleCfg)
	if err != nil {
		return nil, err
	}
	n.bundle = bundle

	return n, nil
}

// effectiveTLS is the shared TLS policy for Nowhere TCP and QUIC carriers.
type effectiveTLS struct {
	serverName     string
	skipCertVerify bool
	fingerprint    string
	pin            string
	certificate    string
	privateKey     string
	clientFP       string
	alpn           string
	ech            *ech.Config
}

func newEffectiveTLS(option NowhereOption, serverName, alpn string, echConfig *ech.Config) effectiveTLS {
	return effectiveTLS{
		serverName:     serverName,
		skipCertVerify: option.SkipCertVerify,
		fingerprint:    option.Fingerprint,
		pin:            option.Pin,
		certificate:    option.Certificate,
		privateKey:     option.PrivateKey,
		clientFP:       option.ClientFingerprint,
		alpn:           alpn,
		ech:            echConfig,
	}
}

func (e effectiveTLS) quicTLSConfig() (*tls.Config, error) {
	fingerprint := e.fingerprint
	skip := e.skipCertVerify
	if e.pin != "" {
		// Pin overrides fingerprint / SNI chain checks.
		fingerprint = ""
		skip = true
	}
	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         e.serverName,
			InsecureSkipVerify: skip,
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{e.alpn},
		},
		Fingerprint: fingerprint,
		Certificate: e.certificate,
		PrivateKey:  e.privateKey,
	})
	if err != nil {
		return nil, err
	}
	if e.pin != "" {
		verifier, err := nowhere.PeerCertificatePinVerifier(e.pin)
		if err != nil {
			return nil, err
		}
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = verifier
	}
	return tlsConfig, nil
}

func (e effectiveTLS) tcpTLSConfig() *vmess.TLSConfig {
	fingerprint := e.fingerprint
	skip := e.skipCertVerify
	if e.pin != "" {
		fingerprint = ""
		skip = true
	}
	return &vmess.TLSConfig{
		Host:              e.serverName,
		SkipCertVerify:    skip,
		FingerPrint:       fingerprint,
		Certificate:       e.certificate,
		PrivateKey:        e.privateKey,
		ClientFingerprint: e.clientFP,
		NextProtos:        []string{e.alpn},
		MinVersion:        tls.VersionTLS13,
		ECH:               e.ech,
	}
}

// pinTLSDialer performs a TLS 1.3 handshake with Nowhere leaf-certificate pin
// verification (overrides SNI/chain checks).
type pinTLSDialer struct {
	cfg *vmess.TLSConfig
	pin string
}

func (t *pinTLSDialer) DialTLSConn(ctx context.Context, c net.Conn) (nowhere.HandshakedConn, error) {
	tlsConfig, err := t.cfg.ToStdConfig()
	if err != nil {
		return nowhere.HandshakedConn{}, err
	}
	verifier, err := nowhere.PeerCertificatePinVerifier(t.pin)
	if err != nil {
		return nowhere.HandshakedConn{}, err
	}
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.VerifyPeerCertificate = verifier
	tlsConn := tls.Client(c, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nowhere.HandshakedConn{}, err
	}
	state := tlsConn.ConnectionState()
	material, err := state.ExportKeyingMaterial(nowhere.TLSExporterLabel, nowhere.EmptyTLSExporterContext(), nowhere.TLSExporterLen)
	if err != nil {
		_ = tlsConn.Close()
		return nowhere.HandshakedConn{}, err
	}
	if len(material) != nowhere.TLSExporterLen {
		_ = tlsConn.Close()
		return nowhere.HandshakedConn{}, errors.New("nowhere: invalid TLS exporter length")
	}
	var exporter nowhere.TLSExporter
	copy(exporter[:], material)
	return nowhere.HandshakedConn{
		Conn: tlsConn,
		TLSHandshakeInfo: nowhere.TLSHandshakeInfo{
			TLSVersion: state.Version, NegotiatedALPN: state.NegotiatedProtocol, Exporter: exporter,
		},
	}, nil
}

// vmessTLSDialer adapts Mihomo's actual TLS handshake and derives the
// connection-bound exporter. A TLS engine that cannot expose exporter material
// is rejected rather than falling back to the retired password-only auth.
type vmessTLSDialer struct{ cfg *vmess.TLSConfig }

func (t *vmessTLSDialer) DialTLSConn(ctx context.Context, c net.Conn) (nowhere.HandshakedConn, error) {
	conn, err := vmess.StreamTLSConn(ctx, c, t.cfg)
	if err != nil {
		return nowhere.HandshakedConn{}, err
	}
	var material []byte
	var version uint16
	var negotiatedALPN string
	switch tlsConn := conn.(type) {
	case *tls.Conn:
		state := tlsConn.ConnectionState()
		version = state.Version
		negotiatedALPN = state.NegotiatedProtocol
		material, err = state.ExportKeyingMaterial(nowhere.TLSExporterLabel, nowhere.EmptyTLSExporterContext(), nowhere.TLSExporterLen)
	case *tlsC.UConn:
		state := tlsConn.ConnectionState()
		version = state.Version
		negotiatedALPN = state.NegotiatedProtocol
		material, err = state.ExportKeyingMaterial(nowhere.TLSExporterLabel, nowhere.EmptyTLSExporterContext(), nowhere.TLSExporterLen)
	default:
		err = errors.New("nowhere: selected TLS engine does not expose TLS exporter")
	}
	if err != nil {
		_ = conn.Close()
		return nowhere.HandshakedConn{}, err
	}
	if len(material) != nowhere.TLSExporterLen {
		_ = conn.Close()
		return nowhere.HandshakedConn{}, errors.New("nowhere: invalid TLS exporter length")
	}
	var exporter nowhere.TLSExporter
	copy(exporter[:], material)
	return nowhere.HandshakedConn{
		Conn: conn,
		TLSHandshakeInfo: nowhere.TLSHandshakeInfo{
			TLSVersion: version, NegotiatedALPN: negotiatedALPN, Exporter: exporter,
		},
	}, nil
}

func nowhereCarrier(value string) nowhere.Carrier {
	if value == "tcp" {
		return nowhere.CarrierTLSTCP
	}
	return nowhere.CarrierQUIC
}

// resolveCarriers validates and resolves the up/down carrier selectors.
// When neither is set both default to "udp".
func (o NowhereOption) resolveCarriers() (up, down string, err error) {
	switch {
	case o.Up != "" && o.Down != "":
		up, down = o.Up, o.Down
	case o.Up != "" || o.Down != "":
		// Setting only one of up/down is ambiguous; reject rather than guess.
		return "", "", fmt.Errorf("nowhere %s: up and down must be set together", o.Name)
	default:
		up, down = "udp", "udp"
	}
	if !validCarrier(up) || !validCarrier(down) {
		return "", "", fmt.Errorf("nowhere %s: invalid carrier (up=%q down=%q, must be tcp or udp)", o.Name, up, down)
	}
	return up, down, nil
}

func validCarrier(s string) bool { return s == "tcp" || s == "udp" }

const defaultNowhereALPN = "now/1"

// normalizeNowhereALPN enforces the one-ALPN Nowhere profile. A missing field
// uses the protocol default; an explicitly supplied field must contain one
// non-empty TLS protocol name that the Go TLS implementation can encode.
func normalizeNowhereALPN(alpn []string) (string, error) {
	if alpn == nil {
		return defaultNowhereALPN, nil
	}
	if len(alpn) != 1 {
		return "", fmt.Errorf("alpn must contain exactly one value")
	}
	if length := len(alpn[0]); length == 0 || length > 255 {
		return "", fmt.Errorf("invalid alpn length %d", length)
	}
	return alpn[0], nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func orInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func derefInt(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}

func secondsPtr(v *int) time.Duration {
	if v == nil || *v == 0 {
		return 0
	}
	return time.Duration(*v) * time.Second
}
