package nowhere

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	tlsC "github.com/metacubex/mihomo/component/tls"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"
	nwtransport "github.com/metacubex/mihomo/transport/nowhere"
	"github.com/metacubex/mihomo/transport/vmess"

	nwserver "github.com/ohmycggk/nowhere-go/server"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

// Native Portal chaining (Nowhere 1.7). When the listener config carries a
// next section, the inbound forwards every authenticated flow to another
// Nowhere Portal through a client-side CarrierBundle wrapped in
// nwserver.PortalUpstream, bypassing the tunnel entirely.

// newPortalUpstream builds the next-hop client bundle for a chained Portal
// and wraps it as the inbound Upstream. The bundle shares the listener ALPN
// (Rust contract: a chained Portal presents the listener ALPN upstream) and
// uses the listener congestion-controller/cwnd for its QUIC backend.
//
// The returned bundle is caller-owned: PortalUpstream borrows it without
// taking ownership, so close the Server using the Upstream first and the
// bundle second.
func newPortalUpstream(next *LC.NowhereNext, alpn, congestionController string, cwnd int) (*nwserver.PortalUpstream, *nwtransport.CarrierBundle, error) {
	up, down, poolSize, err := resolvePortalNext(next)
	if err != nil {
		return nil, nil, err
	}

	addr := net.JoinHostPort(next.Server, strconv.Itoa(next.Port))
	serverName := next.Server
	if next.SNI != "" {
		serverName = next.SNI
	}
	// Rust contract (Nowhere docs/configuration.md): an omitted/empty sni
	// disables certificate verification, while serverName is still sent as
	// ClientHello SNI for virtual-host routing; an explicit sni keeps
	// chain+name verification on; pin overrides both.
	skipCertVerify := next.SNI == "" || next.Pin != ""

	credentials, err := nwtransport.NewCredentials(next.Password)
	if err != nil {
		return nil, nil, err
	}

	// The chained hop always dials directly; the schema exposes no
	// interface/routing-mark/dialer-proxy options.
	portalDialer := dialer.NewDialer()

	bundleCfg := nwtransport.BundleOptions{
		Credentials: credentials, ALPN: alpn, Observer: nwtransport.MihomoObserver{},
		PoolSize: poolSize,
		Up:       portalCarrier(up), Down: portalCarrier(down),
	}
	if up == "udp" || down == "udp" {
		tlsConfig, err := portalQUICTLSConfig(serverName, alpn, skipCertVerify, next.Pin)
		if err != nil {
			return nil, nil, err
		}
		bundleCfg.QUIC = nwtransport.NewQuicBackend(&nwtransport.QUICConfig{
			Addr:       addr,
			ServerName: serverName,
			TLSConfig:  tlsConfig,
			QUICConfig: &quic.Config{
				EnableDatagrams:                true,
				Allow0RTT:                      false,
				KeepAlivePeriod:                0,
				MaxIdleTimeout:                 120 * time.Second, // mirror the nowhere outbound client
				MaxIncomingStreams:             -1,
				MaxIncomingUniStreams:          -1,
				InitialStreamReceiveWindow:     nwtransport.RecommendedStreamReceiveWindow,
				MaxStreamReceiveWindow:         nwtransport.RecommendedStreamReceiveWindow,
				InitialConnectionReceiveWindow: nwtransport.RecommendedConnectionReceiveWindow,
				MaxConnectionReceiveWindow:     nwtransport.RecommendedConnectionReceiveWindow,
			},
			Dialer:     portalDialer,
			Congestion: congestionController,
			CWND:       cwnd,
			Observer:   nwtransport.MihomoObserver{},
		})
	}
	if up == "tcp" || down == "tcp" {
		tlsConfig := portalTCPTLSConfig(serverName, alpn, skipCertVerify)
		var tlsDialer nwtransport.TLSDialer = &vmessTLSDialer{cfg: tlsConfig}
		if next.Pin != "" {
			tlsDialer = &pinTLSDialer{cfg: tlsConfig, pin: next.Pin}
		}
		bundleCfg.TCP, err = nwtransport.NewTCPConfig(nwtransport.TCPOptions{
			Address:        addr,
			ConnectAddress: addr, // direct dialer resolves the host
			Dialer:         portalDialer,
			TLSDialer:      tlsDialer,
			Observer:       nwtransport.MihomoObserver{},
		})
		if err != nil {
			return nil, nil, err
		}
	}
	bundle, err := nwtransport.NewCarrierBundle(bundleCfg)
	if err != nil {
		return nil, nil, err
	}
	portalUpstream, err := nwserver.NewPortalUpstream(bundle)
	if err != nil {
		_ = bundle.Close()
		return nil, nil, err
	}
	return portalUpstream, bundle, nil
}

// resolvePortalNext validates the next section and resolves carrier and pool
// defaults, mirroring the outbound's resolveCarriers/pool rules
// (adapter/outbound/nowhere.go).
func resolvePortalNext(next *LC.NowhereNext) (up, down string, poolSize int, err error) {
	// Rust contract (vector/config.rs): the literal "none" is an alias for an
	// omitted sni/pin; normalize in place so a directly constructed
	// LC.NowhereServer (bypassing the inbound option layer) behaves the same.
	next.SNI = normalizePortalNone(next.SNI)
	next.Pin = normalizePortalNone(next.Pin)
	if next.Server == "" {
		return "", "", 0, errors.New("nowhere: next: missing server")
	}
	// Rust parses the port as u16.
	if next.Port <= 0 || next.Port > 65535 {
		return "", "", 0, fmt.Errorf("nowhere: next: invalid port %d", next.Port)
	}
	if next.Password == "" {
		return "", "", 0, errors.New("nowhere: next: missing password")
	}
	switch {
	case next.Up != "" && next.Down != "":
		up, down = next.Up, next.Down
	case next.Up != "" || next.Down != "":
		// Setting only one of up/down is ambiguous; reject rather than guess.
		return "", "", 0, errors.New("nowhere: next: up and down must be set together")
	default:
		up, down = "udp", "udp"
	}
	if !validPortalCarrier(up) || !validPortalCarrier(down) {
		return "", "", 0, fmt.Errorf("nowhere: next: invalid carrier (up=%q down=%q, must be tcp or udp)", up, down)
	}
	// Pool defaults: tcp/tcp -> 5 (warm pool on); any matrix containing UDP ->
	// 0 (the warm pool only applies to TLS/TCP and only the symmetric tcp/tcp
	// matrix keeps lanes warm). An explicit 0 disables warming.
	if up == "tcp" && down == "tcp" {
		if next.Pool == nil {
			poolSize = nwtransport.DefaultPoolSize
		} else if *next.Pool < 0 {
			return "", "", 0, fmt.Errorf("nowhere: next: invalid pool %d (must be >= 0)", *next.Pool)
		} else if *next.Pool > nwtransport.MaxPoolSize {
			log.Warnln("[Nowhere] next pool %d exceeds maximum %d; using %d", *next.Pool, nwtransport.MaxPoolSize, nwtransport.MaxPoolSize)
			poolSize = nwtransport.MaxPoolSize
		} else {
			poolSize = *next.Pool
		}
	} else if next.Pool != nil && *next.Pool != 0 {
		// Rust v1.7 ignores pool entirely outside tcp/tcp.
		log.Warnln("[Nowhere] next pool is only effective for tcp/tcp; ignoring configured value %d", *next.Pool)
	}
	if next.SNI != "" && !validPortalSNI(next.SNI) {
		return "", "", 0, errors.New("nowhere: next: sni must be an ASCII DNS name")
	}
	if next.Pin != "" {
		if _, err := nwtransport.ParseCertificatePin(next.Pin); err != nil {
			return "", "", 0, fmt.Errorf("nowhere: next: %w", err)
		}
	}
	return up, down, poolSize, nil
}

// normalizePortalNone maps the Rust "none" sentinel for sni/pin onto the
// empty value, which the listener treats as unset.
func normalizePortalNone(value string) string {
	if value == "none" {
		return ""
	}
	return value
}

// validPortalSNI mirrors the Rust sni rule (vector/config.rs): an explicit
// sni must be an ASCII DNS name — at most 253 bytes, no ':'/'['/']', and not
// an IP literal.
func validPortalSNI(sni string) bool {
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

func portalCarrier(value string) nwtransport.Carrier {
	if value == "tcp" {
		return nwtransport.CarrierTLSTCP
	}
	return nwtransport.CarrierQUIC
}

func validPortalCarrier(s string) bool { return s == "tcp" || s == "udp" }

// portalQUICTLSConfig mirrors the outbound's QUIC TLS policy: TLS 1.3 with the
// shared one-ALPN profile; pin overrides SNI/chain verification.
func portalQUICTLSConfig(serverName, alpn string, skipCertVerify bool, pin string) (*tls.Config, error) {
	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: skipCertVerify,
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{alpn},
		},
	})
	if err != nil {
		return nil, err
	}
	if pin != "" {
		verifier, err := nwtransport.PeerCertificatePinVerifier(pin)
		if err != nil {
			return nil, err
		}
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = verifier
	}
	return tlsConfig, nil
}

// portalTCPTLSConfig mirrors the outbound's TCP-carrier TLS policy
// (effectiveTLS.tcpTLSConfig minus fingerprint/client-cert/ECH, which the
// next schema does not expose).
func portalTCPTLSConfig(serverName, alpn string, skipCertVerify bool) *vmess.TLSConfig {
	return &vmess.TLSConfig{
		Host:           serverName,
		SkipCertVerify: skipCertVerify,
		NextProtos:     []string{alpn},
		MinVersion:     tls.VersionTLS13,
	}
}

// vmessTLSDialer adapts Mihomo's actual TLS handshake and derives the
// connection-bound exporter, mirroring the outbound's dialer. A TLS engine
// that cannot expose exporter material is rejected rather than falling back
// to the retired password-only auth.
type vmessTLSDialer struct{ cfg *vmess.TLSConfig }

func (t *vmessTLSDialer) DialTLSConn(ctx context.Context, c net.Conn) (nwtransport.HandshakedConn, error) {
	conn, err := vmess.StreamTLSConn(ctx, c, t.cfg)
	if err != nil {
		return nwtransport.HandshakedConn{}, err
	}
	var material []byte
	var version uint16
	var negotiatedALPN string
	switch tlsConn := conn.(type) {
	case *tls.Conn:
		state := tlsConn.ConnectionState()
		version = state.Version
		negotiatedALPN = state.NegotiatedProtocol
		material, err = state.ExportKeyingMaterial(nwtransport.TLSExporterLabel, nwtransport.EmptyTLSExporterContext(), nwtransport.TLSExporterLen)
	case *tlsC.UConn:
		state := tlsConn.ConnectionState()
		version = state.Version
		negotiatedALPN = state.NegotiatedProtocol
		material, err = state.ExportKeyingMaterial(nwtransport.TLSExporterLabel, nwtransport.EmptyTLSExporterContext(), nwtransport.TLSExporterLen)
	default:
		err = errors.New("nowhere: selected TLS engine does not expose TLS exporter")
	}
	if err != nil {
		_ = conn.Close()
		return nwtransport.HandshakedConn{}, err
	}
	if len(material) != nwtransport.TLSExporterLen {
		_ = conn.Close()
		return nwtransport.HandshakedConn{}, errors.New("nowhere: invalid TLS exporter length")
	}
	var exporter nwtransport.TLSExporter
	copy(exporter[:], material)
	return nwtransport.HandshakedConn{
		Conn: conn,
		TLSHandshakeInfo: nwtransport.TLSHandshakeInfo{
			TLSVersion: version, NegotiatedALPN: negotiatedALPN, Exporter: exporter,
		},
	}, nil
}

// pinTLSDialer performs a TLS 1.3 handshake with Nowhere leaf-certificate pin
// verification (overrides SNI/chain checks), mirroring the outbound's dialer.
type pinTLSDialer struct {
	cfg *vmess.TLSConfig
	pin string
}

func (t *pinTLSDialer) DialTLSConn(ctx context.Context, c net.Conn) (nwtransport.HandshakedConn, error) {
	tlsConfig, err := t.cfg.ToStdConfig()
	if err != nil {
		return nwtransport.HandshakedConn{}, err
	}
	verifier, err := nwtransport.PeerCertificatePinVerifier(t.pin)
	if err != nil {
		return nwtransport.HandshakedConn{}, err
	}
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.VerifyPeerCertificate = verifier
	tlsConn := tls.Client(c, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nwtransport.HandshakedConn{}, err
	}
	state := tlsConn.ConnectionState()
	material, err := state.ExportKeyingMaterial(nwtransport.TLSExporterLabel, nwtransport.EmptyTLSExporterContext(), nwtransport.TLSExporterLen)
	if err != nil {
		_ = tlsConn.Close()
		return nwtransport.HandshakedConn{}, err
	}
	if len(material) != nwtransport.TLSExporterLen {
		_ = tlsConn.Close()
		return nwtransport.HandshakedConn{}, errors.New("nowhere: invalid TLS exporter length")
	}
	var exporter nwtransport.TLSExporter
	copy(exporter[:], material)
	return nwtransport.HandshakedConn{
		Conn: tlsConn,
		TLSHandshakeInfo: nwtransport.TLSHandshakeInfo{
			TLSVersion: state.Version, NegotiatedALPN: state.NegotiatedProtocol, Exporter: exporter,
		},
	}, nil
}
