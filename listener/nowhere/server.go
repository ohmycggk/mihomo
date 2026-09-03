// Package nowhere bridges the Nowhere 1.8 Portal implementation from
// github.com/ohmycggk/nowhere-go/server into Mihomo's inbound listener
// framework: authenticated TCP streams and UDP packet flows are handed to the
// tunnel exactly like any other protocol inbound, or — with a next section —
// forwarded to another Nowhere Portal (native Portal chaining). Inbound TLS
// auto-detects dedicated vs marked Mux lanes after AuthFrame.
package nowhere

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/sockopt"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"
	nwtransport "github.com/metacubex/mihomo/transport/nowhere"
	"github.com/metacubex/mihomo/transport/tuic/common"

	nwserver "github.com/ohmycggk/nowhere-go/server"
	"github.com/ohmycggk/nowhere-go/wire"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

const serverMaxIncomingStreams = (1 << 32) - 1

type Server struct {
	config LC.NowhereServer

	ctx    context.Context
	cancel context.CancelFunc

	servers       []*nwserver.Server
	tcpListeners  []net.Listener
	udpListeners  []net.PacketConn
	quicListeners []*quic.Listener

	// portalBundle is the next-hop client carrier for native Portal chaining
	// (config.Next). PortalUpstream borrows it without owning it, so it must
	// close after every nowhere server has drained.
	portalBundle *nwtransport.CarrierBundle
}

func New(config LC.NowhereServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (*Server, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-NOWHERE"),
			inbound.WithSpecialRules(""),
		}
	}

	credentials, err := wire.NewCredentials(config.Password)
	if err != nil {
		return nil, err
	}
	alpn, err := normalizeALPN(config.ALPN)
	if err != nil {
		return nil, err
	}
	serverConfig, err := nwserver.NewConfig(nwserver.ConfigOptions{
		Credentials: credentials,
		ALPN:        alpn,
	})
	if err != nil {
		return nil, err
	}

	// The TCP carrier handshakes through TLSHandshake (not ServerOptions.TLS)
	// so both carriers share Mihomo's TLS engine, including ECH support.
	tlsConfig := &tls.Config{
		Time:       ntp.Now,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{alpn},
	}
	certificate, privateKey := config.Certificate, config.PrivateKey
	if certificate == "" && privateKey == "" {
		// Nowhere authenticates via the shared key bound to the TLS
		// exporter, so this generated certificate only carries the TLS
		// handshake (same pattern as listener/shadowquic).
		certificate, privateKey, _, err = ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
		if err != nil {
			return nil, err
		}
	}
	certLoader, err := ca.NewTLSKeyPairLoader(certificate, privateKey)
	if err != nil {
		return nil, err
	}
	tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return certLoader()
	}
	if config.EchKey != "" {
		if err := ech.LoadECHKey(config.EchKey, tlsConfig); err != nil {
			return nil, err
		}
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:        120 * time.Second, // mirror the nowhere outbound client
		MaxIncomingStreams:    serverMaxIncomingStreams,
		MaxIncomingUniStreams: serverMaxIncomingStreams,
		EnableDatagrams:       true,
		Allow0RTT:             true,
		DisablePathManager:    true, // for port hopping
	}
	quicConfig.InitialStreamReceiveWindow = nwtransport.RecommendedStreamReceiveWindow
	quicConfig.MaxStreamReceiveWindow = nwtransport.RecommendedStreamReceiveWindow
	quicConfig.InitialConnectionReceiveWindow = nwtransport.RecommendedConnectionReceiveWindow
	quicConfig.MaxConnectionReceiveWindow = nwtransport.RecommendedConnectionReceiveWindow

	// Native Portal chaining (Nowhere 1.7): when next is configured, inbound
	// flows forward to another Nowhere Portal instead of entering the tunnel.
	// The next-hop bundle inherits the listener ALPN (Rust contract) and the
	// listener congestion-controller/cwnd for its QUIC backend.
	var flowUpstream nwserver.Upstream = &upstream{tunnel: tunnel, additions: additions}
	var portalBundle *nwtransport.CarrierBundle
	if config.Next != nil {
		portalUpstream, bundle, err := newPortalUpstream(config.Next, alpn, config.CongestionController, config.CWND)
		if err != nil {
			return nil, err
		}
		flowUpstream = portalUpstream
		portalBundle = bundle
	}

	s := &Server{config: config, portalBundle: portalBundle}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	success := false
	defer func() {
		if !success {
			_ = s.Close()
		}
	}()

	for _, addr := range strings.Split(config.Listen, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}

		tcpListener, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			return nil, err
		}
		// Bind the UDP socket onto the TCP listener's concrete address so both
		// carriers share one port even when the configured port is 0.
		udpConn, err := lc.ListenPacket(context.Background(), "udp", tcpListener.Addr().String())
		if err != nil {
			_ = tcpListener.Close()
			return nil, err
		}
		if err := sockopt.UDPReuseaddr(udpConn); err != nil {
			log.Warnln("Failed to Reuse UDP Address: %s", err)
		}

		// quic.Listen (not ListenEarly): Accept must return connections whose
		// handshake has completed, otherwise the TLS exporter required by
		// QuicConn.TLSHandshakeInfo is not yet available.
		quicListener, err := quic.Listen(udpConn, tlsConfig, quicConfig)
		if err != nil {
			abandonListen(tcpListener, udpConn, nil)
			return nil, err
		}

		srv, err := nwserver.NewServer(nwserver.ServerOptions{
			Config:       serverConfig,
			TLSHandshake: tlsHandshake(tlsConfig),
			Upstream:     flowUpstream,
			Observer:     nwtransport.MihomoObserver{},
			QUICListener: &quicListenerAdapter{
				listener:             quicListener,
				congestionController: config.CongestionController,
				cwnd:                 config.CWND,
			},
		})
		if err != nil {
			abandonListen(tcpListener, udpConn, quicListener)
			return nil, err
		}

		s.servers = append(s.servers, srv)
		s.tcpListeners = append(s.tcpListeners, tcpListener)
		s.udpListeners = append(s.udpListeners, udpConn)
		s.quicListeners = append(s.quicListeners, quicListener)

		go func() {
			if err := srv.Serve(s.ctx, tcpListener); err != nil && s.ctx.Err() == nil {
				log.Warnln("Nowhere TCP carrier serve error: %s", err)
			}
		}()
		go func() {
			if err := srv.ServeQUIC(s.ctx); err != nil && s.ctx.Err() == nil {
				log.Warnln("Nowhere QUIC carrier serve error: %s", err)
			}
		}()
	}

	success = true
	return s, nil
}

// tlsHandshake mirrors nowhere-go's default TCP handshaker but uses Mihomo's
// TLS engine, so the shared key loader and ECH apply to the TCP carrier too.
func tlsHandshake(tlsConfig *tls.Config) nwserver.TLSHandshaker {
	return func(ctx context.Context, raw net.Conn) (wire.HandshakedConn, error) {
		conn := tls.Server(raw, tlsConfig.Clone())
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return wire.HandshakedConn{}, err
		}
		state := conn.ConnectionState()
		material, err := state.ExportKeyingMaterial(wire.TLSExporterLabel, wire.EmptyTLSExporterContext(), wire.TLSExporterLen)
		if err != nil {
			_ = conn.Close()
			return wire.HandshakedConn{}, err
		}
		if len(material) != wire.TLSExporterLen {
			_ = conn.Close()
			return wire.HandshakedConn{}, errors.New("nowhere: invalid TLS exporter length")
		}
		var exporter wire.TLSExporter
		copy(exporter[:], material)
		return wire.HandshakedConn{
			Conn: conn,
			TLSHandshakeInfo: wire.TLSHandshakeInfo{
				TLSVersion: state.Version, NegotiatedALPN: state.NegotiatedProtocol, Exporter: exporter,
			},
		}, nil
	}
}

// normalizeALPN enforces the one-ALPN Nowhere profile, mirroring the
// outbound's normalizeNowhereALPN: an omitted field uses the protocol default,
// an explicitly supplied field must contain exactly one non-empty protocol
// name that the TLS implementation can encode.
func normalizeALPN(alpn []string) (string, error) {
	if len(alpn) == 0 {
		return wire.DefaultALPN, nil
	}
	if len(alpn) != 1 {
		return "", errors.New("nowhere: alpn must contain exactly one value")
	}
	if length := len(alpn[0]); length == 0 || length > 255 {
		return "", fmt.Errorf("nowhere: invalid alpn length %d", length)
	}
	return alpn[0], nil
}

// abandonListen closes listen resources that were opened during New but not yet
// registered on Server (failure mid-address must not leak FDs/ports).
func abandonListen(tcp net.Listener, udp net.PacketConn, qln *quic.Listener) {
	if qln != nil {
		_ = qln.Close()
	}
	if udp != nil {
		_ = udp.Close()
	}
	if tcp != nil {
		_ = tcp.Close()
	}
}

func (s *Server) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	var retErr error
	for _, srv := range s.servers {
		if err := srv.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			retErr = err
		}
	}
	// PortalUpstream is non-owning: the next-hop bundle closes only after
	// every nowhere server has drained its inbound handlers.
	if s.portalBundle != nil {
		if err := s.portalBundle.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			retErr = err
		}
	}
	for _, listener := range s.quicListeners {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			retErr = err
		}
	}
	for _, listener := range s.tcpListeners {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			retErr = err
		}
	}
	for _, listener := range s.udpListeners {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			retErr = err
		}
	}
	return retErr
}

func (s *Server) Config() LC.NowhereServer {
	return s.config
}

func (s *Server) AddrList() []string {
	addrList := make([]string, 0, len(s.tcpListeners))
	for _, listener := range s.tcpListeners {
		addrList = append(addrList, listener.Addr().String())
	}
	return addrList
}

// upstream hands decoded Nowhere flows to the tunnel. Both handlers block for
// the flow's lifetime (the DialUpstream pattern): the tunnel closes the
// tracked conn/pc, which releases the flow claim inside nowhere-go.
type upstream struct {
	tunnel    C.Tunnel
	additions []inbound.Addition
}

var _ nwserver.Upstream = (*upstream)(nil)

// HandleStream implements nwserver.Upstream. Tunnel.HandleTCPConn blocks
// until the proxied connection is done.
func (u *upstream) HandleStream(ctx context.Context, conn net.Conn, source net.Addr, target wire.Target, readiness nwserver.FlowReadiness) error {
	metadata, err := u.buildMetadata(C.TCP, target, source, conn.LocalAddr())
	if err != nil {
		if readiness != nil {
			_ = readiness.Reject(err)
		}
		return err
	}
	if readiness != nil {
		if err := readiness.Ready(); err != nil {
			return err
		}
	}
	u.tunnel.HandleTCPConn(conn, metadata)
	if onClose := nwserver.CloseHandlerFromContext(ctx); onClose != nil {
		onClose(nil)
	}
	return nil
}

// HandlePacket implements nwserver.Upstream. Every datagram read from the
// target-bound flow is delivered to the tunnel until the flow closes.
func (u *upstream) HandlePacket(ctx context.Context, pc net.PacketConn, source net.Addr, target wire.Target, readiness nwserver.FlowReadiness) error {
	metadata, err := u.buildMetadata(C.UDP, target, source, pc.LocalAddr())
	if err != nil {
		if readiness != nil {
			_ = readiness.Reject(err)
		}
		return err
	}
	if readiness != nil {
		if err := readiness.Ready(); err != nil {
			return err
		}
	}
	defer func() {
		_ = pc.Close()
		if onClose := nwserver.CloseHandlerFromContext(ctx); onClose != nil {
			onClose(nil)
		}
	}()

	// give every flow a unique SNAT key, like sing.go's connID
	rAddr := N.NewCustomAddr(C.NOWHERE.String(), utils.NewUUIDV4().String(), source)
	for {
		buf := make([]byte, 64*1024)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return nil // flow closed or ctx done (the server closes pc on cancel)
		}
		u.tunnel.HandleUDPPacket(&packet{pc: pc, rAddr: rAddr, lAddr: pc.LocalAddr(), data: buf[:n]}, metadata)
	}
}

// buildMetadata maps the wire target to tunnel metadata, the reverse of the
// outbound's destination(): domain targets stay unresolved in Host.
func (u *upstream) buildMetadata(network C.NetWork, target wire.Target, source, inAddr net.Addr) (*C.Metadata, error) {
	metadata := &C.Metadata{
		NetWork: network,
		Type:    C.NOWHERE,
		DstPort: target.Port,
	}
	switch target.Type {
	case wire.TargetTypeDomain:
		metadata.Host = target.Host
	case wire.TargetTypeIPv4, wire.TargetTypeIPv6:
		if !target.Addr.IsValid() {
			return nil, errors.New("nowhere: invalid target address")
		}
		metadata.DstIP = target.Addr
		if network == C.UDP {
			metadata.RawDstAddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(target.Addr, target.Port))
		} else {
			metadata.RawDstAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(target.Addr, target.Port))
		}
	default:
		return nil, fmt.Errorf("nowhere: unsupported target type %d", target.Type)
	}
	metadata.RawSrcAddr = source
	inbound.ApplyAdditions(metadata, inbound.WithSrcAddr(source), inbound.WithInAddr(inAddr))
	inbound.ApplyAdditions(metadata, u.additions...)
	return metadata, nil
}

// packet adapts one nowhere datagram to C.UDPPacket. The flow is bound to a
// single target, so WriteBack passes addr through to the flow, which ignores
// it (see nwserver's pairedUDPConn/nowuFlow WriteTo).
type packet struct {
	pc    net.PacketConn
	rAddr net.Addr
	lAddr net.Addr
	data  []byte
}

var _ C.UDPPacketInAddr = (*packet)(nil)

func (p *packet) Data() []byte {
	return p.data
}

func (p *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	return p.pc.WriteTo(b, addr)
}

func (p *packet) Drop() {}

// LocalAddr returns the source IP/Port of UDP Packet
func (p *packet) LocalAddr() net.Addr {
	return p.rAddr
}

func (p *packet) InAddr() net.Addr {
	return p.lAddr
}

// quicListenerAdapter adapts *quic.Listener to nwserver.QuicListener and
// applies the configured congestion controller to every accepted connection.
type quicListenerAdapter struct {
	listener             *quic.Listener
	congestionController string
	cwnd                 int
}

var _ nwserver.QuicListener = (*quicListenerAdapter)(nil)

func (l *quicListenerAdapter) Accept(ctx context.Context) (nwserver.QuicConn, error) {
	conn, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	common.SetCongestionController(conn, l.congestionController, l.cwnd, "")
	return &quicConnAdapter{conn: conn}, nil
}

func (l *quicListenerAdapter) Close() error {
	return l.listener.Close()
}

// quicConnAdapter adapts *quic.Conn to nwserver.QuicConn.
type quicConnAdapter struct {
	conn *quic.Conn
}

var _ nwserver.QuicConn = (*quicConnAdapter)(nil)

func (c *quicConnAdapter) TLSHandshakeInfo() (wire.TLSHandshakeInfo, error) {
	state := c.conn.ConnectionState()
	material, err := state.TLS.ExportKeyingMaterial(wire.TLSExporterLabel, wire.EmptyTLSExporterContext(), wire.TLSExporterLen)
	if err != nil {
		return wire.TLSHandshakeInfo{}, err
	}
	if len(material) != wire.TLSExporterLen {
		return wire.TLSHandshakeInfo{}, errors.New("nowhere: invalid QUIC TLS exporter length")
	}
	var exporter wire.TLSExporter
	copy(exporter[:], material)
	return wire.TLSHandshakeInfo{
		TLSVersion: state.TLS.Version, NegotiatedALPN: state.TLS.NegotiatedProtocol, Exporter: exporter,
	}, nil
}

func (c *quicConnAdapter) AcceptStream(ctx context.Context) (nwserver.QuicStream, error) {
	stream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &quicStreamAdapter{stream: stream}, nil
}

func (c *quicConnAdapter) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.conn.ReceiveDatagram(ctx)
}

func (c *quicConnAdapter) SendDatagram(ctx context.Context, b []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return c.conn.SendDatagram(b)
}

func (c *quicConnAdapter) CloseWithError(code uint64, message string) error {
	return c.conn.CloseWithError(quic.ApplicationErrorCode(code), message)
}

func (c *quicConnAdapter) Close() error {
	return c.conn.CloseWithError(0, "")
}

func (c *quicConnAdapter) Context() context.Context {
	return c.conn.Context()
}

func (c *quicConnAdapter) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *quicConnAdapter) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// quicStreamAdapter adapts *quic.Stream to nwserver.QuicStream.
type quicStreamAdapter struct {
	stream *quic.Stream
}

var _ nwserver.QuicStream = (*quicStreamAdapter)(nil)

func (s *quicStreamAdapter) Read(p []byte) (int, error) {
	return s.stream.Read(p)
}

func (s *quicStreamAdapter) Write(p []byte) (int, error) {
	return s.stream.Write(p)
}

func (s *quicStreamAdapter) Close() error {
	return s.stream.Close()
}

func (s *quicStreamAdapter) SetDeadline(t time.Time) error {
	return s.stream.SetDeadline(t)
}

func (s *quicStreamAdapter) SetReadDeadline(t time.Time) error {
	return s.stream.SetReadDeadline(t)
}

func (s *quicStreamAdapter) SetWriteDeadline(t time.Time) error {
	return s.stream.SetWriteDeadline(t)
}

func (s *quicStreamAdapter) CancelRead(code uint64) {
	s.stream.CancelRead(quic.StreamErrorCode(code))
}

func (s *quicStreamAdapter) CancelWrite(code uint64) {
	s.stream.CancelWrite(quic.StreamErrorCode(code))
}
