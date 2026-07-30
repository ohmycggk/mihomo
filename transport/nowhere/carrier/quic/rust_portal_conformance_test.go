package quic

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
	"github.com/ohmycggk/nowhere-go/wire"
)

const rustPortalConformanceEnv = "NOWHERE_RUST_PORTAL_ADDR"

func TestRustPortalConformance(t *testing.T) {
	portalAddress := os.Getenv(rustPortalConformanceEnv)
	if portalAddress == "" {
		t.Skipf("%s is not set", rustPortalConformanceEnv)
	}
	if _, err := netip.ParseAddrPort(portalAddress); err != nil {
		t.Fatalf("invalid %s: %v", rustPortalConformanceEnv, err)
	}

	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	target, stopEcho := startRustPortalUDPEcho(t)
	defer stopEcho()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sessionID := wire.SessionID{
		0x6e, 0x6f, 0x77, 0x68, 0x65, 0x72, 0x65, 0x2d,
		0x67, 0x6f, 0x2d, 0x68, 0x34, 0x2d, 0x69, 0x64,
	}
	first := newRustPortalSession(t, ctx, portalAddress)
	defer first.Close()

	// The cold stream authenticates a fixed logical Session ID and then sends
	// a valid TCP/TCP FLOW over QUIC. Rust must reject the physical-carrier
	// mismatch with InvalidRequest without tearing down the authenticated
	// physical session.
	auth := rustPortalAuthFrame(t, first, credentials, sessionID)
	mismatch := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 100, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTLSTCP, Downlink: wire.CarrierTLSTCP,
	}
	if result := rustPortalSetup(t, ctx, first, auth[:], mismatch, target); result != wire.SetupResultInvalidRequest {
		t.Fatalf("carrier mismatch result = %v, want %v", result, wire.SetupResultInvalidRequest)
	}

	udpHeader := func(flowID wire.FlowID) wire.FlowHeader {
		return wire.FlowHeader{
			Role: wire.FlowRoleDuplex, FlowID: flowID, Kind: wire.FlowKindUDP,
			Uplink: wire.CarrierQUIC, Downlink: wire.CarrierQUIC,
		}
	}
	if result := rustPortalSetup(t, ctx, first, nil, udpHeader(101), target); result != wire.SetupResultReady {
		t.Fatalf("initial UDP setup result = %v, want READY", result)
	}
	if result := rustPortalSetup(t, ctx, first, nil, udpHeader(101), target); result != wire.SetupResultMetadataConflict {
		t.Fatalf("duplicate FLOW result = %v, want %v", result, wire.SetupResultMetadataConflict)
	}
	rustPortalRoundTripUDP(t, ctx, first, 101, []byte("before-close"))

	closeFrame, err := wire.EncodeUDPClose(101)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.SendDatagram(ctx, closeFrame[:]); err != nil {
		t.Fatalf("send CLOSE: %v", err)
	}
	rustPortalWaitForFlowClosed(t, first, 101)
	if result := rustPortalSetup(t, ctx, first, nil, udpHeader(104), target); result != wire.SetupResultReady {
		t.Fatalf("post-CLOSE UDP setup result = %v, want READY", result)
	}
	rustPortalRoundTripUDP(t, ctx, first, 104, []byte("after-close"))

	// A second physical QUIC connection authenticating the same fixed Session
	// ID must replace the first one and unblock its blocked DATAGRAM receive.
	replaced := make(chan error, 1)
	receiveCtx, stopReceive := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopReceive()
	go func() {
		for {
			if _, receiveErr := first.ReceiveDatagram(receiveCtx); receiveErr != nil {
				replaced <- receiveErr
				return
			}
		}
	}()

	second := newRustPortalSession(t, ctx, portalAddress)
	defer second.Close()
	secondAuth := rustPortalAuthFrame(t, second, credentials, sessionID)
	secondMismatch := mismatch
	secondMismatch.FlowID = 102
	if result := rustPortalSetup(t, ctx, second, secondAuth[:], secondMismatch, target); result != wire.SetupResultInvalidRequest {
		t.Fatalf("replacement carrier mismatch result = %v, want %v", result, wire.SetupResultInvalidRequest)
	}

	select {
	case receiveErr := <-replaced:
		if receiveErr == nil {
			t.Fatal("replaced session DATAGRAM receive returned nil error")
		}
		if errors.Is(receiveErr, context.DeadlineExceeded) {
			t.Fatalf("replacement did not unblock old session: %v", receiveErr)
		}
	case <-ctx.Done():
		t.Fatalf("replacement did not close old session: %v", ctx.Err())
	}

	if result := rustPortalSetup(t, ctx, second, nil, udpHeader(103), target); result != wire.SetupResultReady {
		t.Fatalf("replacement session UDP setup result = %v, want READY", result)
	}
	rustPortalRoundTripUDP(t, ctx, second, 103, []byte("after-replacement"))
}

type rustPortalPacketDialer struct{}

func (rustPortalPacketDialer) ListenPacket(
	ctx context.Context,
	network string,
	address string,
	_ netip.AddrPort,
) (net.PacketConn, error) {
	if address == "" {
		address = "127.0.0.1:0"
	}
	var listenConfig net.ListenConfig
	return listenConfig.ListenPacket(ctx, network, address)
}

func newRustPortalSession(t *testing.T, ctx context.Context, portalAddress string) *Session {
	t.Helper()
	session := NewSession(&QUICConfig{
		Addr:       portalAddress,
		ServerName: "localhost",
		TLSConfig: &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true, // H4 uses the Rust oracle's ephemeral self-signed certificate.
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			NextProtos:         []string{wire.DefaultALPN},
		},
		QUICConfig: &quic.Config{
			EnableDatagrams:    true,
			Allow0RTT:          false,
			KeepAlivePeriod:    0,
			MaxIdleTimeout:     15 * time.Second,
			MaxIncomingStreams: -1,
		},
		Dialer:         rustPortalPacketDialer{},
		Congestion:     "cubic",
		IdleCloseDelay: 15 * time.Second,
	})
	if err := session.EnsureReady(ctx); err != nil {
		t.Fatalf("connect Rust Portal: %v", err)
	}
	info, err := session.TLSHandshakeInfo()
	if err != nil {
		t.Fatalf("Rust Portal TLS handshake info: %v", err)
	}
	if err := info.Validate(wire.DefaultALPN); err != nil {
		t.Fatalf("Rust Portal TLS policy: %v", err)
	}
	return session
}

func rustPortalAuthFrame(
	t *testing.T,
	session *Session,
	credentials *wire.Credentials,
	sessionID wire.SessionID,
) wire.AuthFrame {
	t.Helper()
	info, err := session.TLSHandshakeInfo()
	if err != nil {
		t.Fatal(err)
	}
	frame, err := wire.EncodeAuthFrame(credentials, wire.AuthTransportQUIC, info.Exporter, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func rustPortalSetup(
	t *testing.T,
	ctx context.Context,
	session *Session,
	prefix []byte,
	header wire.FlowHeader,
	target wire.Target,
) wire.SetupResult {
	t.Helper()
	headerBytes, err := wire.EncodeFlowHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	targetBytes, err := wire.EncodeTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	setup := make([]byte, 0, len(prefix)+len(headerBytes)+len(targetBytes))
	setup = append(setup, prefix...)
	setup = append(setup, headerBytes...)
	setup = append(setup, targetBytes...)

	prepared, err := session.PrepareStream(ctx)
	if err != nil {
		t.Fatalf("prepare FLOW %d: %v", header.FlowID, err)
	}
	conn, err := prepared.Commit(ctx, setup, true)
	if err != nil {
		t.Fatalf("commit FLOW %d: %v", header.FlowID, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetReadDeadline(deadline); err != nil {
			t.Fatalf("set FLOW %d result deadline: %v", header.FlowID, err)
		}
	}
	result, err := wire.ReadSetupResult(conn)
	if err != nil {
		t.Fatalf("read FLOW %d result: %v", header.FlowID, err)
	}
	return result
}

func rustPortalRoundTripUDP(
	t *testing.T,
	ctx context.Context,
	session *Session,
	flowID wire.FlowID,
	payload []byte,
) {
	t.Helper()
	frame, err := wire.EncodeUDPData(flowID, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.SendDatagram(ctx, frame); err != nil {
		t.Fatalf("send UDP FLOW %d: %v", flowID, err)
	}
	for {
		datagram, err := session.ReceiveDatagram(ctx)
		if err != nil {
			t.Fatalf("receive UDP FLOW %d: %v", flowID, err)
		}
		decoded, err := wire.DecodeUDPFrame(datagram)
		if err != nil {
			t.Fatalf("decode UDP FLOW %d: %v", flowID, err)
		}
		if decoded.FlowID != flowID || decoded.Type != wire.UDPFrameTypeData {
			continue
		}
		if !bytes.Equal(decoded.Payload, payload) {
			t.Fatalf("UDP FLOW %d payload = %q, want %q", flowID, decoded.Payload, payload)
		}
		return
	}
}

func rustPortalWaitForFlowClosed(t *testing.T, session *Session, flowID wire.FlowID) {
	t.Helper()
	probe, err := wire.EncodeUDPData(flowID, []byte("after-close-probe"))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := session.SendDatagram(context.Background(), probe); err != nil {
			t.Fatalf("send post-CLOSE probe FLOW %d: %v", flowID, err)
		}
		receiveCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		datagram, receiveErr := session.ReceiveDatagram(receiveCtx)
		cancel()
		if errors.Is(receiveErr, context.DeadlineExceeded) {
			return
		}
		if receiveErr != nil {
			t.Fatalf("receive post-CLOSE probe FLOW %d: %v", flowID, receiveErr)
		}
		decoded, decodeErr := wire.DecodeUDPFrame(datagram)
		if decodeErr != nil {
			t.Fatalf("decode post-CLOSE probe FLOW %d: %v", flowID, decodeErr)
		}
		if decoded.FlowID == flowID && decoded.Type == wire.UDPFrameTypeData {
			time.Sleep(20 * time.Millisecond)
		}
	}
	t.Fatalf("CLOSE did not stop UDP FLOW %d", flowID)
}

func startRustPortalUDPEcho(t *testing.T) (wire.Target, func()) {
	t.Helper()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address, ok := packet.LocalAddr().(*net.UDPAddr)
	if !ok {
		packet.Close()
		t.Fatalf("unexpected UDP echo address %T", packet.LocalAddr())
	}
	target, err := wire.NewIPTarget(address.AddrPort().Addr(), address.AddrPort().Port())
	if err != nil {
		packet.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, wire.UDPPacketMax)
		for {
			n, peer, readErr := packet.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			if _, writeErr := packet.WriteTo(buffer[:n], peer); writeErr != nil {
				return
			}
		}
	}()
	return target, func() {
		if err := packet.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close UDP echo: %v", err)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("UDP echo did not stop")
		}
	}
}
