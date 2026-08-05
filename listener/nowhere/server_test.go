package nowhere_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"
	LC "github.com/metacubex/mihomo/listener/config"
	IN "github.com/metacubex/mihomo/listener/inbound"
	nwlisten "github.com/metacubex/mihomo/listener/nowhere"
)

const testPassword = "nowhere-test-secret"

var testCertificate, testPrivateKey, _, _ = ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)

// fakeTunnel echoes every TCP flow and every UDP datagram back to the client.
type fakeTunnel struct{ C.Tunnel }

func (fakeTunnel) HandleTCPConn(conn net.Conn, _ *C.Metadata) {
	defer func() { _ = conn.Close() }()
	_, _ = io.Copy(conn, conn)
}

func (fakeTunnel) HandleUDPPacket(packet C.UDPPacket, _ *C.Metadata) {
	_, _ = packet.WriteBack(packet.Data(), nil)
}

// startTestServer binds 127.0.0.1:0; the listener binds TCP and UDP on the
// same OS-assigned port, reported through AddrList.
func startTestServer(t *testing.T) int {
	t.Helper()
	server, err := nwlisten.New(LC.NowhereServer{
		Enable:               true,
		Listen:               "127.0.0.1:0",
		Password:             testPassword,
		Certificate:          testCertificate,
		PrivateKey:           testPrivateKey,
		ALPN:                 []string{"now/1"},
		CongestionController: "bbr",
	}, inbound.NewListenConfig(), fakeTunnel{})
	if err != nil {
		t.Fatalf("nowhere.New: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	addrList := server.AddrList()
	if len(addrList) != 1 {
		t.Fatalf("AddrList = %v, want one address", addrList)
	}
	_, portStr, err := net.SplitHostPort(addrList[0])
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addrList[0], err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %q: %v", portStr, err)
	}
	return port
}

func newTestClient(t *testing.T, port int, up, down string) *outbound.Nowhere {
	t.Helper()
	client, err := outbound.NewNowhere(outbound.NowhereOption{
		Name: "nowhere-test-client", Server: "127.0.0.1", Port: port,
		Password: testPassword, SkipCertVerify: true,
		Up: up, Down: down,
		UDP: true,
	})
	if err != nil {
		t.Fatalf("outbound.NewNowhere: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func testTCPEcho(t *testing.T, client *outbound.Nowhere) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, &C.Metadata{Host: "example.com", DstPort: 80})
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	payload := []byte("nowhere tcp echo")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("echo = %q, want %q", buf, payload)
	}
}

func testUDPEcho(t *testing.T, client *outbound.Nowhere) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pc, err := client.ListenPacketContext(ctx, &C.Metadata{Host: "example.com", DstPort: 53})
	if err != nil {
		t.Fatalf("ListenPacketContext: %v", err)
	}
	defer func() { _ = pc.Close() }()
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))

	payload := []byte("nowhere udp echo")
	if _, err := pc.WriteTo(payload, nil); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	buf := make([]byte, 2048)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("echo = %q, want %q", buf[:n], payload)
	}
}

// TestNowhereInboundInterop runs the real outbound against the real inbound
// over every carrier matrix: tcp/tcp (TLS/TCP carrier: duplex TCP flow plus
// UoT), udp/udp (QUIC carrier), and the asymmetric tcp/udp + udp/tcp splits
// that exercise cross-carrier OPEN/ATTACH pairing.
func TestNowhereInboundInterop(t *testing.T) {
	for _, carriers := range [][2]string{{"tcp", "tcp"}, {"udp", "udp"}, {"tcp", "udp"}, {"udp", "tcp"}} {
		up, down := carriers[0], carriers[1]
		t.Run(up+"/"+down, func(t *testing.T) {
			client := newTestClient(t, startTestServer(t), up, down)
			t.Run("tcp echo", func(t *testing.T) { testTCPEcho(t, client) })
			t.Run("udp echo", func(t *testing.T) { testUDPEcho(t, client) })
		})
	}
}

// TestNowhereInboundSelfSigned covers the in-memory self-signed fallback:
// a listener started without certificate/private-key must still complete the
// full handshake and relay flows (clients use skip-cert-verify or pin).
func TestNowhereInboundSelfSigned(t *testing.T) {
	server, err := nwlisten.New(LC.NowhereServer{
		Enable:               true,
		Listen:               "127.0.0.1:0",
		Password:             testPassword,
		ALPN:                 []string{"now/1"},
		CongestionController: "bbr",
	}, inbound.NewListenConfig(), fakeTunnel{})
	if err != nil {
		t.Fatalf("nowhere.New without certificate: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	_, portStr, err := net.SplitHostPort(server.AddrList()[0])
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %q: %v", portStr, err)
	}

	client := newTestClient(t, port, "tcp", "tcp")
	t.Run("tcp echo", func(t *testing.T) { testTCPEcho(t, client) })
	t.Run("udp echo", func(t *testing.T) { testUDPEcho(t, client) })
}

func TestParseListenerNowhere(t *testing.T) {
	mapping := map[string]any{
		"name":        "nowhere-in",
		"type":        "nowhere",
		"listen":      "127.0.0.1",
		"port":        "1443",
		"password":    testPassword,
		"certificate": testCertificate,
		"private-key": testPrivateKey,
	}
	parsed, err := listener.ParseListener(mapping)
	if err != nil {
		t.Fatalf("ParseListener: %v", err)
	}
	if parsed.Name() != "nowhere-in" {
		t.Fatalf("Name() = %q, want %q", parsed.Name(), "nowhere-in")
	}
	option, ok := parsed.Config().(*IN.NowhereOption)
	if !ok {
		t.Fatalf("Config() = %T, want *inbound.NowhereOption", parsed.Config())
	}
	if len(option.ALPN) != 1 || option.ALPN[0] != "now/1" {
		t.Fatalf("ALPN = %v, want [now/1]", option.ALPN)
	}
	if option.CongestionController != "bbr" {
		t.Fatalf("CongestionController = %q, want bbr", option.CongestionController)
	}
	parsedAgain, err := listener.ParseListener(mapping)
	if err != nil {
		t.Fatalf("ParseListener again: %v", err)
	}
	if !parsed.Config().Equal(parsedAgain.Config()) {
		t.Fatalf("Config() round-trip mismatch: %v vs %v", parsed.Config(), parsedAgain.Config())
	}

	// certificate/private-key are optional (in-memory self-signed fallback):
	// the structure decoder must not report them as unset fields.
	delete(mapping, "certificate")
	delete(mapping, "private-key")
	parsedSelfSigned, err := listener.ParseListener(mapping)
	if err != nil {
		t.Fatalf("ParseListener without certificate: %v", err)
	}
	optionSelfSigned, ok := parsedSelfSigned.Config().(*IN.NowhereOption)
	if !ok {
		t.Fatalf("Config() = %T, want *inbound.NowhereOption", parsedSelfSigned.Config())
	}
	if optionSelfSigned.Certificate != "" || optionSelfSigned.PrivateKey != "" {
		t.Fatalf("Certificate/PrivateKey = %q/%q, want empty", optionSelfSigned.Certificate, optionSelfSigned.PrivateKey)
	}
}
