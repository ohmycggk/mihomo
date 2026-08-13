package nowhere_test

import (
	"encoding/pem"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	IN "github.com/metacubex/mihomo/listener/inbound"
	nwtransport "github.com/metacubex/mihomo/transport/nowhere"
)

// testNextPin is the leaf-certificate SHA-256 pin of testCertificate: the
// chained Portal verifies the next hop by pin (the next schema exposes no
// skip-cert-verify).
var testNextPin = func() string {
	block, _ := pem.Decode([]byte(testCertificate))
	if block == nil {
		return ""
	}
	return nwtransport.LeafCertificateSHA256Hex(block.Bytes)
}()

// countingTunnel stands in for the relay's local routing: with a next section
// every flow must forward to the origin Portal, so any direct use means
// chaining silently fell back to the tunnel.
type countingTunnel struct {
	C.Tunnel
	tcp atomic.Int32
	udp atomic.Int32
}

func (t *countingTunnel) HandleTCPConn(conn net.Conn, _ *C.Metadata) {
	t.tcp.Add(1)
	_ = conn.Close()
}

func (t *countingTunnel) HandleUDPPacket(packet C.UDPPacket, _ *C.Metadata) {
	t.udp.Add(1)
	packet.Drop()
}

func (t *countingTunnel) calls() int32 { return t.tcp.Load() + t.udp.Load() }

// startRelayServer builds a relay Portal through the public inbound schema
// (NowhereOption -> NewNowhere -> Listen) with a next section pointing at the
// origin Portal: every inbound flow forwards to the origin (native Portal
// chaining, Nowhere 1.7). up/down/pin configure the next hop towards the
// origin; an empty up/down pair exercises the udp/udp default.
func startRelayServer(t *testing.T, originPort int, up, down, pin string) (int, *countingTunnel) {
	t.Helper()
	tunnel := &countingTunnel{}
	relay, err := IN.NewNowhere(&IN.NowhereOption{
		BaseOption:           IN.BaseOption{NameStr: "nowhere-test-relay", Listen: "127.0.0.1", Port: "0"},
		Password:             testPassword,
		Certificate:          testCertificate,
		PrivateKey:           testPrivateKey,
		ALPN:                 []string{"now/1"},
		CongestionController: "bbr",
		Next: &IN.NowhereNextOption{
			Server:   "127.0.0.1",
			Port:     originPort,
			Password: testPassword,
			Up:       up,
			Down:     down,
			Pin:      pin,
		},
	})
	if err != nil {
		t.Fatalf("inbound.NewNowhere with next: %v", err)
	}
	if err := relay.Listen(tunnel); err != nil {
		t.Fatalf("relay Listen: %v", err)
	}
	t.Cleanup(func() { _ = relay.Close() })

	address := relay.Address()
	_, portStr, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", address, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %q: %v", portStr, err)
	}
	return port, tunnel
}

// assertTunnelUnused fails when the relay handed any flow to its local tunnel
// instead of chaining it to the origin Portal.
func assertTunnelUnused(t *testing.T, tunnel *countingTunnel) {
	t.Helper()
	if calls := tunnel.calls(); calls != 0 {
		t.Fatalf("relay tunnel handled %d flows, want 0 (all flows must chain to the origin)", calls)
	}
}

// TestNowhereNextValidation exercises the option-layer next validation
// (validateNowhereNext) through the public schema: the port must fit the Rust
// u16, an explicit sni must be an ASCII DNS name, and the "none" sentinel is
// accepted as an alias for an omitted sni/pin.
func TestNowhereNextValidation(t *testing.T) {
	newNowhere := func(next *IN.NowhereNextOption) error {
		_, err := IN.NewNowhere(&IN.NowhereOption{
			BaseOption: IN.BaseOption{NameStr: "nowhere-test-validation", Listen: "127.0.0.1", Port: "0"},
			Password:   testPassword,
			Next:       next,
		})
		return err
	}
	valid := func() *IN.NowhereNextOption {
		return &IN.NowhereNextOption{Server: "origin.example", Port: 2080, Password: testPassword}
	}

	cases := []struct {
		name    string
		mutate  func(*IN.NowhereNextOption)
		wantErr string
	}{
		{"port above u16", func(n *IN.NowhereNextOption) { n.Port = 65536 }, "invalid port"},
		{"sni none accepted", func(n *IN.NowhereNextOption) { n.SNI = "none" }, ""},
		{"pin none accepted", func(n *IN.NowhereNextOption) { n.Pin = "none" }, ""},
		{"sni dns name", func(n *IN.NowhereNextOption) { n.SNI = "origin.example" }, ""},
		{"sni IP literal", func(n *IN.NowhereNextOption) { n.SNI = "203.0.113.1" }, "must be an ASCII DNS name"},
		{"sni with colon", func(n *IN.NowhereNextOption) { n.SNI = "origin.example:2080" }, "must be an ASCII DNS name"},
		{"sni oversized", func(n *IN.NowhereNextOption) { n.SNI = strings.Repeat("a", 254) }, "must be an ASCII DNS name"},
		{"sni non-ascii", func(n *IN.NowhereNextOption) { n.SNI = "例子.example" }, "must be an ASCII DNS name"},
		{"tcp pool negative", func(n *IN.NowhereNextOption) { n.Up, n.Down, n.Pool = "tcp", "tcp", intPointer(-1) }, "must be >= 0"},
		{"tcp pool above max clamped", func(n *IN.NowhereNextOption) {
			n.Up, n.Down, n.Pool = "tcp", "tcp", intPointer(nwtransport.MaxPoolSize+1)
		}, ""},
		{"udp pool negative ignored", func(n *IN.NowhereNextOption) { n.Up, n.Down, n.Pool = "udp", "udp", intPointer(-1) }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := valid()
			tc.mutate(next)
			err := newNowhere(next)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("NewNowhere: %v, want success", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("NewNowhere error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func intPointer(value int) *int { return &value }

// TestNowhereInboundChain verifies native Portal chaining (Nowhere 1.7): the
// client opens flows to the relay Portal, which forwards them through the
// origin Portal (the relay initializes the HOPS budget) before the origin's
// tunnel upstream echoes them back. Both the client and next-hop side run all
// four carrier matrices, and the relay's own tunnel must never see a flow.
func TestNowhereInboundChain(t *testing.T) {
	originPort := startTestServer(t)
	matrices := [][2]string{{"tcp", "tcp"}, {"udp", "udp"}, {"tcp", "udp"}, {"udp", "tcp"}}
	for _, nextCarriers := range matrices {
		nextUp, nextDown := nextCarriers[0], nextCarriers[1]
		t.Run("next-"+nextUp+"/"+nextDown, func(t *testing.T) {
			relayPort, tunnel := startRelayServer(t, originPort, nextUp, nextDown, testNextPin)
			for _, carriers := range matrices {
				up, down := carriers[0], carriers[1]
				t.Run(up+"/"+down, func(t *testing.T) {
					client := newTestClient(t, relayPort, up, down)
					t.Run("tcp echo", func(t *testing.T) { testTCPEcho(t, client) })
					t.Run("udp echo", func(t *testing.T) { testUDPEcho(t, client) })
				})
			}
			assertTunnelUnused(t, tunnel)
		})
	}
}

// TestNowhereInboundMultiHop verifies that HOPS are initialized and consumed
// across more than one native Portal boundary instead of being flattened into
// a single host-side dial.
func TestNowhereInboundMultiHop(t *testing.T) {
	originPort := startTestServer(t)
	relay2Port, relay2Tunnel := startRelayServer(t, originPort, "tcp", "tcp", testNextPin)
	relay1Port, relay1Tunnel := startRelayServer(t, relay2Port, "tcp", "tcp", testNextPin)
	client := newTestClient(t, relay1Port, "tcp", "tcp")
	t.Run("tcp echo", func(t *testing.T) { testTCPEcho(t, client) })
	t.Run("udp echo", func(t *testing.T) { testUDPEcho(t, client) })
	assertTunnelUnused(t, relay1Tunnel)
	assertTunnelUnused(t, relay2Tunnel)
}

// TestNowhereInboundChainDefaultTLS covers the default next-hop TLS policy:
// no sni, no pin, and a self-signed origin (the in-memory certificate
// fallback). The Rust contract disables certificate verification when sni is
// omitted, so the default next section must still chain successfully.
func TestNowhereInboundChainDefaultTLS(t *testing.T) {
	originPort := startTestServerWith(t, "", "")
	relayPort, tunnel := startRelayServer(t, originPort, "", "", "")
	client := newTestClient(t, relayPort, "udp", "udp")
	t.Run("tcp echo", func(t *testing.T) { testTCPEcho(t, client) })
	t.Run("udp echo", func(t *testing.T) { testUDPEcho(t, client) })
	assertTunnelUnused(t, tunnel)
}
