package nowhere

import (
	"net"
	"testing"
)

func TestAbandonListenClosesTCPAndUDP(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := tcp.Addr().String()
	udp, err := net.ListenPacket("udp", addr)
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}

	abandonListen(tcp, udp, nil)

	// Port must be reusable after abandon; otherwise the sockets leaked.
	tcp2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("TCP listen after abandon: %v", err)
	}
	_ = tcp2.Close()
	udp2, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("UDP listen after abandon: %v", err)
	}
	_ = udp2.Close()
}
