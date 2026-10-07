package nowhere

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestMorphSharedKey(t *testing.T) {
	if got := MorphSharedKey(false, "secret"); got != nil {
		t.Fatalf("disabled MorphSharedKey = %q, want nil", got)
	}
	if got := MorphSharedKey(true, ""); got != nil {
		t.Fatalf("empty-password MorphSharedKey = %q, want nil", got)
	}
	if got := string(MorphSharedKey(true, "secret")); got != "secret" {
		t.Fatalf("MorphSharedKey = %q, want secret", got)
	}
}

func TestWrapMorphPacketConnDirectionalRoundTrip(t *testing.T) {
	clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = clientPC.Close()
		_ = serverPC.Close()
	})
	client := WrapMorphPacketConn(clientPC, "secret", true)
	server := WrapMorphPacketConn(serverPC, "secret", false)
	deadline := time.Now().Add(2 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)

	payload := []byte("facade")
	if _, err := client.WriteTo(payload, server.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 32)
	n, addr, err := server.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], payload) {
		t.Fatalf("client->server = %q", got[:n])
	}
	if _, err := server.WriteTo(payload, addr); err != nil {
		t.Fatal(err)
	}
	n, _, err = client.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], payload) {
		t.Fatalf("server->client = %q", got[:n])
	}
}
