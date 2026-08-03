package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/nowhere"
)

func TestNowhereDestinationBuildsTypedTargets(t *testing.T) {
	n := &Nowhere{}

	tests := []struct {
		name     string
		metadata *C.Metadata
		wantHost string
		wantAddr string
		wantPort uint16
		wantErr  string
	}{
		{
			name:     "domain only",
			metadata: &C.Metadata{Host: "example.com", DstPort: 443},
			wantHost: "example.com", wantPort: 443,
		},
		{
			// Core regression: a resolved DstIP must not downgrade the domain.
			name:     "domain wins over resolved dst ip",
			metadata: &C.Metadata{Host: "example.com", DstIP: netip.MustParseAddr("192.0.2.7"), DstPort: 443},
			wantHost: "example.com", wantPort: 443,
		},
		{
			name:     "ipv4 literal host",
			metadata: &C.Metadata{Host: "192.0.2.7", DstPort: 53},
			wantAddr: "192.0.2.7", wantPort: 53,
		},
		{
			name:     "ipv6 literal host",
			metadata: &C.Metadata{Host: "2001:db8::7", DstPort: 53},
			wantAddr: "2001:db8::7", wantPort: 53,
		},
		{
			name:     "empty host with dst ip",
			metadata: &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.7"), DstPort: 53},
			wantAddr: "192.0.2.7", wantPort: 53,
		},
		{
			name:     "empty host without dst ip",
			metadata: &C.Metadata{DstPort: 443},
			wantErr:  "nowhere: empty destination",
		},
		{
			name:     "nil metadata",
			metadata: nil,
			wantErr:  "nowhere: nil destination metadata",
		},
		{
			// netip.Addr equality also proves Unmap happened: an Is4In6
			// address never equals its Is4 counterpart.
			name:     "ipv4-mapped ipv6 host",
			metadata: &C.Metadata{Host: "::ffff:192.0.2.7", DstPort: 53},
			wantAddr: "192.0.2.7", wantPort: 53,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := n.destination(test.metadata)
			if test.wantErr != "" {
				if err == nil || err.Error() != test.wantErr {
					t.Fatalf("destination error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("destination: %v", err)
			}
			if target.Host != test.wantHost {
				t.Fatalf("target host = %q, want %q", target.Host, test.wantHost)
			}
			if test.wantAddr == "" {
				if target.Addr.IsValid() {
					t.Fatalf("target addr = %v, want none", target.Addr)
				}
			} else if want := netip.MustParseAddr(test.wantAddr); target.Addr != want {
				t.Fatalf("target addr = %v, want %v", target.Addr, want)
			}
			if target.Port != test.wantPort {
				t.Fatalf("target port = %d, want %d", target.Port, test.wantPort)
			}
		})
	}
}

// recordedBundle is a carrierBundle fake that captures the UDP target instead
// of dialing, so tests can assert what would be sent to the Portal.
type recordedBundle struct {
	udpTarget nowhere.Target
	pc        net.PacketConn
}

func (r *recordedBundle) OpenTCP(context.Context, nowhere.Target) (net.Conn, error) {
	return nil, errors.New("unexpected OpenTCP call")
}

func (r *recordedBundle) OpenUDPAsync(_ context.Context, target nowhere.Target) (net.PacketConn, error) {
	r.udpTarget = target
	return r.pc, nil
}

func (r *recordedBundle) Close() error { return nil }

// TestNowhereListenPacketKeepsDomainTarget proves UDP domain targets reach the
// bundle unresolved: no local DNS lookup happens and an unresolvable host is
// not rejected with "can't resolve ip".
func TestNowhereListenPacketKeepsDomainTarget(t *testing.T) {
	n, err := NewNowhere(NowhereOption{
		Name: "nw-test", Server: "example.com", Port: 2077, Password: "secret",
	})
	if err != nil {
		t.Fatalf("NewNowhere: %v", err)
	}

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	rec := &recordedBundle{pc: pc}
	n.bundle = rec

	metadata := &C.Metadata{Host: "unresolvable-nowhere-test.invalid", DstPort: 443}
	if _, err := n.ListenPacketContext(context.Background(), metadata); err != nil {
		t.Fatalf("ListenPacketContext: %v", err)
	}
	if rec.udpTarget.Host != "unresolvable-nowhere-test.invalid" || rec.udpTarget.Addr.IsValid() {
		t.Fatalf("OpenUDPAsync target = %+v, want unresolved domain target", rec.udpTarget)
	}
	if metadata.DstIP.IsValid() {
		t.Fatalf("metadata.DstIP was resolved locally: %v", metadata.DstIP)
	}
}

func TestNormalizeNowhereALPN(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		want    string
		wantErr bool
	}{
		{name: "omitted defaults", want: defaultNowhereALPN},
		{name: "explicit protocol", input: []string{"now/1"}, want: "now/1"},
		{name: "empty list", input: []string{}, wantErr: true},
		{name: "empty protocol", input: []string{""}, wantErr: true},
		{name: "multiple protocols", input: []string{"now/1", "h3"}, wantErr: true},
		{name: "overlong protocol", input: []string{strings.Repeat("x", 256)}, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeNowhereALPN(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatal("normalizeNowhereALPN unexpectedly succeeded")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeNowhereALPN: %v", err)
			}
			if got != test.want {
				t.Fatalf("normalizeNowhereALPN = %q, want %q", got, test.want)
			}
		})
	}
}
