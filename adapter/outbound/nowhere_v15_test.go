package outbound

import (
	"net/netip"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestNowhereDestinationBuildsTypedTargets(t *testing.T) {
	n := &Nowhere{}

	domain, err := n.destination(&C.Metadata{Host: "example.com", DstPort: 443})
	if err != nil {
		t.Fatalf("domain destination: %v", err)
	}
	if domain.Host != "example.com" || domain.Port != 443 || domain.Addr.IsValid() {
		t.Fatalf("domain target = %+v", domain)
	}

	ip, err := n.destination(&C.Metadata{DstIP: netip.MustParseAddr("192.0.2.7"), DstPort: 53})
	if err != nil {
		t.Fatalf("IP destination: %v", err)
	}
	if !ip.Addr.Is4() || ip.Addr.String() != "192.0.2.7" || ip.Port != 53 || ip.Host != "" {
		t.Fatalf("IP target = %+v", ip)
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
