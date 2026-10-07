package nowhere

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseDialPolicy(t *testing.T) {
	tests := []struct {
		name       string
		dial       string
		dial4      string
		dial6      string
		wantErr    string
		wantLegacy netip.Addr
		wantV4     netip.Addr
		wantV6     netip.Addr
	}{
		{name: "auto", dial4: "auto", dial6: "auto"},
		{name: "empty means auto", dial4: "", dial6: ""},
		{name: "v4 literal", dial4: "10.0.0.1", wantV4: netip.MustParseAddr("10.0.0.1")},
		{name: "v6 literal", dial6: "2001:db8::5", wantV6: netip.MustParseAddr("2001:db8::5")},
		{name: "wildcards", dial4: "0.0.0.0", dial6: "::",
			wantV4: netip.MustParseAddr("0.0.0.0"), wantV6: netip.MustParseAddr("::")},
		{name: "legacy source", dial: "127.0.0.1", wantLegacy: netip.MustParseAddr("127.0.0.1")},
		{name: "legacy v4-mapped accepted", dial: "::ffff:192.0.2.1", wantLegacy: netip.MustParseAddr("192.0.2.1")},
		{name: "dial4 rejects v6 literal", dial4: "::1", wantErr: "dial4 must be auto or an IPv4 literal"},
		{name: "dial6 rejects v4 literal", dial6: "1.2.3.4", wantErr: "dial6 must be auto or an IPv6 literal"},
		{name: "dial6 rejects v4-mapped", dial6: "::ffff:1.2.3.4", wantErr: "dial6 must not be an IPv4-mapped IPv6 address"},
		{name: "dial rejects hostname", dial: "localhost", wantErr: "dial must be auto or an IP literal"},
		{name: "dial and dial4 exclusive", dial: "1.2.3.4", dial4: "10.0.0.1", wantErr: "mutually exclusive"},
		{name: "dial and dial6 exclusive", dial: "1.2.3.4", dial6: "2001:db8::1", wantErr: "mutually exclusive"},
		{name: "dial4 rejects port suffix", dial4: "127.0.0.1:80", wantErr: "dial4 must be auto or an IPv4 literal"},
		{name: "dial6 rejects zone", dial6: "fe80::1%en0", wantErr: "dial6 must be auto or an IPv6 literal"},
		{name: "dial4 case sensitive", dial4: "Auto", wantErr: "dial4 must be auto or an IPv4 literal"},
		{name: "dial6 bracketed rejected", dial6: "[::1]", wantErr: "dial6 must be auto or an IPv6 literal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, err := ParseDialPolicy(test.dial, test.dial4, test.dial6)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDialPolicy: %v", err)
			}
			if policy.legacy != test.wantLegacy {
				t.Fatalf("legacy = %v, want %v", policy.legacy, test.wantLegacy)
			}
			if policy.v4 != test.wantV4 {
				t.Fatalf("v4 = %v, want %v", policy.v4, test.wantV4)
			}
			if policy.v6 != test.wantV6 {
				t.Fatalf("v6 = %v, want %v", policy.v6, test.wantV6)
			}
		})
	}
}

func TestDialPolicySourceSelection(t *testing.T) {
	auto, err := ParseDialPolicy("", "", "")
	if err != nil {
		t.Fatalf("ParseDialPolicy auto: %v", err)
	}
	if auto.Configured() {
		t.Fatal("auto policy Configured = true")
	}
	for _, target := range []string{"192.0.2.1", "2001:db8::1"} {
		addr := netip.MustParseAddr(target)
		source, err := auto.SourceFor(addr)
		if err != nil {
			t.Fatalf("SourceFor(%s): %v", target, err)
		}
		if source.IsValid() {
			t.Fatalf("SourceFor(%s) = %v, want the kernel to choose", target, source)
		}
	}

	dual, err := ParseDialPolicy("", "10.0.0.1", "2001:db8::5")
	if err != nil {
		t.Fatalf("ParseDialPolicy dual: %v", err)
	}
	if !dual.Configured() {
		t.Fatal("dual policy Configured = false")
	}
	if source, err := dual.SourceFor(netip.MustParseAddr("192.0.2.1")); err != nil || source != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("SourceFor(192.0.2.1) = %v, %v; want 10.0.0.1", source, err)
	}
	if source, err := dual.SourceFor(netip.MustParseAddr("2001:db8::1")); err != nil || source != netip.MustParseAddr("2001:db8::5") {
		t.Fatalf("SourceFor(2001:db8::1) = %v, %v; want 2001:db8::5", source, err)
	}

	// The legacy single source restricts the family; the dual-stack form does
	// not, it simply has no source for the other family.
	legacy, err := ParseDialPolicy("127.0.0.1", "", "")
	if err != nil {
		t.Fatalf("ParseDialPolicy legacy: %v", err)
	}
	if legacy.Accepts(netip.MustParseAddr("::1")) {
		t.Fatal("legacy policy accepts a conflicting target family")
	}
	if _, err := legacy.SourceFor(netip.MustParseAddr("::1")); err == nil {
		t.Fatal("legacy SourceFor(::1): want a family conflict error")
	}
	if !dual.Accepts(netip.MustParseAddr("192.0.2.1")) || !dual.Accepts(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("dual policy rejects a target family")
	}
}

func TestFamilyNetwork(t *testing.T) {
	tests := []struct {
		network string
		source  string
		want    string
	}{
		{"tcp", "10.0.0.1", "tcp4"},
		{"tcp", "2001:db8::5", "tcp6"},
		{"udp", "10.0.0.1", "udp4"},
		{"udp", "2001:db8::5", "udp6"},
		{"tcp4", "10.0.0.1", "tcp4"},
		{"ip", "10.0.0.1", "ip"},
	}
	for _, test := range tests {
		if got := familyNetwork(test.network, netip.MustParseAddr(test.source)); got != test.want {
			t.Fatalf("familyNetwork(%q, %s) = %q, want %q", test.network, test.source, got, test.want)
		}
	}
}
