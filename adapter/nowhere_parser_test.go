package adapter

import "testing"

// TestParseNowhereProxy drives the public ParseProxy entry point to confirm the
// "nowhere" type is wired into the registry and produces a C.Nowhere proxy.
func TestParseNowhereProxy(t *testing.T) {
	mapping := map[string]any{
		"type":    "nowhere",
		"name":    "nw",
		"server":  "example.com",
		"port":    2077,
		"key":     "secret",
		"network": "udp",
	}
	proxy, err := ParseProxy(mapping)
	if err != nil {
		t.Fatalf("ParseProxy: %v", err)
	}
	if proxy.Type().String() != "Nowhere" {
		t.Fatalf("type = %q, want Nowhere", proxy.Type().String())
	}
	if !proxy.SupportUDP() {
		t.Fatalf("SupportUDP = false, want true when udp key omitted")
	}

	passwordMapping := map[string]any{
		"type":     "nowhere",
		"name":     "nw-password",
		"server":   "example.com",
		"port":     2077,
		"password": "secret",
	}
	if _, err := ParseProxy(passwordMapping); err != nil {
		t.Fatalf("ParseProxy password alias: %v", err)
	}

	sameCredentialMapping := map[string]any{
		"type": "nowhere", "name": "nw-same-credential", "server": "example.com",
		"port": 2077, "password": "secret", "key": "secret",
	}
	if _, err := ParseProxy(sameCredentialMapping); err != nil {
		t.Fatalf("ParseProxy matching password/key aliases: %v", err)
	}

	conflictingCredentialMapping := map[string]any{
		"type": "nowhere", "name": "nw-conflicting-credential", "server": "example.com",
		"port": 2077, "password": "first-secret", "key": "second-secret",
	}
	if _, err := ParseProxy(conflictingCredentialMapping); err == nil {
		t.Fatalf("ParseProxy accepted conflicting password/key aliases")
	}

	netAliasMapping := map[string]any{
		"type":   "nowhere",
		"name":   "nw-net",
		"server": "example.com",
		"port":   2077,
		"key":    "secret",
		"net":    "tcp",
	}
	if _, err := ParseProxy(netAliasMapping); err != nil {
		t.Fatalf("ParseProxy net alias: %v", err)
	}

	// An unknown net value must be rejected at parse time.
	badMapping := map[string]any{
		"type": "nowhere", "name": "nw", "server": "example.com",
		"port": 2077, "key": "secret", "network": "carrier-pigeon",
	}
	if _, err := ParseProxy(badMapping); err == nil {
		t.Fatalf("ParseProxy accepted invalid network")
	}

	// A missing shared secret must be rejected.
	noKeyMapping := map[string]any{
		"type": "nowhere", "name": "nw", "server": "example.com", "port": 2077,
	}
	if _, err := ParseProxy(noKeyMapping); err == nil {
		t.Fatalf("ParseProxy accepted missing password/key")
	}

	udpDisabledMapping := map[string]any{
		"type": "nowhere", "name": "nw", "server": "example.com",
		"port": 2077, "key": "secret", "udp": false,
	}
	udpDisabled, err := ParseProxy(udpDisabledMapping)
	if err != nil {
		t.Fatalf("ParseProxy udp disabled: %v", err)
	}
	if udpDisabled.SupportUDP() {
		t.Fatalf("SupportUDP = true, want false when udp: false")
	}
}
