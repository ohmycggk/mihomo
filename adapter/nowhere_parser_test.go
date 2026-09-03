package adapter

import "testing"

// TestParseNowhereProxy drives the public ParseProxy entry point to confirm the
// "nowhere" type is wired into the registry and produces a C.Nowhere proxy.
func TestParseNowhereProxy(t *testing.T) {
	mapping := map[string]any{
		"type":     "nowhere",
		"name":     "nw",
		"server":   "example.com",
		"port":     2077,
		"password": "secret",
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

	// up/down select the carrier matrix and must be set together.
	upDownMapping := map[string]any{
		"type":     "nowhere",
		"name":     "nw-tcp",
		"server":   "example.com",
		"port":     2077,
		"password": "secret",
		"up":       "tcp",
		"down":     "tcp",
	}
	if _, err := ParseProxy(upDownMapping); err != nil {
		t.Fatalf("ParseProxy up/down: %v", err)
	}

	// An unknown carrier value must be rejected at parse time.
	badMapping := map[string]any{
		"type": "nowhere", "name": "nw", "server": "example.com",
		"port": 2077, "password": "secret", "up": "carrier-pigeon", "down": "udp",
	}
	if _, err := ParseProxy(badMapping); err == nil {
		t.Fatalf("ParseProxy accepted invalid carrier")
	}

	// A missing shared secret must be rejected.
	noPasswordMapping := map[string]any{
		"type": "nowhere", "name": "nw", "server": "example.com", "port": 2077,
	}
	if _, err := ParseProxy(noPasswordMapping); err == nil {
		t.Fatalf("ParseProxy accepted missing password")
	}

	// The legacy key/network/net aliases are gone: a mapping that only sets
	// them decodes with an empty password and must be rejected.
	legacyMapping := map[string]any{
		"type": "nowhere", "name": "nw-legacy", "server": "example.com",
		"port": 2077, "key": "secret", "network": "udp",
	}
	if _, err := ParseProxy(legacyMapping); err == nil {
		t.Fatalf("ParseProxy accepted legacy key/network aliases")
	}

	udpDisabledMapping := map[string]any{
		"type": "nowhere", "name": "nw", "server": "example.com",
		"port": 2077, "password": "secret", "udp": false,
	}
	udpDisabled, err := ParseProxy(udpDisabledMapping)
	if err != nil {
		t.Fatalf("ParseProxy udp disabled: %v", err)
	}
	if udpDisabled.SupportUDP() {
		t.Fatalf("SupportUDP = true, want false when udp: false")
	}

	mixMapping := map[string]any{
		"type": "nowhere", "name": "nw-mix", "server": "example.com",
		"port": 2077, "password": "secret", "up": "mix", "down": "mix", "mux": 1,
	}
	if _, err := ParseProxy(mixMapping); err != nil {
		t.Fatalf("ParseProxy mix/mux: %v", err)
	}
}
