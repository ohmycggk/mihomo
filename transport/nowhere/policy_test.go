package nowhere

import (
	"strings"
	"testing"
)

func TestResolveRoutePolicyDefaults(t *testing.T) {
	policy, err := ResolveRoutePolicy(RouteInputs{Prefix: "nowhere test"})
	if err != nil {
		t.Fatalf("ResolveRoutePolicy: %v", err)
	}
	if policy.Up != "udp" || policy.Down != "udp" {
		t.Fatalf("carriers = %s/%s, want udp/udp", policy.Up, policy.Down)
	}
	if policy.UsesTCP || !policy.UsesQUIC || policy.Mux != MuxDisabled || policy.PoolSize != 0 {
		t.Fatalf("policy = %+v, want QUIC-only dedicated udp/udp", policy)
	}
}

func TestResolveRoutePolicyMixAndMux(t *testing.T) {
	muxOne := 1
	muxBad := 2
	poolFive := 5
	negative := -1
	tooLarge := MaxPoolSize + 1
	timeout := 2

	tests := []struct {
		name     string
		in       RouteInputs
		wantTCP  bool
		wantQUIC bool
		wantMux  MuxMode
		wantPool int
		wantMix  bool
		wantErr  string
	}{
		{
			name:    "tcp/tcp default pool",
			in:      RouteInputs{Prefix: "nowhere test", Up: "tcp", Down: "tcp"},
			wantTCP: true, wantPool: DefaultPoolSize,
		},
		{
			name:    "tcp/tcp mux=1 zeros pool",
			in:      RouteInputs{Prefix: "nowhere test", Up: "tcp", Down: "tcp", Mux: &muxOne, Pool: &poolFive},
			wantTCP: true, wantMux: MuxEnabled,
		},
		{
			name:     "udp/udp mux=1 canonicalizes",
			in:       RouteInputs{Prefix: "nowhere test", Up: "udp", Down: "udp", Mux: &muxOne},
			wantQUIC: true,
		},
		{
			name:    "invalid mux",
			in:      RouteInputs{Prefix: "nowhere test", Mux: &muxBad},
			wantErr: "invalid mux",
		},
		{
			name:    "mix/mix needs both carriers",
			in:      RouteInputs{Prefix: "nowhere test", Up: "mix", Down: "mix", Pool: &poolFive},
			wantTCP: true, wantQUIC: true, wantMix: true,
		},
		{
			name:    "tcp/mix needs both",
			in:      RouteInputs{Prefix: "nowhere test", Up: "tcp", Down: "mix"},
			wantTCP: true, wantQUIC: true, wantMix: true,
		},
		{
			name:    "one-sided up",
			in:      RouteInputs{Prefix: "nowhere test", Up: "tcp"},
			wantErr: "must be set together",
		},
		{
			name:    "negative pool tcp/tcp",
			in:      RouteInputs{Prefix: "nowhere test", Up: "tcp", Down: "tcp", Pool: &negative},
			wantErr: "must be >= 0",
		},
		{
			name:     "negative pool udp ignored",
			in:       RouteInputs{Prefix: "nowhere test", Up: "udp", Down: "udp", Pool: &negative},
			wantQUIC: true,
		},
		{
			name:    "tcp/tcp pool clamped",
			in:      RouteInputs{Prefix: "nowhere test", Up: "tcp", Down: "tcp", Pool: &tooLarge},
			wantTCP: true, wantPool: MaxPoolSize,
		},
		{
			name:    "mix fallback timeout",
			in:      RouteInputs{Prefix: "nowhere test", Up: "mix", Down: "udp", MixFallbackTimeout: &timeout},
			wantTCP: true, wantQUIC: true, wantMix: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, err := ResolveRoutePolicy(test.in)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveRoutePolicy: %v", err)
			}
			if policy.UsesTCP != test.wantTCP || policy.UsesQUIC != test.wantQUIC {
				t.Fatalf("uses TCP/QUIC = %t/%t, want %t/%t", policy.UsesTCP, policy.UsesQUIC, test.wantTCP, test.wantQUIC)
			}
			if policy.Mux != test.wantMux {
				t.Fatalf("mux = %d, want %d", policy.Mux, test.wantMux)
			}
			if policy.PoolSize != test.wantPool {
				t.Fatalf("pool = %d, want %d", policy.PoolSize, test.wantPool)
			}
			if policy.MixEnabled() != test.wantMix {
				t.Fatalf("mix = %t, want %t", policy.MixEnabled(), test.wantMix)
			}
			if test.in.MixFallbackTimeout != nil && policy.MixFallbackTimeout.Seconds() != float64(*test.in.MixFallbackTimeout) {
				t.Fatalf("mix fallback = %s, want %ds", policy.MixFallbackTimeout, *test.in.MixFallbackTimeout)
			}
		})
	}
}
