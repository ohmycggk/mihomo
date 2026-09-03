package nowhere

import (
	"fmt"
	"time"

	"github.com/ohmycggk/nowhere-go/bundle"
)

// RouteInputs is the host-facing carrier/mux/pool policy before it is mapped
// onto a nowhere-go BundleOptions.
type RouteInputs struct {
	// Prefix is prepended to validation errors ("nowhere name", "nowhere: next").
	Prefix string
	Up     string
	Down   string
	Pool   *int
	Mux    *int
	// MixFallbackTimeout is the mix primary-route budget in seconds. Nil or 0
	// leaves the library default (1s).
	MixFallbackTimeout *int
	// Warn reports non-fatal canonicalization. Nil warnings are discarded.
	Warn func(format string, args ...any)
}

// RoutePolicy is the resolved Nowhere 1.8 client route: concrete or mixed
// carriers, TLS Mux, and the dedicated tcp/tcp warm pool.
type RoutePolicy struct {
	Up, Down           string
	MixUp, MixDown     bool
	UsesTCP, UsesQUIC  bool
	PoolSize           int
	Mux                bundle.MuxMode
	MixFallbackTimeout time.Duration
}

// ResolveRoutePolicy validates up/down/mux/pool against Nowhere 1.8.3.
//
// Carriers default to udp/udp. mix is a client-only policy resolved per flow.
// mux=1 enables TLS Mux when TCP is possible; udp/udp&mux=1 canonicalizes to 0.
// The warm pool applies only to dedicated (mux=0) tcp/tcp.
func ResolveRoutePolicy(in RouteInputs) (RoutePolicy, error) {
	up, down := in.Up, in.Down
	switch {
	case up != "" && down != "":
	case up == "" && down == "":
		up, down = "udp", "udp"
	default:
		return RoutePolicy{}, fmt.Errorf("%s: up and down must be set together", in.Prefix)
	}
	if !validCarrierMode(up) || !validCarrierMode(down) {
		return RoutePolicy{}, fmt.Errorf("%s: invalid carrier (up=%q down=%q, must be tcp, udp, or mix)", in.Prefix, up, down)
	}

	usesTCP := up != "udp" || down != "udp"
	usesQUIC := up != "tcp" || down != "tcp"

	mux := bundle.MuxDisabled
	if in.Mux != nil {
		switch *in.Mux {
		case 0:
			mux = bundle.MuxDisabled
		case 1:
			mux = bundle.MuxEnabled
		default:
			return RoutePolicy{}, fmt.Errorf("%s: invalid mux %d (must be 0 or 1)", in.Prefix, *in.Mux)
		}
	}
	if mux == bundle.MuxEnabled && !usesTCP {
		in.warn("mux=1 is canonicalized to 0 for udp/udp")
		mux = bundle.MuxDisabled
	}

	poolSize := 0
	switch {
	case usesQUIC:
		if in.Pool != nil && *in.Pool != 0 {
			in.warn("pool is only effective for dedicated tcp/tcp; ignoring configured value %d", *in.Pool)
		}
	case mux == bundle.MuxEnabled:
		if in.Pool != nil && *in.Pool != 0 {
			in.warn("pool must be zero when TLS mux is enabled; ignoring configured value %d", *in.Pool)
		}
	default:
		if in.Pool == nil {
			poolSize = DefaultPoolSize
		} else if *in.Pool < 0 {
			return RoutePolicy{}, fmt.Errorf("%s: invalid pool %d (must be >= 0)", in.Prefix, *in.Pool)
		} else if *in.Pool > MaxPoolSize {
			in.warn("pool %d exceeds maximum %d; using %d", *in.Pool, MaxPoolSize, MaxPoolSize)
			poolSize = MaxPoolSize
		} else {
			poolSize = *in.Pool
		}
	}

	var mixTimeout time.Duration
	if in.MixFallbackTimeout != nil {
		if *in.MixFallbackTimeout < 0 {
			return RoutePolicy{}, fmt.Errorf("%s: invalid mix-fallback-timeout %d (must be >= 0)", in.Prefix, *in.MixFallbackTimeout)
		}
		mixTimeout = time.Duration(*in.MixFallbackTimeout) * time.Second
	}

	return RoutePolicy{
		Up: up, Down: down,
		MixUp: up == "mix", MixDown: down == "mix",
		UsesTCP: usesTCP, UsesQUIC: usesQUIC,
		PoolSize: poolSize, Mux: mux,
		MixFallbackTimeout: mixTimeout,
	}, nil
}

// UpCarrier is the bundle uplink selector. Mix uplink is 0.
func (p RoutePolicy) UpCarrier() Carrier {
	if p.MixUp {
		return 0
	}
	if p.Up == "tcp" {
		return CarrierTLSTCP
	}
	return CarrierQUIC
}

// DownCarrier is the bundle downlink selector. Mix downlink is 0.
func (p RoutePolicy) DownCarrier() Carrier {
	if p.MixDown {
		return 0
	}
	if p.Down == "tcp" {
		return CarrierTLSTCP
	}
	return CarrierQUIC
}

// MixEnabled reports whether either direction uses the mix policy.
func (p RoutePolicy) MixEnabled() bool { return p.MixUp || p.MixDown }

func (in RouteInputs) warn(format string, args ...any) {
	if in.Warn != nil {
		in.Warn(format, args...)
	}
}

func validCarrierMode(s string) bool {
	return s == "tcp" || s == "udp" || s == "mix"
}
