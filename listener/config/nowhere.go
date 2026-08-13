package config

import (
	"encoding/json"
)

type NowhereServer struct {
	Enable               bool         `yaml:"enable" json:"enable"`
	Listen               string       `yaml:"listen" json:"listen"`
	Password             string       `yaml:"password" json:"password"`
	Certificate          string       `yaml:"certificate" json:"certificate"`
	PrivateKey           string       `yaml:"private-key" json:"private-key"`
	EchKey               string       `yaml:"ech-key" json:"ech-key"`
	ALPN                 []string     `yaml:"alpn" json:"alpn,omitempty"`
	CongestionController string       `yaml:"congestion-controller" json:"congestion-controller,omitempty"`
	CWND                 int          `yaml:"cwnd" json:"cwnd,omitempty"`
	Next                 *NowhereNext `yaml:"next" json:"next,omitempty"`
}

// NowhereNext is the next-hop Portal for native Portal chaining (Nowhere 1.7):
// when set, the listener forwards every inbound flow to another Nowhere Portal
// instead of the tunnel. The forwarding connection inherits the listener ALPN
// and congestion-controller/cwnd.
type NowhereNext struct {
	Server   string `yaml:"server" json:"server"`
	Port     int    `yaml:"port" json:"port"`
	Password string `yaml:"password" json:"password"`
	// Up and Down independently select the carrier towards the next Portal
	// ("tcp" for TLS/TCP or "udp" for QUIC/UDP). Each defaults to "udp" and
	// they must be set together.
	Up   string `yaml:"up" json:"up,omitempty"`
	Down string `yaml:"down" json:"down,omitempty"`
	// Pool is the warm TLS/TCP connection count, only meaningful for the
	// tcp/tcp matrix (default 5 there, 0 otherwise; max tcptls.MaxPoolSize).
	Pool *int `yaml:"pool" json:"pool,omitempty"`
	// SNI overrides the TLS server name used towards the next Portal. Empty or
	// the literal "none" disables certificate verification (a domain server is
	// still sent as ClientHello SNI); an explicit DNS name enables chain+name
	// verification.
	SNI string `yaml:"sni" json:"sni,omitempty"`
	// Pin is the next Portal's leaf-certificate SHA-256 (lowercase hex). When
	// set (non-empty, non-"none") it overrides SNI/chain verification, like
	// the outbound's pin.
	Pin string `yaml:"pin" json:"pin,omitempty"`
}

func (n NowhereServer) String() string {
	b, _ := json.Marshal(n)
	return string(b)
}
