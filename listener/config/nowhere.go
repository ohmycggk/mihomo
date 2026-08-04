package config

import (
	"encoding/json"
)

type NowhereServer struct {
	Enable               bool     `yaml:"enable" json:"enable"`
	Listen               string   `yaml:"listen" json:"listen"`
	Password             string   `yaml:"password" json:"password"`
	Certificate          string   `yaml:"certificate" json:"certificate"`
	PrivateKey           string   `yaml:"private-key" json:"private-key"`
	EchKey               string   `yaml:"ech-key" json:"ech-key"`
	ALPN                 []string `yaml:"alpn" json:"alpn,omitempty"`
	CongestionController string   `yaml:"congestion-controller" json:"congestion-controller,omitempty"`
	CWND                 int      `yaml:"cwnd" json:"cwnd,omitempty"`
}

func (n NowhereServer) String() string {
	b, _ := json.Marshal(n)
	return string(b)
}
