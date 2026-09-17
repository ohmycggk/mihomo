// Package nowhere is the Mihomo host facade for Nowhere outbound.
// Shared protocol core lives in github.com/metacubex/mihomo/transport/nowhere/core;
// this package keeps the platform QUIC backend and thin type aliases.
package nowhere

import (
	"net/netip"

	"github.com/metacubex/mihomo/transport/nowhere/core/bundle"
	"github.com/metacubex/mihomo/transport/nowhere/core/carrier/tcptls"
	"github.com/metacubex/mihomo/transport/nowhere/core/wire"

	quicpkg "github.com/metacubex/mihomo/transport/nowhere/carrier/quic"
)

type (
	Credentials      = wire.Credentials
	HandshakedConn   = wire.HandshakedConn
	TLSHandshakeInfo = wire.TLSHandshakeInfo
	TLSExporter      = wire.TLSExporter
	Target           = wire.Target
	Carrier          = wire.Carrier
	FlowHeader       = wire.FlowHeader
	FlowRole         = wire.FlowRole
	FlowKind         = wire.FlowKind

	QUICConfig = quicpkg.QUICConfig
	TCPConfig  = tcptls.Config
	TCPOptions = tcptls.TCPOptions
	TLSDialer  = tcptls.TLSDialer

	BundleOptions = bundle.BundleOptions
	CarrierBundle = bundle.CarrierBundle
	MuxMode       = bundle.MuxMode
	CarrierMode   = bundle.CarrierMode
)

const (
	DefaultALPN               = wire.DefaultALPN
	DefaultPoolSize           = tcptls.DefaultPoolSize
	MaxPoolSize               = tcptls.MaxPoolSize
	MuxDisabled               = bundle.MuxDisabled
	MuxEnabled                = bundle.MuxEnabled
	ModeTCP                   = bundle.ModeTCP
	ModeUDP                   = bundle.ModeUDP
	ModeMix                   = bundle.ModeMix
	DefaultMixFallbackTimeout = bundle.DefaultMixFallbackTimeout

	FlowRoleOpen        = wire.FlowRoleOpen
	FlowRoleAttach      = wire.FlowRoleAttach
	FlowKindTCP         = wire.FlowKindTCP
	FlowKindUDP         = wire.FlowKindUDP
	CarrierTLSTCP       = wire.CarrierTLSTCP
	CarrierQUIC         = wire.CarrierQUIC
	AuthTransportTLSTCP = wire.AuthTransportTLSTCP
)

var (
	NewCredentials   = wire.NewCredentials
	NewTCPConfig     = tcptls.NewConfig
	NewCarrierBundle = bundle.NewCarrierBundle
	ParseCarrierMode = bundle.ParseCarrierMode

	ParseCertificatePin        = wire.ParseCertificatePin
	PeerCertificatePinVerifier = wire.PeerCertificatePinVerifier
	LeafCertificateSHA256Hex   = wire.LeafCertificateSHA256Hex
	VerifyLeafCertSHA256       = wire.VerifyLeafCertSHA256
)

const (
	TLSExporterLabel = wire.TLSExporterLabel
	TLSExporterLen   = wire.TLSExporterLen

	RecommendedStreamReceiveWindow     = quicpkg.RecommendedStreamReceiveWindow
	RecommendedConnectionReceiveWindow = quicpkg.RecommendedConnectionReceiveWindow
	RecommendedSendWindow              = quicpkg.RecommendedSendWindow
	RecommendedDatagramBufferSize      = quicpkg.RecommendedDatagramBufferSize
)

func EmptyTLSExporterContext() []byte { return wire.EmptyTLSExporterContext() }

func NewIPTarget(addr netip.Addr, port uint16) (Target, error) { return wire.NewIPTarget(addr, port) }

func NewDomainTarget(host string, port uint16) (Target, error) {
	return wire.NewDomainTarget(host, port)
}

// NewQuicBackend wraps the Mihomo QUIC client as a nowhere-go QuicBackend.
func NewQuicBackend(cfg *QUICConfig) *QuicBackend {
	return NewBackend(cfg)
}
