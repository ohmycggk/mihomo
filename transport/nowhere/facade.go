// Package nowhere is the Mihomo host facade for Nowhere outbound.
// Shared protocol core lives in github.com/ohmycggk/nowhere-go;
// this package keeps the platform QUIC backend and thin type aliases.
package nowhere

import (
	"net/netip"

	"github.com/ohmycggk/nowhere-go/bundle"
	"github.com/ohmycggk/nowhere-go/carrier/tcptls"
	"github.com/ohmycggk/nowhere-go/wire"

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
)

const (
	DefaultPoolSize = tcptls.DefaultPoolSize
	MaxPoolSize     = tcptls.MaxPoolSize

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
