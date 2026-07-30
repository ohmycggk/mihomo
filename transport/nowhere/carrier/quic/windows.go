package quic

import corequic "github.com/ohmycggk/nowhere-go/carrier/quic"

// Re-export Nowhere 1.5.2 recommended QUIC windows for the Mihomo backend.
const (
	RecommendedStreamReceiveWindow     = corequic.RecommendedStreamReceiveWindow
	RecommendedConnectionReceiveWindow = corequic.RecommendedConnectionReceiveWindow
	RecommendedSendWindow              = corequic.RecommendedSendWindow
	RecommendedDatagramBufferSize      = corequic.RecommendedDatagramBufferSize
)
