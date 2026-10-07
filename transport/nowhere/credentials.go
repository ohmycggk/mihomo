package nowhere

import (
	"fmt"
	"net/url"
)

// PortalKeyMinLen and PortalKeyMaxLen bound the Portal shared-key text.
// Lengths are inclusive and odd lengths are accepted.
const (
	PortalKeyMinLen = 32
	PortalKeyMaxLen = 64
)

// DecodePortalKey enforces the Portal key admission rule (Rust
// Credentials::for_portal and docs/configuration.md "Shared keys"): after URL
// percent decoding the key must be 32–64 lowercase hexadecimal characters.
// Uppercase letters, non-hex characters, whitespace and other lengths fail
// before certificate loading, DNS resolution or listening. The decoded text
// bytes are the authentication and Morph derivation input — there is no hex
// decoding — so the decoded value is what the caller keeps.
//
// The rule is Portal-side only. Vector, probe and fingerprint clients accept
// 1–255 decoded key bytes, so a client-side key stays lenient.
func DecodePortalKey(key string) (string, error) {
	decoded, err := url.PathUnescape(key)
	if err != nil {
		return "", fmt.Errorf("malformed percent escape in shared key")
	}
	if len(decoded) < PortalKeyMinLen || len(decoded) > PortalKeyMaxLen {
		return "", errPortalKeyFormat
	}
	for i := 0; i < len(decoded); i++ {
		c := decoded[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", errPortalKeyFormat
		}
	}
	return decoded, nil
}

var errPortalKeyFormat = fmt.Errorf("shared key must be %d–%d lowercase hexadecimal characters; use mihomo nowhere generate-key",
	PortalKeyMinLen, PortalKeyMaxLen)
