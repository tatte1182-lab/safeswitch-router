package terminator

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// decodeWGKey accepts a WireGuard key in either base64 (the
// `wg genkey` / `wg pubkey` output format) or hex (the UAPI
// internal format) and returns the hex string wireguard-go's
// IpcSet expects.
//
// We accept both forms because Supabase stores keys however the
// caller wrote them — kernel WG tooling produces base64 by default
// but some of our older test fixtures stored hex.
func decodeWGKey(key string) (string, error) {
	// Try base64 first (most common).
	if b, err := base64.StdEncoding.DecodeString(key); err == nil && len(b) == 32 {
		return hex.EncodeToString(b), nil
	}
	// Fall back to hex.
	if b, err := hex.DecodeString(key); err == nil && len(b) == 32 {
		return hex.EncodeToString(b), nil
	}
	return "", fmt.Errorf("not a valid 32-byte wireguard key (tried base64 and hex)")
}