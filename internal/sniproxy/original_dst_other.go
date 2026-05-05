//go:build !linux

// Non-Linux stub for the SO_ORIGINAL_DST trick used by the
// transparent SNI proxy. The real implementation in
// original_dst.go uses Linux-specific socket options that don't
// exist on Windows or macOS. On dev machines we return an error
// so the proxy fails fast — it shouldn't be running in dev anyway.

package sniproxy

import (
	"errors"
	"net"
)

func originalDst(_ net.Conn) (string, error) {
	return "", errors.New("sniproxy: original destination not available on this platform")
}