package tunnel

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	wgInterface  = "wg0"
	wgConfDir    = "/etc/wireguard"
	wgConfPath   = "/etc/wireguard/wg0.conf"
	// DevConfPath is the path used in dev/test mode — writable without root.
	devConfPath  = "/tmp/ss-wg0.conf"
)

// PeerConfig is one WireGuard peer entry.
type PeerConfig struct {
	// PublicKey is the peer's WireGuard public key (base64).
	PublicKey string
	// AllowedIP is the tunnel IP assigned to this peer (e.g. "10.10.0.2/32").
	AllowedIP string
	// DeviceMAC links the peer back to a device in the registry.
	DeviceMAC string
	// Comment is written into the config file for human readability.
	Comment string
}

// ConfWriter manages the wg0.conf file and applies changes via wg(8).
type ConfWriter struct {
	devMode bool // true = write to /tmp, skip wg commands (for dev/test)
}

// NewConfWriter creates a ConfWriter. In dev mode it writes to /tmp and
// skips wg CLI calls so the binary runs without root or a WireGuard interface.
func NewConfWriter(devMode bool) *ConfWriter {
	return &ConfWriter{devMode: devMode}
}

// Apply writes a fresh wg0.conf from the given peers and calls
// `wg syncconf wg0` to apply changes without restarting the interface.
// Existing handshakes are preserved.
func (w *ConfWriter) Apply(iface InterfaceConfig, peers []PeerConfig) error {
	conf := w.buildConf(iface, peers)

	path := wgConfPath
	if w.devMode {
		path = devConfPath
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("wgconf: mkdir: %w", err)
	}

	// Write atomically: temp file → rename
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(conf), 0o600); err != nil {
		return fmt.Errorf("wgconf: write temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("wgconf: rename: %w", err)
	}

	if w.devMode {
		return nil
	}

	// Apply without full interface restart — existing sessions survive
	return w.syncconf(path)
}

// syncconf runs `wg syncconf wg0 <path>` to apply the new config live.
func (w *ConfWriter) syncconf(path string) error {
	cmd := exec.Command("wg", "syncconf", wgInterface, path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg syncconf: %w — output: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// buildConf generates the wg0.conf content from interface config and peers.
func (w *ConfWriter) buildConf(iface InterfaceConfig, peers []PeerConfig) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# SafeSwitch wg0.conf — generated %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", iface.PrivateKey))
	sb.WriteString(fmt.Sprintf("ListenPort = %d\n", iface.ListenPort))
	if iface.Address != "" {
		sb.WriteString(fmt.Sprintf("Address = %s\n", iface.Address))
	}
	sb.WriteString("\n")

	for _, p := range peers {
		if p.Comment != "" {
			sb.WriteString(fmt.Sprintf("# %s\n", p.Comment))
		}
		sb.WriteString("[Peer]\n")
		sb.WriteString(fmt.Sprintf("PublicKey = %s\n", p.PublicKey))
		sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", p.AllowedIP))
		sb.WriteString("\n")
	}

	return sb.String()
}

// InterfaceConfig holds the [Interface] section parameters.
type InterfaceConfig struct {
	PrivateKey string
	ListenPort int
	Address    string // e.g. "10.10.0.1/24"
}
