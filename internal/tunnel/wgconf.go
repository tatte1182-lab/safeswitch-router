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
	wgInterface = "wg0"
	wgConfDir   = "/etc/wireguard"
	wgConfPath  = "/etc/wireguard/wg0.conf"
	devConfPath = "/tmp/ss-wg0.conf"
)

// natIface returns the upstream network interface for NAT/MASQUERADE rules.
// Reads SS_ROUTER_NAT_IFACE env var; falls back to wlp0s12f0 (Acer Swift WiFi).
// Override in the systemd unit: Environment=SS_ROUTER_NAT_IFACE=eth0
func natIface() string {
	if v := os.Getenv("SS_ROUTER_NAT_IFACE"); v != "" {
		return v
	}
	return "wlp0s12f0"
}

type PeerConfig struct {
	PublicKey string
	AllowedIP string
	DeviceMAC string
	Comment   string
}

type ConfWriter struct {
	devMode bool
}

func NewConfWriter(devMode bool) *ConfWriter {
	return &ConfWriter{devMode: devMode}
}

// EnsureInterface guarantees wg0 exists with the correct IP before Apply/syncconf.
// Idempotent — safe to call on every Start().
func (w *ConfWriter) EnsureInterface(iface InterfaceConfig) error {
	if w.devMode {
		return nil
	}
	// Check if interface exists
	if err := exec.Command("ip", "link", "show", wgInterface).Run(); err != nil {
		// Create it
		if out, err := exec.Command("ip", "link", "add", wgInterface, "type", "wireguard").CombinedOutput(); err != nil {
			return fmt.Errorf("ip link add wg0: %w — %s", err, strings.TrimSpace(string(out)))
		}
		// Apply private key + listen port
		minConf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nListenPort = %d\n", iface.PrivateKey, iface.ListenPort)
		tmp, err := os.CreateTemp("", "ss-wg-init-*.conf")
		if err != nil {
			return fmt.Errorf("wg setconf temp: %w", err)
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.WriteString(minConf); err != nil {
			tmp.Close()
			return fmt.Errorf("wg setconf write: %w", err)
		}
		tmp.Close()
		if out, err := exec.Command("wg", "setconf", wgInterface, tmp.Name()).CombinedOutput(); err != nil {
			return fmt.Errorf("wg setconf: %w — %s", err, strings.TrimSpace(string(out)))
		}
	}
	// Ensure tunnel IP is assigned
	existingAddrs, _ := exec.Command("ip", "addr", "show", wgInterface).Output()
	if !strings.Contains(string(existingAddrs), "10.10.0.1") {
		if out, err := exec.Command("ip", "addr", "add", "10.10.0.1/24", "dev", wgInterface).CombinedOutput(); err != nil {
			return fmt.Errorf("ip addr add 10.10.0.1/24: %w — %s", err, strings.TrimSpace(string(out)))
		}
	}
	// Ensure sinkhole IP is assigned
	if !strings.Contains(string(existingAddrs), "10.10.0.254") {
		exec.Command("ip", "addr", "add", "10.10.0.254/32", "dev", wgInterface).Run() // best-effort
	}
	// Bring up
	exec.Command("ip", "link", "set", wgInterface, "up").Run()
	return nil
}
func (w *ConfWriter) Apply(iface InterfaceConfig, peers []PeerConfig) error {
	conf := w.buildConf(iface, peers)
	path := wgConfPath
	if w.devMode {
		path = devConfPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("wgconf: mkdir: %w", err)
	}
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
	return w.syncconf(path)
}

func (w *ConfWriter) EnsureNAT() error {
	if w.devMode {
		return nil
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}
	iface := natIface()
	check := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING",
		"-s", "10.10.0.0/24", "-o", iface, "-j", "MASQUERADE")
	if err := check.Run(); err == nil {
		return nil
	}
	add := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", "10.10.0.0/24", "-o", iface, "-j", "MASQUERADE")
	out, err := add.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables MASQUERADE: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (w *ConfWriter) syncconf(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("wg syncconf: read conf: %w", err)
	}
	var stripped strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Address") ||
			strings.HasPrefix(trimmed, "PostUp") ||
			strings.HasPrefix(trimmed, "PostDown") ||
			strings.HasPrefix(trimmed, "DNS") {
			continue
		}
		stripped.WriteString(line)
		stripped.WriteByte('\n')
	}
	tmp, err := os.CreateTemp("", "ss-wg-sync-*.conf")
	if err != nil {
		return fmt.Errorf("wg syncconf: create temp: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(stripped.String()); err != nil {
		tmp.Close()
		return fmt.Errorf("wg syncconf: write temp: %w", err)
	}
	tmp.Close()
	cmd := exec.Command("wg", "syncconf", wgInterface, tmp.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg syncconf: %w — output: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (w *ConfWriter) buildConf(iface InterfaceConfig, peers []PeerConfig) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# SafeSwitch wg0.conf — generated %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", iface.PrivateKey))
	sb.WriteString(fmt.Sprintf("ListenPort = %d\n", iface.ListenPort))
	if iface.Address != "" {
		sb.WriteString(fmt.Sprintf("Address = %s\n", iface.Address))
	}
	sb.WriteString(fmt.Sprintf("PostUp = iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o %s -j MASQUERADE; iptables -A FORWARD -i %s -j ACCEPT; iptables -A FORWARD -o %s -j ACCEPT\n", natIface(), wgInterface, wgInterface))
	sb.WriteString(fmt.Sprintf("PostDown = iptables -t nat -D POSTROUTING -s 10.10.0.0/24 -o %s -j MASQUERADE; iptables -D FORWARD -i %s -j ACCEPT; iptables -D FORWARD -o %s -j ACCEPT\n", natIface(), wgInterface, wgInterface))
	sb.WriteString("\n")
	for _, p := range peers {
		if p.Comment != "" {
			sb.WriteString(fmt.Sprintf("# %s\n", p.Comment))
		}
		sb.WriteString("[Peer]\n")
		sb.WriteString(fmt.Sprintf("PublicKey = %s\n", p.PublicKey))
		sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", p.AllowedIP))
		// No PersistentKeepalive on the server side — roaming clients manage
		// keepalive in their own config. Server-side keepalive pins the stale
		// last-seen endpoint and prevents automatic endpoint updates when a
		// client roams from WiFi to mobile data.
		sb.WriteString("\n")
	}
	return sb.String()
}

type InterfaceConfig struct {
	PrivateKey string
	ListenPort int
	Address    string
}
