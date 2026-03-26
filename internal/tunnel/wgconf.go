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
	natIface    = "eth0"
)

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
	check := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING",
		"-s", "10.10.0.0/24", "-o", natIface, "-j", "MASQUERADE")
	if err := check.Run(); err == nil {
		return nil
	}
	add := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", "10.10.0.0/24", "-o", natIface, "-j", "MASQUERADE")
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
	sb.WriteString(fmt.Sprintf("PostUp = iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o %s -j MASQUERADE; iptables -A FORWARD -i %s -j ACCEPT; iptables -A FORWARD -o %s -j ACCEPT\n", natIface, wgInterface, wgInterface))
	sb.WriteString(fmt.Sprintf("PostDown = iptables -t nat -D POSTROUTING -s 10.10.0.0/24 -o %s -j MASQUERADE; iptables -D FORWARD -i %s -j ACCEPT; iptables -D FORWARD -o %s -j ACCEPT\n", natIface, wgInterface, wgInterface))
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

type InterfaceConfig struct {
	PrivateKey string
	ListenPort int
	Address    string
}
