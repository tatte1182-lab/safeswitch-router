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

// natIface returns the upstream interface for NAT/MASQUERADE rules.
// Resolution: SS_ROUTER_NAT_IFACE env → auto-detect from ip route → "eth0"
func natIface() string {
	if v := strings.TrimSpace(os.Getenv("SS_ROUTER_NAT_IFACE")); v != "" {
		return v
	}
	if iface := detectDefaultIface(); iface != "" {
		return iface
	}
	return "eth0"
}

func detectDefaultIface() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "dev" && i+1 < len(fields) {
				c := fields[i+1]
				if c != "lo" && !strings.HasPrefix(c, "wg") {
					return c
				}
			}
		}
	}
	return ""
}

// PeerConfig is one [Peer] block for wg0.conf generation.
type PeerConfig struct {
	PublicKey string
	AllowedIP string
	DeviceMAC string
	Comment   string
}

// InterfaceConfig is the [Interface] section values.
type InterfaceConfig struct {
	PrivateKey string
	ListenPort int
	Address    string
}

// ConfWriter owns all WireGuard interface and peer management.
type ConfWriter struct {
	devMode bool
}

func NewConfWriter(devMode bool) *ConfWriter {
	return &ConfWriter{devMode: devMode}
}

// Apply is the single entry point for all WireGuard state changes.
//
// Strategy (non-disruptive):
//  1. Write wg0.conf atomically to disk (persistent across reboots).
//  2. Ensure wg0 interface exists and has the correct private key + address —
//     using `wg set` (not setconf) so existing peers are never touched.
//  3. Diff live peers via `wg show dump` against desired peers.
//     Add/update only changed peers, remove only orphaned ones.
//     Peers with no changes are never touched — their handshakes survive.
//
// This means a bundle swap or re-enrollment never drops unaffected peers.
func (w *ConfWriter) Apply(iface InterfaceConfig, peers []PeerConfig) error {
	// 1. Write wg0.conf to disk (used for wg-quick up on boot and audit trail)
	if err := w.writeConf(iface, peers); err != nil {
		return err
	}
	if w.devMode {
		return nil
	}

	// 2. Bring the interface up with correct identity — non-disruptive
	if err := w.ensureInterfaceNonDisruptive(iface); err != nil {
		return err
	}

	// 3. Sync NAT rule
	if err := w.EnsureNAT(); err != nil {
		return err
	}

	// 4. Diff and apply only the peer delta
	return w.syncPeersDiff(peers)
}

// ensureInterfaceNonDisruptive brings wg0 up and sets the private key and
// listen port using `wg set` — which does NOT remove existing peers.
// This is safe to call on every Apply().
func (w *ConfWriter) ensureInterfaceNonDisruptive(iface InterfaceConfig) error {
	// Create the interface if it doesn't exist
	if err := exec.Command("ip", "link", "show", wgInterface).Run(); err != nil {
		out, err := exec.Command("ip", "link", "add", wgInterface, "type", "wireguard").CombinedOutput()
		if err != nil {
			return fmt.Errorf("ip link add %s: %w — %s", wgInterface, err, strings.TrimSpace(string(out)))
		}
	}

	// Set private key and listen port non-destructively (wg set, not setconf)
	out, err := exec.Command("wg", "set", wgInterface,
		"listen-port", fmt.Sprintf("%d", iface.ListenPort),
		"private-key", "/dev/stdin",
	).CombinedOutput()
	// wg set private-key reads from a file path, not stdin — use a temp file
	if err != nil {
		// Fallback: write key to temp file and use that
		if err2 := w.setPrivateKeyViaFile(iface.PrivateKey, iface.ListenPort); err2 != nil {
			return fmt.Errorf("wg set interface: %w (also tried file: %v) — %s",
				err, err2, strings.TrimSpace(string(out)))
		}
	}

	// Assign gateway address if not already present
	existingAddrs, _ := exec.Command("ip", "addr", "show", wgInterface).Output()
	if !strings.Contains(string(existingAddrs), TunnelGateway) {
		out, err := exec.Command("ip", "addr", "add", TunnelGatewayCIDR, "dev", wgInterface).CombinedOutput()
		if err != nil && !strings.Contains(string(out), "File exists") {
			return fmt.Errorf("ip addr add %s: %w — %s", TunnelGatewayCIDR, err, strings.TrimSpace(string(out)))
		}
	}

	// Assign sinkhole address (best-effort)
	if !strings.Contains(string(existingAddrs), "10.10.0.254") {
		_ = exec.Command("ip", "addr", "add", "10.10.0.254/32", "dev", wgInterface).Run()
	}

	// Bring up
	if out, err := exec.Command("ip", "link", "set", wgInterface, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set %s up: %w — %s", wgInterface, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// setPrivateKeyViaFile sets the WireGuard private key and listen port by
// writing to a temp file (wg set private-key requires a file path).
func (w *ConfWriter) setPrivateKeyViaFile(privateKey string, listenPort int) error {
	tmp, err := os.CreateTemp("", "ss-wg-key-*.key")
	if err != nil {
		return fmt.Errorf("create temp key file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(privateKey + "\n"); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp key: %w", err)
	}
	tmp.Close()
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("chmod temp key: %w", err)
	}
	out, err := exec.Command("wg", "set", wgInterface,
		"listen-port", fmt.Sprintf("%d", listenPort),
		"private-key", tmp.Name(),
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg set private-key: %w — %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// syncPeersDiff reads the live wg0 peer state and applies only the minimum
// set of changes needed to match the desired peer list.
//
//   - Peers present in desired and live with the same AllowedIPs → no-op
//   - Peers present in desired but not live → add via `wg set peer <key> allowed-ips <ip>`
//   - Peers present in desired with a different AllowedIP (re-key) → remove old, add new
//   - Peers present in live but not desired → remove via `wg set peer <key> remove`
//
// Peers that don't change are never touched. Their handshakes survive.
func (w *ConfWriter) syncPeersDiff(desired []PeerConfig) error {
	// Read live state
	live, err := readLivePeers()
	if err != nil {
		// wg0 might not be up yet on first boot — fall back to syncconf
		return w.syncconfFallback()
	}

	// Index desired by public key
	desiredByKey := make(map[string]PeerConfig, len(desired))
	for _, p := range desired {
		desiredByKey[p.PublicKey] = p
	}

	// Index live by public key
	liveByKey := make(map[string]string, len(live)) // key → allowedIP
	for k, ip := range live {
		liveByKey[k] = ip
	}

	added, updated, removed := 0, 0, 0

	// Add or update
	for _, p := range desired {
		allowedIP := normalizeAllowedIP(p.AllowedIP)
		liveIP, exists := liveByKey[p.PublicKey]

		if exists && liveIP == allowedIP {
			continue // no change — leave handshake intact
		}

		// If this IP is currently assigned to a different key (re-key scenario),
		// remove the old key first so there's no AllowedIP conflict.
		for liveKey, liveKIP := range liveByKey {
			if liveKIP == allowedIP && liveKey != p.PublicKey {
				if out, err := exec.Command("wg", "set", wgInterface,
					"peer", liveKey, "remove").CombinedOutput(); err != nil {
					return fmt.Errorf("wg remove old peer for rekey %s: %w — %s",
						shortKey(liveKey), err, strings.TrimSpace(string(out)))
				}
				delete(liveByKey, liveKey)
				removed++
				break
			}
		}

		out, err := exec.Command("wg", "set", wgInterface,
			"peer", p.PublicKey,
			"allowed-ips", allowedIP,
		).CombinedOutput()
		if err != nil {
			return fmt.Errorf("wg set peer %s: %w — %s",
				shortKey(p.PublicKey), err, strings.TrimSpace(string(out)))
		}
		if exists {
			updated++
		} else {
			added++
		}
	}

	// Remove orphaned peers
	for liveKey := range liveByKey {
		if _, wanted := desiredByKey[liveKey]; !wanted {
			out, err := exec.Command("wg", "set", wgInterface,
				"peer", liveKey, "remove").CombinedOutput()
			if err != nil {
				return fmt.Errorf("wg remove peer %s: %w — %s",
					shortKey(liveKey), err, strings.TrimSpace(string(out)))
			}
			removed++
		}
	}

	if added+updated+removed > 0 {
		// Log is handled by manager — ConfWriter stays silent on no-op
		_ = added + updated + removed // suppress unused warning
	}
	return nil
}

// readLivePeers returns a map of publicKey → allowedIP for all peers
// currently configured in the live wg0 interface.
func readLivePeers() (map[string]string, error) {
	out, err := exec.Command("wg", "show", wgInterface, "dump").Output()
	if err != nil {
		return nil, fmt.Errorf("wg show dump: %w", err)
	}
	peers := make(map[string]string)
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // interface line
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 4 {
			continue
		}
		pubKey := fields[0]
		allowedIPs := fields[3] // e.g. "10.10.0.4/32"
		if pubKey != "" && allowedIPs != "(none)" {
			// Take only the first allowed IP (we only ever set one)
			first := strings.Split(allowedIPs, ",")[0]
			peers[pubKey] = strings.TrimSpace(first)
		}
	}
	return peers, nil
}

// syncconfFallback is used only when wg0 doesn't exist yet (first boot).
// It writes a full syncconf — safe because there are no live peers to disrupt.
func (w *ConfWriter) syncconfFallback() error {
	raw, err := os.ReadFile(wgConfPath)
	if err != nil {
		return fmt.Errorf("syncconf fallback: read conf: %w", err)
	}
	var stripped strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "Address") || strings.HasPrefix(t, "PostUp") ||
			strings.HasPrefix(t, "PostDown") || strings.HasPrefix(t, "DNS") {
			continue
		}
		stripped.WriteString(line)
		stripped.WriteByte('\n')
	}
	tmp, err := os.CreateTemp("", "ss-wg-sync-*.conf")
	if err != nil {
		return fmt.Errorf("syncconf fallback: create temp: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(stripped.String()); err != nil {
		tmp.Close()
		return fmt.Errorf("syncconf fallback: write temp: %w", err)
	}
	tmp.Close()
	out, err := exec.Command("wg", "syncconf", wgInterface, tmp.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("syncconf fallback: %w — %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// EnsureNAT idempotently adds the MASQUERADE rule for the tunnel subnet.
func (w *ConfWriter) EnsureNAT() error {
	if w.devMode {
		return nil
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}
	iface := natIface()
	check := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING",
		"-s", TunnelSubnet, "-o", iface, "-j", "MASQUERADE")
	if check.Run() == nil {
		return nil
	}
	out, err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", TunnelSubnet, "-o", iface, "-j", "MASQUERADE").CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables MASQUERADE (iface=%s): %w — %s", iface, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// writeConf atomically writes wg0.conf to disk.
// This is the persistent copy used by wg-quick on boot and for audit.
func (w *ConfWriter) writeConf(iface InterfaceConfig, peers []PeerConfig) error {
	path := wgConfPath
	if w.devMode {
		path = devConfPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("wgconf mkdir: %w", err)
	}
	conf := buildConf(iface, peers)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(conf), 0o600); err != nil {
		return fmt.Errorf("wgconf write temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("wgconf rename: %w", err)
	}
	return nil
}

func buildConf(iface InterfaceConfig, peers []PeerConfig) string {
	upIface := natIface()
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# SafeSwitch wg0.conf — generated %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", iface.PrivateKey))
	sb.WriteString(fmt.Sprintf("ListenPort = %d\n", iface.ListenPort))
	if iface.Address != "" {
		sb.WriteString(fmt.Sprintf("Address = %s\n", iface.Address))
	}
	sb.WriteString(fmt.Sprintf(
		"PostUp = iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE; iptables -A FORWARD -i %s -j ACCEPT; iptables -A FORWARD -o %s -j ACCEPT\n",
		TunnelSubnet, upIface, wgInterface, wgInterface,
	))
	sb.WriteString(fmt.Sprintf(
		"PostDown = iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE; iptables -D FORWARD -i %s -j ACCEPT; iptables -D FORWARD -o %s -j ACCEPT\n",
		TunnelSubnet, upIface, wgInterface, wgInterface,
	))
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
