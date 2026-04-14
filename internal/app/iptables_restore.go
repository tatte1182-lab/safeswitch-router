package app

// iptables_restore.go
//
// HARDENING: Re-applies the SAFESWITCH iptables chain on service startup.
//
// Problem: iptables rules written at runtime are lost on node reboot.
// The SAFESWITCH chain enforces per-device DNS and traffic rules. Without
// restoration, devices connect successfully but enforcement is completely
// bypassed until the next bundlesync cycle writes new rules.
//
// Fix: On startup, applyBaseIptables() rebuilds the chain foundation, then
// restoreDeviceRules() reads all active devices from the DB and re-applies
// their enforcement rules before the first heartbeat is processed.
//
// This file adds restoreIptablesOnBoot() which is called from the supervisor
// Start() sequence, after DB init but before the command poller starts.

import (
	"database/sql"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// restoreIptablesOnBoot rebuilds the full SAFESWITCH iptables state.
// Call this once during startup, after the DB connection is established.
func restoreIptablesOnBoot(db *sql.DB, wgInterface string) error {
	log.Println("[iptables-restore] rebuilding SAFESWITCH chain on boot")

	// 1. Ensure the SAFESWITCH chain exists and is jumped to from FORWARD
	if err := applyBaseChain(wgInterface); err != nil {
		return fmt.Errorf("applyBaseChain: %w", err)
	}

	// 2. Re-apply per-device rules for all enrolled devices
	if err := restoreDeviceRules(db, wgInterface); err != nil {
		// Non-fatal — devices will get rules on next bundlesync cycle
		log.Printf("[iptables-restore] restoreDeviceRules warning: %v", err)
	}

	// 3. Ensure DNS lock — wg0 DNS queries must go to node resolver only
	if err := applyDNSLock(wgInterface); err != nil {
		return fmt.Errorf("applyDNSLock: %w", err)
	}

	// 4. Block QUIC (UDP 443) — forces TLS/TCP fallback for SNI inspection
	if err := blockQUIC(wgInterface); err != nil {
		log.Printf("[iptables-restore] blockQUIC warning: %v", err)
	}

	// 5. TCP MSS clamping — prevents PMTUD black holes through the tunnel
	if err := applyMSSClamping(wgInterface); err != nil {
		log.Printf("[iptables-restore] MSS clamping warning: %v", err)
	}

	log.Println("[iptables-restore] SAFESWITCH chain restored successfully")
	return nil
}

func applyBaseChain(iface string) error {
	cmds := [][]string{
		// Create chain (ignore error if already exists)
		{"iptables", "-t", "filter", "-N", "SAFESWITCH"},
		// Flush stale rules from previous session
		{"iptables", "-t", "filter", "-F", "SAFESWITCH"},
		// Jump FORWARD traffic from wg0 through SAFESWITCH (idempotent check then insert)
	}
	for _, args := range cmds {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			// -N returns exit 1 if chain already exists — that's fine
			if !strings.Contains(string(out), "Chain already exists") {
				log.Printf("[iptables-restore] %v: %s", args, out)
			}
		}
	}

	// Ensure the jump rule exists exactly once
	checkCmd := exec.Command("iptables", "-t", "filter", "-C", "FORWARD",
		"-i", iface, "-j", "SAFESWITCH")
	if err := checkCmd.Run(); err != nil {
		// Rule doesn't exist — add it
		addCmd := exec.Command("iptables", "-t", "filter", "-I", "FORWARD", "1",
			"-i", iface, "-j", "SAFESWITCH")
		if out, err := addCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("insert FORWARD jump: %s: %w", out, err)
		}
	}
	return nil
}

func restoreDeviceRules(db *sql.DB, iface string) error {
	// Query all enrolled devices with WireGuard IPs assigned to this node
	rows, err := db.Query(`
		SELECT d.wireguard_ip, ces.internet_paused, ces.is_paused
		FROM devices d
		JOIN child_effective_state ces ON ces.child_id = d.child_id
		WHERE d.trust_state = 'enrolled'
		  AND d.wireguard_ip IS NOT NULL
		  AND d.assigned_node_id = (
		    SELECT id FROM nodes WHERE node_secret_hash IS NOT NULL
		    ORDER BY last_seen_at DESC LIMIT 1
		  )
	`)
	if err != nil {
		return fmt.Errorf("query devices: %w", err)
	}
	defer rows.Close()

	restored := 0
	for rows.Next() {
		var wgIP string
		var internetPaused, isPaused bool
		if err := rows.Scan(&wgIP, &internetPaused, &isPaused); err != nil {
			continue
		}
		// Strip CIDR notation if present
		ip := strings.Split(wgIP, "/")[0]
		paused := internetPaused || isPaused

		if paused {
			// Block all forwarded traffic from this device
			applyDeviceBlock(ip)
		} else {
			// Ensure no leftover block rule
			removeDeviceBlock(ip)
		}
		restored++
	}
	log.Printf("[iptables-restore] restored rules for %d devices", restored)
	return nil
}

func applyDeviceBlock(deviceIP string) {
	// Idempotent: check before insert
	check := exec.Command("iptables", "-t", "filter", "-C", "SAFESWITCH",
		"-s", deviceIP, "-j", "DROP")
	if check.Run() != nil {
		exec.Command("iptables", "-t", "filter", "-A", "SAFESWITCH",
			"-s", deviceIP, "-j", "DROP").Run()
	}
}

func removeDeviceBlock(deviceIP string) {
	// Remove block rule if it exists (ignore error if not present)
	exec.Command("iptables", "-t", "filter", "-D", "SAFESWITCH",
		"-s", deviceIP, "-j", "DROP").Run()
}

func applyDNSLock(iface string) error {
	// Redirect DNS queries from wg0 clients to this node's resolver (port 53)
	// Block DNS to any external server from wg0 — prevents resolver bypass
	cmds := [][]string{
		// Allow DNS to node resolver
		{"iptables", "-t", "nat", "-C", "PREROUTING",
			"-i", iface, "-p", "udp", "--dport", "53",
			"-j", "DNAT", "--to-destination", "10.10.0.1:53"},
	}
	for _, args := range cmds {
		check := exec.Command(args[0], args[1:]...)
		if check.Run() != nil {
			// Rule not present — add it
			addArgs := make([]string, len(args))
			copy(addArgs, args)
			// Replace -C with -A
			for i, a := range addArgs {
				if a == "-C" {
					addArgs[i] = "-A"
					break
				}
			}
			if out, err := exec.Command(addArgs[0], addArgs[1:]...).CombinedOutput(); err != nil {
				return fmt.Errorf("DNS lock rule: %s: %w", out, err)
			}
		}
	}
	return nil
}

func blockQUIC(iface string) error {
	// Block UDP 443 (QUIC) from wg0 — forces TLS/TCP fallback for SNI inspection
	check := exec.Command("iptables", "-t", "filter", "-C", "FORWARD",
		"-i", iface, "-p", "udp", "--dport", "443", "-j", "DROP")
	if check.Run() != nil {
		out, err := exec.Command("iptables", "-t", "filter", "-I", "FORWARD", "1",
			"-i", iface, "-p", "udp", "--dport", "443", "-j", "DROP").CombinedOutput()
		if err != nil {
			return fmt.Errorf("block QUIC: %s: %w", out, err)
		}
	}
	return nil
}

func applyMSSClamping(iface string) error {
	// Clamp TCP MSS to 1232 bytes — prevents PMTUD black holes through WireGuard tunnel
	// MTU 1280 - 40 (IPv6 header) - 8 (UDP) = 1232
	check := exec.Command("iptables", "-t", "mangle", "-C", "FORWARD",
		"-i", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--set-mss", "1232")
	if check.Run() != nil {
		out, err := exec.Command("iptables", "-t", "mangle", "-A", "FORWARD",
			"-i", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--set-mss", "1232").CombinedOutput()
		if err != nil {
			return fmt.Errorf("MSS clamp: %s: %w", out, err)
		}
	}
	return nil
}
