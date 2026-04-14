package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type RuleSet struct {
	IP    string
	State string
	Rules []Rule
}

type Rule struct {
	Args    []string
	Comment string
}

const (
	StatePaused      = "paused"
	StateFullTunnel  = "full_tunnel"
	StateServiceOnly = "service_only"
	StateFullAccess  = "full_access"
	SSChain          = "SAFESWITCH"
	wgIface          = "wg0"
)

// natIface returns the upstream network interface used for FORWARD rules.
// Must stay in sync with the same function in tunnel/wgconf.go.
// Resolution order:
//  1. SS_ROUTER_NAT_IFACE environment variable
//  2. Auto-detect from `ip route show default`
//  3. "eth0" (safe default for VPS / cloud servers)
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
				candidate := fields[i+1]
				if candidate != "lo" && !strings.HasPrefix(candidate, "wg") {
					return candidate
				}
			}
		}
	}
	return ""
}

// BuildRules returns the iptables rules for a given child device IP and state.
func BuildRules(ip, state string) RuleSet {
	rs := RuleSet{IP: ip, State: state}
	switch state {
	case StatePaused:
		rs.Rules = []Rule{
			{Args: []string{"-A", SSChain, "-s", ip, "-j", "DROP"}, Comment: fmt.Sprintf("pause: drop outbound from %s", ip)},
			{Args: []string{"-A", SSChain, "-d", ip, "-j", "DROP"}, Comment: fmt.Sprintf("pause: drop inbound to %s", ip)},
		}
	case StateFullTunnel:
		// No interface qualifiers — FORWARD chain sees packets after routing.
		// ESTABLISHED/RELATED return traffic is ACCEPTed by EnsureForwardJump
		// before SAFESWITCH is evaluated.
		rs.Rules = []Rule{
			{Args: []string{"-A", SSChain, "-s", ip, "-j", "ACCEPT"}, Comment: fmt.Sprintf("full_tunnel: accept from %s", ip)},
			{Args: []string{"-A", SSChain, "-d", ip, "-j", "ACCEPT"}, Comment: fmt.Sprintf("full_tunnel: accept to %s", ip)},
		}
	case StateServiceOnly:
		rs.Rules = []Rule{
			{Args: []string{"-A", SSChain, "-s", ip, "-d", "10.10.0.1", "-j", "ACCEPT"}, Comment: fmt.Sprintf("service_only: allow %s to gateway", ip)},
			{Args: []string{"-A", SSChain, "-s", "10.10.0.1", "-d", ip, "-j", "ACCEPT"}, Comment: fmt.Sprintf("service_only: allow gateway to %s", ip)},
			{Args: []string{"-A", SSChain, "-s", ip, "-j", "DROP"}, Comment: fmt.Sprintf("service_only: drop outbound from %s", ip)},
			{Args: []string{"-A", SSChain, "-d", ip, "-j", "DROP"}, Comment: fmt.Sprintf("service_only: drop inbound to %s", ip)},
		}
	case StateFullAccess:
		rs.Rules = []Rule{
			{Args: []string{"-A", SSChain, "-s", ip, "-j", "ACCEPT"}, Comment: fmt.Sprintf("full_access: accept outbound from %s", ip)},
			{Args: []string{"-A", SSChain, "-d", ip, "-j", "ACCEPT"}, Comment: fmt.Sprintf("full_access: accept inbound to %s", ip)},
		}
	}
	return rs
}

// ChainEnsureArgs returns args to create the SAFESWITCH chain (idempotent).
func ChainEnsureArgs() [][]string {
	return [][]string{
		{"-N", SSChain},
	}
}

// EnsureForwardJump returns check-args for the three FORWARD base rules.
// The enforcer calls -C first; if absent it calls InsertForwardJump.
// The upstream interface is resolved at call-time so a restart isn't needed
// if SS_ROUTER_NAT_IFACE changes.
func EnsureForwardJump() [][]string {
	iface := natIface()
	return [][]string{
		// Allow return traffic for established connections
		{"-C", "FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		// Allow tunnel traffic to exit via the upstream interface
		{"-C", "FORWARD", "-i", wgIface, "-o", iface, "-j", "ACCEPT"},
		// Jump into the SAFESWITCH per-device chain
		{"-C", "FORWARD", "-j", SSChain},
	}
}

// InsertForwardJump converts a -C (check) arg set to a -I (insert) arg set.
func InsertForwardJump(checkArgs []string) []string {
	args := make([]string, len(checkArgs))
	copy(args, checkArgs)
	args[0] = "-I"
	// Insert at position 1 so SAFESWITCH is evaluated first
	return append([]string{args[0], "FORWARD", "1"}, args[2:]...)
}

// ChainFlushArgs returns args to flush (clear) the SAFESWITCH chain.
func ChainFlushArgs() []string {
	return []string{"-F", SSChain}
}
