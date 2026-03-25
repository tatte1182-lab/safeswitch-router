package firewall

import "fmt"

// RuleSet is the complete set of iptables rules for one device.
type RuleSet struct {
	// IP is the device's tunnel IP (e.g. "10.10.0.2")
	IP string
	// State is the enforcement state: paused, service_only, full_access
	State string
	// Rules are the iptables -A arguments (without the leading "iptables")
	Rules []Rule
}

// Rule is one iptables rule expressed as a slice of arguments.
type Rule struct {
	// Args are passed directly to iptables(8)
	Args []string
	// Comment describes the rule for logging
	Comment string
}

const (
	StatePaused      = "paused"
	StateServiceOnly = "service_only"
	StateFullAccess  = "full_access"

	// SSChain is the SafeSwitch iptables chain name.
	// All rules are written into this chain so they can be flushed
	// atomically on resync without touching any other chains.
	SSChain = "SAFESWITCH"
)

// BuildRules returns the iptables rules for the given device IP and state.
//
// Architecture:
//   - All rules live in the SAFESWITCH chain in the FORWARD table.
//   - The chain is flushed and rebuilt on every policy sync — idempotent.
//   - Rules target the device's WireGuard tunnel IP (10.10.x.x), not MAC,
//     so they work for both tunnel and LAN traffic.
//   - Paused:       DROP all FORWARD traffic from/to this IP.
//   - Service-only: ACCEPT traffic to tunnel gateway only; DROP rest.
//   - Full-access:  ACCEPT all (effectively a no-op — the default policy allows).
func BuildRules(ip, state string) RuleSet {
	rs := RuleSet{IP: ip, State: state}

	switch state {
	case StatePaused:
		rs.Rules = []Rule{
			{
				Args:    []string{"-A", SSChain, "-s", ip, "-j", "DROP"},
				Comment: fmt.Sprintf("pause: drop outbound from %s", ip),
			},
			{
				Args:    []string{"-A", SSChain, "-d", ip, "-j", "DROP"},
				Comment: fmt.Sprintf("pause: drop inbound to %s", ip),
			},
		}

	case StateServiceOnly:
		// Allow only traffic to/from the WireGuard gateway (SafeSwitch services)
		rs.Rules = []Rule{
			{
				Args:    []string{"-A", SSChain, "-s", ip, "-d", "10.10.0.1", "-j", "ACCEPT"},
				Comment: fmt.Sprintf("service_only: allow %s → gateway", ip),
			},
			{
				Args:    []string{"-A", SSChain, "-s", "10.10.0.1", "-d", ip, "-j", "ACCEPT"},
				Comment: fmt.Sprintf("service_only: allow gateway → %s", ip),
			},
			{
				Args:    []string{"-A", SSChain, "-s", ip, "-j", "DROP"},
				Comment: fmt.Sprintf("service_only: drop all other outbound from %s", ip),
			},
			{
				Args:    []string{"-A", SSChain, "-d", ip, "-j", "DROP"},
				Comment: fmt.Sprintf("service_only: drop all other inbound to %s", ip),
			},
		}

	case StateFullAccess:
		// Explicit ACCEPT so the chain short-circuits — no DROP follows
		rs.Rules = []Rule{
			{
				Args:    []string{"-A", SSChain, "-s", ip, "-j", "ACCEPT"},
				Comment: fmt.Sprintf("full_access: accept outbound from %s", ip),
			},
			{
				Args:    []string{"-A", SSChain, "-d", ip, "-j", "ACCEPT"},
				Comment: fmt.Sprintf("full_access: accept inbound to %s", ip),
			},
		}
	}

	return rs
}

// ChainEnsureArgs returns the iptables arguments to create SSChain if it does
// not exist and insert a jump from FORWARD into it.
func ChainEnsureArgs() [][]string {
	return [][]string{
		// Create the chain — fails silently if it already exists
		{"-N", SSChain},
		// Jump from FORWARD into our chain (insert at position 1 so it runs first)
		{"-I", "FORWARD", "1", "-j", SSChain},
	}
}

// ChainFlushArgs returns the iptables arguments to flush all rules from SSChain.
// Called before reapplying a fresh rule set — makes sync idempotent.
func ChainFlushArgs() []string {
	return []string{"-F", SSChain}
}
