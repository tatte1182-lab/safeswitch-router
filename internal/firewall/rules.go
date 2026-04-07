package firewall

import "fmt"

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
	SSChain = "SAFESWITCH"
	wgIface = "wg0"
)

func BuildRules(ip, state string) RuleSet {
	rs := RuleSet{IP: ip, State: state}
	switch state {
	case StatePaused:
		rs.Rules = []Rule{
			{Args: []string{"-A", SSChain, "-s", ip, "-j", "DROP"}, Comment: fmt.Sprintf("pause: drop outbound from %s", ip)},
			{Args: []string{"-A", SSChain, "-d", ip, "-j", "DROP"}, Comment: fmt.Sprintf("pause: drop inbound to %s", ip)},
		}
	case StateFullTunnel:
		// No interface qualifiers — FORWARD chain sees packets after routing,
		// so -i/-o don't match as expected for forwarded tunnel traffic.
		// ESTABLISHED/RELATED return traffic is already ACCEPTed by the
		// EnsureForwardJump rule before SAFESWITCH is evaluated.
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

// ChainEnsureArgs creates the SAFESWITCH chain if it doesn't exist.
// The FORWARD jump is NOT added here — it is handled idempotently in
// EnsureForwardJump so we never accumulate duplicate rules.
func ChainEnsureArgs() [][]string {
	return [][]string{
		{"-N", SSChain},
	}
}

// EnsureForwardJump inserts the SAFESWITCH jump into FORWARD exactly once.
// It checks first with -C (check); only inserts with -I if absent.
// Also ensures ESTABLISHED/RELATED and wg0→eth0 ACCEPT rules exist.
func EnsureForwardJump() [][]string {
	return [][]string{
		// conntrack: allow return traffic for all established connections
		{"-C", "FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		// wg0 forwarding: allow all tunnel traffic out to internet
		{"-C", "FORWARD", "-i", wgIface, "-o", "eth0", "-j", "ACCEPT"},
		// SAFESWITCH chain jump
		{"-C", "FORWARD", "-j", SSChain},
	}
}

// InsertForwardJump returns the -I args to insert a rule that was absent.
func InsertForwardJump(checkArgs []string) []string {
	// Replace -C with -I at position 1
	args := make([]string, len(checkArgs))
	copy(args, checkArgs)
	args[0] = "-I"
	// Insert at position 1 so SAFESWITCH is first, ESTABLISHED second, etc.
	return append([]string{args[0], "FORWARD", "1"}, args[2:]...)
}

func ChainFlushArgs() []string {
	return []string{"-F", SSChain}
}
