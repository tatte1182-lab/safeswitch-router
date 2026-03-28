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
		rs.Rules = []Rule{
			{Args: []string{"-A", SSChain, "-s", ip, "-i", wgIface, "-j", "ACCEPT"}, Comment: fmt.Sprintf("full_tunnel: accept outbound from %s via wg0", ip)},
			{Args: []string{"-A", SSChain, "-d", ip, "-o", wgIface, "-j", "ACCEPT"}, Comment: fmt.Sprintf("full_tunnel: accept inbound to %s via wg0", ip)},
			{Args: []string{"-A", SSChain, "-s", ip, "-j", "DROP"}, Comment: fmt.Sprintf("full_tunnel: drop outbound from %s not via tunnel", ip)},
			{Args: []string{"-A", SSChain, "-d", ip, "-j", "DROP"}, Comment: fmt.Sprintf("full_tunnel: drop inbound to %s not via tunnel", ip)},
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

func ChainEnsureArgs() [][]string {
	return [][]string{
		{"-N", SSChain},
		{"-I", "FORWARD", "1", "-j", SSChain},
	}
}

func ChainFlushArgs() []string {
	return []string{"-F", SSChain}
}

func EnsureForwardJump() [][]string {
return [][]string{
{"-C", "FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
{"-C", "FORWARD", "-i", wgIface, "-o", "eth0", "-j", "ACCEPT"},
{"-C", "FORWARD", "-j", SSChain},
}
}

func InsertForwardJump(checkArgs []string) []string {
args := make([]string, len(checkArgs))
copy(args, checkArgs)
args[0] = "-I"
return append([]string{args[0], "FORWARD", "1"}, args[2:]...)
}
