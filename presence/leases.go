package presence

import (
	"bufio"
	"os"
	"strings"
)

// leasePaths lists the dnsmasq lease file locations across OpenWrt variants
// and common Linux distributions. The engine tries each in order and uses the
// first one that exists.
var leasePaths = []string{
	"/tmp/dhcp.leases",                   // OpenWrt default
	"/var/lib/misc/dnsmasq.leases",       // Debian/Ubuntu dnsmasq
	"/var/lib/dnsmasq/dnsmasq.leases",    // some distros
	"/var/db/dnsmasq.leases",             // BSD-adjacent
}

// readLeases returns a map of IP → hostname parsed from the first
// dnsmasq lease file found on disk.
//
// dnsmasq lease format (space-separated):
//
//	<expiry-epoch> <mac> <ip> <hostname> <client-id>
//
// Hostname is "*" when the client sent none — we treat that as empty.
func readLeases() map[string]string {
	hostByIP := make(map[string]string)

	for _, path := range leasePaths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 {
				continue
			}
			ip       := fields[2]
			hostname := fields[3]
			if hostname == "*" || hostname == "" {
				continue
			}
			hostByIP[ip] = hostname
		}
		// found a file — no need to keep looking
		return hostByIP
	}

	return hostByIP
}
