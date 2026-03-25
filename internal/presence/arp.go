package presence

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// arpEntry is one row from /proc/net/arp.
type arpEntry struct {
	IP  string
	MAC string
}

// readARP parses /proc/net/arp and returns all complete, non-zero entries.
// The kernel ARP table is available on every Linux system including OpenWrt.
//
// /proc/net/arp format:
//
//	IP address       HW type     Flags       HW address            Mask     Device
//	192.168.1.42     0x1         0x2         aa:bb:cc:dd:ee:ff     *        br-lan
func readARP() ([]arpEntry, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("open /proc/net/arp: %w", err)
	}
	defer f.Close()

	var entries []arpEntry
	scanner := bufio.NewScanner(f)

	// skip header line
	if scanner.Scan() {
		_ = scanner.Text()
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		// need at least: IP hwtype flags hwaddr mask device
		if len(fields) < 4 {
			continue
		}

		ip  := fields[0]
		mac := NormaliseMAC(fields[3])

		// skip incomplete or zero entries the kernel uses as placeholders
		if mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}

		entries = append(entries, arpEntry{IP: ip, MAC: mac})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan /proc/net/arp: %w", err)
	}

	return entries, nil
}
