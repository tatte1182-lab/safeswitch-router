package presence

import (
	"net"
	"strings"
	"time"
)

// Device is one entry in the local device registry.
// It represents any device the router has observed — enrolled or not.
type Device struct {
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Enrolled is true when the MAC maps to a child device
	// in the active policy bundle. Set by the engine during refresh.
	Enrolled bool `json:"enrolled"`
}

// NormaliseMAC converts a MAC address to lowercase colon-separated form.
// Returns empty string if the input is not a valid MAC address.
func NormaliseMAC(raw string) string {
	hw, err := net.ParseMAC(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(hw.String())
}
