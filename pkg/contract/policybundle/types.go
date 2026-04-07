package policybundle

import "time"

type Bundle struct {
	Version   string               `json:"version"`
	IssuedAt  time.Time            `json:"issued_at"`
	ExpiresAt time.Time            `json:"expires_at"`
	Signature        string   `json:"signature"`
	EmergencyDomains []string `json:"emergency_domains,omitempty"`
	Children  []ChildEffectiveState `json:"children"`
}

type ChildEffectiveState struct {
	ChildID            string   `json:"child_id"`
	DeviceMAC          string   `json:"device_mac,omitempty"`
	WireGuardPublicKey string   `json:"wireguard_public_key,omitempty"`
	WireguardIP        string   `json:"wireguard_ip,omitempty"`
	Mode               string   `json:"mode"`
	LockEnabled        bool     `json:"lock_enabled"`
	DNSProfileID       string   `json:"dns_profile_id"`
	AllowedServices    []string `json:"allowed_services,omitempty"`
}
