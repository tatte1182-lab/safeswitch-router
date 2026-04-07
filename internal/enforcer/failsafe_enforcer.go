package enforcer

import (
	"context"
	"log"
	"sync"
	"time"
)

// ReportFunc is called when the node enters or exits fail-safe.
// The controlsync layer injects this at startup via SetReporter.
// Keeping HTTP out of this package avoids a circular import.
type ReportFunc func(ctx context.Context, entry bool, triggerReason string, bundleExpiredAt, offlineSince time.Time)

type FailsafeState struct {
	Active           bool
	TriggeredAt      time.Time
	TriggerReason    string
	BundleExpiredAt  time.Time
	OfflineSince     time.Time
	EmergencyDomains []string
	mu               sync.RWMutex
	reporter         ReportFunc
}

var globalFailsafe = &FailsafeState{
	EmergencyDomains: []string{
		"google.com",
		"apple.com",
		"microsoft.com",
		"icloud.com",
		"gmail.com",
		"outlook.com",
	},
}

// SetReporter injects the cloud-reporting callback.
// Call once from controlsync Service.Start() after the HTTP client is ready.
func SetReporter(fn ReportFunc) {
	globalFailsafe.mu.Lock()
	defer globalFailsafe.mu.Unlock()
	globalFailsafe.reporter = fn
}

func GetFailsafeState() (active bool, domains []string) {
	globalFailsafe.mu.RLock()
	defer globalFailsafe.mu.RUnlock()
	return globalFailsafe.Active, globalFailsafe.EmergencyDomains
}

func UpdateEmergencyDomains(domains []string) {
	globalFailsafe.mu.Lock()
	defer globalFailsafe.mu.Unlock()
	if len(domains) > 0 {
		globalFailsafe.EmergencyDomains = domains
	}
}

func CheckAndEnterFailsafe(
	ctx context.Context,
	bundleExpiresAt time.Time,
	cloudReachable bool,
	gracePeriod time.Duration,
) {
	now := time.Now()
	bundleExpired := !bundleExpiresAt.IsZero() && now.After(bundleExpiresAt.Add(gracePeriod))
	shouldBeActive := bundleExpired && !cloudReachable

	globalFailsafe.mu.Lock()
	reporter := globalFailsafe.reporter
	offlineSince := globalFailsafe.OfflineSince

	if shouldBeActive && !globalFailsafe.Active {
		globalFailsafe.Active = true
		globalFailsafe.TriggeredAt = now
		globalFailsafe.BundleExpiredAt = bundleExpiresAt
		if globalFailsafe.OfflineSince.IsZero() {
			globalFailsafe.OfflineSince = now
			offlineSince = now
		}
		globalFailsafe.TriggerReason = "bundle_expired_cloud_unreachable"
		globalFailsafe.mu.Unlock()

		log.Printf("[FAILSAFE] ENTERING fail-safe. bundle_expired=%s cloud=%v",
			bundleExpiresAt.Format(time.RFC3339), cloudReachable)

		if reporter != nil {
			go reporter(ctx, true, "bundle_expired_cloud_unreachable", bundleExpiresAt, offlineSince)
		}

	} else if !shouldBeActive && globalFailsafe.Active {
		globalFailsafe.Active = false
		globalFailsafe.OfflineSince = time.Time{}
		globalFailsafe.mu.Unlock()

		log.Printf("[FAILSAFE] EXITING fail-safe. bundle_valid_until=%s",
			bundleExpiresAt.Format(time.RFC3339))

		if reporter != nil {
			go reporter(ctx, false, "recovered", time.Time{}, time.Time{})
		}

	} else {
		if !cloudReachable && globalFailsafe.OfflineSince.IsZero() {
			globalFailsafe.OfflineSince = now
		} else if cloudReachable {
			globalFailsafe.OfflineSince = time.Time{}
		}
		globalFailsafe.mu.Unlock()
	}
}

func IsAllowedInFailsafe(domain string, emergencyDomains []string) bool {
	if len(domain) > 0 && domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}
	for _, allowed := range emergencyDomains {
		if domain == allowed || hasSuffix(domain, "."+allowed) {
			return true
		}
	}
	return false
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
