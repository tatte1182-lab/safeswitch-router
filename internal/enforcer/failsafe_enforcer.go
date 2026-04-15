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

// IsActive returns true when the failsafe is currently enforced.
// DNS handlers and the bundle applier should call this before every decision.
func IsActive() bool {
	globalFailsafe.mu.RLock()
	defer globalFailsafe.mu.RUnlock()
	return globalFailsafe.Active
}

// IsDenyAll returns true when failsafe is active AND no bundle was ever
// received. In this state the emergency domain allowlist does NOT apply —
// all traffic should be dropped. This prevents a fresh enrollment from
// silently passing all traffic if cloud connectivity is lost before the
// first bundle sync.
func IsDenyAll() bool {
	globalFailsafe.mu.RLock()
	defer globalFailsafe.mu.RUnlock()
	return globalFailsafe.Active && globalFailsafe.BundleExpiredAt.IsZero()
}

// TriggerReason returns the reason string for the current or last failsafe trigger.
func TriggerReason() string {
	globalFailsafe.mu.RLock()
	defer globalFailsafe.mu.RUnlock()
	return globalFailsafe.TriggerReason
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
	// A zero bundleExpiresAt means no bundle has ever been received.
	// Treat that as immediately expired — a device with no policy bundle must
	// not pass traffic silently when the cloud is also unreachable.
	noBundleEver := bundleExpiresAt.IsZero()
	bundleExpired := noBundleEver || now.After(bundleExpiresAt.Add(gracePeriod))
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
		if noBundleEver {
			globalFailsafe.TriggerReason = "no_bundle_cloud_unreachable"
		} else {
			globalFailsafe.TriggerReason = "bundle_expired_cloud_unreachable"
		}
		globalFailsafe.mu.Unlock()

		if noBundleEver {
			log.Printf("[FAILSAFE] ENTERING fail-safe. reason=no_bundle_ever cloud=%v", cloudReachable)
		} else {
			log.Printf("[FAILSAFE] ENTERING fail-safe. bundle_expired=%s cloud=%v",
				bundleExpiresAt.Format(time.RFC3339), cloudReachable)
		}

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
