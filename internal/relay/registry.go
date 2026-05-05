package relay

import (
	"sort"
	"sync"
	"time"
)

// NodePreference is the family-level routing preference for a node.
//
// Primary nodes are picked first when healthy. Secondary nodes serve
// as warm standbys — used when the primary is stale, unhealthy, or
// disconnected. The preference is set in the cloud (Supabase) and
// pushed to the broker via the heartbeat path.
type NodePreference uint8

const (
	PrefSecondary NodePreference = iota
	PrefPrimary
)

// NodeHealth tracks per-node liveness on the broker side.
//
// LastSeen advances every time we receive a frame (data or pong) on
// the node's WebSocket. Stale > 60s means the WG underneath is
// almost certainly dead even if the WS is technically still open
// (TCP keepalives can lag for minutes on residential ISPs).
type NodeHealth struct {
	NodeID     string
	FamilyID   string
	Conn       *Conn
	Pref       NodePreference
	LastSeen   time.Time
	JoinedAt   time.Time
	PacketsIn  uint64
	PacketsOut uint64
}

// stalenessThreshold is the cutoff for treating a node as unhealthy.
// Heartbeat interval is 15s (handler.go:pingInterval), so 60s gives
// us a 4× cushion before fallback kicks in. Tunable via env if we
// hit edge cases on residential ISPs with deeper buffers.
const stalenessThreshold = 60 * time.Second

// NodeRegistry indexes connected home nodes for fast per-family lookup.
//
// Hot path is PickHealthyNode, called once per inbound child UDP
// packet. The map is read-locked and the slice is pre-sorted by
// preference, so the picker is O(k) where k is the number of nodes
// for one family — typically 1, occasionally 2-3 for households
// running redundant Pi + laptop.
type NodeRegistry struct {
	mu sync.RWMutex

	// byNode is the canonical map. One entry per connected node.
	byNode map[string]*NodeHealth

	// byFamily is a denormalised secondary index sorted by preference,
	// rebuilt whenever a node is added/removed/changes pref. We sort
	// once on write so PickHealthyNode never sorts on the hot path.
	byFamily map[string][]*NodeHealth
}

func NewNodeRegistry() *NodeRegistry {
	return &NodeRegistry{
		byNode:   make(map[string]*NodeHealth),
		byFamily: make(map[string][]*NodeHealth),
	}
}

// Add registers a freshly connected node. If a node with the same
// nodeID is already registered (e.g. reconnect after WS drop), the
// existing entry is replaced atomically — the old Conn's Send chan
// is left for the broker's UnregisterNode path to close.
func (r *NodeRegistry) Add(h *NodeHealth) {
	if h.JoinedAt.IsZero() {
		h.JoinedAt = time.Now()
	}
	if h.LastSeen.IsZero() {
		h.LastSeen = h.JoinedAt
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.byNode[h.NodeID] = h
	r.rebuildFamilyIndexLocked(h.FamilyID)
}

// Remove unregisters a node. Safe to call on a nodeID that isn't
// registered — no-op in that case. Returns the removed entry so the
// caller can close its Send channel.
func (r *NodeRegistry) Remove(nodeID string) *NodeHealth {
	r.mu.Lock()
	defer r.mu.Unlock()

	h, ok := r.byNode[nodeID]
	if !ok {
		return nil
	}
	delete(r.byNode, nodeID)
	r.rebuildFamilyIndexLocked(h.FamilyID)
	return h
}

// Touch bumps the node's LastSeen to now. Called on every received
// frame from the node — data, ping, pong. Cheap: write lock held
// for one map lookup and one timestamp assignment.
//
// We deliberately do not rebuild the family index here. LastSeen
// changes don't affect ordering; PickHealthyNode reads LastSeen
// directly when deciding healthy vs stale.
func (r *NodeRegistry) Touch(nodeID string) {
	r.mu.Lock()
	if h, ok := r.byNode[nodeID]; ok {
		h.LastSeen = time.Now()
	}
	r.mu.Unlock()
}

// PickHealthyNode is the hot path. Returns the highest-preference
// healthy node for the family, or nil if none are healthy.
//
// "Healthy" means: connected (in the registry) AND last seen within
// stalenessThreshold. The slice is pre-sorted, so we walk it in
// order and return the first match.
func (r *NodeRegistry) PickHealthyNode(familyID string) *NodeHealth {
	now := time.Now()

	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, h := range r.byFamily[familyID] {
		if now.Sub(h.LastSeen) <= stalenessThreshold {
			return h
		}
	}
	return nil
}

// FamilyStatus reports liveness state for a family. Used by metrics
// and the fallback path. Returns counts of healthy and total nodes
// plus the staleness of the most-recently-seen node (zero if none).
type FamilyStatus struct {
	HealthyCount   int
	TotalCount     int
	LastSeenAgo    time.Duration
	HasFallback    bool // true if at least one node was ever connected
}

func (r *NodeRegistry) Status(familyID string) FamilyStatus {
	now := time.Now()
	out := FamilyStatus{}

	r.mu.RLock()
	defer r.mu.RUnlock()

	nodes := r.byFamily[familyID]
	out.TotalCount = len(nodes)
	out.HasFallback = len(nodes) > 0

	freshest := time.Time{}
	for _, h := range nodes {
		if now.Sub(h.LastSeen) <= stalenessThreshold {
			out.HealthyCount++
		}
		if h.LastSeen.After(freshest) {
			freshest = h.LastSeen
		}
	}
	if !freshest.IsZero() {
		out.LastSeenAgo = now.Sub(freshest)
	}
	return out
}

// SetPreference updates a node's primary/secondary role. Called
// when the cloud pushes a routing preference change (e.g. a
// household promotes their backup laptop to primary while the Pi
// is being relocated). Triggers a family-index rebuild so picker
// ordering reflects the new preference immediately.
func (r *NodeRegistry) SetPreference(nodeID string, p NodePreference) {
	r.mu.Lock()
	defer r.mu.Unlock()

	h, ok := r.byNode[nodeID]
	if !ok {
		return
	}
	if h.Pref == p {
		return
	}
	h.Pref = p
	r.rebuildFamilyIndexLocked(h.FamilyID)
}

// SweepStale walks every node and returns the IDs of those that
// have crossed the staleness threshold. Caller is responsible for
// any side effects (logging, cloud notification, fallback flag).
//
// We intentionally don't remove stale nodes here — the WS may
// recover. Removal happens only on explicit disconnect.
func (r *NodeRegistry) SweepStale() []string {
	now := time.Now()
	var stale []string

	r.mu.RLock()
	defer r.mu.RUnlock()

	for id, h := range r.byNode {
		if now.Sub(h.LastSeen) > stalenessThreshold {
			stale = append(stale, id)
		}
	}
	return stale
}

// rebuildFamilyIndexLocked rebuilds the by-family slice for one
// family, sorted by preference (primary first) then JoinedAt
// (older first — stable within a preference tier).
//
// Must be called with mu held for writing.
func (r *NodeRegistry) rebuildFamilyIndexLocked(familyID string) {
	var nodes []*NodeHealth
	for _, h := range r.byNode {
		if h.FamilyID == familyID {
			nodes = append(nodes, h)
		}
	}
	if len(nodes) == 0 {
		delete(r.byFamily, familyID)
		return
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Pref != nodes[j].Pref {
			return nodes[i].Pref > nodes[j].Pref // primary > secondary
		}
		return nodes[i].JoinedAt.Before(nodes[j].JoinedAt)
	})
	r.byFamily[familyID] = nodes
}