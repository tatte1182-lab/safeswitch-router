package enrollment

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/getsafeswitch/safeswitch-router/internal/identity"
)

// Logger is the minimal logging interface this service needs.
type Logger interface {
	Printf(format string, v ...any)
}

// State represents the current enrollment status of this node.
type State struct {
	Enrolled   bool      `json:"enrolled"`
	FamilyID   string    `json:"family_id,omitempty"`
	NodeID     string    `json:"node_id"`
	PublicKey  string    `json:"public_key"`
	EnrolledAt time.Time `json:"enrolled_at,omitempty"`
}

// EnrollRequest carries the data needed to claim this node into a family.
type EnrollRequest struct {
	ClaimToken string `json:"claim_token"`
	FamilyID   string `json:"family_id"`
}

// Service handles node enrollment against the SafeSwitch cloud.
type Service struct {
	db       *sql.DB
	logger   Logger
	identity *identity.Service
	baseURL  string
}

func NewService(db *sql.DB, logger Logger, identity *identity.Service, baseURL string) *Service {
	return &Service{db: db, logger: logger, identity: identity, baseURL: baseURL}
}

// CurrentState returns the node's current enrollment state by reading
// family_id and enrolled_at from tunnel_config.
func (s *Service) CurrentState(ctx context.Context) State {
	id := s.identity.Current()
	st := State{NodeID: id.NodeID, PublicKey: id.PublicKey}

	var familyID string
	if err := s.db.QueryRowContext(ctx,
		`SELECT value FROM tunnel_config WHERE key = 'family_id'`,
	).Scan(&familyID); err == nil && familyID != "" {
		st.Enrolled = true
		st.FamilyID = familyID
	}

	var enrolledAtStr string
	if err := s.db.QueryRowContext(ctx,
		`SELECT value FROM tunnel_config WHERE key = 'enrolled_at'`,
	).Scan(&enrolledAtStr); err == nil && enrolledAtStr != "" {
		st.EnrolledAt, _ = time.Parse(time.RFC3339, enrolledAtStr)
	}
	return st
}

// Enroll sends the node's identity and claim token to the cloud enroll Edge
// Function, then persists the returned family_id and node_token to SQLite.
func (s *Service) Enroll(ctx context.Context, req EnrollRequest) (State, error) {
	if req.ClaimToken == "" {
		return State{}, fmt.Errorf("claim_token is required")
	}

	id := s.identity.Current()
	payload, err := json.Marshal(map[string]string{
		"claim_token": req.ClaimToken,
		"family_id":   req.FamilyID,
		"node_id":     id.NodeID,
		"public_key":  id.PublicKey,
		"node_name":   id.NodeName,
	})
	if err != nil {
		return State{}, fmt.Errorf("marshal enroll payload: %w", err)
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := httpClient.Post(
		s.baseURL+"/functions/v1/enroll",
		"application/json",
		strings.NewReader(string(payload)),
	)
	if err != nil {
		return State{}, fmt.Errorf("enroll request: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		NodeID    string `json:"node_id"`
		FamilyID  string `json:"family_id"`
		NodeToken string `json:"node_token"`
		Error     string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return State{}, fmt.Errorf("decode enroll response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return State{}, fmt.Errorf("enroll failed (http %d): %s", resp.StatusCode, result.Error)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	for key, val := range map[string]string{
		"family_id":   result.FamilyID,
		"node_token":  result.NodeToken,
		"enrolled_at": now,
	} {
		if err := s.setConfig(ctx, key, val); err != nil {
			return State{}, fmt.Errorf("persist %s: %w", key, err)
		}
	}

	s.logger.Printf("[enrollment] enrolled node_id=%s family_id=%s", id.NodeID, result.FamilyID)
	return State{
		Enrolled:   true,
		FamilyID:   result.FamilyID,
		NodeID:     id.NodeID,
		PublicKey:  id.PublicKey,
		EnrolledAt: time.Now().UTC(),
	}, nil
}

// GenerateClaimToken produces a human-readable 3-word claim token used to
// pair this node with a family from the parent app.
func GenerateClaimToken() (string, error) {
	words := []string{
		"anchor", "beacon", "cedar", "delta", "ember", "falcon", "grove",
		"harbor", "island", "jasper", "kestrel", "linden", "marble", "nova",
		"orchid", "pine", "quartz", "river", "stone", "thorn", "ultra",
		"valley", "willow", "xenon", "yield", "zephyr", "bridge", "cliff",
		"drift", "eagle", "flint", "glacier", "haven", "inlet", "juniper",
	}
	var parts [3]string
	for i := range parts {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
		if err != nil {
			return "", fmt.Errorf("generate token: %w", err)
		}
		parts[i] = words[n.Int64()]
	}
	return parts[0] + "-" + parts[1] + "-" + parts[2], nil
}

// setConfig upserts a key/value pair in tunnel_config.
// tunnel_config is the single source of truth for all persisted node state.
func (s *Service) setConfig(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tunnel_config (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, key, value)
	return err
}
