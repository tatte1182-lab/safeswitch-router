package commands

type Status string

const (
	StatusPending   Status = "pending"
	StatusAcked     Status = "acked"
	StatusExecuting Status = "executing"
	StatusDone      Status = "done"
	StatusFailed    Status = "failed"
	StatusExpired   Status = "expired"
)

type Command struct {
	ID      string         `json:"id"`
	Type    string         `json:"type"`
	Payload map[string]any `json:"payload"`
}
