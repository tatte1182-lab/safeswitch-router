package events

type Event struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Payload  any    `json:"payload"`
}
