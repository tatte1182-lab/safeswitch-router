package dns

// BlockEvent is emitted by the Resolver each time a domain is blocked.
//
// Category carries the matched-row category from the SQLite blocklist
// ("malware", "phishing", "gambling", etc.) so downstream sinks can
// classify the event correctly without re-looking-up the domain.
// Empty when the block came from a path that doesn't have a category
// (e.g. NRD — the row itself is the category).
type BlockEvent struct {
	Domain   string
	SrcIP    string
	Category string
}

// BlockSink receives block events from the Resolver.
// Implementations must be safe for concurrent use and must not block.
type BlockSink interface {
	RecordBlock(evt BlockEvent)
}

// NoopBlockSink discards all events. Used when no sink is wired.
type NoopBlockSink struct{}

func (NoopBlockSink) RecordBlock(_ BlockEvent) {}
