package dns

// BlockEvent is emitted by the Resolver each time a domain is blocked.
type BlockEvent struct {
	Domain string
	SrcIP  string
}

// BlockSink receives block events from the Resolver.
// Implementations must be safe for concurrent use and must not block.
type BlockSink interface {
	RecordBlock(evt BlockEvent)
}

// NoopBlockSink discards all events. Used when no sink is wired.
type NoopBlockSink struct{}

func (NoopBlockSink) RecordBlock(_ BlockEvent) {}
