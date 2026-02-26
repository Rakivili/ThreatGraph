package pipeline

// RawWriter writes raw input payloads for replay.
type RawWriter interface {
	WriteRawMessages(messages [][]byte) error
	Close() error
}
