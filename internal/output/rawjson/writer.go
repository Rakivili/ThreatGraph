package rawjson

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"threatgraph/internal/logger"
)

// Writer outputs raw messages to a JSONL file for replay.
type Writer struct {
	file *os.File
	mu   sync.Mutex
}

// NewWriter creates a raw message JSONL writer.
func NewWriter(path string) (*Writer, error) {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open output file: %w", err)
	}

	logger.Infof("Raw JSON writer initialized: %s", path)
	return &Writer{file: f}, nil
}

// WriteRawMessages writes raw byte messages, one per line.
func (w *Writer) WriteRawMessages(messages [][]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, msg := range messages {
		if _, err := w.file.Write(msg); err != nil {
			return fmt.Errorf("failed to write raw message: %w", err)
		}
		if _, err := w.file.Write([]byte("\n")); err != nil {
			return fmt.Errorf("failed to write newline: %w", err)
		}
	}
	return nil
}

// Close closes the output file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		return w.file.Close()
	}
	return nil
}
