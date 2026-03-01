package incidentjson

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"threatgraph/internal/analyzer"
	"threatgraph/internal/logger"
)

// Writer outputs incidents to a JSONL file.
type Writer struct {
	file    *os.File
	encoder *json.Encoder
	mu      sync.Mutex
}

// NewWriter creates a JSONL writer for incidents.
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

	logger.Infof("Incident JSON writer initialized: %s", path)
	return &Writer{
		file:    f,
		encoder: json.NewEncoder(f),
	}, nil
}

// WriteIncidents writes a batch of incidents as JSONL.
func (w *Writer) WriteIncidents(incidents []analyzer.Incident) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, inc := range incidents {
		if err := w.encoder.Encode(inc); err != nil {
			return fmt.Errorf("failed to encode incident: %w", err)
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
