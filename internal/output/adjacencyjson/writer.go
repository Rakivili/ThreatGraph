package adjacencyjson

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"threatgraph/internal/logger"
	"threatgraph/pkg/models"
)

// Writer outputs adjacency rows to a JSON lines file.
type Writer struct {
	file    *os.File
	encoder *json.Encoder
	mu      sync.Mutex
}

// NewWriter creates a JSONL writer for adjacency rows.
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

	logger.Infof("Adjacency JSON writer initialized: %s", path)
	return &Writer{
		file:    f,
		encoder: json.NewEncoder(f),
	}, nil
}

// WriteRows writes a batch of adjacency rows.
func (w *Writer) WriteRows(rows []*models.AdjacencyRow) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, row := range rows {
		if err := w.encoder.Encode(row); err != nil {
			return fmt.Errorf("failed to encode adjacency row: %w", err)
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
