package alertjson

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"threatgraph/internal/logger"
	"threatgraph/pkg/models"
)

// Writer outputs alerts to a JSON lines file.
type Writer struct {
	file    *os.File
	encoder *json.Encoder
	mu      sync.Mutex
}

// NewWriter creates a JSONL writer for alerts.
func NewWriter(path string) (*Writer, error) {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}

	logger.Infof("Alert JSON writer initialized: %s", path)
	return &Writer{
		file:    f,
		encoder: json.NewEncoder(f),
	}, nil
}

// WriteAlerts writes a batch of alerts.
func (w *Writer) WriteAlerts(alerts []*models.Alert) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, alert := range alerts {
		if err := w.encoder.Encode(alert); err != nil {
			return fmt.Errorf("failed to encode alert: %w", err)
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
