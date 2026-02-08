package alerthttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"threatgraph/pkg/models"
)

// Writer sends alerts to a remote HTTP endpoint.
type Writer struct {
	url     string
	headers map[string]string
	client  *http.Client
}

// Config configures the HTTP writer.
type Config struct {
	URL     string
	Timeout time.Duration
	Headers map[string]string
}

// NewWriter creates an HTTP writer.
func NewWriter(cfg Config) (*Writer, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("http alert URL is empty")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Writer{
		url:     cfg.URL,
		headers: cfg.Headers,
		client:  &http.Client{Timeout: timeout},
	}, nil
}

// WriteAlerts posts a batch of alerts.
func (w *Writer) WriteAlerts(alerts []*models.Alert) error {
	if len(alerts) == 0 {
		return nil
	}

	body, err := json.Marshal(alerts)
	if err != nil {
		return fmt.Errorf("failed to marshal alerts: %w", err)
	}

	req, err := http.NewRequest("POST", w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("http request failed with status %s", resp.Status)
	}

	return nil
}

// Close releases HTTP resources.
func (w *Writer) Close() error {
	return nil
}
