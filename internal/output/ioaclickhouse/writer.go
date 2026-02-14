package ioaclickhouse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"threatgraph/pkg/models"
)

// Config configures the ClickHouse HTTP writer.
type Config struct {
	URL      string
	Database string
	Table    string
	Username string
	Password string
	Timeout  time.Duration
	Headers  map[string]string
}

// Writer sends IOA events to ClickHouse via HTTP JSONEachRow.
type Writer struct {
	endpoint string
	headers  map[string]string
	client   *http.Client
}

// NewWriter creates a ClickHouse HTTP writer.
func NewWriter(cfg Config) (*Writer, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("clickhouse URL is empty")
	}
	if cfg.Database == "" {
		cfg.Database = "default"
	}
	if cfg.Table == "" {
		cfg.Table = "ioa_events"
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	q := fmt.Sprintf("INSERT INTO %s.%s FORMAT JSONEachRow", quoteIdent(cfg.Database), quoteIdent(cfg.Table))
	base := strings.TrimRight(cfg.URL, "/")
	endpoint := base + "/?query=" + url.QueryEscape(q)

	headers := map[string]string{}
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	if cfg.Username != "" {
		headers["X-ClickHouse-User"] = cfg.Username
	}
	if cfg.Password != "" {
		headers["X-ClickHouse-Key"] = cfg.Password
	}

	return &Writer{
		endpoint: endpoint,
		headers:  headers,
		client:   &http.Client{Timeout: timeout},
	}, nil
}

// WriteEvents sends a batch of IOA events.
func (w *Writer) WriteEvents(events []*models.IOAEvent) error {
	if len(events) == 0 {
		return nil
	}

	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, event := range events {
		if err := enc.Encode(event); err != nil {
			return fmt.Errorf("failed to marshal ioa event: %w", err)
		}
	}

	req, err := http.NewRequest(http.MethodPost, w.endpoint, &body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("clickhouse request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("clickhouse request failed with status %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	return nil
}

// Close releases resources.
func (w *Writer) Close() error {
	return nil
}

func quoteIdent(v string) string {
	if v == "" {
		return ""
	}
	v = strings.ReplaceAll(v, "`", "")
	return "`" + v + "`"
}
