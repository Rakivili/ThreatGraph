package adjacencyclickhouse

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

// Config configures the ClickHouse HTTP writer for adjacency rows.
type Config struct {
	URL      string
	Database string
	Table    string
	Username string
	Password string
	Timeout  time.Duration
	Headers  map[string]string
}

// Writer sends adjacency rows to ClickHouse via HTTP JSONEachRow.
type Writer struct {
	endpoint string
	headers  map[string]string
	client   *http.Client
}

type insertRow struct {
	TS         string `json:"ts"`
	RecordType string `json:"record_type"`
	Type       string `json:"type"`
	VertexID   string `json:"vertex_id"`
	AdjacentID string `json:"adjacent_id"`
	EventID    int    `json:"event_id"`
	Host       string `json:"host"`
	AgentID    string `json:"agent_id"`
	RecordID   string `json:"record_id"`
	IoaTags    string `json:"ioa_tags"`
}

// NewWriter creates a ClickHouse HTTP writer for adjacency rows.
func NewWriter(cfg Config) (*Writer, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("clickhouse URL is empty")
	}
	if cfg.Database == "" {
		cfg.Database = "threatgraph"
	}
	if cfg.Table == "" {
		cfg.Table = "adjacency"
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

// WriteRows sends a batch of adjacency rows to ClickHouse.
func (w *Writer) WriteRows(rows []*models.AdjacencyRow) error {
	if len(rows) == 0 {
		return nil
	}

	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, row := range rows {
		tagsJSON := "[]"
		if len(row.IoaTags) > 0 {
			b, err := json.Marshal(row.IoaTags)
			if err != nil {
				return fmt.Errorf("failed to marshal ioa_tags: %w", err)
			}
			tagsJSON = string(b)
		}
		ir := insertRow{
			TS:         row.Timestamp.UTC().Format("2006-01-02 15:04:05.000"),
			RecordType: row.RecordType,
			Type:       row.Type,
			VertexID:   row.VertexID,
			AdjacentID: row.AdjacentID,
			EventID:    row.EventID,
			Host:       row.Hostname,
			AgentID:    row.AgentID,
			RecordID:   row.RecordID,
			IoaTags:    tagsJSON,
		}
		if err := enc.Encode(ir); err != nil {
			return fmt.Errorf("failed to marshal adjacency row: %w", err)
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
