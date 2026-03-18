package adjacencyclickhouse

import (
	"bytes"
	"encoding/binary"
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
	Format   string
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
	format   string
}

const (
	formatJSONEachRow = "json_each_row"
	formatRowBinary   = "row_binary"
)

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
	format := normalizeFormat(cfg.Format)
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	formatClause := "JSONEachRow"
	if format == formatRowBinary {
		formatClause = "RowBinary"
	}
	q := fmt.Sprintf("INSERT INTO %s.%s (ts, record_type, type, vertex_id, adjacent_id, event_id, host, agent_id, record_id, ioa_tags) FORMAT %s", quoteIdent(cfg.Database), quoteIdent(cfg.Table), formatClause)
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
		format:   format,
	}, nil
}

// WriteRows sends a batch of adjacency rows to ClickHouse.
func (w *Writer) WriteRows(rows []*models.AdjacencyRow) error {
	if len(rows) == 0 {
		return nil
	}
	if w.format == formatRowBinary {
		return w.writeRowsRowBinary(rows)
	}
	return w.writeRowsJSONEachRow(rows)
}

func (w *Writer) writeRowsJSONEachRow(rows []*models.AdjacencyRow) error {
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, row := range rows {
		tagsJSON, err := marshalTags(row)
		if err != nil {
			return err
		}
		ir := insertRow{
			TS:         row.Timestamp.In(time.Local).Format("2006-01-02 15:04:05.000"),
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
	return w.execInsert(&body, "application/json")
}

func (w *Writer) writeRowsRowBinary(rows []*models.AdjacencyRow) error {
	var body bytes.Buffer
	for _, row := range rows {
		tagsJSON, err := marshalTags(row)
		if err != nil {
			return err
		}
		if err := writeDateTime64Milli(&body, row.Timestamp); err != nil {
			return err
		}
		if err := writeString(&body, row.RecordType); err != nil {
			return err
		}
		if err := writeString(&body, row.Type); err != nil {
			return err
		}
		if err := writeString(&body, row.VertexID); err != nil {
			return err
		}
		if err := writeString(&body, row.AdjacentID); err != nil {
			return err
		}
		if err := binary.Write(&body, binary.LittleEndian, uint16(row.EventID)); err != nil {
			return fmt.Errorf("failed to encode event_id: %w", err)
		}
		if err := writeString(&body, row.Hostname); err != nil {
			return err
		}
		if err := writeString(&body, row.AgentID); err != nil {
			return err
		}
		if err := writeString(&body, row.RecordID); err != nil {
			return err
		}
		if err := writeString(&body, tagsJSON); err != nil {
			return err
		}
	}
	return w.execInsert(&body, "application/octet-stream")
}

func (w *Writer) execInsert(body *bytes.Buffer, contentType string) error {
	req, err := http.NewRequest(http.MethodPost, w.endpoint, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
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

func marshalTags(row *models.AdjacencyRow) (string, error) {
	tagsJSON := "[]"
	if len(row.IoaTags) > 0 {
		b, err := json.Marshal(row.IoaTags)
		if err != nil {
			return "", fmt.Errorf("failed to marshal ioa_tags: %w", err)
		}
		tagsJSON = string(b)
	}
	return tagsJSON, nil
}

func normalizeFormat(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", formatJSONEachRow, "jsoneachrow", "json":
		return formatJSONEachRow
	case formatRowBinary, "rowbinary":
		return formatRowBinary
	default:
		return formatJSONEachRow
	}
}

func writeDateTime64Milli(buf *bytes.Buffer, ts time.Time) error {
	return binary.Write(buf, binary.LittleEndian, ts.UnixMilli())
}

func writeString(buf *bytes.Buffer, s string) error {
	if err := writeUVarInt(buf, uint64(len(s))); err != nil {
		return fmt.Errorf("failed to encode string length: %w", err)
	}
	if _, err := buf.WriteString(s); err != nil {
		return fmt.Errorf("failed to encode string data: %w", err)
	}
	return nil
}

func writeUVarInt(buf *bytes.Buffer, v uint64) error {
	for v >= 0x80 {
		if err := buf.WriteByte(byte(v) | 0x80); err != nil {
			return err
		}
		v >>= 7
	}
	return buf.WriteByte(byte(v))
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
