package clickhouse

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"threatgraph/pkg/models"
)

// Config configures the ClickHouse HTTP reader.
type Config struct {
	URL            string
	Database       string
	AdjacencyTable string
	IOATable       string
	ProcessedTable string
	Username       string
	Password       string
	Timeout        time.Duration
}

// Reader queries ClickHouse for adjacency rows and IOA host lists.
type Reader struct {
	baseURL        string
	database       string
	adjTable       string
	ioaTable       string
	processedTable string
	headers        map[string]string
	client         *http.Client
}

type ProcessedIOA struct {
	TS       time.Time
	Host     string
	RecordID string
	Name     string
	IIPRoot  string
	IIPTS    time.Time
}

// NewReader creates a ClickHouse HTTP reader.
func NewReader(cfg Config) (*Reader, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("clickhouse URL is empty")
	}
	if cfg.Database == "" {
		cfg.Database = "threatgraph"
	}
	if cfg.AdjacencyTable == "" {
		cfg.AdjacencyTable = "adjacency"
	}
	if cfg.IOATable == "" {
		cfg.IOATable = "ioa_events"
	}
	if cfg.ProcessedTable == "" {
		cfg.ProcessedTable = "ioa_processed"
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	headers := map[string]string{}
	if cfg.Username != "" {
		headers["X-ClickHouse-User"] = cfg.Username
	}
	if cfg.Password != "" {
		headers["X-ClickHouse-Key"] = cfg.Password
	}

	return &Reader{
		baseURL:        strings.TrimRight(cfg.URL, "/"),
		database:       cfg.Database,
		adjTable:       cfg.AdjacencyTable,
		ioaTable:       cfg.IOATable,
		processedTable: cfg.ProcessedTable,
		headers:        headers,
		client:         &http.Client{Timeout: timeout},
	}, nil
}

func (r *Reader) ReadIOABatch(sinceTS time.Time, sinceRecordID string, limit int) ([]*models.IOAEvent, error) {
	if limit <= 0 {
		limit = 1000
	}

	q := fmt.Sprintf(
		"SELECT ts, host, agent_id, record_id, event_id, edge_type, vertex_id, adjacent_id, name FROM %s.%s AS i "+
			"WHERE (i.ts > '%s' OR (i.ts = '%s' AND i.record_id > '%s')) "+
			"AND NOT EXISTS (SELECT 1 FROM %s.%s AS p WHERE p.host = i.host AND p.record_id = i.record_id AND p.name = i.name) "+
			"ORDER BY i.ts, i.record_id LIMIT %d FORMAT JSONEachRow",
		quoteIdent(r.database), quoteIdent(r.ioaTable),
		sinceTS.In(time.Local).Format("2006-01-02 15:04:05.000"),
		sinceTS.In(time.Local).Format("2006-01-02 15:04:05.000"),
		escapeSQLString(sinceRecordID),
		quoteIdent(r.database), quoteIdent(r.processedTable),
		limit,
	)

	body, err := r.execQuery(q)
	if err != nil {
		return nil, fmt.Errorf("ReadIOABatch: %w", err)
	}
	defer body.Close()

	rows := make([]*models.IOAEvent, 0, limit)
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row struct {
			TS         string `json:"ts"`
			Host       string `json:"host"`
			AgentID    string `json:"agent_id"`
			RecordID   string `json:"record_id"`
			EventID    int    `json:"event_id"`
			EdgeType   string `json:"edge_type"`
			VertexID   string `json:"vertex_id"`
			AdjacentID string `json:"adjacent_id"`
			Name       string `json:"name"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		ts, err := parseTimestamp(row.TS)
		if err != nil {
			continue
		}
		rows = append(rows, &models.IOAEvent{
			Timestamp:  ts,
			Host:       row.Host,
			AgentID:    row.AgentID,
			RecordID:   row.RecordID,
			EventID:    row.EventID,
			EdgeType:   row.EdgeType,
			VertexID:   row.VertexID,
			AdjacentID: row.AdjacentID,
			Name:       row.Name,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

func (r *Reader) MarkProcessedIOAs(items []ProcessedIOA) error {
	if len(items) == 0 {
		return nil
	}

	var body strings.Builder
	enc := json.NewEncoder(&body)
	for _, it := range items {
		row := map[string]any{
			"ts":           it.TS.In(time.Local).Format("2006-01-02 15:04:05.000"),
			"host":         it.Host,
			"record_id":    it.RecordID,
			"name":         it.Name,
			"iip_root":     it.IIPRoot,
			"iip_ts":       it.IIPTS.In(time.Local).Format("2006-01-02 15:04:05.000"),
			"processed_at": time.Now().In(time.Local).Format("2006-01-02 15:04:05.000"),
		}
		if err := enc.Encode(row); err != nil {
			return fmt.Errorf("MarkProcessedIOAs encode: %w", err)
		}
	}

	q := fmt.Sprintf("INSERT INTO %s.%s FORMAT JSONEachRow", quoteIdent(r.database), quoteIdent(r.processedTable))
	return r.execInsert(q, strings.NewReader(body.String()))
}

// ReadHosts returns distinct hosts with IOA events since the given timestamp.
func (r *Reader) ReadHosts(since time.Time) ([]string, error) {
	q := fmt.Sprintf(
		"SELECT DISTINCT host FROM %s.%s WHERE ts > '%s' FORMAT JSONEachRow",
		quoteIdent(r.database), quoteIdent(r.ioaTable),
		since.In(time.Local).Format("2006-01-02 15:04:05.000"),
	)

	body, err := r.execQuery(q)
	if err != nil {
		return nil, fmt.Errorf("ReadHosts: %w", err)
	}
	defer body.Close()

	var hosts []string
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row struct {
			Host string `json:"host"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		if row.Host != "" {
			hosts = append(hosts, row.Host)
		}
	}
	return hosts, scanner.Err()
}

// ReadRows returns adjacency rows for the given host within a time window.
func (r *Reader) ReadRows(host string, since, until time.Time) ([]*models.AdjacencyRow, error) {
	q := fmt.Sprintf(
		"SELECT * FROM %s.%s WHERE host = '%s' AND ts BETWEEN '%s' AND '%s' ORDER BY ts, record_id FORMAT JSONEachRow",
		quoteIdent(r.database), quoteIdent(r.adjTable),
		escapeSQLString(host),
		since.In(time.Local).Format("2006-01-02 15:04:05.000"),
		until.In(time.Local).Format("2006-01-02 15:04:05.000"),
	)

	body, err := r.execQuery(q)
	if err != nil {
		return nil, fmt.Errorf("ReadRows: %w", err)
	}
	defer body.Close()

	var rows []*models.AdjacencyRow
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		row, err := parseAdjacencyRow([]byte(line))
		if err != nil {
			continue
		}
		rows = append(rows, row)
	}
	return rows, scanner.Err()
}

func (r *Reader) ReadAlertHostsFromAdjacency(since, until time.Time) ([]string, error) {
	q := fmt.Sprintf(
		"SELECT DISTINCT host FROM %s.%s WHERE record_type = 'edge' AND ioa_tags != '[]' AND ts BETWEEN '%s' AND '%s' ORDER BY host FORMAT JSONEachRow",
		quoteIdent(r.database), quoteIdent(r.adjTable),
		since.In(time.Local).Format("2006-01-02 15:04:05.000"),
		until.In(time.Local).Format("2006-01-02 15:04:05.000"),
	)

	body, err := r.execQuery(q)
	if err != nil {
		return nil, fmt.Errorf("ReadAlertHostsFromAdjacency: %w", err)
	}
	defer body.Close()

	var hosts []string
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row struct {
			Host string `json:"host"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		if strings.TrimSpace(row.Host) != "" {
			hosts = append(hosts, strings.TrimSpace(row.Host))
		}
	}
	return hosts, scanner.Err()
}

func (r *Reader) execQuery(query string) (io.ReadCloser, error) {
	endpoint := r.baseURL + "/?query=" + url.QueryEscape(query)

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	for k, v := range r.headers {
		req.Header.Set(k, v)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("clickhouse request failed: %w", err)
	}
	if resp.StatusCode >= 300 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("clickhouse request failed with status %s: %s", resp.Status, strings.TrimSpace(string(errBody)))
	}
	return resp.Body, nil
}

func (r *Reader) execInsert(query string, body io.Reader) error {
	endpoint := r.baseURL + "/?query=" + url.QueryEscape(query)
	req, err := http.NewRequest(http.MethodPost, endpoint, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range r.headers {
		req.Header.Set(k, v)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("clickhouse request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("clickhouse request failed with status %s: %s", resp.Status, strings.TrimSpace(string(errBody)))
	}
	return nil
}

// chAdjacencyRow is the ClickHouse wire representation of an adjacency row.
type chAdjacencyRow struct {
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

func parseAdjacencyRow(data []byte) (*models.AdjacencyRow, error) {
	var ch chAdjacencyRow
	if err := json.Unmarshal(data, &ch); err != nil {
		return nil, err
	}

	ts, err := parseTimestamp(ch.TS)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp %q: %w", ch.TS, err)
	}

	var tags []models.IoaTag
	if ch.IoaTags != "" && ch.IoaTags != "[]" {
		if err := json.Unmarshal([]byte(ch.IoaTags), &tags); err != nil {
			return nil, fmt.Errorf("failed to parse ioa_tags: %w", err)
		}
	}

	return &models.AdjacencyRow{
		Timestamp:  ts,
		RecordType: ch.RecordType,
		Type:       ch.Type,
		VertexID:   ch.VertexID,
		AdjacentID: ch.AdjacentID,
		EventID:    ch.EventID,
		Hostname:   ch.Host,
		AgentID:    ch.AgentID,
		RecordID:   ch.RecordID,
		IoaTags:    tags,
	}, nil
}

func quoteIdent(v string) string {
	if v == "" {
		return ""
	}
	v = strings.ReplaceAll(v, "`", "")
	return "`" + v + "`"
}

func escapeSQLString(v string) string {
	return strings.ReplaceAll(v, "'", "\\'")
}

func parseTimestamp(v string) (time.Time, error) {
	ts, err := time.ParseInLocation("2006-01-02 15:04:05.000", v, time.Local)
	if err == nil {
		return ts, nil
	}
	ts, err = time.Parse("2006-01-02T15:04:05.000Z", v)
	if err == nil {
		return ts.In(time.Local), nil
	}
	ts, err = time.Parse(time.RFC3339Nano, v)
	if err == nil {
		return ts.In(time.Local), nil
	}
	return time.Time{}, err
}
