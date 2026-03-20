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
	Username       string
	Password       string
	Timeout        time.Duration
}

// Reader queries ClickHouse for adjacency rows and IOA host lists.
type Reader struct {
	baseURL  string
	database string
	adjTable string
	headers  map[string]string
	client   *http.Client
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
		baseURL:  strings.TrimRight(cfg.URL, "/"),
		database: cfg.Database,
		adjTable: cfg.AdjacencyTable,
		headers:  headers,
		client:   &http.Client{Timeout: timeout},
	}, nil
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
