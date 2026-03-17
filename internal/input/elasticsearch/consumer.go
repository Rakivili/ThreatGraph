package elasticsearch

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	URL        string
	Username   string
	Password   string
	Index      string
	Query      string
	BatchSize  int
	Scroll     time.Duration
	Timeout    time.Duration
	Headers    map[string]string
	CACertPath string
	Insecure   bool
}

type Consumer struct {
	endpoint string
	username string
	password string
	headers  map[string]string
	client   *http.Client
	query    map[string]interface{}
	scroll   string

	mu        sync.Mutex
	started   bool
	closed    bool
	exhausted bool
	scrollID  string
	buffer    [][]byte
}

type searchResponse struct {
	ScrollID string `json:"_scroll_id"`
	Hits     struct {
		Hits []struct {
			Source json.RawMessage `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

func NewConsumer(cfg Config) (*Consumer, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("elasticsearch url is required")
	}
	if strings.TrimSpace(cfg.Index) == "" {
		return nil, fmt.Errorf("elasticsearch index is required")
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 1000
	}
	if cfg.Scroll <= 0 {
		cfg.Scroll = 5 * time.Minute
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}

	query := map[string]interface{}{"query": map[string]interface{}{"match_all": map[string]interface{}{}}}
	if strings.TrimSpace(cfg.Query) != "" {
		if err := json.Unmarshal([]byte(cfg.Query), &query); err != nil {
			return nil, fmt.Errorf("invalid elasticsearch query json: %w", err)
		}
	}
	if _, ok := query["size"]; !ok {
		query["size"] = cfg.BatchSize
	}
	if _, ok := query["sort"]; !ok {
		query["sort"] = []interface{}{"_doc"}
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: cfg.Insecure}
	if strings.TrimSpace(cfg.CACertPath) != "" {
		ca, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("read ca cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("append ca cert failed")
		}
		tlsConfig.RootCAs = pool
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	headers := map[string]string{}
	for k, v := range cfg.Headers {
		headers[k] = v
	}

	base := strings.TrimRight(cfg.URL, "/")
	endpoint := fmt.Sprintf("%s/%s", base, strings.TrimLeft(cfg.Index, "/"))
	return &Consumer{
		endpoint: endpoint,
		username: cfg.Username,
		password: cfg.Password,
		headers:  headers,
		client:   &http.Client{Timeout: cfg.Timeout, Transport: transport},
		query:    query,
		scroll:   durationToES(cfg.Scroll),
	}, nil
}

func (c *Consumer) Pop(ctx context.Context) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, nil
	}
	if c.exhausted {
		return nil, io.EOF
	}
	if len(c.buffer) == 0 {
		var err error
		if !c.started {
			c.started = true
			err = c.search(ctx)
		} else {
			err = c.scrollNext(ctx)
		}
		if err != nil {
			return nil, err
		}
		if len(c.buffer) == 0 {
			c.exhausted = true
			return nil, io.EOF
		}
	}
	payload := c.buffer[0]
	c.buffer = c.buffer[1:]
	return payload, nil
}

func (c *Consumer) Close() error {
	c.mu.Lock()
	scrollID := c.scrollID
	client := c.client
	username := c.username
	password := c.password
	defer c.mu.Unlock()
	c.closed = true
	if scrollID == "" {
		return nil
	}
	u, err := url.Parse(c.endpoint)
	if err != nil {
		return nil
	}
	base := u.Scheme + "://" + u.Host
	body, _ := json.Marshal(map[string]interface{}{"scroll_id": []string{scrollID}})
	req, err := http.NewRequest(http.MethodDelete, base+"/_search/scroll", bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	if username != "" {
		req.SetBasicAuth(username, password)
	}
	resp, err := client.Do(req)
	if err == nil && resp != nil {
		resp.Body.Close()
	}
	return nil
}

func (c *Consumer) search(ctx context.Context) error {
	body, err := json.Marshal(c.query)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/_search?scroll=%s", c.endpoint, c.scroll)
	resp, err := c.doJSON(ctx, http.MethodPost, url, body)
	if err != nil {
		return err
	}
	return c.fillBuffer(resp)
}

func (c *Consumer) scrollNext(ctx context.Context) error {
	if c.scrollID == "" {
		return nil
	}
	body, err := json.Marshal(map[string]interface{}{"scroll": c.scroll, "scroll_id": c.scrollID})
	if err != nil {
		return err
	}
	base := c.endpoint
	if idx := strings.Index(base[8:], "/"); idx >= 0 {
		base = base[:8+idx]
	}
	resp, err := c.doJSON(ctx, http.MethodPost, base+"/_search/scroll", body)
	if err != nil {
		return err
	}
	return c.fillBuffer(resp)
}

func (c *Consumer) fillBuffer(resp []byte) error {
	var sr searchResponse
	if err := json.Unmarshal(resp, &sr); err != nil {
		return err
	}
	c.scrollID = sr.ScrollID
	c.buffer = c.buffer[:0]
	for _, hit := range sr.Hits.Hits {
		if len(hit.Source) == 0 {
			continue
		}
		payload := make([]byte, len(hit.Source))
		copy(payload, hit.Source)
		c.buffer = append(c.buffer, payload)
	}
	if len(c.buffer) == 0 {
		c.exhausted = true
	}
	return nil
}

func (c *Consumer) doJSON(ctx context.Context, method, url string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("elasticsearch request failed: %s %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return data, nil
}

func durationToES(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(d/time.Hour))
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
	return fmt.Sprintf("%ds", int(d/time.Second))
}
