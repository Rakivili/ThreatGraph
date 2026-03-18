package adjacencyclickhouse

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"threatgraph/pkg/models"
)

func TestWriterUsesJSONEachRowByDefault(t *testing.T) {
	var gotQuery string
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		data, _ := io.ReadAll(r.Body)
		gotBody = string(data)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	w, err := NewWriter(Config{URL: server.URL, Database: "db", Table: "tbl"})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	row := sampleRow()
	if err := w.WriteRows([]*models.AdjacencyRow{row}); err != nil {
		t.Fatalf("WriteRows: %v", err)
	}
	if !strings.Contains(gotQuery, "FORMAT JSONEachRow") {
		t.Fatalf("expected JSONEachRow query, got %q", gotQuery)
	}
	if !strings.Contains(gotBody, `"record_type":"edge"`) {
		t.Fatalf("expected JSON body, got %q", gotBody)
	}
}

func TestWriterUsesRowBinaryWhenConfigured(t *testing.T) {
	var gotQuery string
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	w, err := NewWriter(Config{URL: server.URL, Database: "db", Table: "tbl", Format: "row_binary"})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	row := sampleRow()
	if err := w.WriteRows([]*models.AdjacencyRow{row}); err != nil {
		t.Fatalf("WriteRows: %v", err)
	}
	if !strings.Contains(gotQuery, "FORMAT RowBinary") {
		t.Fatalf("expected RowBinary query, got %q", gotQuery)
	}
	decoded, err := decodeSingleRowBinary(gotBody)
	if err != nil {
		t.Fatalf("decodeSingleRowBinary: %v", err)
	}
	if decoded.RecordType != row.RecordType || decoded.Type != row.Type || decoded.EventID != uint16(row.EventID) {
		t.Fatalf("unexpected decoded row: %#v", decoded)
	}
	if decoded.TS != row.Timestamp.UnixMilli() {
		t.Fatalf("unexpected ts: got %d want %d", decoded.TS, row.Timestamp.UnixMilli())
	}
}

type decodedRow struct {
	TS         int64
	RecordType string
	Type       string
	VertexID   string
	AdjacentID string
	EventID    uint16
	Host       string
	AgentID    string
	RecordID   string
	IoaTags    string
}

func decodeSingleRowBinary(data []byte) (*decodedRow, error) {
	r := bytes.NewReader(data)
	ts, err := readInt64(r)
	if err != nil {
		return nil, err
	}
	recordType, err := readString(r)
	if err != nil {
		return nil, err
	}
	typeName, err := readString(r)
	if err != nil {
		return nil, err
	}
	vertexID, err := readString(r)
	if err != nil {
		return nil, err
	}
	adjacentID, err := readString(r)
	if err != nil {
		return nil, err
	}
	var eventID uint16
	if err := binary.Read(r, binary.LittleEndian, &eventID); err != nil {
		return nil, err
	}
	host, err := readString(r)
	if err != nil {
		return nil, err
	}
	agentID, err := readString(r)
	if err != nil {
		return nil, err
	}
	recordID, err := readString(r)
	if err != nil {
		return nil, err
	}
	ioaTags, err := readString(r)
	if err != nil {
		return nil, err
	}
	return &decodedRow{TS: ts, RecordType: recordType, Type: typeName, VertexID: vertexID, AdjacentID: adjacentID, EventID: eventID, Host: host, AgentID: agentID, RecordID: recordID, IoaTags: ioaTags}, nil
}

func readInt64(r io.Reader) (int64, error) {
	var v int64
	err := binary.Read(r, binary.LittleEndian, &v)
	return v, err
}

func readString(r *bytes.Reader) (string, error) {
	length, err := binary.ReadUvarint(r)
	if err != nil {
		return "", err
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func sampleRow() *models.AdjacencyRow {
	return &models.AdjacencyRow{
		Timestamp:  time.Date(2026, 3, 4, 1, 2, 3, 456000000, time.UTC),
		RecordType: "edge",
		Type:       "ParentOfEdge",
		VertexID:   "proc:host:a",
		AdjacentID: "proc:host:b",
		EventID:    1,
		Hostname:   "host",
		AgentID:    "agent",
		RecordID:   "rid",
	}
}

func TestQueryEscapesFormatInURL(t *testing.T) {
	w, err := NewWriter(Config{URL: "http://127.0.0.1:8123", Database: "db", Table: "tbl", Format: "rowbinary"})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	u, err := url.Parse(w.endpoint)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := u.Query().Get("query"); !strings.Contains(got, "FORMAT RowBinary") {
		t.Fatalf("unexpected query: %q", got)
	}
}
