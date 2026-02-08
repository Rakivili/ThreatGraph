package models

import "time"

// AdjacencyRow is an append-only graph record.
type AdjacencyRow struct {
	Timestamp  time.Time              `json:"ts"`
	RecordType string                 `json:"record_type"` // vertex or edge
	Type       string                 `json:"type"`
	VertexID   string                 `json:"vertex_id"`
	AdjacentID string                 `json:"adjacent_id,omitempty"`
	EventID    int                    `json:"event_id,omitempty"`
	Hostname   string                 `json:"host,omitempty"`
	AgentID    string                 `json:"agent_id,omitempty"`
	RecordID   string                 `json:"record_id,omitempty"`
	Data       map[string]interface{} `json:"data,omitempty"`
	IoaTags    []IoaTag               `json:"ioa_tags,omitempty"`
}
