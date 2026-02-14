package models

import "time"

// IOAEvent is a lightweight time-series row for sequence prefiltering.
type IOAEvent struct {
	Timestamp  time.Time `json:"ts"`
	Host       string    `json:"host"`
	AgentID    string    `json:"agent_id,omitempty"`
	RecordID   string    `json:"record_id,omitempty"`
	EventID    int       `json:"event_id,omitempty"`
	EdgeType   string    `json:"edge_type,omitempty"`
	VertexID   string    `json:"vertex_id,omitempty"`
	AdjacentID string    `json:"adjacent_id,omitempty"`
	Name       string    `json:"name"`
}
