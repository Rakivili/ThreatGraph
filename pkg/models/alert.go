package models

import "time"

// Alert describes a suspicious subgraph summary.
type Alert struct {
	AlertID     string          `json:"alert_id"`
	VertexID    string          `json:"vertex_id"`
	Score       int             `json:"score"`
	Hostname    string          `json:"host,omitempty"`
	AgentID     string          `json:"agent_id,omitempty"`
	WindowStart time.Time       `json:"window_start"`
	WindowEnd   time.Time       `json:"window_end"`
	IoaTags     []IoaTag        `json:"ioa_tags,omitempty"`
	Counts      AlertCounts     `json:"counts,omitempty"`
	Evidence    []*AdjacencyRow `json:"evidence,omitempty"`
}

// AlertCounts summarizes signal density.
type AlertCounts struct {
	IoaRules          int `json:"ioa_rules"`
	IoaEdges          int `json:"ioa_edges"`
	CrossProcessEdges int `json:"cross_process_edges"`
	EntityTypes       int `json:"entity_types"`
}
