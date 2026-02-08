package alerts

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"threatgraph/pkg/models"
)

// Config controls alert scoring behavior.
type Config struct {
	Window    time.Duration
	Threshold int
	MaxRows   int
	Cooldown  time.Duration
}

// Scorer builds simple alert subgraphs around IOA edges.
type Scorer struct {
	mu       sync.Mutex
	cfg      Config
	byVertex map[string]*vertexState
	now      func() time.Time
}

type vertexState struct {
	rows      []*models.AdjacencyRow
	lastAlert time.Time
}

// NewScorer creates a new scorer.
func NewScorer(cfg Config) *Scorer {
	if cfg.Window <= 0 {
		cfg.Window = 5 * time.Minute
	}
	if cfg.Threshold <= 0 {
		cfg.Threshold = 8
	}
	if cfg.MaxRows <= 0 {
		cfg.MaxRows = 50
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 2 * time.Minute
	}
	return &Scorer{
		cfg:      cfg,
		byVertex: make(map[string]*vertexState),
		now:      time.Now,
	}
}

// AddRows ingests rows and returns alerts if triggered.
func (s *Scorer) AddRows(rows []*models.AdjacencyRow) []*models.Alert {
	if len(rows) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var alertsOut []*models.Alert
	for _, row := range rows {
		if row == nil || row.VertexID == "" {
			continue
		}
		state := s.byVertex[row.VertexID]
		if state == nil {
			state = &vertexState{}
			s.byVertex[row.VertexID] = state
		}

		if row.Timestamp.IsZero() {
			row.Timestamp = s.now()
		}

		state.rows = append(state.rows, row)
		s.prune(state, s.now())

		if len(row.IoaTags) == 0 {
			continue
		}

		score, summary, tags := s.score(state.rows)
		if score < s.cfg.Threshold {
			continue
		}
		if !state.lastAlert.IsZero() && row.Timestamp.Sub(state.lastAlert) < s.cfg.Cooldown {
			continue
		}

		alert := &models.Alert{
			AlertID:     newAlertID(row.VertexID),
			VertexID:    row.VertexID,
			Score:       score,
			Hostname:    row.Hostname,
			AgentID:     row.AgentID,
			WindowStart: row.Timestamp.Add(-s.cfg.Window),
			WindowEnd:   row.Timestamp,
			IoaTags:     tags,
			Counts:      summary,
			Evidence:    s.sampleEvidence(state.rows, s.cfg.MaxRows),
		}
		state.lastAlert = row.Timestamp
		alertsOut = append(alertsOut, alert)
	}

	return alertsOut
}

func (s *Scorer) prune(state *vertexState, now time.Time) {
	cutoff := now.Add(-s.cfg.Window)
	idx := 0
	for idx < len(state.rows) {
		if state.rows[idx].Timestamp.After(cutoff) || state.rows[idx].Timestamp.Equal(cutoff) {
			break
		}
		idx++
	}
	if idx > 0 {
		state.rows = state.rows[idx:]
	}
	if len(state.rows) > s.cfg.MaxRows {
		state.rows = state.rows[len(state.rows)-s.cfg.MaxRows:]
	}
}

func (s *Scorer) score(rows []*models.AdjacencyRow) (int, models.AlertCounts, []models.IoaTag) {
	severitySum := 0
	unique := make(map[string]struct{})
	entityTypes := make(map[string]struct{})
	ioaEdges := 0
	crossProc := 0
	var tags []models.IoaTag

	for _, row := range rows {
		if row == nil {
			continue
		}
		if row.RecordType == "edge" && row.AdjacentID != "" {
			if typ := adjacentType(row.AdjacentID); typ != "" {
				entityTypes[typ] = struct{}{}
			}
			if row.Type == "ProcessAccessEdge" || row.Type == "RemoteThreadEdge" {
				crossProc++
			}
		}
		if len(row.IoaTags) == 0 {
			continue
		}
		ioaEdges++
		for _, tag := range row.IoaTags {
			key := tag.ID
			if key == "" {
				key = tag.Name
			}
			if key != "" {
				unique[key] = struct{}{}
			}
			severitySum += severityWeight(tag.Severity)
			tags = append(tags, tag)
		}
	}

	score := severitySum + 2*len(unique) + crossProc + len(entityTypes)
	return score, models.AlertCounts{
		IoaRules:          len(unique),
		IoaEdges:          ioaEdges,
		CrossProcessEdges: crossProc,
		EntityTypes:       len(entityTypes),
	}, tags
}

func (s *Scorer) sampleEvidence(rows []*models.AdjacencyRow, maxRows int) []*models.AdjacencyRow {
	if len(rows) <= maxRows {
		return rows
	}
	return rows[len(rows)-maxRows:]
}

func adjacentType(adjacentID string) string {
	idx := strings.Index(adjacentID, ":")
	if idx <= 0 {
		return ""
	}
	return adjacentID[:idx]
}

func severityWeight(level string) int {
	switch strings.ToLower(level) {
	case "critical":
		return 7
	case "high":
		return 5
	case "medium":
		return 3
	case "low":
		return 1
	default:
		return 1
	}
}

func newAlertID(vertexID string) string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return vertexID + "-" + time.Now().Format("20060102150405")
	}
	return vertexID + "-" + hex.EncodeToString(buf)
}
