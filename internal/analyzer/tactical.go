package analyzer

import (
	"sort"
	"strings"
	"time"

	"threatgraph/pkg/models"
)

// AlertEvent is an edge-backed alert event extracted from adjacency rows.
type AlertEvent struct {
	Host     string               `json:"host"`
	From     string               `json:"from"`
	To       string               `json:"to"`
	Type     string               `json:"type"`
	TS       time.Time            `json:"ts"`
	RecordID string               `json:"record_id,omitempty"`
	IoaTags  []models.IoaTag      `json:"ioa_tags"`
	Row      *models.AdjacencyRow `json:"-"`
}

// IIPGraph is a practical approximation of an Initial Intrusion Point graph.
//
// Approximation used in this step:
//   - Group by host + alert source process/vertex (row.VertexID).
//   - The IIP timestamp is the earliest alert event in that group.
//   - Include edges on or after the IIP timestamp that are reachable from
//     vertices touched by alert edges in the group.
//
// This keeps the result deterministic and lightweight without enforcing the
// full RapSheet formal definition yet.
type IIPGraph struct {
	Host        string                 `json:"host"`
	Root        string                 `json:"root"`
	IIPTS       time.Time              `json:"iip_ts"`
	IIPRecordID string                 `json:"iip_record_id,omitempty"`
	AlertEvents []AlertEvent           `json:"alert_events"`
	Edges       []*models.AdjacencyRow `json:"edges"`
}

// TPGSequenceEdge links two alert-event vertices in temporal order.
type TPGSequenceEdge struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// TPG is a tactical provenance graph containing alert-event vertices and
// temporal sequence edges.
type TPG struct {
	Host          string            `json:"host"`
	Root          string            `json:"root"`
	Vertices      []AlertEvent      `json:"vertices"`
	SequenceEdges []TPGSequenceEdge `json:"sequence_edges"`
}

// CollectAlertEvents extracts alert events from edge rows with non-empty IOA tags.
func CollectAlertEvents(rows []*models.AdjacencyRow) []AlertEvent {
	alerts := make([]AlertEvent, 0, 128)
	for _, row := range rows {
		if row == nil || row.RecordType != "edge" {
			continue
		}
		if len(row.IoaTags) == 0 {
			continue
		}
		if row.VertexID == "" || row.AdjacentID == "" || row.Timestamp.IsZero() {
			continue
		}
		alerts = append(alerts, AlertEvent{
			Host:     hostForRow(row),
			From:     row.VertexID,
			To:       row.AdjacentID,
			Type:     row.Type,
			TS:       row.Timestamp,
			RecordID: row.RecordID,
			IoaTags:  append([]models.IoaTag(nil), row.IoaTags...),
			Row:      row,
		})
	}
	sort.Slice(alerts, func(i, j int) bool {
		if c := compareAlertEvents(alerts[i], alerts[j]); c != 0 {
			return c < 0
		}
		return false
	})
	return alerts
}

// BuildIIPGraphs builds tactical IIP approximations from adjacency rows.
func BuildIIPGraphs(rows []*models.AdjacencyRow) []IIPGraph {
	alerts := CollectAlertEvents(rows)
	if len(alerts) == 0 {
		return nil
	}

	hostEdges := make(map[string][]edgeRef, 64)
	for _, row := range rows {
		if row == nil || row.RecordType != "edge" {
			continue
		}
		if row.VertexID == "" || row.AdjacentID == "" || row.Timestamp.IsZero() {
			continue
		}
		host := hostForRow(row)
		hostEdges[host] = append(hostEdges[host], edgeRef{row: row, tk: buildTimeKey(row.Timestamp, row.RecordID)})
	}
	for host := range hostEdges {
		sort.Slice(hostEdges[host], func(i, j int) bool {
			return timeKeyLE(hostEdges[host][i].tk, hostEdges[host][j].tk)
		})
	}

	type key struct {
		host string
		root string
	}
	groups := make(map[key][]AlertEvent, len(alerts))
	for _, ev := range alerts {
		k := key{host: ev.Host, root: ev.From}
		groups[k] = append(groups[k], ev)
	}

	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].host != keys[j].host {
			return keys[i].host < keys[j].host
		}
		return keys[i].root < keys[j].root
	})

	out := make([]IIPGraph, 0, len(keys))
	for _, k := range keys {
		events := append([]AlertEvent(nil), groups[k]...)
		sort.Slice(events, func(i, j int) bool {
			return compareAlertEvents(events[i], events[j]) < 0
		})
		if len(events) == 0 {
			continue
		}

		start := buildTimeKey(events[0].TS, events[0].RecordID)
		seedVertices := make(map[string]struct{}, len(events)*2)
		for _, ev := range events {
			seedVertices[ev.From] = struct{}{}
			seedVertices[ev.To] = struct{}{}
		}

		adj := make(map[string][]edgeRef, 1024)
		for _, er := range hostEdges[k.host] {
			if !timeKeyGE(er.tk, start) {
				continue
			}
			adj[er.row.VertexID] = append(adj[er.row.VertexID], er)
		}

		edges := collectReachableEdges(adj, seedVertices)
		sort.Slice(edges, func(i, j int) bool {
			a := buildTimeKey(edges[i].Timestamp, edges[i].RecordID)
			b := buildTimeKey(edges[j].Timestamp, edges[j].RecordID)
			if timeKeyLT(a, b) {
				return true
			}
			if timeKeyLT(b, a) {
				return false
			}
			if edges[i].VertexID != edges[j].VertexID {
				return edges[i].VertexID < edges[j].VertexID
			}
			if edges[i].AdjacentID != edges[j].AdjacentID {
				return edges[i].AdjacentID < edges[j].AdjacentID
			}
			return edges[i].Type < edges[j].Type
		})

		out = append(out, IIPGraph{
			Host:        k.host,
			Root:        k.root,
			IIPTS:       events[0].TS,
			IIPRecordID: events[0].RecordID,
			AlertEvents: events,
			Edges:       edges,
		})
	}

	return out
}

// BuildTPG builds a tactical provenance graph from one IIP graph.
func BuildTPG(iip IIPGraph) TPG {
	vertices := append([]AlertEvent(nil), iip.AlertEvents...)
	sort.Slice(vertices, func(i, j int) bool {
		return compareAlertEvents(vertices[i], vertices[j]) < 0
	})

	filtered := make([]AlertEvent, 0, len(vertices))
	seenBySource := make(map[string]map[string]struct{}, 32)
	for _, ev := range vertices {
		tech, name := firstTechniqueAndName(ev.IoaTags)
		if tech != "" || name != "" {
			bySig := seenBySource[ev.From]
			if bySig == nil {
				bySig = make(map[string]struct{}, 8)
				seenBySource[ev.From] = bySig
			}
			sig := strings.ToLower(strings.TrimSpace(tech)) + "|" + strings.ToLower(strings.TrimSpace(name))
			if _, ok := bySig[sig]; ok {
				continue
			}
			bySig[sig] = struct{}{}
		}
		filtered = append(filtered, ev)
	}

	seq := make([]TPGSequenceEdge, 0, len(filtered)-1)
	for i := 0; i+1 < len(filtered); i++ {
		if filtered[i].Host != filtered[i+1].Host {
			continue
		}
		seq = append(seq, TPGSequenceEdge{From: i, To: i + 1})
	}

	return TPG{
		Host:          iip.Host,
		Root:          iip.Root,
		Vertices:      filtered,
		SequenceEdges: seq,
	}
}

func collectReachableEdges(adj map[string][]edgeRef, seeds map[string]struct{}) []*models.AdjacencyRow {
	type state struct {
		node string
	}
	queue := make([]state, 0, len(seeds))
	visited := make(map[string]struct{}, len(seeds)*2)
	for node := range seeds {
		queue = append(queue, state{node: node})
		visited[node] = struct{}{}
	}

	edges := make([]*models.AdjacencyRow, 0, 128)
	seenEdge := make(map[string]struct{}, 256)

	head := 0
	for head < len(queue) {
		cur := queue[head]
		head++
		for _, er := range adj[cur.node] {
			k := edgeIdentityKey(er.row)
			if _, ok := seenEdge[k]; !ok {
				seenEdge[k] = struct{}{}
				edges = append(edges, er.row)
			}
			next := er.row.AdjacentID
			if _, ok := visited[next]; ok {
				continue
			}
			visited[next] = struct{}{}
			queue = append(queue, state{node: next})
		}
	}

	return edges
}

func hostForRow(row *models.AdjacencyRow) string {
	host := strings.TrimSpace(row.Hostname)
	if host == "" {
		host = strings.TrimSpace(row.AgentID)
	}
	if host == "" {
		host = "unknown"
	}
	return host
}

func compareAlertEvents(a, b AlertEvent) int {
	if a.Host != b.Host {
		if a.Host < b.Host {
			return -1
		}
		return 1
	}
	atk := buildTimeKey(a.TS, a.RecordID)
	btk := buildTimeKey(b.TS, b.RecordID)
	if timeKeyLT(atk, btk) {
		return -1
	}
	if timeKeyLT(btk, atk) {
		return 1
	}
	if a.From != b.From {
		if a.From < b.From {
			return -1
		}
		return 1
	}
	if a.To != b.To {
		if a.To < b.To {
			return -1
		}
		return 1
	}
	if a.Type != b.Type {
		if a.Type < b.Type {
			return -1
		}
		return 1
	}
	return 0
}

func edgeIdentityKey(row *models.AdjacencyRow) string {
	if row == nil {
		return ""
	}
	return row.Hostname + "|" + row.AgentID + "|" + row.RecordID + "|" + row.VertexID + "|" + row.AdjacentID + "|" + row.Type + "|" + row.Timestamp.UTC().Format(time.RFC3339Nano)
}

func firstTechniqueAndName(tags []models.IoaTag) (string, string) {
	for _, tag := range tags {
		tech := strings.TrimSpace(tag.Technique)
		name := strings.TrimSpace(tag.Name)
		if tech != "" || name != "" {
			return tech, name
		}
	}
	return "", ""
}
