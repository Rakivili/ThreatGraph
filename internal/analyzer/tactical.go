package analyzer

import (
	"sort"
	"strconv"
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

// IIPGraph is an Initial Infection Point rooted subgraph.
//
// Generation strategy:
//   - Process alert edges in temporal order.
//   - A seed alert is accepted as IIP only if backward trace from seed process
//     (with < seed timestamp filter) has no earlier alert edge.
//   - Expand forward from IIP root and keep only alert-relevant paths based on
//     can_reach_alert pre-marking.
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

type iipIndex struct {
	forward       map[string]map[string][]edgeRef
	reverse       map[string]map[string][]edgeRef
	canReachAlert map[string]map[string]bool
	alertsByHost  map[string][]AlertEvent
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
		return compareAlertEvents(alerts[i], alerts[j]) < 0
	})
	return alerts
}

// BuildIIPGraphs builds IIP graphs from adjacency rows.
func BuildIIPGraphs(rows []*models.AdjacencyRow) []IIPGraph {
	alerts := CollectAlertEvents(rows)
	if len(alerts) == 0 {
		return nil
	}

	idx := buildIIPIndex(rows, alerts)
	seenAlert := make(map[string]struct{}, len(alerts))
	backtraceCache := make(map[string]bool, len(alerts)*2)
	out := make([]IIPGraph, 0, len(alerts))

	hosts := make([]string, 0, len(idx.alertsByHost))
	for host := range idx.alertsByHost {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	for _, host := range hosts {
		for _, alert := range idx.alertsByHost[host] {
			if _, ok := seenAlert[alertIdentity(alert)]; ok {
				continue
			}
			if backwardHasEarlierAlert(idx, alert, backtraceCache) {
				continue
			}

			iip := buildIIPGraph(idx, alert)
			if len(iip.AlertEvents) == 0 {
				continue
			}
			for _, ev := range iip.AlertEvents {
				seenAlert[alertIdentity(ev)] = struct{}{}
			}
			out = append(out, iip)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		a := buildTimeKey(out[i].IIPTS, out[i].IIPRecordID)
		b := buildTimeKey(out[j].IIPTS, out[j].IIPRecordID)
		if timeKeyLT(a, b) {
			return true
		}
		if timeKeyLT(b, a) {
			return false
		}
		return out[i].Root < out[j].Root
	})

	return out
}

func buildIIPIndex(rows []*models.AdjacencyRow, alerts []AlertEvent) iipIndex {
	idx := iipIndex{
		forward:       make(map[string]map[string][]edgeRef, 32),
		reverse:       make(map[string]map[string][]edgeRef, 32),
		canReachAlert: make(map[string]map[string]bool, 32),
		alertsByHost:  make(map[string][]AlertEvent, 32),
	}

	for _, row := range rows {
		if row == nil || row.RecordType != "edge" {
			continue
		}
		if row.VertexID == "" || row.AdjacentID == "" || row.Timestamp.IsZero() {
			continue
		}
		host := hostForRow(row)
		if idx.forward[host] == nil {
			idx.forward[host] = make(map[string][]edgeRef, 256)
		}
		if idx.reverse[host] == nil {
			idx.reverse[host] = make(map[string][]edgeRef, 256)
		}
		er := edgeRef{row: row, tk: buildTimeKey(row.Timestamp, row.RecordID)}
		idx.forward[host][row.VertexID] = append(idx.forward[host][row.VertexID], er)
		idx.reverse[host][row.AdjacentID] = append(idx.reverse[host][row.AdjacentID], er)
	}

	for host := range idx.forward {
		for src := range idx.forward[host] {
			sort.Slice(idx.forward[host][src], func(i, j int) bool {
				return timeKeyLE(idx.forward[host][src][i].tk, idx.forward[host][src][j].tk)
			})
		}
	}
	for host := range idx.reverse {
		for dst := range idx.reverse[host] {
			sort.Slice(idx.reverse[host][dst], func(i, j int) bool {
				return timeKeyLE(idx.reverse[host][dst][i].tk, idx.reverse[host][dst][j].tk)
			})
		}
	}

	for _, ev := range alerts {
		idx.alertsByHost[ev.Host] = append(idx.alertsByHost[ev.Host], ev)
	}
	for host := range idx.alertsByHost {
		sort.Slice(idx.alertsByHost[host], func(i, j int) bool {
			return compareAlertEvents(idx.alertsByHost[host][i], idx.alertsByHost[host][j]) < 0
		})
	}

	idx.canReachAlert = markCanReachAlert(idx.reverse, alerts)
	return idx
}

func markCanReachAlert(reverse map[string]map[string][]edgeRef, alerts []AlertEvent) map[string]map[string]bool {
	out := make(map[string]map[string]bool, 32)
	type node struct {
		host   string
		vertex string
	}
	queue := make([]node, 0, len(alerts)*2)

	push := func(host, vertex string) {
		if host == "" || vertex == "" {
			return
		}
		if out[host] == nil {
			out[host] = make(map[string]bool, 512)
		}
		if out[host][vertex] {
			return
		}
		out[host][vertex] = true
		queue = append(queue, node{host: host, vertex: vertex})
	}

	for _, ev := range alerts {
		push(ev.Host, ev.From)
		push(ev.Host, ev.To)
	}

	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		for _, incoming := range reverse[cur.host][cur.vertex] {
			push(cur.host, incoming.row.VertexID)
		}
	}

	return out
}

func backwardHasEarlierAlert(idx iipIndex, seed AlertEvent, cache map[string]bool) bool {
	seedTK := buildTimeKey(seed.TS, seed.RecordID)
	bucket := seed.TS.UTC().Unix() / 60
	cacheKey := seed.Host + "|" + seed.From + "|" + strconv.FormatInt(bucket, 10)
	if cached, ok := cache[cacheKey]; ok {
		return cached
	}

	visited := make(map[string]struct{}, 128)
	queue := []string{seed.From}
	visited[seed.From] = struct{}{}

	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		for _, incoming := range idx.reverse[seed.Host][cur] {
			if !timeKeyLT(incoming.tk, seedTK) {
				break
			}
			if isAlertEdge(incoming.row) {
				cache[cacheKey] = true
				return true
			}
			prev := incoming.row.VertexID
			if _, ok := visited[prev]; ok {
				continue
			}
			visited[prev] = struct{}{}
			queue = append(queue, prev)
		}
	}

	cache[cacheKey] = false
	return false
}

func buildIIPGraph(idx iipIndex, seed AlertEvent) IIPGraph {
	seedTK := buildTimeKey(seed.TS, seed.RecordID)
	host := seed.Host
	canReach := idx.canReachAlert[host]

	queue := []string{seed.From}
	seenVertex := map[string]struct{}{seed.From: {}}
	seenEdge := make(map[string]struct{}, 256)
	edges := make([]*models.AdjacencyRow, 0, 128)
	alerts := make([]AlertEvent, 0, 32)

	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		for _, er := range idx.forward[host][cur] {
			if !timeKeyGE(er.tk, seedTK) {
				continue
			}
			if !isAlertEdge(er.row) && (canReach == nil || !canReach[er.row.AdjacentID]) {
				continue
			}

			edgeKey := edgeIdentityKey(er.row)
			if _, ok := seenEdge[edgeKey]; !ok {
				seenEdge[edgeKey] = struct{}{}
				edges = append(edges, er.row)
				if isAlertEdge(er.row) {
					alerts = append(alerts, AlertEvent{
						Host:     host,
						From:     er.row.VertexID,
						To:       er.row.AdjacentID,
						Type:     er.row.Type,
						TS:       er.row.Timestamp,
						RecordID: er.row.RecordID,
						IoaTags:  append([]models.IoaTag(nil), er.row.IoaTags...),
						Row:      er.row,
					})
				}
			}

			next := er.row.AdjacentID
			if _, ok := seenVertex[next]; ok {
				continue
			}
			seenVertex[next] = struct{}{}
			queue = append(queue, next)
		}
	}

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

	sort.Slice(alerts, func(i, j int) bool {
		return compareAlertEvents(alerts[i], alerts[j]) < 0
	})

	return IIPGraph{
		Host:        host,
		Root:        seed.From,
		IIPTS:       seed.TS,
		IIPRecordID: seed.RecordID,
		AlertEvents: alerts,
		Edges:       edges,
	}
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
		tech, _ := firstTechniqueAndName(ev.IoaTags)
		if tech != "" {
			bySig := seenBySource[ev.From]
			if bySig == nil {
				bySig = make(map[string]struct{}, 8)
				seenBySource[ev.From] = bySig
			}
			sig := strings.ToLower(strings.TrimSpace(tech))
			if _, ok := bySig[sig]; ok {
				continue
			}
			bySig[sig] = struct{}{}
		}
		filtered = append(filtered, ev)
	}

	seqSet := make(map[TPGSequenceEdge]struct{}, len(filtered)*2)
	seq := make([]TPGSequenceEdge, 0, len(filtered)*2)
	addSeq := func(from, to int) {
		if from == to || from < 0 || to < 0 || from >= len(filtered) || to >= len(filtered) {
			return
		}
		e := TPGSequenceEdge{From: from, To: to}
		if _, ok := seqSet[e]; ok {
			return
		}
		seqSet[e] = struct{}{}
		seq = append(seq, e)
	}

	// same-host temporal chain
	for i := 0; i+1 < len(filtered); i++ {
		if filtered[i].Host != filtered[i+1].Host {
			continue
		}
		addSeq(i, i+1)
	}

	// causal alert pairs on IIP paths
	for _, pair := range deriveCausalAlertPairs(iip, filtered) {
		addSeq(pair.From, pair.To)
	}

	sort.Slice(seq, func(i, j int) bool {
		if seq[i].From != seq[j].From {
			return seq[i].From < seq[j].From
		}
		return seq[i].To < seq[j].To
	})

	return TPG{
		Host:          iip.Host,
		Root:          iip.Root,
		Vertices:      filtered,
		SequenceEdges: seq,
	}
}

func deriveCausalAlertPairs(iip IIPGraph, alerts []AlertEvent) []TPGSequenceEdge {
	if len(alerts) < 2 || len(iip.Edges) == 0 {
		return nil
	}

	adj := make(map[string][]edgeRef, 256)
	for _, row := range iip.Edges {
		if row == nil || row.RecordType != "edge" {
			continue
		}
		if row.VertexID == "" || row.AdjacentID == "" || row.Timestamp.IsZero() {
			continue
		}
		er := edgeRef{row: row, tk: buildTimeKey(row.Timestamp, row.RecordID)}
		adj[row.VertexID] = append(adj[row.VertexID], er)
	}
	for src := range adj {
		sort.Slice(adj[src], func(i, j int) bool {
			return timeKeyLE(adj[src][i].tk, adj[src][j].tk)
		})
	}

	idxByFrom := make(map[string][]int, len(alerts))
	for i, ev := range alerts {
		idxByFrom[ev.From] = append(idxByFrom[ev.From], i)
	}

	pairs := make([]TPGSequenceEdge, 0, len(alerts))
	for i, srcAlert := range alerts {
		startTK := buildTimeKey(srcAlert.TS, srcAlert.RecordID)
		queue := []string{srcAlert.To}
		seen := map[string]struct{}{srcAlert.To: {}}

		for head := 0; head < len(queue); head++ {
			cur := queue[head]
			for _, er := range adj[cur] {
				if !timeKeyGE(er.tk, startTK) {
					continue
				}
				next := er.row.AdjacentID
				if candidates := idxByFrom[next]; len(candidates) > 0 {
					for _, j := range candidates {
						if j <= i {
							continue
						}
						dstAlert := alerts[j]
						if dstAlert.Host != srcAlert.Host {
							continue
						}
						dstTK := buildTimeKey(dstAlert.TS, dstAlert.RecordID)
						if timeKeyGE(dstTK, startTK) {
							pairs = append(pairs, TPGSequenceEdge{From: i, To: j})
						}
					}
				}

				if _, ok := seen[next]; ok {
					continue
				}
				seen[next] = struct{}{}
				queue = append(queue, next)
			}
		}
	}

	return pairs
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

func alertIdentity(ev AlertEvent) string {
	if ev.Row != nil {
		return edgeIdentityKey(ev.Row)
	}
	return ev.Host + "|" + ev.RecordID + "|" + ev.From + "|" + ev.To + "|" + ev.Type + "|" + ev.TS.UTC().Format(time.RFC3339Nano)
}

func isAlertEdge(row *models.AdjacencyRow) bool {
	return row != nil && row.RecordType == "edge" && len(row.IoaTags) > 0
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

// FilterRowsByHostAndTime keeps rows for selected hosts within a time window.
func FilterRowsByHostAndTime(rows []*models.AdjacencyRow, hosts map[string]struct{}, since time.Time) []*models.AdjacencyRow {
	if len(rows) == 0 {
		return nil
	}
	filtered := make([]*models.AdjacencyRow, 0, len(rows)/4)
	for _, row := range rows {
		if row == nil || row.RecordType != "edge" {
			continue
		}
		if !since.IsZero() && row.Timestamp.Before(since) {
			continue
		}
		if len(hosts) > 0 {
			host := hostForRow(row)
			if _, ok := hosts[host]; !ok {
				continue
			}
		}
		filtered = append(filtered, row)
	}
	return filtered
}
