package analyzer

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"threatgraph/pkg/models"
)

// IncidentSubgraphSummary describes one emitted incident subgraph.
type IncidentSubgraphSummary struct {
	Host                string  `json:"host"`
	Root                string  `json:"root"`
	IIPTS               string  `json:"iip_ts,omitempty"`
	Severity            string  `json:"severity,omitempty"`
	RiskProduct         float64 `json:"risk_product"`
	AlertCount          int     `json:"alert_count"`
	TotalHostEdges      int     `json:"total_host_edges"`
	SubgraphEdgesRaw    int     `json:"subgraph_edges_raw"`
	SubgraphEdgesPruned int     `json:"subgraph_edges_pruned"`
	IOAEdges            int     `json:"ioa_edges"`
	OutputFile          string  `json:"output_file"`
}

type traversalSeed struct {
	node string
	time *timeKey
}

type hostSubgraphIndex struct {
	vertices   map[string]*models.AdjacencyRow
	edges      []edgeRef
	edgesBySrc map[string][]edgeRef
}

// WriteIncidentSubgraphs writes one subgraph JSONL file per deduplicated incident root.
// Incidents are deduplicated by (host, root) and processed in input order.
func WriteIncidentSubgraphs(outDir, host string, hostRows []*models.AdjacencyRow, incidents []Incident) ([]IncidentSubgraphSummary, error) {
	outDir = strings.TrimSpace(outDir)
	if outDir == "" || len(incidents) == 0 {
		return nil, nil
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, fmt.Errorf("create subgraph output dir: %w", err)
	}

	idx := buildHostSubgraphIndex(hostRows)
	if len(idx.edges) == 0 {
		return nil, nil
	}

	summaries := make([]IncidentSubgraphSummary, 0, len(incidents))
	seen := make(map[string]struct{}, len(incidents))
	for _, inc := range incidents {
		incHost := strings.TrimSpace(inc.Host)
		if incHost == "" {
			incHost = host
		}
		if incHost == "" {
			continue
		}
		root := strings.TrimSpace(inc.Root)
		if root == "" {
			continue
		}
		key := incHost + "|" + root
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		var seed *timeKey
		if !inc.IIPTS.IsZero() {
			tk := buildTimeKey(inc.IIPTS, "")
			seed = &tk
		}

		raw := buildSubgraphFromRoot(idx, root, seed)
		pruned := pruneIOAPaths(raw)
		ioaCount := 0
		for _, row := range pruned {
			if isAlertEdge(row) {
				ioaCount++
			}
		}

		outPath := filepath.Join(outDir, incidentSubgraphFilename(incHost, root))
		if err := writeIncidentSubgraphFile(outPath, inc, incHost, pruned, idx.vertices); err != nil {
			return nil, fmt.Errorf("write incident subgraph for host=%s root=%s: %w", incHost, root, err)
		}

		iipTS := ""
		if !inc.IIPTS.IsZero() {
			iipTS = inc.IIPTS.Format(time.RFC3339Nano)
		}
		summaries = append(summaries, IncidentSubgraphSummary{
			Host:                incHost,
			Root:                root,
			IIPTS:               iipTS,
			Severity:            inc.Severity,
			RiskProduct:         inc.RiskProduct,
			AlertCount:          inc.AlertCount,
			TotalHostEdges:      len(idx.edges),
			SubgraphEdgesRaw:    len(raw),
			SubgraphEdgesPruned: len(pruned),
			IOAEdges:            ioaCount,
			OutputFile:          filepath.Base(outPath),
		})
	}

	return summaries, nil
}

func buildHostSubgraphIndex(rows []*models.AdjacencyRow) hostSubgraphIndex {
	idx := hostSubgraphIndex{
		vertices:   make(map[string]*models.AdjacencyRow, 256),
		edges:      make([]edgeRef, 0, len(rows)),
		edgesBySrc: make(map[string][]edgeRef, 256),
	}
	for _, row := range rows {
		if row == nil {
			continue
		}
		if row.RecordType == "vertex" {
			if row.VertexID == "" {
				continue
			}
			if _, ok := idx.vertices[row.VertexID]; !ok {
				idx.vertices[row.VertexID] = row
			}
			continue
		}
		if row.RecordType != "edge" {
			continue
		}
		if strings.TrimSpace(row.VertexID) == "" || strings.TrimSpace(row.AdjacentID) == "" {
			continue
		}
		er := edgeRef{row: row, tk: buildTimeKey(row.Timestamp, row.RecordID)}
		idx.edges = append(idx.edges, er)
	}

	sort.Slice(idx.edges, func(i, j int) bool {
		if timeKeyLT(idx.edges[i].tk, idx.edges[j].tk) {
			return true
		}
		if timeKeyLT(idx.edges[j].tk, idx.edges[i].tk) {
			return false
		}
		a := idx.edges[i].row
		b := idx.edges[j].row
		if a.VertexID != b.VertexID {
			return a.VertexID < b.VertexID
		}
		if a.AdjacentID != b.AdjacentID {
			return a.AdjacentID < b.AdjacentID
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.RecordID < b.RecordID
	})

	for _, er := range idx.edges {
		src := er.row.VertexID
		idx.edgesBySrc[src] = append(idx.edgesBySrc[src], er)
	}
	for src := range idx.edgesBySrc {
		sort.Slice(idx.edgesBySrc[src], func(i, j int) bool {
			return timeKeyLE(idx.edgesBySrc[src][i].tk, idx.edgesBySrc[src][j].tk)
		})
	}

	return idx
}

func buildSubgraphFromRoot(idx hostSubgraphIndex, root string, seed *timeKey) []*models.AdjacencyRow {
	selected := traverseForwardKeys(idx.edgesBySrc, []traversalSeed{{node: root, time: seed}})
	if len(selected) == 0 {
		return nil
	}
	out := make([]*models.AdjacencyRow, 0, len(selected))
	for _, er := range idx.edges {
		if _, ok := selected[edgeIdentityKey(er.row)]; !ok {
			continue
		}
		out = append(out, er.row)
	}
	return out
}

func pruneIOAPaths(edges []*models.AdjacencyRow) []*models.AdjacencyRow {
	if len(edges) == 0 {
		return nil
	}
	edgesBySrc := make(map[string][]edgeRef, 256)
	edgesByDst := make(map[string][]edgeRef, 256)
	ioaSeedsPre := make([]traversalSeed, 0, 64)
	ioaSeedsPost := make([]traversalSeed, 0, 64)
	ioaKeys := make(map[string]struct{}, 64)

	for _, row := range edges {
		if row == nil || row.RecordType != "edge" || row.VertexID == "" || row.AdjacentID == "" {
			continue
		}
		er := edgeRef{row: row, tk: buildTimeKey(row.Timestamp, row.RecordID)}
		edgesBySrc[row.VertexID] = append(edgesBySrc[row.VertexID], er)
		edgesByDst[row.AdjacentID] = append(edgesByDst[row.AdjacentID], er)
		if isAlertEdge(row) {
			id := edgeIdentityKey(row)
			ioaKeys[id] = struct{}{}
			tk := er.tk
			ioaSeedsPre = append(ioaSeedsPre, traversalSeed{node: row.VertexID, time: &tk})
			ioaSeedsPost = append(ioaSeedsPost, traversalSeed{node: row.AdjacentID, time: &tk})
		}
	}
	if len(ioaKeys) == 0 {
		return nil
	}

	for src := range edgesBySrc {
		sort.Slice(edgesBySrc[src], func(i, j int) bool {
			return timeKeyLE(edgesBySrc[src][i].tk, edgesBySrc[src][j].tk)
		})
	}
	for dst := range edgesByDst {
		sort.Slice(edgesByDst[dst], func(i, j int) bool {
			return timeKeyLE(edgesByDst[dst][i].tk, edgesByDst[dst][j].tk)
		})
	}

	preKeys := traverseReverseKeys(edgesByDst, ioaSeedsPre)
	postKeys := traverseForwardKeys(edgesBySrc, ioaSeedsPost)
	keep := make(map[string]struct{}, len(preKeys)+len(postKeys)+len(ioaKeys))
	for k := range preKeys {
		keep[k] = struct{}{}
	}
	for k := range postKeys {
		keep[k] = struct{}{}
	}
	for k := range ioaKeys {
		keep[k] = struct{}{}
	}

	out := make([]*models.AdjacencyRow, 0, len(keep))
	seen := make(map[string]struct{}, len(keep))
	for _, row := range edges {
		id := edgeIdentityKey(row)
		if _, ok := keep[id]; !ok {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, row)
	}
	return out
}

func traverseForwardKeys(edgesBySrc map[string][]edgeRef, seeds []traversalSeed) map[string]struct{} {
	selected := make(map[string]struct{}, 256)
	best := make(map[string]timeKey, 256)
	typedQueue := make([]traversalSeed, 0, len(seeds)+64)
	for _, seed := range seeds {
		if strings.TrimSpace(seed.node) == "" {
			continue
		}
		typedQueue = append(typedQueue, seed)
		if seed.time != nil {
			best[seed.node] = *seed.time
		}
	}

	for head := 0; head < len(typedQueue); head++ {
		cur := typedQueue[head]
		for _, er := range edgesBySrc[cur.node] {
			if cur.time != nil && !timeKeyGE(er.tk, *cur.time) {
				continue
			}
			id := edgeIdentityKey(er.row)
			selected[id] = struct{}{}
			nextNode := er.row.AdjacentID
			nextTime := er.tk
			old, ok := best[nextNode]
			if !ok {
				best[nextNode] = nextTime
				tk := nextTime
				typedQueue = append(typedQueue, traversalSeed{node: nextNode, time: &tk})
				continue
			}
			if !timeKeyLT(nextTime, old) {
				continue
			}
			best[nextNode] = nextTime
			tk := nextTime
			typedQueue = append(typedQueue, traversalSeed{node: nextNode, time: &tk})
		}
	}

	return selected
}

func traverseReverseKeys(edgesByDst map[string][]edgeRef, seeds []traversalSeed) map[string]struct{} {
	selected := make(map[string]struct{}, 256)
	best := make(map[string]timeKey, 256)
	typedQueue := make([]traversalSeed, 0, len(seeds)+64)
	for _, seed := range seeds {
		if strings.TrimSpace(seed.node) == "" {
			continue
		}
		typedQueue = append(typedQueue, seed)
		if seed.time != nil {
			best[seed.node] = *seed.time
		}
	}

	for head := 0; head < len(typedQueue); head++ {
		cur := typedQueue[head]
		for _, er := range edgesByDst[cur.node] {
			if cur.time != nil && !timeKeyLE(er.tk, *cur.time) {
				continue
			}
			id := edgeIdentityKey(er.row)
			selected[id] = struct{}{}
			nextNode := er.row.VertexID
			nextTime := er.tk
			old, ok := best[nextNode]
			if !ok {
				best[nextNode] = nextTime
				tk := nextTime
				typedQueue = append(typedQueue, traversalSeed{node: nextNode, time: &tk})
				continue
			}
			if !timeKeyLT(old, nextTime) {
				continue
			}
			best[nextNode] = nextTime
			tk := nextTime
			typedQueue = append(typedQueue, traversalSeed{node: nextNode, time: &tk})
		}
	}

	return selected
}

func incidentSubgraphFilename(host, root string) string {
	hostPart := sanitizeFilenameComponent(host, 16)
	if hostPart == "" {
		hostPart = "unknown"
	}
	hash := md5.Sum([]byte(root))
	rootHash := hex.EncodeToString(hash[:])[:8]
	return fmt.Sprintf("subgraph_%s_%s.jsonl", hostPart, rootHash)
}

func sanitizeFilenameComponent(v string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 40
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
		if b.Len() >= maxLen {
			break
		}
	}
	return b.String()
}

func writeIncidentSubgraphFile(path string, inc Incident, host string, edges []*models.AdjacencyRow, vertices map[string]*models.AdjacencyRow) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create subgraph directory: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create subgraph file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)

	iipTS := ""
	if !inc.IIPTS.IsZero() {
		iipTS = inc.IIPTS.Format(time.RFC3339Nano)
	}
	header := map[string]interface{}{
		"record_type":         "_incident_meta",
		"host":                host,
		"root":                inc.Root,
		"iip_ts":              iipTS,
		"severity":            inc.Severity,
		"risk_product":        inc.RiskProduct,
		"alert_count":         inc.AlertCount,
		"tactic_coverage":     inc.TacticCoverage,
		"subgraph_edge_count": len(edges),
	}
	ioaCount := 0
	for _, row := range edges {
		if isAlertEdge(row) {
			ioaCount++
		}
	}
	header["ioa_edge_count"] = ioaCount
	if err := enc.Encode(header); err != nil {
		return fmt.Errorf("encode incident meta: %w", err)
	}

	vertexIDs := make(map[string]struct{}, len(edges)*2)
	for _, row := range edges {
		if row == nil {
			continue
		}
		if row.VertexID != "" {
			vertexIDs[row.VertexID] = struct{}{}
		}
		if row.AdjacentID != "" {
			vertexIDs[row.AdjacentID] = struct{}{}
		}
	}

	sortedVertexIDs := make([]string, 0, len(vertexIDs))
	for vid := range vertexIDs {
		sortedVertexIDs = append(sortedVertexIDs, vid)
	}
	sort.Strings(sortedVertexIDs)

	for _, vid := range sortedVertexIDs {
		if row, ok := vertices[vid]; ok {
			if err := enc.Encode(row); err != nil {
				return fmt.Errorf("encode vertex row: %w", err)
			}
			continue
		}
		typeName := "unknown"
		if i := strings.IndexByte(vid, ':'); i > 0 {
			typeName = vid[:i]
		}
		synthetic := map[string]interface{}{
			"record_type": "vertex",
			"vertex_id":   vid,
			"type":        typeName,
		}
		if host != "" {
			synthetic["host"] = host
			synthetic["agent_id"] = host
		}
		if err := enc.Encode(synthetic); err != nil {
			return fmt.Errorf("encode synthetic vertex row: %w", err)
		}
	}

	for _, row := range edges {
		if err := enc.Encode(row); err != nil {
			return fmt.Errorf("encode edge row: %w", err)
		}
	}
	return nil
}
