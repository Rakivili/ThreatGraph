package analyzer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"threatgraph/pkg/models"
)

// Config controls temporal graph traversal behavior.
type Config struct {
	MaxDepth    int
	MaxFindings int
}

// SequenceEdge is a simplified edge view for output.
type SequenceEdge struct {
	Type     string    `json:"type"`
	Name     string    `json:"name,omitempty"`
	From     string    `json:"from"`
	To       string    `json:"to"`
	TS       time.Time `json:"ts"`
	RecordID string    `json:"record_id,omitempty"`
}

// Finding describes a matched IOA sequence.
type Finding struct {
	RuleID       string         `json:"rule_id"`
	Root         string         `json:"root"`
	MatchedNames []string       `json:"matched_names,omitempty"`
	Triggered    SequenceEdge   `json:"triggered_edge"`
	Sequence     []SequenceEdge `json:"sequence"`
}

type timeKey struct {
	ts     time.Time
	rid    int64
	hasRID bool
}

type edgeRef struct {
	row *models.AdjacencyRow
	tk  timeKey
}

type nameStateID struct {
	node string
	idx  int
}

type nameParentLink struct {
	prev    nameStateID
	edge    edgeRef
	matched bool
}

type nameQueueState struct {
	id    nameStateID
	time  *timeKey
	depth int
}

// LoadRowsJSONL reads adjacency rows from JSONL.
func LoadRowsJSONL(path string) ([]*models.AdjacencyRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open input: %w", err)
	}
	defer f.Close()

	rows := make([]*models.AdjacencyRow, 0, 4096)
	s := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	s.Buffer(buf, 8*1024*1024)

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var row models.AdjacencyRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		rows = append(rows, &row)
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("scan input: %w", err)
	}
	return rows, nil
}

// DetectRemoteThreadPaths traverses time-respecting paths and finds process-injection-related edges.
// It currently emits findings for both RemoteThreadEdge and ProcessAccessEdge.
func DetectRemoteThreadPaths(rows []*models.AdjacencyRow, cfg Config) []Finding {
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 64
	}
	if cfg.MaxFindings <= 0 {
		cfg.MaxFindings = 10000
	}

	edgesBySrc := make(map[string][]edgeRef, 2048)
	incomingParentCount := make(map[string]int, 2048)
	allProcSources := make(map[string]struct{}, 2048)

	for _, row := range rows {
		if row == nil || row.RecordType != "edge" {
			continue
		}
		if row.VertexID == "" || row.AdjacentID == "" || row.Timestamp.IsZero() {
			continue
		}
		tk := buildTimeKey(row.Timestamp, row.RecordID)
		edgesBySrc[row.VertexID] = append(edgesBySrc[row.VertexID], edgeRef{row: row, tk: tk})
		if strings.HasPrefix(row.VertexID, "proc:") {
			allProcSources[row.VertexID] = struct{}{}
		}
		if row.Type == "ParentOfEdge" && strings.HasPrefix(row.AdjacentID, "proc:") {
			incomingParentCount[row.AdjacentID]++
		}
	}

	for src := range edgesBySrc {
		sort.Slice(edgesBySrc[src], func(i, j int) bool {
			return timeKeyLE(edgesBySrc[src][i].tk, edgesBySrc[src][j].tk)
		})
	}

	roots := make([]string, 0, len(allProcSources))
	for proc := range allProcSources {
		if incomingParentCount[proc] == 0 {
			roots = append(roots, proc)
		}
	}
	if len(roots) == 0 {
		for proc := range allProcSources {
			roots = append(roots, proc)
		}
	}
	sort.Strings(roots)

	findings := make([]Finding, 0, 128)
	seen := make(map[string]struct{}, 1024)

	for _, root := range roots {
		if len(findings) >= cfg.MaxFindings {
			break
		}
		fs := traverseFromRoot(root, edgesBySrc, cfg.MaxDepth, cfg.MaxFindings-len(findings), seen)
		findings = append(findings, fs...)
	}

	return findings
}

// DetectNamedSequencePaths traverses time-respecting paths and finds ordered name matches.
// A path matches when edge names contain sequence[0], sequence[1], ... in order.
func DetectNamedSequencePaths(rows []*models.AdjacencyRow, sequence []string, cfg Config) []Finding {
	if len(sequence) == 0 {
		return nil
	}
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 64
	}
	if cfg.MaxFindings <= 0 {
		cfg.MaxFindings = 10000
	}

	normalizedSeq := make([]string, 0, len(sequence))
	for _, name := range sequence {
		v := normalizeName(name)
		if v != "" {
			normalizedSeq = append(normalizedSeq, v)
		}
	}
	if len(normalizedSeq) == 0 {
		return nil
	}

	edgesBySrc := make(map[string][]edgeRef, 2048)
	incomingParentCount := make(map[string]int, 2048)
	allProcSources := make(map[string]struct{}, 2048)

	for _, row := range rows {
		if row == nil || row.RecordType != "edge" {
			continue
		}
		if row.VertexID == "" || row.AdjacentID == "" || row.Timestamp.IsZero() {
			continue
		}
		tk := buildTimeKey(row.Timestamp, row.RecordID)
		edgesBySrc[row.VertexID] = append(edgesBySrc[row.VertexID], edgeRef{row: row, tk: tk})
		if strings.HasPrefix(row.VertexID, "proc:") {
			allProcSources[row.VertexID] = struct{}{}
		}
		if row.Type == "ParentOfEdge" && strings.HasPrefix(row.AdjacentID, "proc:") {
			incomingParentCount[row.AdjacentID]++
		}
	}

	for src := range edgesBySrc {
		sort.Slice(edgesBySrc[src], func(i, j int) bool {
			return timeKeyLE(edgesBySrc[src][i].tk, edgesBySrc[src][j].tk)
		})
	}

	roots := make([]string, 0, len(allProcSources))
	for proc := range allProcSources {
		if incomingParentCount[proc] == 0 {
			roots = append(roots, proc)
		}
	}
	if len(roots) == 0 {
		for proc := range allProcSources {
			roots = append(roots, proc)
		}
	}
	sort.Strings(roots)

	findings := make([]Finding, 0, 128)
	seen := make(map[string]struct{}, 1024)

	for _, root := range roots {
		if len(findings) >= cfg.MaxFindings {
			break
		}

		bestTime := make(map[nameStateID]timeKey, 2048)
		parents := make(map[nameStateID]nameParentLink, 2048)

		queue := make([]nameQueueState, 0, 1024)
		start := nameStateID{node: root, idx: 0}
		queue = append(queue, nameQueueState{id: start, time: nil, depth: 0})

		head := 0
		for head < len(queue) {
			cur := queue[head]
			head++
			if cur.depth >= cfg.MaxDepth {
				continue
			}

			for _, er := range edgesBySrc[cur.id.node] {
				if cur.time != nil && !timeKeyGE(er.tk, *cur.time) {
					continue
				}

				nextIdx := cur.id.idx
				matched := false
				if nextIdx < len(normalizedSeq) && edgeHasName(er.row, normalizedSeq[nextIdx]) {
					nextIdx++
					matched = true
				}

				next := nameStateID{node: er.row.AdjacentID, idx: nextIdx}
				update := false
				old, ok := bestTime[next]
				if !ok || timeKeyLT(er.tk, old) {
					bestTime[next] = er.tk
					parents[next] = nameParentLink{prev: cur.id, edge: er, matched: matched}
					update = true
				}

				if matched && nextIdx == len(normalizedSeq) {
					seq := reconstructMatchedSequence(start, next, parents)
					if len(seq) == len(normalizedSeq) {
						trigger := seq[len(seq)-1]
						key := root + "|" + trigger.From + "|" + trigger.To + "|" + trigger.RecordID + "|" + strings.Join(normalizedSeq, ",")
						if _, exists := seen[key]; !exists {
							seen[key] = struct{}{}
							findings = append(findings, Finding{
								RuleID:       "IOA-NAMED-SEQUENCE",
								Root:         root,
								MatchedNames: append([]string(nil), sequence...),
								Triggered:    trigger,
								Sequence:     seq,
							})
							if len(findings) >= cfg.MaxFindings {
								return findings
							}
						}
					}
				}

				if update {
					tk := bestTime[next]
					queue = append(queue, nameQueueState{id: next, time: &tk, depth: cur.depth + 1})
				}
			}
		}
	}

	return findings
}

func traverseFromRoot(root string, edgesBySrc map[string][]edgeRef, maxDepth, budget int, seen map[string]struct{}) []Finding {
	type state struct {
		node  string
		time  *timeKey
		depth int
	}

	bestTime := make(map[string]timeKey, 2048)
	parentEdge := make(map[string]edgeRef, 2048)
	parentNode := make(map[string]string, 2048)

	queue := make([]state, 0, 1024)
	queue = append(queue, state{node: root, time: nil, depth: 0})

	found := make([]Finding, 0, 32)
	head := 0
	for head < len(queue) {
		cur := queue[head]
		head++
		if cur.depth >= maxDepth {
			continue
		}

		for _, er := range edgesBySrc[cur.node] {
			if cur.time != nil && !timeKeyGE(er.tk, *cur.time) {
				continue
			}

			to := er.row.AdjacentID
			nextDepth := cur.depth + 1
			update := false
			old, ok := bestTime[to]
			if !ok || timeKeyLT(er.tk, old) {
				bestTime[to] = er.tk
				parentEdge[to] = er
				parentNode[to] = cur.node
				update = true
			}

			ruleID := ""
			switch er.row.Type {
			case "RemoteThreadEdge":
				ruleID = "IOA-REMOTE-THREAD"
			case "ProcessAccessEdge":
				ruleID = "IOA-PROCESS-ACCESS"
			}
			if ruleID != "" {
				seq := reconstructSequence(root, cur.node, parentEdge, parentNode)
				trigger := toSequenceEdge(er)
				seq = append(seq, trigger)
				key := ruleID + "|" + root + "|" + er.row.VertexID + "|" + er.row.AdjacentID + "|" + er.row.RecordID
				if _, exists := seen[key]; !exists {
					seen[key] = struct{}{}
					found = append(found, Finding{
						RuleID:       ruleID,
						Root:         root,
						MatchedNames: edgeNames(er.row),
						Triggered:    trigger,
						Sequence:     seq,
					})
					if len(found) >= budget {
						return found
					}
				}
			}

			if update {
				tk := bestTime[to]
				queue = append(queue, state{node: to, time: &tk, depth: nextDepth})
			}
		}
	}

	return found
}

func reconstructSequence(root, node string, parentEdge map[string]edgeRef, parentNode map[string]string) []SequenceEdge {
	if node == "" || node == root {
		return nil
	}
	seq := make([]SequenceEdge, 0, 16)
	cur := node
	for cur != "" && cur != root {
		er, ok := parentEdge[cur]
		if !ok {
			break
		}
		seq = append(seq, toSequenceEdge(er))
		cur = parentNode[cur]
	}
	for i, j := 0, len(seq)-1; i < j; i, j = i+1, j-1 {
		seq[i], seq[j] = seq[j], seq[i]
	}
	return seq
}

func toSequenceEdge(er edgeRef) SequenceEdge {
	return SequenceEdge{
		Type:     er.row.Type,
		Name:     firstEdgeName(er.row),
		From:     er.row.VertexID,
		To:       er.row.AdjacentID,
		TS:       er.row.Timestamp,
		RecordID: er.row.RecordID,
	}
}

func reconstructMatchedSequence(start, end nameStateID, parents map[nameStateID]nameParentLink) []SequenceEdge {
	seq := make([]SequenceEdge, 0, end.idx)
	cur := end
	for cur != start {
		link, ok := parents[cur]
		if !ok {
			break
		}
		if link.matched {
			seq = append(seq, toSequenceEdge(link.edge))
		}
		cur = link.prev
	}
	for i, j := 0, len(seq)-1; i < j; i, j = i+1, j-1 {
		seq[i], seq[j] = seq[j], seq[i]
	}
	return seq
}

func firstEdgeName(row *models.AdjacencyRow) string {
	names := edgeNames(row)
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

func edgeHasName(row *models.AdjacencyRow, expected string) bool {
	if expected == "" {
		return false
	}
	for _, name := range edgeNames(row) {
		if normalizeName(name) == expected {
			return true
		}
	}
	return false
}

func edgeNames(row *models.AdjacencyRow) []string {
	if row == nil {
		return nil
	}
	values := make([]string, 0, 4)
	appendIfString := func(v interface{}) {
		s, ok := v.(string)
		if !ok {
			return
		}
		for _, part := range splitNameParts(s) {
			if part != "" {
				values = append(values, part)
			}
		}
	}

	appendIfString(row.Data["name"])
	appendIfString(row.Data["rule_name"])
	appendIfString(row.Data["ruleName"])

	if fields, ok := row.Data["fields"].(map[string]interface{}); ok {
		appendIfString(fields["RuleName"])
		appendIfString(fields["rule_name"])
		appendIfString(fields["name"])
	}

	if len(values) == 0 {
		return nil
	}
	uniq := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, name := range values {
		n := strings.TrimSpace(name)
		if n == "" || n == "-" {
			continue
		}
		if _, ok := uniq[n]; ok {
			continue
		}
		uniq[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func splitNameParts(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	parts := strings.FieldsFunc(v, func(r rune) bool {
		switch r {
		case ';', '|':
			return true
		default:
			return false
		}
	})
	if len(parts) == 0 {
		parts = []string{v}
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "=") {
			kv := strings.SplitN(p, "=", 2)
			k := strings.ToLower(strings.TrimSpace(kv[0]))
			val := strings.TrimSpace(kv[1])
			if (k == "name" || k == "rulename" || k == "rule_name") && val != "" {
				out = append(out, val)
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

func normalizeName(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func buildTimeKey(ts time.Time, rid string) timeKey {
	tk := timeKey{ts: ts}
	if rid == "" {
		return tk
	}
	v, err := strconv.ParseInt(rid, 10, 64)
	if err != nil {
		return tk
	}
	tk.rid = v
	tk.hasRID = true
	return tk
}

func timeKeyLT(a, b timeKey) bool {
	if a.ts.Before(b.ts) {
		return true
	}
	if a.ts.After(b.ts) {
		return false
	}
	if !a.hasRID || !b.hasRID {
		return false
	}
	return a.rid < b.rid
}

func timeKeyLE(a, b timeKey) bool {
	if a.ts.Before(b.ts) {
		return true
	}
	if a.ts.After(b.ts) {
		return false
	}
	if !a.hasRID || !b.hasRID {
		return true
	}
	return a.rid <= b.rid
}

func timeKeyGE(a, b timeKey) bool {
	if a.ts.After(b.ts) {
		return true
	}
	if a.ts.Before(b.ts) {
		return false
	}
	if !a.hasRID || !b.hasRID {
		return true
	}
	return a.rid >= b.rid
}
