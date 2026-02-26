package analyzer

import (
	"math"
	"sort"
	"strings"

	"threatgraph/pkg/models"
)

// TacticalScore captures kill-chain sequence quality and risk weighting.
type TacticalScore struct {
	SequenceLength     int      `json:"sequence_length"`
	RiskProduct        float64  `json:"risk_product"`
	RiskSum            float64  `json:"risk_sum"`
	TacticCoverage     int      `json:"tactic_coverage"`
	BestVertexIndexes  []int    `json:"best_vertex_indexes,omitempty"`
	BestVertexRecordID []string `json:"best_vertex_record_ids,omitempty"`
}

// ScoredTPG combines a TPG with its tactical score.
type ScoredTPG struct {
	Host  string        `json:"host"`
	Root  string        `json:"root"`
	Score TacticalScore `json:"score"`
	TPG   TPG           `json:"tpg"`
}

var tacticOrder = map[string]int{
	"initial-access":       1,
	"execution":            2,
	"persistence":          3,
	"privilege-escalation": 4,
	"defense-evasion":      5,
	"credential-access":    6,
	"discovery":            7,
	"lateral-movement":     8,
	"collection":           9,
	"command-and-control":  10,
	"exfiltration":         11,
	"impact":               12,
}

var severityWeight = map[string]float64{
	"informational": 1,
	"low":           2,
	"medium":        3,
	"high":          4,
	"critical":      5,
}

// BuildScoredTPGs creates TPGs for all IIP graphs and ranks them by score.
func BuildScoredTPGs(iips []IIPGraph) []ScoredTPG {
	out := make([]ScoredTPG, 0, len(iips))
	for _, iip := range iips {
		tpg := BuildTPG(iip)
		score := ScoreTPG(tpg)
		out = append(out, ScoredTPG{Host: tpg.Host, Root: tpg.Root, Score: score, TPG: tpg})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Score.SequenceLength != out[j].Score.SequenceLength {
			return out[i].Score.SequenceLength > out[j].Score.SequenceLength
		}
		if out[i].Score.RiskProduct != out[j].Score.RiskProduct {
			return out[i].Score.RiskProduct > out[j].Score.RiskProduct
		}
		if out[i].Score.TacticCoverage != out[j].Score.TacticCoverage {
			return out[i].Score.TacticCoverage > out[j].Score.TacticCoverage
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Root < out[j].Root
	})
	return out
}

// ScoreTPG scores TPG alerts with DAG DP using sequence edges.
// Comparison is lexicographic: longer sequence first, then higher score.
func ScoreTPG(tpg TPG) TacticalScore {
	n := len(tpg.Vertices)
	if n == 0 {
		return TacticalScore{}
	}

	ranks := make([]int, n)
	baseScore := make([]float64, n)
	for i, v := range tpg.Vertices {
		ranks[i], baseScore[i] = alertRankAndSingleScore(v)
	}

	adj := make([][]int, n)
	for _, e := range tpg.SequenceEdges {
		if e.From < 0 || e.To < 0 || e.From >= n || e.To >= n {
			continue
		}
		adj[e.From] = append(adj[e.From], e.To)
	}
	reach := buildReachability(adj)

	dpLen := make([]int, n)
	dpLog := make([]float64, n)
	parent := make([]int, n)
	for i := range parent {
		parent[i] = -1
		score := math.Log(max(baseScore[i], 1e-9))
		dpLen[i] = 1
		dpLog[i] = score
		if ranks[i] == 0 {
			dpLen[i] = 0
			dpLog[i] = math.Inf(-1)
		}
	}

	best := -1
	for v := 0; v < n; v++ {
		if ranks[v] == 0 {
			continue
		}
		for u := 0; u < v; u++ {
			if !reach[u][v] {
				continue
			}
			if ranks[u] == 0 || dpLen[u] == 0 {
				continue
			}
			if ranks[u] > ranks[v] {
				continue
			}
			candLen := dpLen[u] + 1
			candLog := dpLog[u] + math.Log(max(baseScore[v], 1e-9))
			if candLen > dpLen[v] || (candLen == dpLen[v] && candLog > dpLog[v]) {
				dpLen[v] = candLen
				dpLog[v] = candLog
				parent[v] = u
			}
		}

		if best == -1 || dpLen[v] > dpLen[best] || (dpLen[v] == dpLen[best] && dpLog[v] > dpLog[best]) {
			best = v
		}
	}

	if best == -1 || dpLen[best] <= 0 {
		return TacticalScore{}
	}

	path := make([]int, 0, dpLen[best])
	for cur := best; cur >= 0; cur = parent[cur] {
		path = append(path, cur)
		if parent[cur] == -1 {
			break
		}
	}
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}

	usedTactics := map[int]struct{}{}
	riskProduct := 1.0
	riskSum := 0.0
	recordIDs := make([]string, 0, len(path))
	for _, idx := range path {
		usedTactics[ranks[idx]] = struct{}{}
		riskProduct *= baseScore[idx]
		riskSum += baseScore[idx]
		recordIDs = append(recordIDs, strings.TrimSpace(tpg.Vertices[idx].RecordID))
	}

	return TacticalScore{
		SequenceLength:     dpLen[best],
		RiskProduct:        riskProduct,
		RiskSum:            riskSum,
		TacticCoverage:     len(usedTactics),
		BestVertexIndexes:  path,
		BestVertexRecordID: recordIDs,
	}
}

func buildReachability(adj [][]int) [][]bool {
	n := len(adj)
	reach := make([][]bool, n)
	for i := 0; i < n; i++ {
		reach[i] = make([]bool, n)
		queue := append([]int(nil), adj[i]...)
		for _, v := range queue {
			reach[i][v] = true
		}
		for head := 0; head < len(queue); head++ {
			cur := queue[head]
			for _, nxt := range adj[cur] {
				if reach[i][nxt] {
					continue
				}
				reach[i][nxt] = true
				queue = append(queue, nxt)
			}
		}
	}
	return reach
}

func alertRankAndSingleScore(ev AlertEvent) (int, float64) {
	for _, tag := range ev.IoaTags {
		rank := tacticRank(tag.Tactic)
		if rank <= 0 {
			continue
		}
		return rank, singleAlertScore(tag)
	}
	return 0, 0
}

func tacticRank(v string) int {
	n := strings.ToLower(strings.TrimSpace(v))
	if n == "" {
		return 0
	}
	n = strings.ReplaceAll(n, "_", "-")
	n = strings.ReplaceAll(n, " ", "-")
	return tacticOrder[n]
}

// singleAlertScore follows engineering fallback of TS = 2*severity + likelihood.
// Likelihood falls back to severity when no explicit signal exists.
func singleAlertScore(tag models.IoaTag) float64 {
	severity := strings.ToLower(strings.TrimSpace(tag.Severity))
	sev := severityWeight[severity]
	if sev <= 0 {
		sev = 3
	}
	likelihood := sev
	if strings.TrimSpace(tag.Technique) == "" {
		likelihood = max(1, sev-1)
	}
	return (2 * sev) + likelihood
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
