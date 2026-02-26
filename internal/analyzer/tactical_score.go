package analyzer

import (
	"math"
	"sort"
	"strings"

	"threatgraph/pkg/models"
)

// TacticalScore captures kill-chain sequence quality and risk weighting.
type TacticalScore struct {
	SequenceLength int     `json:"sequence_length"`
	RiskProduct    float64 `json:"risk_product"`
	RiskSum        float64 `json:"risk_sum"`
	TacticCoverage int     `json:"tactic_coverage"`
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
		out = append(out, ScoredTPG{
			Host:  tpg.Host,
			Root:  tpg.Root,
			Score: score,
			TPG:   tpg,
		})
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

// ScoreTPG finds the longest kill-chain-consistent subsequence and scores it.
func ScoreTPG(tpg TPG) TacticalScore {
	if len(tpg.Vertices) == 0 {
		return TacticalScore{}
	}

	type seqItem struct {
		rank int
		risk float64
	}

	items := make([]seqItem, 0, len(tpg.Vertices))
	for _, v := range tpg.Vertices {
		rank, risk := alertRankAndRisk(v)
		if rank <= 0 || risk <= 0 {
			continue
		}
		items = append(items, seqItem{rank: rank, risk: risk})
	}
	if len(items) == 0 {
		return TacticalScore{}
	}

	dpLen := make([]int, len(items))
	dpRiskLog := make([]float64, len(items))
	parent := make([]int, len(items))
	for i := range items {
		dpLen[i] = 1
		dpRiskLog[i] = math.Log(items[i].risk)
		parent[i] = -1
	}

	best := 0
	for i := 0; i < len(items); i++ {
		for j := 0; j < i; j++ {
			if items[j].rank > items[i].rank {
				continue
			}
			candLen := dpLen[j] + 1
			candRisk := dpRiskLog[j] + math.Log(items[i].risk)
			if candLen > dpLen[i] || (candLen == dpLen[i] && candRisk > dpRiskLog[i]) {
				dpLen[i] = candLen
				dpRiskLog[i] = candRisk
				parent[i] = j
			}
		}
		if dpLen[i] > dpLen[best] || (dpLen[i] == dpLen[best] && dpRiskLog[i] > dpRiskLog[best]) {
			best = i
		}
	}

	usedTactics := map[int]struct{}{}
	riskProduct := 1.0
	riskSum := 0.0
	for cur := best; cur >= 0; cur = parent[cur] {
		riskProduct *= items[cur].risk
		riskSum += items[cur].risk
		usedTactics[items[cur].rank] = struct{}{}
	}

	return TacticalScore{
		SequenceLength: dpLen[best],
		RiskProduct:    riskProduct,
		RiskSum:        riskSum,
		TacticCoverage: len(usedTactics),
	}
}

func alertRankAndRisk(ev AlertEvent) (int, float64) {
	for _, tag := range ev.IoaTags {
		rank := tacticRank(tag.Tactic)
		if rank <= 0 {
			continue
		}
		return rank, tagRisk(tag)
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

func tagRisk(tag models.IoaTag) float64 {
	severity := strings.ToLower(strings.TrimSpace(tag.Severity))
	w := severityWeight[severity]
	if w <= 0 {
		w = 3
	}
	if strings.TrimSpace(tag.Technique) != "" {
		w += 1
	}
	if w < 1 {
		w = 1
	}
	return w
}
