package analyzer

import "time"

// Incident is a compact output for SOC triage.
type Incident struct {
	Host           string    `json:"host"`
	Root           string    `json:"root"`
	IIPTS          time.Time `json:"iip_ts"`
	SequenceLength int       `json:"sequence_length"`
	RiskProduct    float64   `json:"risk_product"`
	RiskSum        float64   `json:"risk_sum"`
	TacticCoverage int       `json:"tactic_coverage"`
	AlertCount     int       `json:"alert_count"`
	Severity       string    `json:"severity"`
}

// BuildIncidents converts scored TPGs into prioritized incidents.
func BuildIncidents(scored []ScoredTPG, minSeq int) []Incident {
	if minSeq <= 0 {
		minSeq = 1
	}
	out := make([]Incident, 0, len(scored))
	for _, s := range scored {
		if s.Score.SequenceLength < minSeq {
			continue
		}
		iipTS := s.TPG.Vertices[0].TS
		if len(s.TPG.Vertices) == 0 {
			iipTS = time.Time{}
		}
		out = append(out, Incident{
			Host:           s.Host,
			Root:           s.Root,
			IIPTS:          iipTS,
			SequenceLength: s.Score.SequenceLength,
			RiskProduct:    s.Score.RiskProduct,
			RiskSum:        s.Score.RiskSum,
			TacticCoverage: s.Score.TacticCoverage,
			AlertCount:     len(s.TPG.Vertices),
			Severity:       incidentSeverity(s.Score.SequenceLength, s.Score.RiskProduct),
		})
	}
	return out
}

func incidentSeverity(seq int, riskProduct float64) string {
	if seq >= 4 || riskProduct >= 100 {
		return "critical"
	}
	if seq >= 3 || riskProduct >= 25 {
		return "high"
	}
	if seq >= 2 || riskProduct >= 9 {
		return "medium"
	}
	return "low"
}
