package analyzer

import (
	"sort"
	"strings"
	"time"

	"threatgraph/pkg/models"
)

// CandidateSequence is a stage-1 time-series sequence hit before graph validation.
type CandidateSequence struct {
	RuleID   string         `json:"rule_id"`
	Host     string         `json:"host"`
	StartTS  time.Time      `json:"start_ts"`
	EndTS    time.Time      `json:"end_ts"`
	Sequence []SequenceEdge `json:"sequence"`
}

type ruleEvent struct {
	er    edgeRef
	host  string
	names []string
}

type partialSequence struct {
	matched []ruleEvent
	start   timeKey
	last    timeKey
}

// AnalyzeRuleSet runs staged detection: time-series prefilter then graph connectivity validation.
func AnalyzeRuleSet(rows []*models.AdjacencyRow, rs *RuleSet, cfg Config) ([]CandidateSequence, []Finding) {
	if rs == nil {
		return nil, nil
	}
	eventsByHost := buildRuleEventsByHost(rows)
	edgesByHostSrc := buildEdgesByHostSrc(rows)
	ruleCandidatesByHost := make(map[string]map[string][]CandidateSequence, 64)

	candidates := make([]CandidateSequence, 0, 256)
	findings := make([]Finding, 0, 128)
	for _, rule := range rs.Rules {
		if !rule.Enabled || len(rule.Sequence) == 0 {
			continue
		}
		ruleCandidates := prefilterRuleCandidates(eventsByHost, rule)
		candidates = append(candidates, ruleCandidates...)
		for _, cand := range ruleCandidates {
			byRule := ruleCandidatesByHost[cand.Host]
			if byRule == nil {
				byRule = make(map[string][]CandidateSequence, 16)
				ruleCandidatesByHost[cand.Host] = byRule
			}
			byRule[rule.ID] = append(byRule[rule.ID], cand)
		}
		for _, cand := range ruleCandidates {
			if validateCandidateConnectivity(cand, edgesByHostSrc[cand.Host], rule.MaxDepth) {
				findings = append(findings, Finding{
					RuleID:       cand.RuleID,
					Root:         rootFromCandidate(cand),
					MatchedNames: sequenceNames(cand.Sequence),
					Triggered:    cand.Sequence[len(cand.Sequence)-1],
					Sequence:     cand.Sequence,
				})
				if cfg.MaxFindings > 0 && len(findings) >= cfg.MaxFindings {
					return candidates, findings
				}
			}
		}
	}

	compositeCandidates, compositeFindings := analyzeComposites(rs.Composites, ruleCandidatesByHost, edgesByHostSrc, cfg)
	candidates = append(candidates, compositeCandidates...)
	findings = append(findings, compositeFindings...)
	if cfg.MaxFindings > 0 && len(findings) > cfg.MaxFindings {
		findings = findings[:cfg.MaxFindings]
	}
	return candidates, findings
}

func analyzeComposites(composites []CompositeRule, ruleCandidatesByHost map[string]map[string][]CandidateSequence, edgesByHostSrc map[string]map[string][]edgeRef, cfg Config) ([]CandidateSequence, []Finding) {
	if len(composites) == 0 {
		return nil, nil
	}
	allCandidates := make([]CandidateSequence, 0, 128)
	findings := make([]Finding, 0, 64)
	seen := make(map[string]struct{}, 256)

	for _, composite := range composites {
		if !composite.Enabled || len(composite.Parts) < 2 {
			continue
		}
		for host, byRule := range ruleCandidatesByHost {
			lists := make([][]CandidateSequence, 0, len(composite.Parts))
			missing := false
			for _, part := range composite.Parts {
				partList := byRule[part]
				if len(partList) == 0 {
					missing = true
					break
				}
				sort.Slice(partList, func(i, j int) bool {
					return candidateStartsBefore(partList[i], partList[j])
				})
				lists = append(lists, partList)
			}
			if missing {
				continue
			}

			combos := composeCandidateChain(lists, composite.Window, composite.MaxCandidates)
			for _, chain := range combos {
				merged := mergeCandidateChain(chain)
				cand := CandidateSequence{
					RuleID:   composite.ID,
					Host:     host,
					StartTS:  merged[0].TS,
					EndTS:    merged[len(merged)-1].TS,
					Sequence: merged,
				}
				allCandidates = append(allCandidates, cand)

				if !validateCandidateChainConnectivity(chain, edgesByHostSrc[host], composite.MaxDepth) {
					continue
				}

				key := composite.ID + "|" + host + "|" + chainKey(chain)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}

				findings = append(findings, Finding{
					RuleID:       composite.ID,
					Root:         merged[0].From,
					MatchedNames: sequenceNames(merged),
					Triggered:    merged[len(merged)-1],
					Sequence:     merged,
				})
				if cfg.MaxFindings > 0 && len(findings) >= cfg.MaxFindings {
					return allCandidates, findings
				}
			}
		}
	}

	return allCandidates, findings
}

func buildRuleEventsByHost(rows []*models.AdjacencyRow) map[string][]ruleEvent {
	byHost := make(map[string][]ruleEvent, 128)
	for _, row := range rows {
		if row == nil || row.RecordType != "edge" || row.Timestamp.IsZero() {
			continue
		}
		names := edgeNames(row)
		if len(names) == 0 {
			continue
		}
		host := row.Hostname
		if host == "" {
			host = row.AgentID
		}
		if host == "" {
			host = "unknown"
		}
		norm := make([]string, 0, len(names))
		for _, n := range names {
			v := normalizeName(n)
			if v != "" {
				norm = append(norm, v)
			}
		}
		if len(norm) == 0 {
			continue
		}
		byHost[host] = append(byHost[host], ruleEvent{
			er:    edgeRef{row: row, tk: buildTimeKey(row.Timestamp, row.RecordID)},
			host:  host,
			names: norm,
		})
	}
	for host := range byHost {
		sort.Slice(byHost[host], func(i, j int) bool {
			return timeKeyLE(byHost[host][i].er.tk, byHost[host][j].er.tk)
		})
	}
	return byHost
}

func buildEdgesByHostSrc(rows []*models.AdjacencyRow) map[string]map[string][]edgeRef {
	out := make(map[string]map[string][]edgeRef, 128)
	for _, row := range rows {
		if row == nil || row.RecordType != "edge" || row.Timestamp.IsZero() {
			continue
		}
		if row.VertexID == "" || row.AdjacentID == "" {
			continue
		}
		host := row.Hostname
		if host == "" {
			host = row.AgentID
		}
		if host == "" {
			host = "unknown"
		}
		m := out[host]
		if m == nil {
			m = make(map[string][]edgeRef, 2048)
			out[host] = m
		}
		er := edgeRef{row: row, tk: buildTimeKey(row.Timestamp, row.RecordID)}
		m[row.VertexID] = append(m[row.VertexID], er)
	}
	for _, bySrc := range out {
		for src := range bySrc {
			sort.Slice(bySrc[src], func(i, j int) bool {
				return timeKeyLE(bySrc[src][i].tk, bySrc[src][j].tk)
			})
		}
	}
	return out
}

func prefilterRuleCandidates(eventsByHost map[string][]ruleEvent, rule Rule) []CandidateSequence {
	seq := make([]string, 0, len(rule.Sequence))
	for _, item := range rule.Sequence {
		v := normalizeName(item)
		if v != "" {
			seq = append(seq, v)
		}
	}
	if len(seq) == 0 {
		return nil
	}

	out := make([]CandidateSequence, 0, 64)
	for host, events := range eventsByHost {
		buckets := make([][]partialSequence, len(seq)+1)
		for _, ev := range events {
			for idx := 1; idx < len(seq); idx++ {
				buckets[idx] = prunePartialsByWindow(buckets[idx], ev.er.tk, rule.Window)
			}

			if hasName(ev, seq[0]) {
				p := partialSequence{matched: []ruleEvent{ev}, start: ev.er.tk, last: ev.er.tk}
				buckets[1] = appendBoundedPartial(buckets[1], p, rule.MaxCandidates)
			}

			for idx := len(seq) - 1; idx >= 1; idx-- {
				if len(buckets[idx]) == 0 || !hasName(ev, seq[idx]) {
					continue
				}
				for _, p := range buckets[idx] {
					if !timeKeyGE(ev.er.tk, p.last) {
						continue
					}
					if rule.Window > 0 && ev.er.tk.ts.Sub(p.start.ts) > rule.Window {
						continue
					}
					nextMatched := make([]ruleEvent, 0, len(p.matched)+1)
					nextMatched = append(nextMatched, p.matched...)
					nextMatched = append(nextMatched, ev)
					next := partialSequence{matched: nextMatched, start: p.start, last: ev.er.tk}

					if idx+1 == len(seq) {
						out = append(out, toCandidate(rule.ID, host, next.matched))
						if rule.MaxCandidates > 0 && len(out) >= rule.MaxCandidates {
							return out
						}
						continue
					}
					buckets[idx+1] = appendBoundedPartial(buckets[idx+1], next, rule.MaxCandidates)
				}
			}
		}
	}
	return out
}

func validateCandidateConnectivity(c CandidateSequence, edgesBySrc map[string][]edgeRef, maxDepth int) bool {
	if len(c.Sequence) == 0 {
		return false
	}
	if maxDepth <= 0 {
		maxDepth = 64
	}
	for i := 0; i < len(c.Sequence)-1; i++ {
		left := c.Sequence[i]
		right := c.Sequence[i+1]
		if left.To == right.From {
			continue
		}
		start := buildTimeKey(left.TS, left.RecordID)
		end := buildTimeKey(right.TS, right.RecordID)
		if !temporalReachable(edgesBySrc, left.To, right.From, start, end, maxDepth) {
			return false
		}
	}
	return true
}

func validateCandidateChainConnectivity(chain []CandidateSequence, edgesBySrc map[string][]edgeRef, maxDepth int) bool {
	if len(chain) < 2 {
		return false
	}
	if maxDepth <= 0 {
		maxDepth = 64
	}
	for i := 0; i < len(chain)-1; i++ {
		left := chain[i]
		right := chain[i+1]
		if len(left.Sequence) == 0 || len(right.Sequence) == 0 {
			return false
		}
		leftLast := left.Sequence[len(left.Sequence)-1]
		rightFirst := right.Sequence[0]
		if leftLast.To == rightFirst.From {
			continue
		}
		start := buildTimeKey(leftLast.TS, leftLast.RecordID)
		end := buildTimeKey(rightFirst.TS, rightFirst.RecordID)
		if !temporalReachable(edgesBySrc, leftLast.To, rightFirst.From, start, end, maxDepth) {
			return false
		}
	}
	return true
}

func composeCandidateChain(lists [][]CandidateSequence, window time.Duration, maxCandidates int) [][]CandidateSequence {
	out := make([][]CandidateSequence, 0, 64)
	if len(lists) < 2 {
		return out
	}

	var walk func(idx int, current []CandidateSequence)
	walk = func(idx int, current []CandidateSequence) {
		if maxCandidates > 0 && len(out) >= maxCandidates {
			return
		}
		if idx == len(lists) {
			combo := make([]CandidateSequence, len(current))
			copy(combo, current)
			out = append(out, combo)
			return
		}

		for _, cand := range lists[idx] {
			if len(current) > 0 {
				prev := current[len(current)-1]
				if !timeKeyLE(candidateEndKey(prev), candidateStartKey(cand)) {
					continue
				}
				if window > 0 {
					start := candidateStartKey(current[0])
					end := candidateEndKey(cand)
					if end.ts.Sub(start.ts) > window {
						continue
					}
				}
			}
			next := append(current, cand)
			walk(idx+1, next)
		}
	}

	walk(0, nil)
	return out
}

func mergeCandidateChain(chain []CandidateSequence) []SequenceEdge {
	out := make([]SequenceEdge, 0, len(chain)*2)
	seen := make(map[string]struct{}, len(chain)*4)
	for _, cand := range chain {
		for _, edge := range cand.Sequence {
			key := edge.From + "|" + edge.To + "|" + edge.Type + "|" + edge.RecordID
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, edge)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return timeKeyLE(buildTimeKey(out[i].TS, out[i].RecordID), buildTimeKey(out[j].TS, out[j].RecordID))
	})
	return out
}

func candidateStartKey(c CandidateSequence) timeKey {
	if len(c.Sequence) == 0 {
		return timeKey{}
	}
	first := c.Sequence[0]
	return buildTimeKey(first.TS, first.RecordID)
}

func candidateEndKey(c CandidateSequence) timeKey {
	if len(c.Sequence) == 0 {
		return timeKey{}
	}
	last := c.Sequence[len(c.Sequence)-1]
	return buildTimeKey(last.TS, last.RecordID)
}

func candidateStartsBefore(a, b CandidateSequence) bool {
	return timeKeyLE(candidateStartKey(a), candidateStartKey(b))
}

func chainKey(chain []CandidateSequence) string {
	parts := make([]string, 0, len(chain))
	for _, cand := range chain {
		if len(cand.Sequence) == 0 {
			continue
		}
		first := cand.Sequence[0]
		last := cand.Sequence[len(cand.Sequence)-1]
		parts = append(parts, first.RecordID+":"+last.RecordID)
	}
	return strings.Join(parts, ",")
}

func temporalReachable(edgesBySrc map[string][]edgeRef, src, dst string, start, end timeKey, maxDepth int) bool {
	if src == "" || dst == "" {
		return false
	}
	if src == dst {
		return true
	}

	type state struct {
		node  string
		time  timeKey
		depth int
	}
	queue := make([]state, 0, 256)
	queue = append(queue, state{node: src, time: start, depth: 0})
	head := 0
	best := make(map[string]timeKey, 256)

	for head < len(queue) {
		cur := queue[head]
		head++
		if maxDepth > 0 && cur.depth >= maxDepth {
			continue
		}
		for _, er := range edgesBySrc[cur.node] {
			if !timeKeyGE(er.tk, cur.time) {
				continue
			}
			if !timeKeyLE(er.tk, end) {
				continue
			}
			nextNode := er.row.AdjacentID
			if nextNode == dst {
				return true
			}
			if old, ok := best[nextNode]; ok && timeKeyLE(old, er.tk) {
				continue
			}
			best[nextNode] = er.tk
			queue = append(queue, state{node: nextNode, time: er.tk, depth: cur.depth + 1})
		}
	}
	return false
}

func appendBoundedPartial(parts []partialSequence, p partialSequence, limit int) []partialSequence {
	parts = append(parts, p)
	if limit <= 0 || len(parts) <= limit {
		return parts
	}
	start := len(parts) - limit
	if start < 0 {
		start = 0
	}
	trimmed := make([]partialSequence, 0, limit)
	trimmed = append(trimmed, parts[start:]...)
	return trimmed
}

func prunePartialsByWindow(parts []partialSequence, now timeKey, window time.Duration) []partialSequence {
	if window <= 0 || len(parts) == 0 {
		return parts
	}
	out := parts[:0]
	for _, p := range parts {
		if now.ts.Sub(p.start.ts) <= window {
			out = append(out, p)
		}
	}
	return out
}

func hasName(ev ruleEvent, expected string) bool {
	for _, n := range ev.names {
		if n == expected {
			return true
		}
	}
	return false
}

func toCandidate(ruleID, host string, matched []ruleEvent) CandidateSequence {
	seq := make([]SequenceEdge, 0, len(matched))
	for _, ev := range matched {
		seq = append(seq, toSequenceEdge(ev.er))
	}
	start := time.Time{}
	end := time.Time{}
	if len(seq) > 0 {
		start = seq[0].TS
		end = seq[len(seq)-1].TS
	}
	return CandidateSequence{
		RuleID:   ruleID,
		Host:     host,
		StartTS:  start,
		EndTS:    end,
		Sequence: seq,
	}
}

func rootFromCandidate(c CandidateSequence) string {
	if len(c.Sequence) == 0 {
		return ""
	}
	return c.Sequence[0].From
}

func sequenceNames(seq []SequenceEdge) []string {
	out := make([]string, 0, len(seq))
	for _, s := range seq {
		if strings.TrimSpace(s.Name) != "" {
			out = append(out, s.Name)
		}
	}
	return out
}
