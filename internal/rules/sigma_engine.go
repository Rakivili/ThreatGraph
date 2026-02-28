package rules

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	sigma "github.com/bradleyjkemp/sigma-go"
	sigmaevaluator "github.com/bradleyjkemp/sigma-go/evaluator"

	"threatgraph/pkg/models"
)

var techniqueTagRegex = regexp.MustCompile(`^attack\.t\d{4}(?:\.\d{3})?$`)

// SigmaLoadStats tracks the number of loaded and skipped rules.
type SigmaLoadStats struct {
	TotalFiles        int
	Loaded            int
	SkippedComplex    int
	SkippedDatasource int
	SkippedInvalid    int
}

type compiledSigmaRule struct {
	rule  sigma.Rule
	eval  *sigmaevaluator.RuleEvaluator
	label models.IoaTag
	// Optional Sysmon EventID prefilter inferred from rule metadata/path.
	// When empty, the rule is evaluated for all incoming events.
	eventIDs map[int]struct{}
}

// SigmaEngine evaluates Sigma rules against individual Sysmon events.
type SigmaEngine struct {
	rules []compiledSigmaRule
	ctx   context.Context
}

// NewSigmaEngine loads Sigma rules from a file or directory and compiles evaluators.
// Unsupported or complex rules are skipped and included in stats.
func NewSigmaEngine(path string) (*SigmaEngine, SigmaLoadStats, error) {
	var stats SigmaLoadStats

	resolved, err := filepath.Abs(path)
	if err != nil {
		return nil, stats, fmt.Errorf("resolve rule path: %w", err)
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return nil, stats, fmt.Errorf("stat rule path: %w", err)
	}

	files := make([]string, 0, 256)
	if info.IsDir() {
		err = filepath.WalkDir(resolved, func(filePath string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			if isYAMLFile(filePath) {
				files = append(files, filePath)
			}
			return nil
		})
		if err != nil {
			return nil, stats, fmt.Errorf("walk rule directory: %w", err)
		}
	} else {
		if !isYAMLFile(resolved) {
			return nil, stats, fmt.Errorf("rule file must end with .yml or .yaml: %s", resolved)
		}
		files = append(files, resolved)
	}

	stats.TotalFiles = len(files)
	compiled := make([]compiledSigmaRule, 0, len(files))
	for _, ruleFile := range files {
		rule, err := parseSigmaRuleFile(ruleFile)
		if err != nil {
			stats.SkippedInvalid++
			continue
		}

		if !isSysmonCompatible(rule) {
			stats.SkippedDatasource++
			continue
		}

		if ok, _ := isSimpleSingleEventRule(rule); !ok {
			stats.SkippedComplex++
			continue
		}

		compiled = append(compiled, compiledSigmaRule{
			rule:     rule,
			eval:     sigmaevaluator.ForRule(rule),
			label:    ioaTagFromRule(rule),
			eventIDs: inferSysmonEventIDs(rule, ruleFile),
		})
		stats.Loaded++
	}

	return &SigmaEngine{rules: compiled, ctx: context.Background()}, stats, nil
}

// Apply evaluates all loaded Sigma rules and returns IOA tags for matched rules.
func (e *SigmaEngine) Apply(event *models.Event) []models.IoaTag {
	if e == nil || event == nil || len(e.rules) == 0 {
		return nil
	}

	eventMap := sigmaEventFrom(event)
	out := make([]models.IoaTag, 0, 4)
	for _, rule := range e.rules {
		if len(rule.eventIDs) > 0 {
			if _, ok := rule.eventIDs[event.EventID]; !ok {
				continue
			}
		}
		res, err := rule.eval.Matches(e.ctx, eventMap)
		if err != nil {
			continue
		}
		if res.Match {
			out = append(out, rule.label)
		}
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

func parseSigmaRuleFile(path string) (sigma.Rule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return sigma.Rule{}, fmt.Errorf("read sigma rule %s: %w", path, err)
	}
	rule, err := sigma.ParseRule(raw)
	if err != nil {
		return sigma.Rule{}, fmt.Errorf("parse sigma rule %s: %w", path, err)
	}
	return rule, nil
}

func isYAMLFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
}

func isSysmonCompatible(rule sigma.Rule) bool {
	product := strings.ToLower(strings.TrimSpace(rule.Logsource.Product))
	service := strings.ToLower(strings.TrimSpace(rule.Logsource.Service))

	if product != "" && product != "windows" {
		return false
	}
	if service != "" && service != "sysmon" {
		return false
	}
	return true
}

func isSimpleSingleEventRule(rule sigma.Rule) (bool, string) {
	if rule.Detection.Timeframe > 0 {
		return false, "timeframe is not supported"
	}

	for _, cond := range rule.Detection.Conditions {
		if cond.Aggregation != nil {
			return false, "aggregation condition is not supported"
		}
		if !isSimpleSearchExpression(cond.Search) {
			return false, "complex condition expression is not supported"
		}
	}

	for _, search := range rule.Detection.Searches {
		if len(search.Keywords) > 0 {
			return false, "keyword search is not supported"
		}
		if len(search.EventMatchers) == 0 {
			return false, "search has no event matchers"
		}
	}

	return true, ""
}

func isSimpleSearchExpression(expr sigma.SearchExpr) bool {
	switch e := expr.(type) {
	case sigma.SearchIdentifier:
		return true
	case sigma.And:
		for _, child := range e {
			if !isSimpleSearchExpression(child) {
				return false
			}
		}
		return true
	case sigma.Or:
		for _, child := range e {
			if !isSimpleSearchExpression(child) {
				return false
			}
		}
		return true
	case sigma.Not:
		return isSimpleSearchExpression(e.Expr)
	default:
		return false
	}
}

func sigmaEventFrom(event *models.Event) map[string]interface{} {
	buf := make(map[string]interface{}, len(event.Fields)+8)
	for k, v := range event.Fields {
		buf[k] = v
	}
	buf["EventID"] = event.EventID
	buf["event_id"] = event.EventID
	if event.RecordID != "" {
		buf["RecordID"] = event.RecordID
	}
	if event.Channel != "" {
		buf["Channel"] = event.Channel
	}
	if event.Hostname != "" {
		buf["Computer"] = event.Hostname
		buf["Hostname"] = event.Hostname
	}
	if event.AgentID != "" {
		buf["AgentID"] = event.AgentID
	}
	return buf
}

func ioaTagFromRule(rule sigma.Rule) models.IoaTag {
	id := strings.TrimSpace(rule.ID)
	if id == "" {
		id = strings.TrimSpace(rule.Title)
	}

	level := strings.ToLower(strings.TrimSpace(rule.Level))
	if level == "" {
		level = "medium"
	}

	tactic, technique := parseAttackTags(rule.Tags)
	return models.IoaTag{
		ID:        id,
		Name:      strings.TrimSpace(rule.Title),
		Severity:  level,
		Tactic:    tactic,
		Technique: technique,
	}
}

func parseAttackTags(tags []string) (string, string) {
	var tactic string
	var technique string

	for _, raw := range tags {
		tag := strings.ToLower(strings.TrimSpace(raw))
		if !strings.HasPrefix(tag, "attack.") {
			continue
		}
		suffix := strings.TrimPrefix(tag, "attack.")
		if technique == "" && techniqueTagRegex.MatchString(tag) {
			technique = strings.ToUpper(strings.ReplaceAll(suffix, ".", "/"))
			continue
		}
		if tactic == "" && !strings.HasPrefix(suffix, "t") {
			tactic = strings.ReplaceAll(suffix, "_", "-")
		}
	}

	return tactic, technique
}

func inferSysmonEventIDs(rule sigma.Rule, ruleFile string) map[int]struct{} {
	category := strings.ToLower(strings.TrimSpace(rule.Logsource.Category))
	if category != "" {
		if ids := categoryToSysmonEventIDs(category); len(ids) > 0 {
			return ids
		}
	}

	// Fall back to path-based inference for repositories that organize rules by
	// category directories (for example windows/image_load/... ).
	lowerPath := strings.ToLower(filepath.ToSlash(ruleFile))
	for key := range sysmonCategoryEventMap {
		needle := "/" + key + "/"
		if strings.Contains(lowerPath, needle) {
			if ids := categoryToSysmonEventIDs(key); len(ids) > 0 {
				return ids
			}
		}
	}

	return nil
}

var sysmonCategoryEventMap = map[string][]int{
	"process_creation":     {1},
	"network_connection":   {3},
	"driver_load":          {6},
	"image_load":           {7},
	"create_remote_thread": {8},
	"process_access":       {10},
	"file_create":          {11},
	"file_event":           {11},
	"file":                 {11},
	"dns_query":            {22},
}

func categoryToSysmonEventIDs(category string) map[int]struct{} {
	vals, ok := sysmonCategoryEventMap[strings.ToLower(strings.TrimSpace(category))]
	if !ok || len(vals) == 0 {
		return nil
	}
	out := make(map[int]struct{}, len(vals))
	for _, v := range vals {
		out[v] = struct{}{}
	}
	return out
}
