package analyzer

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// RuleSet defines sequence detection rules for staged analysis.
type RuleSet struct {
	Version  int          `yaml:"version"`
	Defaults RuleDefaults `yaml:"defaults"`
	Rules    []Rule       `yaml:"rules"`
}

// RuleDefaults are fallback options for rules.
type RuleDefaults struct {
	Window        time.Duration `yaml:"window"`
	MaxDepth      int           `yaml:"max_depth"`
	MaxCandidates int           `yaml:"max_candidates"`
}

// Rule defines one ordered IOA name sequence.
type Rule struct {
	ID            string        `yaml:"id"`
	Enabled       bool          `yaml:"enabled"`
	Sequence      []string      `yaml:"sequence"`
	Window        time.Duration `yaml:"window"`
	MaxDepth      int           `yaml:"max_depth"`
	MaxCandidates int           `yaml:"max_candidates"`
}

// LoadRuleSet reads sequence rules from a YAML file.
func LoadRuleSet(path string) (*RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rule file: %w", err)
	}
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("parse rule file: %w", err)
	}
	if rs.Defaults.Window <= 0 {
		rs.Defaults.Window = 10 * time.Minute
	}
	if rs.Defaults.MaxDepth <= 0 {
		rs.Defaults.MaxDepth = 64
	}
	if rs.Defaults.MaxCandidates <= 0 {
		rs.Defaults.MaxCandidates = 2000
	}
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if r.ID == "" {
			r.ID = fmt.Sprintf("rule-%d", i+1)
		}
		if r.Window <= 0 {
			if r.Window == 0 {
				r.Window = rs.Defaults.Window
			}
		}
		if r.MaxDepth <= 0 {
			r.MaxDepth = rs.Defaults.MaxDepth
		}
		if r.MaxCandidates <= 0 {
			r.MaxCandidates = rs.Defaults.MaxCandidates
		}
		if len(r.Sequence) > 0 {
			clean := make([]string, 0, len(r.Sequence))
			for _, s := range r.Sequence {
				s = strings.TrimSpace(s)
				if s != "" {
					clean = append(clean, s)
				}
			}
			r.Sequence = clean
		}
	}
	return &rs, nil
}
