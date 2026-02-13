package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"threatgraph/internal/analyzer"
)

func main() {
	input := flag.String("input", "output/adjacency.jsonl", "Adjacency JSONL input path")
	output := flag.String("output", "output/ioa_findings.jsonl", "Findings JSONL output path")
	maxDepth := flag.Int("max-depth", 64, "Maximum traversal depth from each root")
	maxFindings := flag.Int("max-findings", 10000, "Maximum number of findings to emit")
	nameSeq := flag.String("name-seq", "", "Comma-separated edge name sequence (for example: stepA,stepB,stepC)")
	flag.Parse()

	rows, err := analyzer.LoadRowsJSONL(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load adjacency rows: %v\n", err)
		os.Exit(1)
	}

	cfg := analyzer.Config{MaxDepth: *maxDepth, MaxFindings: *maxFindings}
	var findings []analyzer.Finding
	if strings.TrimSpace(*nameSeq) != "" {
		findings = analyzer.DetectNamedSequencePaths(rows, parseNameSequence(*nameSeq), cfg)
	} else {
		findings = analyzer.DetectRemoteThreadPaths(rows, cfg)
	}

	if err := writeFindings(*output, findings); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write findings: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("analyzed rows=%d findings=%d output=%s\n", len(rows), len(findings), *output)
}

func writeFindings(path string, findings []analyzer.Finding) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, item := range findings {
		if err := enc.Encode(item); err != nil {
			return fmt.Errorf("encode finding: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush output: %w", err)
	}
	return nil
}

func parseNameSequence(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
