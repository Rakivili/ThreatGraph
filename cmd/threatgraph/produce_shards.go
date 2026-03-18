package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"threatgraph/config"
	"threatgraph/internal/logger"
)

func runTimeShardedProducer(configPath string, cfg *config.Config) error {
	start, end, err := extractQueryWindow(cfg.ThreatGraph.Input.Elasticsearch.Query)
	if err != nil {
		return err
	}
	shards := cfg.ThreatGraph.Input.Elasticsearch.TimeShards
	minutes := cfg.ThreatGraph.Input.Elasticsearch.TimeShardMinutes
	if shards <= 1 && minutes <= 0 {
		return nil
	}
	windows := splitWindows(start, end, shards, minutes)
	if len(windows) <= 1 {
		return nil
	}
	workers := cfg.ThreatGraph.Input.Elasticsearch.TimeShardWorkers
	if workers <= 0 {
		workers = 4
	}
	if workers > len(windows) {
		workers = len(windows)
	}
	runID := time.Now().Format("20060102_150405")
	genDir := filepath.Join(filepath.Dir(configPath), "output", "produce_time_shards", runID)
	if err := os.MkdirAll(genDir, 0o755); err != nil {
		return fmt.Errorf("mkdir shard dir: %w", err)
	}
	logger.Infof("Time-sharded produce enabled: windows=%d workers=%d range=%s..%s dir=%s", len(windows), workers, start.Format(time.RFC3339), end.Format(time.RFC3339), genDir)
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	paths := make([]string, 0, len(windows))
	for i, window := range windows {
		childCfg, err := cloneConfig(cfg)
		if err != nil {
			return err
		}
		childCfg.ThreatGraph.Input.Elasticsearch.TimeShards = 1
		childCfg.ThreatGraph.Input.Elasticsearch.TimeShardMinutes = 0
		childCfg.ThreatGraph.Input.Elasticsearch.TimeShardWorkers = 1
		childCfg.ThreatGraph.Input.Elasticsearch.Slices = 1
		childCfg.ThreatGraph.Input.Elasticsearch.Query, err = setQueryWindow(childCfg.ThreatGraph.Input.Elasticsearch.Query, window.start, window.end)
		if err != nil {
			return err
		}
		suffix := fmt.Sprintf("_part%02d", i)
		childCfg.ThreatGraph.Logging.File = suffixPath(childCfg.ThreatGraph.Logging.File, suffix)
		childCfg.ThreatGraph.Logging.Console = false
		if childCfg.ThreatGraph.Output.Mode == "file" {
			childCfg.ThreatGraph.Output.File.Path = suffixPath(childCfg.ThreatGraph.Output.File.Path, suffix)
		}
		if childCfg.ThreatGraph.IOA.Enabled && childCfg.ThreatGraph.IOA.Output.Mode == "file" {
			childCfg.ThreatGraph.IOA.Output.File.Path = suffixPath(childCfg.ThreatGraph.IOA.Output.File.Path, suffix)
		}
		if childCfg.ThreatGraph.ReplayCapture.Enabled {
			childCfg.ThreatGraph.ReplayCapture.File.Path = suffixPath(childCfg.ThreatGraph.ReplayCapture.File.Path, suffix)
		}
		cfgPath := filepath.Join(genDir, fmt.Sprintf("produce_part%02d.yml", i))
		if err := writeConfig(cfgPath, childCfg); err != nil {
			return err
		}
		paths = append(paths, cfgPath)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jobs := make(chan string)
	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	for workerID := 0; workerID < workers; workerID++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for cfgPath := range jobs {
				logger.Infof("Worker %d starting shard config=%s", id+1, cfgPath)
				cmd := exec.CommandContext(ctx, exePath, "produce", cfgPath)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				cmd.Env = append(os.Environ(), "THREATGRAPH_TIME_SHARD_CHILD=1")
				if err := cmd.Run(); err != nil {
					select {
					case errCh <- fmt.Errorf("worker %d config %s: %w", id+1, cfgPath, err):
					default:
					}
					cancel()
					return
				}
				logger.Infof("Worker %d completed shard config=%s", id+1, cfgPath)
			}
		}(workerID)
	}
dispatchLoop:
	for _, cfgPath := range paths {
		select {
		case <-ctx.Done():
			break dispatchLoop
		case jobs <- cfgPath:
		}
	}
	close(jobs)
	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
	}
	return nil
}

type timeWindow struct {
	start time.Time
	end   time.Time
}

func splitTimeRange(start, end time.Time, shards int) []timeWindow {
	windows := make([]timeWindow, 0, shards)
	total := end.Sub(start)
	step := total / time.Duration(shards)
	cur := start
	for i := 0; i < shards; i++ {
		next := cur.Add(step)
		if i == shards-1 {
			next = end
		}
		windows = append(windows, timeWindow{start: cur, end: next})
		cur = next
	}
	return windows
}

func splitWindows(start, end time.Time, shards, minutes int) []timeWindow {
	if minutes > 0 {
		return splitTimeRangeByMinutes(start, end, minutes)
	}
	return splitTimeRange(start, end, shards)
}

func splitTimeRangeByMinutes(start, end time.Time, minutes int) []timeWindow {
	if minutes <= 0 || !start.Before(end) {
		return nil
	}
	step := time.Duration(minutes) * time.Minute
	windows := make([]timeWindow, 0, int(end.Sub(start)/step)+1)
	cur := start
	for cur.Before(end) {
		next := cur.Add(step)
		if next.After(end) {
			next = end
		}
		windows = append(windows, timeWindow{start: cur, end: next})
		cur = next
	}
	return windows
}

func extractQueryWindow(query string) (time.Time, time.Time, error) {
	var root map[string]any
	if err := json.Unmarshal([]byte(query), &root); err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("parse query json: %w", err)
	}
	queryNode, ok := root["query"].(map[string]any)
	if !ok {
		return time.Time{}, time.Time{}, fmt.Errorf("query missing top-level query object")
	}
	boolNode, ok := queryNode["bool"].(map[string]any)
	if !ok {
		return time.Time{}, time.Time{}, fmt.Errorf("query missing bool object")
	}
	filters, ok := boolNode["filter"].([]any)
	if !ok {
		return time.Time{}, time.Time{}, fmt.Errorf("query missing bool.filter array")
	}
	for _, item := range filters {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		rangeNode, ok := m["range"].(map[string]any)
		if !ok {
			continue
		}
		tsNode, ok := rangeNode["@timestamp"].(map[string]any)
		if !ok {
			continue
		}
		gte, _ := tsNode["gte"].(string)
		lt, _ := tsNode["lt"].(string)
		if gte == "" || lt == "" {
			return time.Time{}, time.Time{}, fmt.Errorf("query timestamp range must use gte and lt")
		}
		start, err := time.Parse(time.RFC3339, gte)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("parse gte: %w", err)
		}
		end, err := time.Parse(time.RFC3339, lt)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("parse lt: %w", err)
		}
		return start, end, nil
	}
	return time.Time{}, time.Time{}, fmt.Errorf("query missing @timestamp range filter")
}

func setQueryWindow(query string, start, end time.Time) (string, error) {
	var root map[string]any
	if err := json.Unmarshal([]byte(query), &root); err != nil {
		return "", fmt.Errorf("parse query json: %w", err)
	}
	queryNode, ok := root["query"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("query missing top-level query object")
	}
	boolNode, ok := queryNode["bool"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("query missing bool object")
	}
	filters, ok := boolNode["filter"].([]any)
	if !ok {
		return "", fmt.Errorf("query missing bool.filter array")
	}
	updated := false
	for _, item := range filters {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		rangeNode, ok := m["range"].(map[string]any)
		if !ok {
			continue
		}
		tsNode, ok := rangeNode["@timestamp"].(map[string]any)
		if !ok {
			continue
		}
		tsNode["gte"] = start.UTC().Format(time.RFC3339)
		tsNode["lt"] = end.UTC().Format(time.RFC3339)
		updated = true
		break
	}
	if !updated {
		return "", fmt.Errorf("query missing @timestamp range filter")
	}
	b, err := json.Marshal(root)
	if err != nil {
		return "", fmt.Errorf("marshal query json: %w", err)
	}
	return string(b), nil
}

func cloneConfig(cfg *config.Config) (*config.Config, error) {
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal config clone: %w", err)
	}
	var out config.Config
	if err := yaml.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("unmarshal config clone: %w", err)
	}
	return &out, nil
}

func writeConfig(path string, cfg *config.Config) error {
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func suffixPath(path, suffix string) string {
	if path == "" {
		return path
	}
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	return base + suffix + ext
}
