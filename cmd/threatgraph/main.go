package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"threatgraph/config"
	"threatgraph/internal/alerts"
	"threatgraph/internal/analyzer"
	"threatgraph/internal/graph/adjacency"
	inputredis "threatgraph/internal/input/redis"
	"threatgraph/internal/logger"
	"threatgraph/internal/output/adjacencyhttp"
	"threatgraph/internal/output/adjacencyjson"
	"threatgraph/internal/output/alerthttp"
	"threatgraph/internal/output/alertjson"
	"threatgraph/internal/output/ioaclickhouse"
	"threatgraph/internal/output/ioajson"
	"threatgraph/internal/pipeline"
	"threatgraph/internal/rules"
)

func findConfigFile(configArg string) string {
	if configArg != "" {
		path := configArg
		if _, err := os.Stat(path); err == nil {
			return path
		}
		log.Printf("Warning: config file not found at %s, trying default locations", path)
	}

	if _, err := os.Stat("threatgraph.yml"); err == nil {
		return "threatgraph.yml"
	}

	exePath, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exePath)
		path := filepath.Join(exeDir, "threatgraph.yml")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return "threatgraph.yml"
}

func applyDefaults(cfg *config.Config) {
	if cfg.ThreatGraph.Input.Redis.Addr == "" {
		cfg.ThreatGraph.Input.Redis.Addr = "127.0.0.1:6379"
	}
	if cfg.ThreatGraph.Input.Redis.Key == "" {
		cfg.ThreatGraph.Input.Redis.Key = "sysmon_events"
	}
	if cfg.ThreatGraph.Input.Redis.BlockTimeout == 0 {
		cfg.ThreatGraph.Input.Redis.BlockTimeout = 5 * time.Second
	}

	if cfg.ThreatGraph.Pipeline.Workers <= 0 {
		cfg.ThreatGraph.Pipeline.Workers = 8
	}
	if cfg.ThreatGraph.Pipeline.BatchSize <= 0 {
		cfg.ThreatGraph.Pipeline.BatchSize = 1000
	}
	if cfg.ThreatGraph.Pipeline.FlushInterval <= 0 {
		cfg.ThreatGraph.Pipeline.FlushInterval = 2 * time.Second
	}

	if cfg.ThreatGraph.Alerts.Window <= 0 {
		cfg.ThreatGraph.Alerts.Window = 5 * time.Minute
	}
	if cfg.ThreatGraph.Alerts.Threshold <= 0 {
		cfg.ThreatGraph.Alerts.Threshold = 8
	}
	if cfg.ThreatGraph.Alerts.MaxRows <= 0 {
		cfg.ThreatGraph.Alerts.MaxRows = 50
	}
	if cfg.ThreatGraph.Alerts.Cooldown <= 0 {
		cfg.ThreatGraph.Alerts.Cooldown = 2 * time.Minute
	}
	if cfg.ThreatGraph.Alerts.Output.Mode == "" {
		cfg.ThreatGraph.Alerts.Output.Mode = "file"
	}
	if cfg.ThreatGraph.Alerts.Output.File.Path == "" {
		cfg.ThreatGraph.Alerts.Output.File.Path = "output/alerts.jsonl"
	}

	if cfg.ThreatGraph.Output.Mode == "" {
		cfg.ThreatGraph.Output.Mode = "file"
	}
	if cfg.ThreatGraph.Output.File.Path == "" {
		cfg.ThreatGraph.Output.File.Path = "output/adjacency.jsonl"
	}

	if cfg.ThreatGraph.IOA.Output.Mode == "" {
		cfg.ThreatGraph.IOA.Output.Mode = "file"
	}
	if cfg.ThreatGraph.IOA.Output.File.Path == "" {
		cfg.ThreatGraph.IOA.Output.File.Path = "output/ioa_events.jsonl"
	}
	if cfg.ThreatGraph.IOA.Output.ClickHouse.Database == "" {
		cfg.ThreatGraph.IOA.Output.ClickHouse.Database = "threatgraph"
	}
	if cfg.ThreatGraph.IOA.Output.ClickHouse.Table == "" {
		cfg.ThreatGraph.IOA.Output.ClickHouse.Table = "ioa_events"
	}

	if cfg.ThreatGraph.Logging.Level == "" {
		cfg.ThreatGraph.Logging.Level = "info"
	}
}

func runProducer(args []string) {
	configArg := ""
	if len(args) > 0 {
		configArg = args[0]
	}

	configPath := findConfigFile(configArg)

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	applyDefaults(cfg)

	if err := logger.Init(cfg.ThreatGraph.Logging.Enabled, cfg.ThreatGraph.Logging.Level, cfg.ThreatGraph.Logging.File, cfg.ThreatGraph.Logging.Console); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	logger.Infof("ThreatGraph starting")
	logger.Infof("Config loaded from: %s", configPath)

	consumer, err := inputredis.NewConsumer(inputredis.Config{
		Addr:         cfg.ThreatGraph.Input.Redis.Addr,
		Password:     cfg.ThreatGraph.Input.Redis.Password,
		DB:           cfg.ThreatGraph.Input.Redis.DB,
		Key:          cfg.ThreatGraph.Input.Redis.Key,
		BlockTimeout: cfg.ThreatGraph.Input.Redis.BlockTimeout,
	})
	if err != nil {
		logger.Errorf("Failed to create Redis consumer: %v", err)
		log.Fatalf("Failed to create Redis consumer: %v", err)
	}

	mapper := adjacency.NewMapper()
	var engine rules.Engine
	if cfg.ThreatGraph.Rules.Enabled {
		if strings.TrimSpace(cfg.ThreatGraph.Rules.Path) == "" {
			logger.Warnf("Rules enabled but rules.path is empty; IOA tagging disabled")
		} else {
			sigmaEngine, stats, err := rules.NewSigmaEngine(cfg.ThreatGraph.Rules.Path)
			if err != nil {
				logger.Errorf("Failed to load Sigma rules from %s: %v", cfg.ThreatGraph.Rules.Path, err)
				log.Fatalf("Failed to load Sigma rules: %v", err)
			}
			engine = sigmaEngine
			logger.Infof("Sigma rules loaded: loaded=%d skipped_complex=%d skipped_datasource=%d skipped_invalid=%d files=%d",
				stats.Loaded,
				stats.SkippedComplex,
				stats.SkippedDatasource,
				stats.SkippedInvalid,
				stats.TotalFiles,
			)
			if stats.Loaded == 0 {
				logger.Warnf("No compatible Sigma rules loaded; IOA tagging is effectively disabled")
			}
		}
	}

	var scorer *alerts.Scorer
	var alertWriter pipeline.AlertWriter
	if cfg.ThreatGraph.Alerts.Enabled {
		scorer = alerts.NewScorer(alerts.Config{
			Window:    cfg.ThreatGraph.Alerts.Window,
			Threshold: cfg.ThreatGraph.Alerts.Threshold,
			MaxRows:   cfg.ThreatGraph.Alerts.MaxRows,
			Cooldown:  cfg.ThreatGraph.Alerts.Cooldown,
		})
		switch cfg.ThreatGraph.Alerts.Output.Mode {
		case "file":
			w, err := alertjson.NewWriter(cfg.ThreatGraph.Alerts.Output.File.Path)
			if err != nil {
				logger.Errorf("Failed to create alert file writer: %v", err)
				log.Fatalf("Failed to create alert file writer: %v", err)
			}
			alertWriter = w
			logger.Infof("Alert output mode: file (%s)", cfg.ThreatGraph.Alerts.Output.File.Path)
		case "http":
			w, err := alerthttp.NewWriter(alerthttp.Config{
				URL:     cfg.ThreatGraph.Alerts.Output.HTTP.URL,
				Timeout: cfg.ThreatGraph.Alerts.Output.HTTP.Timeout,
				Headers: cfg.ThreatGraph.Alerts.Output.HTTP.Headers,
			})
			if err != nil {
				logger.Errorf("Failed to create alert HTTP writer: %v", err)
				log.Fatalf("Failed to create alert HTTP writer: %v", err)
			}
			alertWriter = w
			logger.Infof("Alert output mode: http (%s)", cfg.ThreatGraph.Alerts.Output.HTTP.URL)
		default:
			log.Fatalf("Unknown alert output mode: %s", cfg.ThreatGraph.Alerts.Output.Mode)
		}
	}

	var adjWriter pipeline.AdjacencyWriter
	switch cfg.ThreatGraph.Output.Mode {
	case "file":
		w, err := adjacencyjson.NewWriter(cfg.ThreatGraph.Output.File.Path)
		if err != nil {
			logger.Errorf("Failed to create adjacency file writer: %v", err)
			log.Fatalf("Failed to create adjacency file writer: %v", err)
		}
		adjWriter = w
		logger.Infof("Output mode: file (%s)", cfg.ThreatGraph.Output.File.Path)
	case "http":
		w, err := adjacencyhttp.NewWriter(adjacencyhttp.Config{
			URL:     cfg.ThreatGraph.Output.HTTP.URL,
			Timeout: cfg.ThreatGraph.Output.HTTP.Timeout,
			Headers: cfg.ThreatGraph.Output.HTTP.Headers,
		})
		if err != nil {
			logger.Errorf("Failed to create adjacency HTTP writer: %v", err)
			log.Fatalf("Failed to create adjacency HTTP writer: %v", err)
		}
		adjWriter = w
		logger.Infof("Output mode: http (%s)", cfg.ThreatGraph.Output.HTTP.URL)
	default:
		log.Fatalf("Unknown output mode: %s", cfg.ThreatGraph.Output.Mode)
	}

	var ioaWriter pipeline.IOAWriter
	if cfg.ThreatGraph.IOA.Enabled {
		switch cfg.ThreatGraph.IOA.Output.Mode {
		case "file":
			w, err := ioajson.NewWriter(cfg.ThreatGraph.IOA.Output.File.Path)
			if err != nil {
				logger.Errorf("Failed to create IOA file writer: %v", err)
				log.Fatalf("Failed to create IOA file writer: %v", err)
			}
			ioaWriter = w
			logger.Infof("IOA output mode: file (%s)", cfg.ThreatGraph.IOA.Output.File.Path)
		case "clickhouse":
			w, err := ioaclickhouse.NewWriter(ioaclickhouse.Config{
				URL:      cfg.ThreatGraph.IOA.Output.ClickHouse.URL,
				Database: cfg.ThreatGraph.IOA.Output.ClickHouse.Database,
				Table:    cfg.ThreatGraph.IOA.Output.ClickHouse.Table,
				Username: cfg.ThreatGraph.IOA.Output.ClickHouse.Username,
				Password: cfg.ThreatGraph.IOA.Output.ClickHouse.Password,
				Timeout:  cfg.ThreatGraph.IOA.Output.ClickHouse.Timeout,
				Headers:  cfg.ThreatGraph.IOA.Output.ClickHouse.Headers,
			})
			if err != nil {
				logger.Errorf("Failed to create IOA ClickHouse writer: %v", err)
				log.Fatalf("Failed to create IOA ClickHouse writer: %v", err)
			}
			ioaWriter = w
			logger.Infof("IOA output mode: clickhouse (%s/%s.%s)", cfg.ThreatGraph.IOA.Output.ClickHouse.URL, cfg.ThreatGraph.IOA.Output.ClickHouse.Database, cfg.ThreatGraph.IOA.Output.ClickHouse.Table)
		default:
			log.Fatalf("Unknown IOA output mode: %s", cfg.ThreatGraph.IOA.Output.Mode)
		}
	}

	pipe := pipeline.NewRedisAdjacencyPipeline(
		consumer,
		engine,
		mapper,
		adjWriter,
		ioaWriter,
		scorer,
		alertWriter,
		cfg.ThreatGraph.Pipeline.Workers,
		cfg.ThreatGraph.Pipeline.BatchSize,
		cfg.ThreatGraph.Pipeline.FlushInterval,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := pipe.Run(ctx); err != nil && err != context.Canceled {
			logger.Errorf("Pipeline error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Infof("Shutting down")
	cancel()
	time.Sleep(1 * time.Second)

	if err := pipe.Close(); err != nil {
		logger.Errorf("Error closing pipeline: %v", err)
	}

	logger.Infof("ThreatGraph stopped")
}

func runAnalyzer(args []string) int {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	input := fs.String("input", "output/adjacency.jsonl", "Adjacency JSONL input path")
	output := fs.String("output", "output/ioa_findings.jsonl", "Findings JSONL output path")
	candidatesOutput := fs.String("candidates-output", "", "Optional stage-1 candidate JSONL output path")
	rulesFile := fs.String("rules-file", "", "YAML file that defines sequence rules")
	maxDepth := fs.Int("max-depth", 64, "Maximum traversal depth from each root")
	maxFindings := fs.Int("max-findings", 10000, "Maximum number of findings to emit")
	nameSeq := fs.String("name-seq", "", "Comma-separated edge name sequence (for example: stepA,stepB,stepC)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	rows, err := analyzer.LoadRowsJSONL(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load adjacency rows: %v\n", err)
		return 1
	}

	cfg := analyzer.Config{MaxDepth: *maxDepth, MaxFindings: *maxFindings}
	if strings.TrimSpace(*rulesFile) != "" {
		rs, err := analyzer.LoadRuleSet(*rulesFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load rules file: %v\n", err)
			return 1
		}
		candidates, findings := analyzer.AnalyzeRuleSet(rows, rs, cfg)
		if strings.TrimSpace(*candidatesOutput) != "" {
			if err := writeJSONLines(*candidatesOutput, candidates); err != nil {
				fmt.Fprintf(os.Stderr, "failed to write candidates: %v\n", err)
				return 1
			}
		}
		if err := writeJSONLines(*output, findings); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write findings: %v\n", err)
			return 1
		}
		fmt.Printf("analyzed rows=%d candidates=%d findings=%d output=%s\n", len(rows), len(candidates), len(findings), *output)
		return 0
	}

	var findings []analyzer.Finding
	if strings.TrimSpace(*nameSeq) != "" {
		findings = analyzer.DetectNamedSequencePaths(rows, parseNameSequence(*nameSeq), cfg)
	} else {
		findings = analyzer.DetectRemoteThreadPaths(rows, cfg)
	}

	if err := writeJSONLines(*output, findings); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write findings: %v\n", err)
		return 1
	}

	fmt.Printf("analyzed rows=%d findings=%d output=%s\n", len(rows), len(findings), *output)
	return 0
}

func writeJSONLines[T any](path string, rows []T) error {
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
	for _, item := range rows {
		if err := enc.Encode(item); err != nil {
			return fmt.Errorf("encode row: %w", err)
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

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "produce":
			runProducer(os.Args[2:])
			return
		case "analyze":
			os.Exit(runAnalyzer(os.Args[2:]))
		default:
			// Backward-compatible mode: first arg is config path.
			runProducer(os.Args[1:])
			return
		}
	}

	runProducer(nil)
}
