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
	"threatgraph/internal/analyzer"
	"threatgraph/internal/graph/adjacency"
	inputredis "threatgraph/internal/input/redis"
	"threatgraph/internal/logger"
	"threatgraph/internal/output/adjacencyhttp"
	"threatgraph/internal/output/adjacencyjson"
	"threatgraph/internal/output/ioaclickhouse"
	"threatgraph/internal/output/ioajson"
	"threatgraph/internal/output/rawjson"
	"threatgraph/internal/pipeline"
	"threatgraph/internal/rules"
	"threatgraph/internal/vertexstate"
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

	if cfg.ThreatGraph.ReplayCapture.File.Path == "" {
		cfg.ThreatGraph.ReplayCapture.File.Path = "output/raw_events.jsonl"
	}
	if cfg.ThreatGraph.ReplayCapture.BatchSize <= 0 {
		cfg.ThreatGraph.ReplayCapture.BatchSize = cfg.ThreatGraph.Pipeline.BatchSize
	}
	if cfg.ThreatGraph.ReplayCapture.FlushInterval <= 0 {
		cfg.ThreatGraph.ReplayCapture.FlushInterval = cfg.ThreatGraph.Pipeline.FlushInterval
	}

	if cfg.ThreatGraph.VertexState.Redis.Addr == "" {
		cfg.ThreatGraph.VertexState.Redis.Addr = cfg.ThreatGraph.Input.Redis.Addr
	}
	if cfg.ThreatGraph.VertexState.KeyPrefix == "" {
		cfg.ThreatGraph.VertexState.KeyPrefix = "threatgraph:vertex_state"
	}
	if cfg.ThreatGraph.VertexState.ScanInterval <= 0 {
		cfg.ThreatGraph.VertexState.ScanInterval = 30 * time.Second
	}
	if cfg.ThreatGraph.VertexState.Lookback <= 0 {
		cfg.ThreatGraph.VertexState.Lookback = 5 * time.Minute
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

	var rawWriter pipeline.RawWriter
	if cfg.ThreatGraph.ReplayCapture.Enabled {
		w, err := rawjson.NewWriter(cfg.ThreatGraph.ReplayCapture.File.Path)
		if err != nil {
			logger.Errorf("Failed to create raw replay writer: %v", err)
			log.Fatalf("Failed to create raw replay writer: %v", err)
		}
		rawWriter = w
		logger.Infof("Raw replay capture enabled: %s", cfg.ThreatGraph.ReplayCapture.File.Path)
	}

	var stateWriter pipeline.VertexStateWriter
	if cfg.ThreatGraph.VertexState.Enabled {
		store, err := vertexstate.NewRedisStore(vertexstate.RedisConfig{
			Addr:      cfg.ThreatGraph.VertexState.Redis.Addr,
			Password:  cfg.ThreatGraph.VertexState.Redis.Password,
			DB:        cfg.ThreatGraph.VertexState.Redis.DB,
			KeyPrefix: cfg.ThreatGraph.VertexState.KeyPrefix,
		})
		if err != nil {
			logger.Errorf("Failed to create vertex-state Redis store: %v", err)
			log.Fatalf("Failed to create vertex-state Redis store: %v", err)
		}
		stateWriter = store
		logger.Infof("Vertex-state index enabled: redis=%s prefix=%s", cfg.ThreatGraph.VertexState.Redis.Addr, cfg.ThreatGraph.VertexState.KeyPrefix)
	}

	pipe := pipeline.NewRedisAdjacencyPipeline(
		consumer,
		engine,
		mapper,
		adjWriter,
		ioaWriter,
		rawWriter,
		stateWriter,
		cfg.ThreatGraph.Pipeline.Workers,
		cfg.ThreatGraph.Pipeline.BatchSize,
		cfg.ThreatGraph.Pipeline.FlushInterval,
		cfg.ThreatGraph.ReplayCapture.BatchSize,
		cfg.ThreatGraph.ReplayCapture.FlushInterval,
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
	output := fs.String("output", "output/iip_graphs.jsonl", "IIP graph JSONL output path")
	tacticalOutput := fs.String("tactical-output", "", "Optional tactical scored TPG JSONL output path")
	incidentOutput := fs.String("incident-output", "", "Optional incident JSONL output path")
	incidentMinSeq := fs.Int("incident-min-seq", 2, "Minimum sequence length for incident output")
	stateMode := fs.Bool("state-mode", false, "Run periodic analysis using Redis vertex-state candidates")
	stateRedisAddr := fs.String("state-redis-addr", "127.0.0.1:6379", "Redis address for vertex-state mode")
	stateRedisPassword := fs.String("state-redis-password", "", "Redis password for vertex-state mode")
	stateRedisDB := fs.Int("state-redis-db", 0, "Redis DB for vertex-state mode")
	stateKeyPrefix := fs.String("state-key-prefix", "threatgraph:vertex_state", "Redis key prefix for vertex-state mode")
	pollInterval := fs.Duration("poll-interval", 30*time.Second, "Polling interval for --state-mode")
	lookback := fs.Duration("lookback", 5*time.Minute, "Lookback window for --state-mode")
	once := fs.Bool("once", false, "Run a single polling cycle in --state-mode")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*tacticalOutput) == "" && strings.TrimSpace(*incidentOutput) == "" {
		fmt.Fprintf(os.Stderr, "analyze requires at least one of --tactical-output or --incident-output\n")
		return 2
	}

	if *stateMode {
		store, err := vertexstate.NewRedisStore(vertexstate.RedisConfig{
			Addr:      *stateRedisAddr,
			Password:  *stateRedisPassword,
			DB:        *stateRedisDB,
			KeyPrefix: *stateKeyPrefix,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to connect vertex-state redis: %v\n", err)
			return 1
		}
		defer store.Close()

		nextSince := time.Now().UTC().Add(-*lookback)
		for {
			pollStart := time.Now().UTC()
			states, err := store.FetchDirtySince(nextSince, 5000)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to fetch vertex-state updates: %v\n", err)
				return 1
			}
			candidates := vertexstate.BuildIIPCandidates(states)

			hosts := make(map[string]struct{}, len(candidates))
			sinceTS := pollStart.Add(-*lookback)
			for _, c := range candidates {
				hosts[c.Host] = struct{}{}
				if !c.FirstIOATimestamp.IsZero() && c.FirstIOATimestamp.Before(sinceTS) {
					sinceTS = c.FirstIOATimestamp
				}
			}

			if len(hosts) > 0 {
				rows, err := analyzer.LoadRowsJSONL(*input)
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to load adjacency rows in state-mode: %v\n", err)
					return 1
				}
				filteredRows := analyzer.FilterRowsByHostAndTime(rows, hosts, sinceTS)
				iips := analyzer.BuildIIPGraphs(filteredRows)
				scored := analyzer.BuildScoredTPGs(iips)

				if err := writeJSONLines(*output, iips); err != nil {
					fmt.Fprintf(os.Stderr, "failed to write iip output in state-mode: %v\n", err)
					return 1
				}
				if strings.TrimSpace(*tacticalOutput) != "" {
					if err := writeJSONLines(*tacticalOutput, scored); err != nil {
						fmt.Fprintf(os.Stderr, "failed to write tactical output in state-mode: %v\n", err)
						return 1
					}
				}
				if strings.TrimSpace(*incidentOutput) != "" {
					incidents := analyzer.BuildIncidents(scored, *incidentMinSeq)
					if err := writeJSONLines(*incidentOutput, incidents); err != nil {
						fmt.Fprintf(os.Stderr, "failed to write incidents in state-mode: %v\n", err)
						return 1
					}
				}
			}

			fmt.Printf("state-mode vertices=%d iip_candidates=%d iip_output=%s since=%s\n", len(states), len(candidates), *output, nextSince.Format(time.RFC3339))

			nextSince = pollStart
			if *once {
				return 0
			}
			time.Sleep(*pollInterval)
		}
	}

	rows, err := analyzer.LoadRowsJSONL(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load adjacency rows: %v\n", err)
		return 1
	}
	iips := analyzer.BuildIIPGraphs(rows)
	scored := analyzer.BuildScoredTPGs(iips)

	if err := writeJSONLines(*output, iips); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write iip output: %v\n", err)
		return 1
	}
	if strings.TrimSpace(*tacticalOutput) != "" {
		if err := writeJSONLines(*tacticalOutput, scored); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write tactical output: %v\n", err)
			return 1
		}
	}
	if strings.TrimSpace(*incidentOutput) != "" {
		incidents := analyzer.BuildIncidents(scored, *incidentMinSeq)
		if err := writeJSONLines(*incidentOutput, incidents); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write incidents: %v\n", err)
			return 1
		}
		fmt.Printf("analyzed rows=%d iips=%d incidents=%d iip_output=%s\n", len(rows), len(iips), len(incidents), *output)
		return 0
	}

	fmt.Printf("analyzed rows=%d iips=%d iip_output=%s\n", len(rows), len(iips), *output)
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
