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
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"threatgraph/config"
	"threatgraph/internal/analyzer"
	"threatgraph/internal/graph/adjacency"
	inputclickhouse "threatgraph/internal/input/clickhouse"
	inputelasticsearch "threatgraph/internal/input/elasticsearch"
	inputredis "threatgraph/internal/input/redis"
	"threatgraph/internal/logger"
	"threatgraph/internal/metrics"
	"threatgraph/internal/output/adjacencyclickhouse"
	"threatgraph/internal/output/adjacencyhttp"
	"threatgraph/internal/output/adjacencyjson"
	"threatgraph/internal/output/ioaclickhouse"
	"threatgraph/internal/output/ioajson"
	"threatgraph/internal/output/rawjson"
	"threatgraph/internal/pipeline"
	"threatgraph/internal/transform/sysmon"
	"threatgraph/pkg/models"
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
	if cfg.ThreatGraph.Input.Mode == "" {
		cfg.ThreatGraph.Input.Mode = "redis"
	}
	if cfg.ThreatGraph.Input.Redis.Key == "" {
		cfg.ThreatGraph.Input.Redis.Key = "sysmon_events"
	}
	if cfg.ThreatGraph.Input.Redis.BlockTimeout == 0 {
		cfg.ThreatGraph.Input.Redis.BlockTimeout = 5 * time.Second
	}
	if cfg.ThreatGraph.Input.Elasticsearch.BatchSize <= 0 {
		cfg.ThreatGraph.Input.Elasticsearch.BatchSize = 1000
	}
	if cfg.ThreatGraph.Input.Elasticsearch.Scroll <= 0 {
		cfg.ThreatGraph.Input.Elasticsearch.Scroll = 5 * time.Minute
	}
	if cfg.ThreatGraph.Input.Elasticsearch.Timeout <= 0 {
		cfg.ThreatGraph.Input.Elasticsearch.Timeout = 30 * time.Second
	}
	if cfg.ThreatGraph.Input.Elasticsearch.Slices <= 0 {
		cfg.ThreatGraph.Input.Elasticsearch.Slices = 1
	}
	if cfg.ThreatGraph.Input.Elasticsearch.HostBatchSize <= 0 {
		cfg.ThreatGraph.Input.Elasticsearch.HostBatchSize = 50
	}
	if cfg.ThreatGraph.Input.Elasticsearch.HostBatchWorkers <= 0 {
		cfg.ThreatGraph.Input.Elasticsearch.HostBatchWorkers = 4
	}
	if cfg.ThreatGraph.Input.Elasticsearch.TimeShards <= 0 {
		cfg.ThreatGraph.Input.Elasticsearch.TimeShards = 1
	}
	if cfg.ThreatGraph.Input.Elasticsearch.TimeShardWorkers <= 0 {
		cfg.ThreatGraph.Input.Elasticsearch.TimeShardWorkers = 4
	}

	if cfg.ThreatGraph.Pipeline.Workers <= 0 {
		cfg.ThreatGraph.Pipeline.Workers = 8
	}
	if cfg.ThreatGraph.Pipeline.WriteWorkers <= 0 {
		cfg.ThreatGraph.Pipeline.WriteWorkers = 1
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

	if cfg.ThreatGraph.Output.ClickHouse.Database == "" {
		cfg.ThreatGraph.Output.ClickHouse.Database = "threatgraph"
	}
	if cfg.ThreatGraph.Output.ClickHouse.Table == "" {
		cfg.ThreatGraph.Output.ClickHouse.Table = "adjacency"
	}
	if strings.TrimSpace(cfg.ThreatGraph.Output.ClickHouse.Format) == "" {
		cfg.ThreatGraph.Output.ClickHouse.Format = "json_each_row"
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

	if cfg.ThreatGraph.Logging.Level == "" {
		cfg.ThreatGraph.Logging.Level = "info"
	}

	if cfg.ThreatGraph.Metrics.Addr == "" {
		cfg.ThreatGraph.Metrics.Addr = ":9091"
	}
}

func metricsEnabled(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	if cfg.ThreatGraph.Metrics.Enabled == nil {
		return false
	}
	return *cfg.ThreatGraph.Metrics.Enabled
}

func ensureDefaultElasticsearchQuery(cfg *config.Config) error {
	if cfg == nil {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(cfg.ThreatGraph.Input.Mode), "elasticsearch") {
		return nil
	}
	esCfg := &cfg.ThreatGraph.Input.Elasticsearch
	if strings.TrimSpace(esCfg.Query) != "" {
		return nil
	}

	sinceRaw := strings.TrimSpace(esCfg.Since)
	untilRaw := strings.TrimSpace(esCfg.Until)
	if sinceRaw == "" || untilRaw == "" {
		return fmt.Errorf("elasticsearch.query is empty; set input.elasticsearch.query or both input.elasticsearch.since and input.elasticsearch.until")
	}

	since, err := time.Parse(time.RFC3339, sinceRaw)
	if err != nil {
		return fmt.Errorf("invalid input.elasticsearch.since (must be RFC3339): %w", err)
	}
	until, err := time.Parse(time.RFC3339, untilRaw)
	if err != nil {
		return fmt.Errorf("invalid input.elasticsearch.until (must be RFC3339): %w", err)
	}
	if !since.Before(until) {
		return fmt.Errorf("input.elasticsearch.since must be earlier than input.elasticsearch.until")
	}

	query, err := buildDefaultElasticsearchQuery(since.UTC(), until.UTC())
	if err != nil {
		return fmt.Errorf("build default elasticsearch query: %w", err)
	}
	esCfg.Query = query
	return nil
}

func buildDefaultElasticsearchQuery(since, until time.Time) (string, error) {
	query := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []any{
					map[string]any{
						"range": map[string]any{
							"@timestamp": map[string]any{
								"gte": since.Format(time.RFC3339),
								"lt":  until.Format(time.RFC3339),
							},
						},
					},
				},
				"should": []any{
					map[string]any{
						"bool": map[string]any{
							"must": []any{
								map[string]any{"term": map[string]any{"risk_level": "notice"}},
								map[string]any{"term": map[string]any{"operation": "CreateProcess"}},
								map[string]any{"term": map[string]any{"fltrname.keyword": "CommonCreateProcess"}},
							},
						},
					},
					map[string]any{
						"bool": map[string]any{
							"must": []any{
								map[string]any{"term": map[string]any{"risk_level": "notice"}},
								map[string]any{"term": map[string]any{"operation": "WriteComplete"}},
								map[string]any{"term": map[string]any{"fltrname.keyword": "WriteNewFile.ExcuteFile"}},
							},
						},
					},
					map[string]any{
						"bool": map[string]any{
							"must": []any{
								map[string]any{"exists": map[string]any{"field": "risk_level"}},
							},
							"must_not": []any{
								map[string]any{"term": map[string]any{"risk_level": "notice"}},
							},
						},
					},
				},
				"minimum_should_match": 1,
			},
		},
	}

	raw, err := json.Marshal(query)
	if err != nil {
		return "", err
	}
	return string(raw), nil
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
	if err := ensureDefaultElasticsearchQuery(cfg); err != nil {
		log.Fatalf("Failed to prepare elasticsearch query: %v", err)
	}
	sysmon.ResetStats()

	if err := logger.Init(cfg.ThreatGraph.Logging.Enabled, cfg.ThreatGraph.Logging.Level, cfg.ThreatGraph.Logging.File, cfg.ThreatGraph.Logging.Console); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	if metricsEnabled(cfg) {
		metrics.StartServer(cfg.ThreatGraph.Metrics.Addr)
		logger.Infof("Prometheus metrics enabled on %s", cfg.ThreatGraph.Metrics.Addr)
		defer metrics.StopServer()
	}

	if strings.EqualFold(strings.TrimSpace(cfg.ThreatGraph.Input.Mode), "elasticsearch") && cfg.ThreatGraph.Input.Elasticsearch.HostPrefilter {
		if err := runHostPrefilteredProducer(cfg); err != nil {
			logger.Errorf("Failed to run host-prefiltered producer: %v", err)
			log.Fatalf("Failed to run host-prefiltered producer: %v", err)
		}
		return
	}
	if strings.EqualFold(strings.TrimSpace(cfg.ThreatGraph.Input.Mode), "elasticsearch") && (cfg.ThreatGraph.Input.Elasticsearch.TimeShards > 1 || cfg.ThreatGraph.Input.Elasticsearch.TimeShardMinutes > 0) && os.Getenv("THREATGRAPH_TIME_SHARD_CHILD") != "1" {
		if err := runTimeShardedProducer(configPath, cfg); err != nil {
			logger.Errorf("Failed to run time-sharded producer: %v", err)
			log.Fatalf("Failed to run time-sharded producer: %v", err)
		}
		return
	}

	logger.Infof("ThreatGraph starting")
	logger.Infof("Config loaded from: %s", configPath)

	sliceCount := 1
	inputMode := strings.ToLower(strings.TrimSpace(cfg.ThreatGraph.Input.Mode))
	if inputMode == "" {
		inputMode = "redis"
	}
	if inputMode == "elasticsearch" {
		sliceCount = cfg.ThreatGraph.Input.Elasticsearch.Slices
		if sliceCount <= 0 {
			sliceCount = 1
		}
	}
	if sliceCount > 1 {
		if strings.ToLower(strings.TrimSpace(cfg.ThreatGraph.Output.Mode)) != "clickhouse" {
			log.Fatalf("elasticsearch slices > 1 require clickhouse adjacency output")
		}
		if cfg.ThreatGraph.ReplayCapture.Enabled {
			log.Fatalf("elasticsearch slices > 1 do not support replay_capture.enabled")
		}
		if cfg.ThreatGraph.IOA.Enabled && strings.ToLower(strings.TrimSpace(cfg.ThreatGraph.IOA.Output.Mode)) == "file" {
			log.Fatalf("elasticsearch slices > 1 require clickhouse IOA output or ioa.disabled")
		}
	}
	if inputMode == "redis" {
		logger.Infof("Input mode: redis (%s key=%s)", cfg.ThreatGraph.Input.Redis.Addr, cfg.ThreatGraph.Input.Redis.Key)
	} else if sliceCount > 1 {
		logger.Infof("Input mode: elasticsearch (%s index=%s slices=%d)", cfg.ThreatGraph.Input.Elasticsearch.URL, cfg.ThreatGraph.Input.Elasticsearch.Index, sliceCount)
	} else {
		logger.Infof("Input mode: elasticsearch (%s index=%s)", cfg.ThreatGraph.Input.Elasticsearch.URL, cfg.ThreatGraph.Input.Elasticsearch.Index)
	}

	pipes := make([]*pipeline.RedisAdjacencyPipeline, 0, sliceCount)
	for sliceID := 0; sliceID < sliceCount; sliceID++ {
		pipe, err := newProducerPipeline(cfg, sliceID, sliceCount, nil)
		if err != nil {
			logger.Errorf("Failed to create producer slice %d/%d: %v", sliceID+1, sliceCount, err)
			log.Fatalf("Failed to create producer pipeline: %v", err)
		}
		pipes = append(pipes, pipe)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if strings.EqualFold(inputMode, "elasticsearch") && cfg.ThreatGraph.Input.Elasticsearch.RunOnce {
		logger.Infof("Run-once enabled for elasticsearch input")
	}

	var wg sync.WaitGroup
	doneCh := make(chan struct{})
	errCh := make(chan error, len(pipes))
	for i, pipe := range pipes {
		wg.Add(1)
		go func(idx int, p *pipeline.RedisAdjacencyPipeline) {
			defer wg.Done()
			if err := p.Run(ctx); err != nil && err != context.Canceled {
				errCh <- fmt.Errorf("slice %d: %w", idx, err)
			}
		}(i, pipe)
	}
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		logger.Errorf("Pipeline error: %v", err)
		cancel()
		<-doneCh
	case <-doneCh:
	case <-sigCh:
		logger.Infof("Shutting down")
		cancel()
		<-doneCh
	}
	for _, pipe := range pipes {
		if err := pipe.Close(); err != nil {
			logger.Errorf("Error closing pipeline: %v", err)
		}
	}
	sysmon.LogStats()
	logger.Infof("ThreatGraph stopped")
}

func newProducerPipeline(cfg *config.Config, sliceID, sliceCount int, hostFilter []string) (*pipeline.RedisAdjacencyPipeline, error) {
	var consumer pipeline.MessageConsumer
	var err error
	inputMode := strings.ToLower(strings.TrimSpace(cfg.ThreatGraph.Input.Mode))
	switch inputMode {
	case "", "redis":
		consumer, err = inputredis.NewConsumer(inputredis.Config{
			Addr:         cfg.ThreatGraph.Input.Redis.Addr,
			Password:     cfg.ThreatGraph.Input.Redis.Password,
			DB:           cfg.ThreatGraph.Input.Redis.DB,
			Key:          cfg.ThreatGraph.Input.Redis.Key,
			BlockTimeout: cfg.ThreatGraph.Input.Redis.BlockTimeout,
		})
	case "elasticsearch":
		consumer, err = inputelasticsearch.NewConsumer(inputelasticsearch.Config{
			URL:        cfg.ThreatGraph.Input.Elasticsearch.URL,
			Username:   cfg.ThreatGraph.Input.Elasticsearch.Username,
			Password:   cfg.ThreatGraph.Input.Elasticsearch.Password,
			Index:      cfg.ThreatGraph.Input.Elasticsearch.Index,
			Query:      cfg.ThreatGraph.Input.Elasticsearch.Query,
			HostFilter: hostFilter,
			SliceID:    sliceID,
			SliceMax:   sliceCount,
			BatchSize:  cfg.ThreatGraph.Input.Elasticsearch.BatchSize,
			Scroll:     cfg.ThreatGraph.Input.Elasticsearch.Scroll,
			Timeout:    cfg.ThreatGraph.Input.Elasticsearch.Timeout,
			Headers:    cfg.ThreatGraph.Input.Elasticsearch.Headers,
			CACertPath: cfg.ThreatGraph.Input.Elasticsearch.CACertPath,
			Insecure:   cfg.ThreatGraph.Input.Elasticsearch.Insecure,
		})
	default:
		return nil, fmt.Errorf("unknown input mode: %s", cfg.ThreatGraph.Input.Mode)
	}
	if err != nil {
		return nil, err
	}

	mapper := adjacency.NewMapper(adjacency.MapperOptions{
		WriteVertexRows: cfg.ThreatGraph.Graph.WriteVertexRows,
		IncludeEdgeData: cfg.ThreatGraph.Graph.IncludeEdgeData,
	})

	var adjWriter pipeline.AdjacencyWriter
	switch cfg.ThreatGraph.Output.Mode {
	case "file":
		adjWriter, err = adjacencyjson.NewWriter(cfg.ThreatGraph.Output.File.Path)
	case "http":
		adjWriter, err = adjacencyhttp.NewWriter(adjacencyhttp.Config{
			URL:     cfg.ThreatGraph.Output.HTTP.URL,
			Timeout: cfg.ThreatGraph.Output.HTTP.Timeout,
			Headers: cfg.ThreatGraph.Output.HTTP.Headers,
		})
	case "clickhouse":
		adjWriter, err = adjacencyclickhouse.NewWriter(adjacencyclickhouse.Config{
			URL:      cfg.ThreatGraph.Output.ClickHouse.URL,
			Database: cfg.ThreatGraph.Output.ClickHouse.Database,
			Table:    cfg.ThreatGraph.Output.ClickHouse.Table,
			Format:   cfg.ThreatGraph.Output.ClickHouse.Format,
			Username: cfg.ThreatGraph.Output.ClickHouse.Username,
			Password: cfg.ThreatGraph.Output.ClickHouse.Password,
			Timeout:  cfg.ThreatGraph.Output.ClickHouse.Timeout,
			Headers:  cfg.ThreatGraph.Output.ClickHouse.Headers,
		})
	default:
		return nil, fmt.Errorf("unknown output mode: %s", cfg.ThreatGraph.Output.Mode)
	}
	if err != nil {
		return nil, err
	}

	var ioaWriter pipeline.IOAWriter
	if cfg.ThreatGraph.IOA.Enabled {
		switch cfg.ThreatGraph.IOA.Output.Mode {
		case "file":
			ioaWriter, err = ioajson.NewWriter(cfg.ThreatGraph.IOA.Output.File.Path)
		case "clickhouse":
			ioaWriter, err = ioaclickhouse.NewWriter(ioaclickhouse.Config{
				URL:      cfg.ThreatGraph.IOA.Output.ClickHouse.URL,
				Database: cfg.ThreatGraph.IOA.Output.ClickHouse.Database,
				Table:    cfg.ThreatGraph.IOA.Output.ClickHouse.Table,
				Username: cfg.ThreatGraph.IOA.Output.ClickHouse.Username,
				Password: cfg.ThreatGraph.IOA.Output.ClickHouse.Password,
				Timeout:  cfg.ThreatGraph.IOA.Output.ClickHouse.Timeout,
				Headers:  cfg.ThreatGraph.IOA.Output.ClickHouse.Headers,
			})
		default:
			return nil, fmt.Errorf("unknown IOA output mode: %s", cfg.ThreatGraph.IOA.Output.Mode)
		}
		if err != nil {
			return nil, err
		}
	}

	var rawWriter pipeline.RawWriter
	if cfg.ThreatGraph.ReplayCapture.Enabled {
		rawWriter, err = rawjson.NewWriter(cfg.ThreatGraph.ReplayCapture.File.Path)
		if err != nil {
			return nil, err
		}
	}

	if sliceCount > 1 {
		logger.Infof("Starting producer slice %d/%d -> %s.%s", sliceID+1, sliceCount, cfg.ThreatGraph.Output.ClickHouse.Database, cfg.ThreatGraph.Output.ClickHouse.Table)
	}
	return pipeline.NewRedisAdjacencyPipeline(
		consumer,
		mapper,
		adjWriter,
		ioaWriter,
		rawWriter,
		cfg.ThreatGraph.Pipeline.Workers,
		cfg.ThreatGraph.Pipeline.WriteWorkers,
		cfg.ThreatGraph.Pipeline.BatchSize,
		cfg.ThreatGraph.Pipeline.FlushInterval,
		cfg.ThreatGraph.ReplayCapture.BatchSize,
		cfg.ThreatGraph.ReplayCapture.FlushInterval,
	), nil
}

func runAnalyzer(args []string) int {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	source := fs.String("source", "file", "Analyze source: file|clickhouse")
	configPath := fs.String("config", "", "Config YAML path (required for clickhouse source)")
	input := fs.String("input", "output/adjacency.jsonl", "Adjacency JSONL input path")
	hostFilter := fs.String("host", "", "Optional host filter for clickhouse source (comma-separated)")
	sinceRaw := fs.String("since", "", "Start time for clickhouse source (RFC3339)")
	untilRaw := fs.String("until", "", "End time for clickhouse source (RFC3339)")
	adjTable := fs.String("adjacency-table", "", "ClickHouse adjacency table override")
	output := fs.String("output", "output/iip_graphs.jsonl", "IIP graph JSONL output path")
	tacticalOutput := fs.String("tactical-output", "", "Optional tactical scored TPG JSONL output path")
	incidentOutput := fs.String("incident-output", "", "Optional incident JSONL output path")
	incidentMinSeq := fs.Int("incident-min-seq", 2, "Minimum sequence length for incident output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*tacticalOutput) == "" && strings.TrimSpace(*incidentOutput) == "" {
		fmt.Fprintf(os.Stderr, "analyze requires at least one of --tactical-output or --incident-output\n")
		return 2
	}

	var rows []*models.AdjacencyRow
	var iips []analyzer.IIPGraph
	var err error
	switch strings.ToLower(strings.TrimSpace(*source)) {
	case "", "file":
		rows, err = analyzer.LoadRowsJSONL(*input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load adjacency rows: %v\n", err)
			return 1
		}
		iips = analyzer.BuildIIPGraphs(rows)
	case "clickhouse":
		cfg, err := config.LoadConfig(findConfigFile(*configPath))
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
			return 1
		}
		applyDefaults(cfg)
		sinceText := strings.TrimSpace(*sinceRaw)
		if sinceText == "" {
			sinceText = strings.TrimSpace(cfg.ThreatGraph.Input.Elasticsearch.Since)
		}
		untilText := strings.TrimSpace(*untilRaw)
		if untilText == "" {
			untilText = strings.TrimSpace(cfg.ThreatGraph.Input.Elasticsearch.Until)
		}
		if sinceText == "" || untilText == "" {
			fmt.Fprintf(os.Stderr, "analyze --source=clickhouse requires --since/--until or input.elasticsearch.since/until in config\n")
			return 2
		}
		since, err := time.Parse(time.RFC3339, sinceText)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid since (must be RFC3339): %v\n", err)
			return 2
		}
		until, err := time.Parse(time.RFC3339, untilText)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid until (must be RFC3339): %v\n", err)
			return 2
		}
		if !since.Before(until) {
			fmt.Fprintf(os.Stderr, "--since must be earlier than --until\n")
			return 2
		}
		chCfg := cfg.ThreatGraph.Output.ClickHouse
		table := strings.TrimSpace(*adjTable)
		if table == "" {
			table = cfg.ThreatGraph.Output.ClickHouse.Table
		}
		reader, err := inputclickhouse.NewReader(inputclickhouse.Config{
			URL:            chCfg.URL,
			Database:       chCfg.Database,
			AdjacencyTable: table,
			Username:       chCfg.Username,
			Password:       chCfg.Password,
			Timeout:        chCfg.Timeout,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create clickhouse reader: %v\n", err)
			return 1
		}
		hosts := splitCSV(strings.TrimSpace(*hostFilter))
		if len(hosts) == 0 {
			hosts, err = reader.ReadAlertHostsFromAdjacency(since, until)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to discover clickhouse hosts: %v\n", err)
				return 1
			}
		}
		if len(hosts) == 0 {
			fmt.Printf("analyzed rows=0 iips=0 iip_output=%s\n", *output)
			return 0
		}
		sort.Strings(hosts)
		if err := prepareJSONLinesFile(*output); err != nil {
			fmt.Fprintf(os.Stderr, "failed to prepare iip output: %v\n", err)
			return 1
		}
		if strings.TrimSpace(*tacticalOutput) != "" {
			if err := prepareJSONLinesFile(*tacticalOutput); err != nil {
				fmt.Fprintf(os.Stderr, "failed to prepare tactical output: %v\n", err)
				return 1
			}
		}
		if strings.TrimSpace(*incidentOutput) != "" {
			if err := prepareJSONLinesFile(*incidentOutput); err != nil {
				fmt.Fprintf(os.Stderr, "failed to prepare incident output: %v\n", err)
				return 1
			}
		}
		totalRows := 0
		totalIIPs := 0
		totalIncidents := 0
		for _, host := range hosts {
			hostRows, err := reader.ReadRows(host, since, until)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to read adjacency rows for host %s: %v\n", host, err)
				return 1
			}
			if len(hostRows) == 0 {
				continue
			}
			totalRows += len(hostRows)
			hostIIPs := analyzer.BuildIIPGraphs(hostRows)
			if len(hostIIPs) == 0 {
				continue
			}
			totalIIPs += len(hostIIPs)
			if err := appendJSONLines(*output, hostIIPs); err != nil {
				fmt.Fprintf(os.Stderr, "failed to append iip output: %v\n", err)
				return 1
			}
			hostScored := analyzer.BuildScoredTPGs(hostIIPs)
			if strings.TrimSpace(*tacticalOutput) != "" {
				if err := appendJSONLines(*tacticalOutput, hostScored); err != nil {
					fmt.Fprintf(os.Stderr, "failed to append tactical output: %v\n", err)
					return 1
				}
			}
			if strings.TrimSpace(*incidentOutput) != "" {
				hostIncidents := analyzer.BuildIncidents(hostScored, *incidentMinSeq)
				totalIncidents += len(hostIncidents)
				if err := appendJSONLines(*incidentOutput, hostIncidents); err != nil {
					fmt.Fprintf(os.Stderr, "failed to append incidents: %v\n", err)
					return 1
				}
			}
		}
		if strings.TrimSpace(*incidentOutput) != "" {
			fmt.Printf("analyzed rows=%d iips=%d incidents=%d iip_output=%s\n", totalRows, totalIIPs, totalIncidents, *output)
			return 0
		}
		fmt.Printf("analyzed rows=%d iips=%d iip_output=%s\n", totalRows, totalIIPs, *output)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown analyze source: %s\n", *source)
		return 2
	}

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

func splitCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func writeJSONLines[T any](path string, rows []T) error {
	if err := prepareJSONLinesFile(path); err != nil {
		return err
	}
	return appendJSONLines(path, rows)
}

func prepareJSONLinesFile(path string) error {
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
	return f.Close()
}

func appendJSONLines[T any](path string, rows []T) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open output file: %w", err)
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
			firstArg := strings.TrimSpace(os.Args[1])
			if strings.HasSuffix(strings.ToLower(firstArg), ".yml") ||
				strings.HasSuffix(strings.ToLower(firstArg), ".yaml") {
				runProducer(os.Args[1:])
				return
			}
			if _, err := os.Stat(firstArg); err == nil {
				runProducer(os.Args[1:])
				return
			}
			fmt.Fprintf(os.Stderr, "unknown command: %s (supported: produce, analyze)\n", os.Args[1])
			os.Exit(2)
		}
	}

	runProducer(nil)
}
