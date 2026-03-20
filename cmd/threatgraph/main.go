package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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
	"threatgraph/internal/output/adjacencyclickhouse"
	"threatgraph/internal/output/adjacencyhttp"
	"threatgraph/internal/output/adjacencyjson"
	"threatgraph/internal/output/incidenthttp"
	"threatgraph/internal/output/incidentjson"
	"threatgraph/internal/output/ioaclickhouse"
	"threatgraph/internal/output/ioajson"
	"threatgraph/internal/output/rawjson"
	"threatgraph/internal/metrics"
	"threatgraph/internal/pipeline"
	"threatgraph/internal/service"
	"threatgraph/internal/transform/sysmon"
	"threatgraph/pkg/models"
)

type incidentExplainOutput struct {
	Incident analyzer.Incident      `json:"incident"`
	Window   incidentExplainWindow  `json:"window"`
	Summary  incidentExplainSummary `json:"summary"`
	IIP      analyzer.IIPGraph      `json:"iip"`
	TPG      analyzer.TPG           `json:"tpg"`
	Score    analyzer.TacticalScore `json:"score"`
	Timeline []timelineEvent        `json:"timeline"`
}

type incidentExplainWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type incidentExplainSummary struct {
	RowsInWindow      int `json:"rows_in_window"`
	IIPCountInWindow  int `json:"iip_count_in_window"`
	TPGVertexCount    int `json:"tpg_vertex_count"`
	TPGSequenceEdges  int `json:"tpg_sequence_edges"`
	DistinctIOARules  int `json:"distinct_ioa_rules"`
	DistinctTactics   int `json:"distinct_tactics"`
	DistinctTechnique int `json:"distinct_techniques"`
}

type timelineEvent struct {
	TS         time.Time `json:"ts"`
	RecordID   string    `json:"record_id"`
	From       string    `json:"from"`
	To         string    `json:"to"`
	EdgeType   string    `json:"edge_type"`
	IOANames   []string  `json:"ioa_names,omitempty"`
	Tactics    []string  `json:"tactics,omitempty"`
	Techniques []string  `json:"techniques,omitempty"`
}

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

	if cfg.ThreatGraph.Serve.Analyze.ClickHouse.Database == "" {
		cfg.ThreatGraph.Serve.Analyze.ClickHouse.Database = "threatgraph"
	}
	if cfg.ThreatGraph.Serve.Analyze.BatchSize <= 0 {
		cfg.ThreatGraph.Serve.Analyze.BatchSize = 1000
	}
	if strings.TrimSpace(cfg.ThreatGraph.Serve.Analyze.AdjacencyTable) == "" {
		cfg.ThreatGraph.Serve.Analyze.AdjacencyTable = "adjacency"
	}
	if strings.TrimSpace(cfg.ThreatGraph.Serve.Analyze.IOATable) == "" {
		cfg.ThreatGraph.Serve.Analyze.IOATable = "ioa_events"
	}
	if strings.TrimSpace(cfg.ThreatGraph.Serve.Analyze.ProcessedTable) == "" {
		cfg.ThreatGraph.Serve.Analyze.ProcessedTable = "ioa_processed"
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
	sysmon.ResetStats()

	if err := logger.Init(cfg.ThreatGraph.Logging.Enabled, cfg.ThreatGraph.Logging.Level, cfg.ThreatGraph.Logging.File, cfg.ThreatGraph.Logging.Console); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	if cfg.ThreatGraph.Metrics.Enabled {
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
		if strings.TrimSpace(*sinceRaw) == "" || strings.TrimSpace(*untilRaw) == "" {
			fmt.Fprintf(os.Stderr, "analyze --source=clickhouse requires --since and --until\n")
			return 2
		}
		since, err := time.Parse(time.RFC3339, strings.TrimSpace(*sinceRaw))
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --since (must be RFC3339): %v\n", err)
			return 2
		}
		until, err := time.Parse(time.RFC3339, strings.TrimSpace(*untilRaw))
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --until (must be RFC3339): %v\n", err)
			return 2
		}
		if !since.Before(until) {
			fmt.Fprintf(os.Stderr, "--since must be earlier than --until\n")
			return 2
		}
		chCfg := cfg.ThreatGraph.Serve.Analyze.ClickHouse
		table := strings.TrimSpace(*adjTable)
		if table == "" {
			table = cfg.ThreatGraph.Serve.Analyze.AdjacencyTable
		}
		reader, err := inputclickhouse.NewReader(inputclickhouse.Config{
			URL:            chCfg.URL,
			Database:       chCfg.Database,
			AdjacencyTable: table,
			IOATable:       cfg.ThreatGraph.Serve.Analyze.IOATable,
			ProcessedTable: cfg.ThreatGraph.Serve.Analyze.ProcessedTable,
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

func runServe(args []string) {
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

	if cfg.ThreatGraph.Metrics.Enabled {
		metrics.StartServer(cfg.ThreatGraph.Metrics.Addr)
		logger.Infof("Prometheus metrics enabled on %s", cfg.ThreatGraph.Metrics.Addr)
		defer metrics.StopServer()
	}

	logger.Infof("ThreatGraph serve starting")
	logger.Infof("Config loaded from: %s", configPath)

	chCfg := cfg.ThreatGraph.Serve.Analyze.ClickHouse
	reader, err := inputclickhouse.NewReader(inputclickhouse.Config{
		URL:            chCfg.URL,
		Database:       chCfg.Database,
		AdjacencyTable: cfg.ThreatGraph.Serve.Analyze.AdjacencyTable,
		IOATable:       cfg.ThreatGraph.Serve.Analyze.IOATable,
		ProcessedTable: cfg.ThreatGraph.Serve.Analyze.ProcessedTable,
		Username:       chCfg.Username,
		Password:       chCfg.Password,
		Timeout:        chCfg.Timeout,
	})
	if err != nil {
		logger.Errorf("Failed to create ClickHouse reader: %v", err)
		log.Fatalf("Failed to create ClickHouse reader: %v", err)
	}

	var incidentOut pipeline.IncidentWriter
	compatIncidentPath := ""
	compatScoredPath := ""
	switch cfg.ThreatGraph.Serve.Incident.Mode {
	case "file", "":
		path := cfg.ThreatGraph.Serve.Incident.File.Path
		if path == "" {
			path = "output/incidents.jsonl"
		}
		w, err := incidentjson.NewWriter(path)
		if err != nil {
			logger.Errorf("Failed to create incident file writer: %v", err)
			log.Fatalf("Failed to create incident file writer: %v", err)
		}
		incidentOut = w
		logger.Infof("Incident output mode: file (%s)", path)
		if dir := strings.TrimSpace(filepath.Dir(path)); dir != "" && dir != "." {
			compatIncidentPath = filepath.Join(dir, "incidents.latest.min2.jsonl")
			compatScoredPath = filepath.Join(dir, "scored_tpg.latest.jsonl")
		}
	case "http":
		w, err := incidenthttp.NewWriter(incidenthttp.Config{
			URL:     cfg.ThreatGraph.Serve.Incident.HTTP.URL,
			Timeout: cfg.ThreatGraph.Serve.Incident.HTTP.Timeout,
			Headers: cfg.ThreatGraph.Serve.Incident.HTTP.Headers,
		})
		if err != nil {
			logger.Errorf("Failed to create incident HTTP writer: %v", err)
			log.Fatalf("Failed to create incident HTTP writer: %v", err)
		}
		incidentOut = w
		logger.Infof("Incident output mode: http (%s)", cfg.ThreatGraph.Serve.Incident.HTTP.URL)
	default:
		log.Fatalf("Unknown incident output mode: %s", cfg.ThreatGraph.Serve.Incident.Mode)
	}

	svc := service.NewAnalyzeService(service.AnalyzeServiceConfig{
		Reader:             reader,
		IncidentOut:        incidentOut,
		Window:             cfg.ThreatGraph.Serve.Analyze.Window,
		Interval:           cfg.ThreatGraph.Serve.Analyze.Interval,
		BatchSize:          cfg.ThreatGraph.Serve.Analyze.BatchSize,
		MinSeq:             cfg.ThreatGraph.Serve.Analyze.MinSeq,
		Workers:            cfg.ThreatGraph.Serve.Analyze.Workers,
		ScoredOutPath:      compatScoredPath,
		CompatIncidentPath: compatIncidentPath,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := svc.Run(ctx); err != nil {
			logger.Errorf("AnalyzeService error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Infof("Shutting down serve")
	cancel()
	time.Sleep(1 * time.Second)

	if err := incidentOut.Close(); err != nil {
		logger.Errorf("Error closing incident writer: %v", err)
	}

	logger.Infof("ThreatGraph serve stopped")
}

func runExplainIncident(args []string) int {
	fs := flag.NewFlagSet("explain-incident", flag.ContinueOnError)
	configPath := fs.String("config", "", "Config YAML path (defaults to threatgraph.yml lookup)")
	incidentPath := fs.String("incident-file", "", "Incident JSONL path (default from serve config)")
	index := fs.Int("index", -1, "Incident index (0-based). -1 means latest")
	host := fs.String("host", "", "Filter incident by host")
	root := fs.String("root", "", "Filter incident by root")
	iipTSRaw := fs.String("iip-ts", "", "Filter incident by iip timestamp (RFC3339)")
	window := fs.Duration("window", 0, "Time window around incident iip_ts (default analyze.window)")
	outPath := fs.String("out", "output/incident_explain.json", "Output JSON path")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.LoadConfig(findConfigFile(*configPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		return 1
	}
	applyDefaults(cfg)

	path := strings.TrimSpace(*incidentPath)
	if path == "" {
		path = strings.TrimSpace(cfg.ThreatGraph.Serve.Incident.File.Path)
	}
	if path == "" {
		path = "output/incidents.jsonl"
	}

	incidents, err := loadIncidents(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load incidents: %v\n", err)
		return 1
	}

	var iipTSFilter time.Time
	if strings.TrimSpace(*iipTSRaw) != "" {
		iipTSFilter, err = time.Parse(time.RFC3339, strings.TrimSpace(*iipTSRaw))
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --iip-ts (must be RFC3339): %v\n", err)
			return 2
		}
	}

	selected, err := selectIncident(incidents, *index, strings.TrimSpace(*host), strings.TrimSpace(*root), iipTSFilter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to select incident: %v\n", err)
		return 1
	}

	analysisWindow := *window
	if analysisWindow <= 0 {
		analysisWindow = cfg.ThreatGraph.Serve.Analyze.Window
	}
	if analysisWindow <= 0 {
		analysisWindow = 2 * time.Hour
	}

	since := selected.IIPTS.Add(-analysisWindow)
	until := selected.IIPTS.Add(analysisWindow)

	chCfg := cfg.ThreatGraph.Serve.Analyze.ClickHouse
	reader, err := inputclickhouse.NewReader(inputclickhouse.Config{
		URL:            chCfg.URL,
		Database:       chCfg.Database,
		AdjacencyTable: cfg.ThreatGraph.Serve.Analyze.AdjacencyTable,
		IOATable:       cfg.ThreatGraph.Serve.Analyze.IOATable,
		ProcessedTable: cfg.ThreatGraph.Serve.Analyze.ProcessedTable,
		Username:       chCfg.Username,
		Password:       chCfg.Password,
		Timeout:        chCfg.Timeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create clickhouse reader: %v\n", err)
		return 1
	}

	rows, err := reader.ReadRows(selected.Host, since, until)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read adjacency rows: %v\n", err)
		return 1
	}

	iips := analyzer.BuildIIPGraphs(rows)
	matchedIIP, err := pickIncidentIIP(iips, selected)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to locate incident iip: %v\n", err)
		return 1
	}

	tpg := analyzer.BuildTPG(matchedIIP)
	score := analyzer.ScoreTPG(tpg)
	timeline, ruleCount, tacticCount, techniqueCount := buildTimeline(tpg.Vertices)

	out := incidentExplainOutput{
		Incident: selected,
		Window: incidentExplainWindow{
			Start: since,
			End:   until,
		},
		Summary: incidentExplainSummary{
			RowsInWindow:      len(rows),
			IIPCountInWindow:  len(iips),
			TPGVertexCount:    len(tpg.Vertices),
			TPGSequenceEdges:  len(tpg.SequenceEdges),
			DistinctIOARules:  ruleCount,
			DistinctTactics:   tacticCount,
			DistinctTechnique: techniqueCount,
		},
		IIP:      matchedIIP,
		TPG:      tpg,
		Score:    score,
		Timeline: timeline,
	}

	if err := writeJSONFile(*outPath, out); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write output: %v\n", err)
		return 1
	}

	fmt.Printf("incident_explain_ok host=%s root=%s tpg_vertices=%d out=%s\n", selected.Host, selected.Root, len(tpg.Vertices), *outPath)
	return 0
}

func loadIncidents(path string) ([]analyzer.Incident, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make([]analyzer.Incident, 0, 64)
	dec := json.NewDecoder(f)
	for {
		var inc analyzer.Incident
		if err := dec.Decode(&inc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		out = append(out, inc)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no incidents found in %s", path)
	}
	return out, nil
}

func selectIncident(incidents []analyzer.Incident, index int, host, root string, iipTS time.Time) (analyzer.Incident, error) {
	if len(incidents) == 0 {
		return analyzer.Incident{}, fmt.Errorf("incident list is empty")
	}

	filtered := make([]analyzer.Incident, 0, len(incidents))
	for _, inc := range incidents {
		if host != "" && inc.Host != host {
			continue
		}
		if root != "" && inc.Root != root {
			continue
		}
		if !iipTS.IsZero() && !inc.IIPTS.UTC().Equal(iipTS.UTC()) {
			continue
		}
		filtered = append(filtered, inc)
	}
	if len(filtered) == 0 {
		return analyzer.Incident{}, fmt.Errorf("no incident matched filters")
	}

	if index < 0 {
		return filtered[len(filtered)-1], nil
	}
	if index >= len(filtered) {
		return analyzer.Incident{}, fmt.Errorf("index out of range: %d (matched=%d)", index, len(filtered))
	}
	return filtered[index], nil
}

func pickIncidentIIP(iips []analyzer.IIPGraph, incident analyzer.Incident) (analyzer.IIPGraph, error) {
	if len(iips) == 0 {
		return analyzer.IIPGraph{}, fmt.Errorf("no iip built in selected window")
	}

	best := -1
	bestDelta := time.Duration(1<<63 - 1)
	for i := range iips {
		iip := iips[i]
		if iip.Host != incident.Host {
			continue
		}
		if iip.Root != incident.Root {
			continue
		}
		d := iip.IIPTS.Sub(incident.IIPTS)
		if d < 0 {
			d = -d
		}
		if d < bestDelta {
			best = i
			bestDelta = d
		}
	}
	if best >= 0 {
		return iips[best], nil
	}

	for i := range iips {
		if iips[i].Host == incident.Host {
			return iips[i], nil
		}
	}
	return analyzer.IIPGraph{}, fmt.Errorf("no iip matches incident host/root")
}

func buildTimeline(vertices []analyzer.AlertEvent) ([]timelineEvent, int, int, int) {
	out := make([]timelineEvent, 0, len(vertices))
	rules := make(map[string]struct{}, 16)
	tactics := make(map[string]struct{}, 16)
	techniques := make(map[string]struct{}, 16)

	for _, v := range vertices {
		names := make([]string, 0, len(v.IoaTags))
		tacticList := make([]string, 0, len(v.IoaTags))
		techList := make([]string, 0, len(v.IoaTags))
		for _, tag := range v.IoaTags {
			if name := strings.TrimSpace(tag.Name); name != "" {
				names = append(names, name)
				rules[strings.ToLower(name)] = struct{}{}
			}
			if t := strings.TrimSpace(tag.Tactic); t != "" {
				tacticList = append(tacticList, t)
				tactics[strings.ToLower(t)] = struct{}{}
			}
			if tech := strings.TrimSpace(tag.Technique); tech != "" {
				techList = append(techList, tech)
				techniques[strings.ToLower(tech)] = struct{}{}
			}
		}

		out = append(out, timelineEvent{
			TS:         v.TS,
			RecordID:   v.RecordID,
			From:       v.From,
			To:         v.To,
			EdgeType:   v.Type,
			IOANames:   names,
			Tactics:    tacticList,
			Techniques: techList,
		})
	}

	return out, len(rules), len(tactics), len(techniques)
}

func writeJSONFile(path string, v any) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "produce":
			runProducer(os.Args[2:])
			return
		case "analyze":
			os.Exit(runAnalyzer(os.Args[2:]))
		case "serve":
			runServe(os.Args[2:])
			return
		case "explain-incident":
			os.Exit(runExplainIncident(os.Args[2:]))
		default:
			// Backward-compatible mode: first arg is config path.
			runProducer(os.Args[1:])
			return
		}
	}

	runProducer(nil)
}
