package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"threatgraph/config"
	"threatgraph/internal/alerts"
	"threatgraph/internal/graph/adjacency"
	inputredis "threatgraph/internal/input/redis"
	"threatgraph/internal/logger"
	"threatgraph/internal/output/adjacencyhttp"
	"threatgraph/internal/output/adjacencyjson"
	"threatgraph/internal/output/alerthttp"
	"threatgraph/internal/output/alertjson"
	"threatgraph/internal/pipeline"
	"threatgraph/internal/rules"
)

func findConfigFile() string {
	if len(os.Args) > 1 {
		path := os.Args[1]
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

	if cfg.ThreatGraph.Logging.Level == "" {
		cfg.ThreatGraph.Logging.Level = "info"
	}
}

func main() {
	configPath := findConfigFile()

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
		logger.Infof("Rules enabled but no engine configured; IOA tagging disabled")
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

	pipe := pipeline.NewRedisAdjacencyPipeline(
		consumer,
		engine,
		mapper,
		adjWriter,
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
