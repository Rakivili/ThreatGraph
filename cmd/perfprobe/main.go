package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"threatgraph/config"
	"threatgraph/internal/graph/adjacency"
	inputelasticsearch "threatgraph/internal/input/elasticsearch"
	"threatgraph/internal/transform/sysmon"
)

func main() {
	mode := flag.String("mode", "es", "Probe mode: es|map")
	configPath := flag.String("config", "", "Config YAML path")
	seconds := flag.Int("seconds", 120, "Duration in seconds")
	flag.Parse()

	if strings.TrimSpace(*configPath) == "" {
		log.Fatal("--config is required")
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	applyProbeDefaults(cfg)

	consumer, err := inputelasticsearch.NewConsumer(inputelasticsearch.Config{
		URL:        cfg.ThreatGraph.Input.Elasticsearch.URL,
		Username:   cfg.ThreatGraph.Input.Elasticsearch.Username,
		Password:   cfg.ThreatGraph.Input.Elasticsearch.Password,
		Index:      cfg.ThreatGraph.Input.Elasticsearch.Index,
		Query:      cfg.ThreatGraph.Input.Elasticsearch.Query,
		BatchSize:  cfg.ThreatGraph.Input.Elasticsearch.BatchSize,
		Scroll:     cfg.ThreatGraph.Input.Elasticsearch.Scroll,
		Timeout:    cfg.ThreatGraph.Input.Elasticsearch.Timeout,
		Headers:    cfg.ThreatGraph.Input.Elasticsearch.Headers,
		CACertPath: cfg.ThreatGraph.Input.Elasticsearch.CACertPath,
		Insecure:   cfg.ThreatGraph.Input.Elasticsearch.Insecure,
	})
	if err != nil {
		log.Fatalf("new consumer: %v", err)
	}
	defer consumer.Close()

	mapper := adjacency.NewMapper(adjacency.MapperOptions{
		WriteVertexRows: cfg.ThreatGraph.Graph.WriteVertexRows,
		IncludeEdgeData: cfg.ThreatGraph.Graph.IncludeEdgeData,
	})
	sysmon.ResetStats()

	ctx := context.Background()
	start := time.Now()
	deadline := start.Add(time.Duration(*seconds) * time.Second)
	var docs, rows, bytes int64
	var parseErrs int64

	if *mode == "es" {
		for time.Now().Before(deadline) {
			payload, err := consumer.Pop(ctx)
			if err != nil {
				if err == io.EOF {
					break
				}
				log.Fatalf("pop: %v", err)
			}
			if len(payload) == 0 {
				continue
			}
			docs++
			bytes += int64(len(payload))
		}
	} else {
		workerCount := cfg.ThreatGraph.Pipeline.Workers
		if workerCount <= 0 {
			workerCount = 8
		}
		msgCh := make(chan []byte, workerCount*4)
		var readWG sync.WaitGroup
		readWG.Add(1)
		go func() {
			defer readWG.Done()
			for time.Now().Before(deadline) {
				payload, err := consumer.Pop(ctx)
				if err != nil {
					if err == io.EOF {
						break
					}
					log.Fatalf("pop: %v", err)
				}
				if len(payload) == 0 {
					continue
				}
				atomic.AddInt64(&docs, 1)
				atomic.AddInt64(&bytes, int64(len(payload)))
				msgCh <- payload
			}
			close(msgCh)
		}()

		var workerWG sync.WaitGroup
		for i := 0; i < workerCount; i++ {
			workerWG.Add(1)
			go func() {
				defer workerWG.Done()
				for payload := range msgCh {
					event, err := sysmon.Parse(payload)
					if err != nil {
						atomic.AddInt64(&parseErrs, 1)
						continue
					}
					atomic.AddInt64(&rows, int64(len(mapper.Map(event))))
				}
			}()
		}
		readWG.Wait()
		workerWG.Wait()
	}

	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}
	fmt.Printf("mode=%s docs=%d rows=%d bytes=%d parse_errors=%d missing_winlog_event_data=%d elapsed_seconds=%.2f docs_per_sec=%.2f rows_per_sec=%.2f\n",
		*mode,
		docs,
		rows,
		bytes,
		parseErrs,
		sysmon.MissingWinlogEventDataCount(),
		elapsed,
		float64(docs)/elapsed,
		float64(rows)/elapsed,
	)
}

func applyProbeDefaults(cfg *config.Config) {
	if cfg.ThreatGraph.Input.Elasticsearch.BatchSize <= 0 {
		cfg.ThreatGraph.Input.Elasticsearch.BatchSize = 1000
	}
	if cfg.ThreatGraph.Input.Elasticsearch.Scroll <= 0 {
		cfg.ThreatGraph.Input.Elasticsearch.Scroll = 5 * time.Minute
	}
	if cfg.ThreatGraph.Input.Elasticsearch.Timeout <= 0 {
		cfg.ThreatGraph.Input.Elasticsearch.Timeout = 30 * time.Second
	}
}
