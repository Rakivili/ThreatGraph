package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"threatgraph/config"
	inputelasticsearch "threatgraph/internal/input/elasticsearch"
	"threatgraph/internal/logger"
	"threatgraph/internal/transform/sysmon"
)

func runHostPrefilteredProducer(cfg *config.Config) error {
	if !stringsEqualFold(strings.TrimSpace(cfg.ThreatGraph.Input.Mode), "elasticsearch") {
		return fmt.Errorf("host prefilter requires elasticsearch input")
	}
	logger.Infof("ThreatGraph starting")
	logger.Infof("Host-prefiltered produce enabled")
	sysmon.ResetStats()

	hosts, err := inputelasticsearch.DiscoverNonNoticeHosts(context.Background(), inputelasticsearch.Config{
		URL:        cfg.ThreatGraph.Input.Elasticsearch.URL,
		Username:   cfg.ThreatGraph.Input.Elasticsearch.Username,
		Password:   cfg.ThreatGraph.Input.Elasticsearch.Password,
		Index:      cfg.ThreatGraph.Input.Elasticsearch.Index,
		Query:      cfg.ThreatGraph.Input.Elasticsearch.Query,
		Timeout:    cfg.ThreatGraph.Input.Elasticsearch.Timeout,
		Headers:    cfg.ThreatGraph.Input.Elasticsearch.Headers,
		CACertPath: cfg.ThreatGraph.Input.Elasticsearch.CACertPath,
		Insecure:   cfg.ThreatGraph.Input.Elasticsearch.Insecure,
	})
	if err != nil {
		return fmt.Errorf("discover hosts: %w", err)
	}
	if len(hosts) == 0 {
		logger.Infof("No non-notice IOA hosts discovered; nothing to produce")
		logger.Infof("ThreatGraph stopped")
		return nil
	}
	sort.Strings(hosts)
	batches := chunkStrings(hosts, cfg.ThreatGraph.Input.Elasticsearch.HostBatchSize)
	workers := cfg.ThreatGraph.Input.Elasticsearch.HostBatchWorkers
	if workers <= 0 {
		workers = 4
	}
	if workers > len(batches) {
		workers = len(batches)
	}
	logger.Infof("Discovered %d host(s), %d batch(es), %d worker(s)", len(hosts), len(batches), workers)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jobs := make(chan []string)
	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	for workerID := 0; workerID < workers; workerID++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for batch := range jobs {
				pipe, err := newProducerPipeline(cfg, 0, 1, batch)
				if err != nil {
					select {
					case errCh <- fmt.Errorf("worker %d create pipeline: %w", id+1, err):
					default:
					}
					cancel()
					return
				}
				logger.Infof("Worker %d starting host batch size=%d", id+1, len(batch))
				if err := pipe.Run(ctx); err != nil && err != context.Canceled {
					_ = pipe.Close()
					select {
					case errCh <- fmt.Errorf("worker %d run batch: %w", id+1, err):
					default:
					}
					cancel()
					return
				}
				if err := pipe.Close(); err != nil {
					select {
					case errCh <- fmt.Errorf("worker %d close batch: %w", id+1, err):
					default:
					}
					cancel()
					return
				}
				logger.Infof("Worker %d completed host batch size=%d", id+1, len(batch))
			}
		}(workerID)
	}
dispatchLoop:
	for _, batch := range batches {
		select {
		case <-ctx.Done():
			break dispatchLoop
		case jobs <- batch:
		}
	}
	close(jobs)
	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
	}
	sysmon.LogStats()
	logger.Infof("ThreatGraph stopped")
	return nil
}

func chunkStrings(items []string, size int) [][]string {
	if size <= 0 {
		size = 50
	}
	out := make([][]string, 0, (len(items)+size-1)/size)
	for start := 0; start < len(items); start += size {
		end := start + size
		if end > len(items) {
			end = len(items)
		}
		batch := make([]string, end-start)
		copy(batch, items[start:end])
		out = append(out, batch)
	}
	return out
}

func stringsEqualFold(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
