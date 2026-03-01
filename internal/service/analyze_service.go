package service

import (
	"context"
	"sync"
	"time"

	"threatgraph/internal/analyzer"
	"threatgraph/internal/input/clickhouse"
	"threatgraph/internal/logger"
	"threatgraph/internal/pipeline"
)

// AnalyzeService polls ClickHouse for IOA-active hosts and runs incremental
// analysis on their adjacency data.
type AnalyzeService struct {
	reader      *clickhouse.Reader
	incidentOut pipeline.IncidentWriter
	window      time.Duration
	interval    time.Duration
	minSeq      int
	workers     int
	checkpoint  time.Time
}

// AnalyzeServiceConfig configures the analyze service.
type AnalyzeServiceConfig struct {
	Reader      *clickhouse.Reader
	IncidentOut pipeline.IncidentWriter
	Window      time.Duration
	Interval    time.Duration
	MinSeq      int
	Workers     int
}

// NewAnalyzeService creates a new analyze service.
func NewAnalyzeService(cfg AnalyzeServiceConfig) *AnalyzeService {
	window := cfg.Window
	if window <= 0 {
		window = 15 * time.Minute
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	minSeq := cfg.MinSeq
	if minSeq <= 0 {
		minSeq = 2
	}
	workers := cfg.Workers
	if workers <= 0 {
		workers = 4
	}
	return &AnalyzeService{
		reader:      cfg.Reader,
		incidentOut: cfg.IncidentOut,
		window:      window,
		interval:    interval,
		minSeq:      minSeq,
		workers:     workers,
		checkpoint:  time.Now().UTC().Add(-window),
	}
}

// Run starts the polling loop and blocks until the context is cancelled.
func (s *AnalyzeService) Run(ctx context.Context) error {
	logger.Infof("AnalyzeService started: window=%s interval=%s workers=%d minSeq=%d",
		s.window, s.interval, s.workers, s.minSeq)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Infof("AnalyzeService stopped")
			return nil
		case <-ticker.C:
			s.poll(ctx)
		}
	}
}

func (s *AnalyzeService) poll(ctx context.Context) {
	now := time.Now().UTC()

	hosts, err := s.reader.ReadHosts(s.checkpoint)
	if err != nil {
		logger.Errorf("AnalyzeService: failed to read hosts: %v", err)
		return
	}
	s.checkpoint = now

	if len(hosts) == 0 {
		return
	}

	logger.Infof("AnalyzeService: polling %d active hosts", len(hosts))

	since := now.Add(-s.window)
	sem := make(chan struct{}, s.workers)
	var wg sync.WaitGroup

	for _, host := range hosts {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			s.analyzeHost(h, since, now)
		}(host)
	}

	wg.Wait()
}

func (s *AnalyzeService) analyzeHost(host string, since, until time.Time) {
	rows, err := s.reader.ReadRows(host, since, until)
	if err != nil {
		logger.Errorf("AnalyzeService: failed to read rows for host %s: %v", host, err)
		return
	}
	if len(rows) == 0 {
		return
	}

	iips := analyzer.BuildIIPGraphs(rows)
	if len(iips) == 0 {
		return
	}

	scored := analyzer.BuildScoredTPGs(iips)
	incidents := analyzer.BuildIncidents(scored, s.minSeq)
	if len(incidents) == 0 {
		return
	}

	if err := s.incidentOut.WriteIncidents(incidents); err != nil {
		logger.Errorf("AnalyzeService: failed to write incidents for host %s: %v", host, err)
		return
	}

	logger.Infof("AnalyzeService: host=%s rows=%d iips=%d incidents=%d", host, len(rows), len(iips), len(incidents))
}
