package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"threatgraph/internal/analyzer"
	"threatgraph/internal/input/clickhouse"
	"threatgraph/internal/logger"
	"threatgraph/internal/pipeline"
	"threatgraph/pkg/models"
)

// AnalyzeService polls ClickHouse for IOA-active hosts and runs incremental
// analysis on their adjacency data.
type AnalyzeService struct {
	reader        *clickhouse.Reader
	incidentOut   pipeline.IncidentWriter
	window        time.Duration
	interval      time.Duration
	minSeq        int
	workers       int
	checkpoint    time.Time
	checkpointRID string
	batchSize     int

	// dedup: key = "host|root", value = digest of last emitted incident
	mu   sync.Mutex
	seen map[string]incidentDigest
}

// incidentDigest captures the scoring signature of an incident for dedup.
type incidentDigest struct {
	seqLen      int
	riskProduct float64
	alertCount  int
	emittedAt   time.Time
}

// AnalyzeServiceConfig configures the analyze service.
type AnalyzeServiceConfig struct {
	Reader      *clickhouse.Reader
	IncidentOut pipeline.IncidentWriter
	Window      time.Duration
	Interval    time.Duration
	BatchSize   int
	MinSeq      int
	Workers     int
}

// NewAnalyzeService creates a new analyze service.
func NewAnalyzeService(cfg AnalyzeServiceConfig) *AnalyzeService {
	window := cfg.Window
	if window <= 0 {
		window = 2 * time.Hour
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
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 1000
	}
	return &AnalyzeService{
		reader:        cfg.Reader,
		incidentOut:   cfg.IncidentOut,
		window:        window,
		interval:      interval,
		minSeq:        minSeq,
		workers:       workers,
		checkpoint:    time.Now().UTC().Add(-window),
		checkpointRID: "",
		batchSize:     batchSize,
		seen:          make(map[string]incidentDigest),
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
	batch, err := s.reader.ReadIOABatch(s.checkpoint, s.checkpointRID, s.batchSize)
	if err != nil {
		logger.Errorf("AnalyzeService: failed to read ioa batch: %v", err)
		return
	}
	if len(batch) == 0 {
		return
	}

	hosts, bounds := groupIOAByHost(batch)
	logger.Infof("AnalyzeService: ioa_batch=%d hosts=%d", len(batch), len(hosts))

	sinceCutoff := now.Add(-s.window)
	s.evictSeen(sinceCutoff)

	sem := make(chan struct{}, s.workers)
	var wg sync.WaitGroup
	errCh := make(chan error, len(hosts))

	for host := range hosts {
		select {
		case <-ctx.Done():
			return
		default:
		}

		hostBounds := bounds[host]
		since := hostBounds.minTS.Add(-s.window)
		until := now

		wg.Add(1)
		sem <- struct{}{}
		batchIOA := hosts[host]
		go func(h string, from, to time.Time, hostBatch []*models.IOAEvent) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := s.analyzeHost(h, from, to, hostBatch); err != nil {
				errCh <- err
			}
		}(host, since, until, batchIOA)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			logger.Errorf("AnalyzeService: host analysis failed: %v", err)
			return
		}
	}

	last := batch[len(batch)-1]
	s.checkpoint = last.Timestamp.UTC()
	s.checkpointRID = strings.TrimSpace(last.RecordID)
}

func (s *AnalyzeService) analyzeHost(host string, since, until time.Time, batchIOA []*models.IOAEvent) error {
	rows, err := s.reader.ReadRows(host, since, until)
	if err != nil {
		return fmt.Errorf("read rows host=%s: %w", host, err)
	}
	if len(rows) == 0 {
		return nil
	}

	iips, iipStats := analyzer.BuildIIPGraphsWithStats(rows)
	if len(iips) == 0 {
		return nil
	}

	processed := processedFromIIPs(iips)
	coveredBatchIOA, batchIOATotal, batchIIPRoots := countCoveredBatchIOA(host, batchIOA, processed)
	if err := s.reader.MarkProcessedIOAs(processed); err != nil {
		return fmt.Errorf("mark processed host=%s: %w", host, err)
	}

	scored := analyzer.BuildScoredTPGs(iips)
	incidents := analyzer.BuildIncidents(scored, s.minSeq)
	novelCount := 0
	if len(incidents) > 0 {
		novel := s.filterNovel(incidents, until)
		novelCount = len(novel)
		if novelCount > 0 {
			if err := s.incidentOut.WriteIncidents(novel); err != nil {
				return fmt.Errorf("write incidents host=%s: %w", host, err)
			}
		}
	}

	coveragePct := 0.0
	if batchIOATotal > 0 {
		coveragePct = float64(coveredBatchIOA) * 100.0 / float64(batchIOATotal)
	}

	logger.Infof("AnalyzeService: host=%s rows=%d batch_ioa=%d covered_ioa=%d coverage=%.1f%% batch_iips=%d window_iips=%d alerts=%d backward=%d forward=%d incidents=%d (new=%d)",
		host,
		len(rows),
		batchIOATotal,
		coveredBatchIOA,
		coveragePct,
		batchIIPRoots,
		len(iips),
		iipStats.AlertCount,
		iipStats.BackwardTraversalCount,
		iipStats.ForwardTraversalCount,
		len(incidents),
		novelCount,
	)
	return nil
}

func countCoveredBatchIOA(host string, batch []*models.IOAEvent, processed []clickhouse.ProcessedIOA) (covered int, total int, batchIIPRoots int) {
	if len(batch) == 0 {
		return 0, 0, 0
	}

	procSet := make(map[string]struct{}, len(processed))
	rootByKey := make(map[string]string, len(processed))
	for _, p := range processed {
		if strings.TrimSpace(p.Host) != host {
			continue
		}
		k := p.Host + "|" + strings.TrimSpace(p.RecordID) + "|" + strings.TrimSpace(p.Name)
		procSet[k] = struct{}{}
		rootByKey[k] = strings.TrimSpace(p.IIPRoot)
	}
	roots := make(map[string]struct{}, 16)

	for _, ev := range batch {
		if ev == nil {
			continue
		}
		if strings.TrimSpace(ev.Host) != host {
			continue
		}
		total++
		k := host + "|" + strings.TrimSpace(ev.RecordID) + "|" + strings.TrimSpace(ev.Name)
		if _, ok := procSet[k]; ok {
			covered++
			if root := rootByKey[k]; root != "" {
				roots[root] = struct{}{}
			}
		}
	}

	return covered, total, len(roots)
}

// filterNovel returns only incidents that are new or have a higher sequence
// length / risk than the previously emitted version.
func (s *AnalyzeService) filterNovel(incidents []analyzer.Incident, now time.Time) []analyzer.Incident {
	s.mu.Lock()
	defer s.mu.Unlock()

	novel := make([]analyzer.Incident, 0, len(incidents))
	for _, inc := range incidents {
		key := fmt.Sprintf("%s|%s", inc.Host, inc.Root)
		prev, exists := s.seen[key]
		if exists && inc.SequenceLength <= prev.seqLen && inc.RiskProduct <= prev.riskProduct && inc.AlertCount <= prev.alertCount {
			continue
		}
		s.seen[key] = incidentDigest{
			seqLen:      inc.SequenceLength,
			riskProduct: inc.RiskProduct,
			alertCount:  inc.AlertCount,
			emittedAt:   now,
		}
		novel = append(novel, inc)
	}
	return novel
}

// evictSeen removes dedup entries whose emittedAt is older than cutoff.
func (s *AnalyzeService) evictSeen(cutoff time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, d := range s.seen {
		if d.emittedAt.Before(cutoff) {
			delete(s.seen, key)
		}
	}
}

type hostTimeBounds struct {
	minTS time.Time
	maxTS time.Time
}

func groupIOAByHost(events []*models.IOAEvent) (map[string][]*models.IOAEvent, map[string]hostTimeBounds) {
	grouped := make(map[string][]*models.IOAEvent, 32)
	bounds := make(map[string]hostTimeBounds, 32)
	for _, ev := range events {
		if ev == nil || strings.TrimSpace(ev.Host) == "" || ev.Timestamp.IsZero() {
			continue
		}
		host := strings.TrimSpace(ev.Host)
		grouped[host] = append(grouped[host], ev)
		b, ok := bounds[host]
		if !ok {
			bounds[host] = hostTimeBounds{minTS: ev.Timestamp, maxTS: ev.Timestamp}
			continue
		}
		if ev.Timestamp.Before(b.minTS) {
			b.minTS = ev.Timestamp
		}
		if ev.Timestamp.After(b.maxTS) {
			b.maxTS = ev.Timestamp
		}
		bounds[host] = b
	}
	return grouped, bounds
}

func processedFromIIPs(iips []analyzer.IIPGraph) []clickhouse.ProcessedIOA {
	out := make([]clickhouse.ProcessedIOA, 0, 128)
	seen := make(map[string]struct{}, 128)
	for _, iip := range iips {
		for _, ev := range iip.AlertEvents {
			for _, tag := range ev.IoaTags {
				name := strings.TrimSpace(tag.Name)
				if name == "" {
					continue
				}
				key := ev.Host + "|" + ev.RecordID + "|" + name
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, clickhouse.ProcessedIOA{
					TS:       ev.TS,
					Host:     ev.Host,
					RecordID: ev.RecordID,
					Name:     name,
					IIPRoot:  iip.Root,
					IIPTS:    iip.IIPTS,
				})
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if !out[i].TS.Equal(out[j].TS) {
			return out[i].TS.Before(out[j].TS)
		}
		if out[i].RecordID != out[j].RecordID {
			return out[i].RecordID < out[j].RecordID
		}
		return out[i].Name < out[j].Name
	})

	return out
}
