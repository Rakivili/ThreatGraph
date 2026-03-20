package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"threatgraph/internal/graph/adjacency"
	"threatgraph/internal/logger"
	"threatgraph/internal/metrics"
	"threatgraph/internal/transform/sysmon"
	"threatgraph/pkg/models"
)

type MessageConsumer interface {
	Pop(ctx context.Context) ([]byte, error)
	Close() error
}

// AdjacencyPipeline consumes events and writes adjacency rows.
type AdjacencyPipeline struct {
	consumer      MessageConsumer
	mapper        *adjacency.Mapper
	writer        AdjacencyWriter
	ioaWriter     IOAWriter
	rawWriter     RawWriter
	workers       int
	writeWorkers  int
	batchSize     int
	flushInterval time.Duration
	rawBatchSize  int
	rawFlushIntvl time.Duration

	consumedEvents uint64
	parsedEvents   uint64
	parseErrors    uint64
	mappedRows     uint64
	writtenRows    uint64
}

type adjacencyWorkItem struct {
	rows      []*models.AdjacencyRow
	ioaEvents []*models.IOAEvent
}

type writeBatch struct {
	rows      []*models.AdjacencyRow
	ioaEvents []*models.IOAEvent
}

// NewAdjacencyPipeline creates a pipeline for adjacency output.
func NewAdjacencyPipeline(consumer MessageConsumer, mapper *adjacency.Mapper, writer AdjacencyWriter, ioaWriter IOAWriter, rawWriter RawWriter, workers, writeWorkers, batchSize int, flushInterval time.Duration, rawBatchSize int, rawFlushInterval time.Duration) *AdjacencyPipeline {
	return &AdjacencyPipeline{
		consumer:      consumer,
		mapper:        mapper,
		writer:        writer,
		ioaWriter:     ioaWriter,
		rawWriter:     rawWriter,
		workers:       workers,
		writeWorkers:  writeWorkers,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		rawBatchSize:  rawBatchSize,
		rawFlushIntvl: rawFlushInterval,
	}
}

// Run starts the pipeline loop.
func (p *AdjacencyPipeline) Run(ctx context.Context) error {
	logger.Infof("Adjacency pipeline started")
	startedAt := time.Now()

	if p.workers <= 0 {
		p.workers = 8
	}
	if p.batchSize <= 0 {
		p.batchSize = 1000
	}
	if p.writeWorkers <= 0 {
		p.writeWorkers = 1
	}
	if p.flushInterval <= 0 {
		p.flushInterval = 2 * time.Second
	}
	if p.rawBatchSize <= 0 {
		p.rawBatchSize = p.batchSize
	}
	if p.rawFlushIntvl <= 0 {
		p.rawFlushIntvl = p.flushInterval
	}

	msgCh := make(chan []byte, p.workers*4)
	workCh := make(chan adjacencyWorkItem, p.workers*4)
	batchCh := make(chan writeBatch, p.writeWorkers*2)
	var rawCh chan []byte
	if p.rawWriter != nil {
		rawCh = make(chan []byte, p.workers*8)
	}

	var producerWG sync.WaitGroup
	var writerWG sync.WaitGroup
	producerDone := make(chan struct{})
	progressDone := make(chan struct{})
	go p.progressLoop(progressDone, startedAt)

	producerWG.Add(1)
	go func() {
		defer producerWG.Done()
		p.readLoop(ctx, msgCh, rawCh)
		close(msgCh)
		if rawCh != nil {
			close(rawCh)
		}
	}()

	for i := 0; i < p.workers; i++ {
		producerWG.Add(1)
		go func() {
			defer producerWG.Done()
			p.workerLoop(msgCh, workCh)
		}()
	}

	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		p.batchLoop(workCh, batchCh)
		close(batchCh)
	}()

	for i := 0; i < p.writeWorkers; i++ {
		writerWG.Add(1)
		go func() {
			defer writerWG.Done()
			p.writeLoop(batchCh)
		}()
	}
	if rawCh != nil {
		writerWG.Add(1)
		go func() {
			defer writerWG.Done()
			p.rawWriteLoop(rawCh)
		}()
	}

	go func() {
		producerWG.Wait()
		close(producerDone)
	}()

	select {
	case <-ctx.Done():
	case <-producerDone:
	}
	producerWG.Wait()
	close(workCh)
	writerWG.Wait()
	close(progressDone)
	p.logRunSummary(time.Since(startedAt))
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

// Close releases pipeline resources.
func (p *AdjacencyPipeline) Close() error {
	if p.writer != nil {
		if err := p.writer.Close(); err != nil {
			logger.Errorf("Failed to close adjacency writer: %v", err)
		}
	}
	if p.ioaWriter != nil {
		if err := p.ioaWriter.Close(); err != nil {
			logger.Errorf("Failed to close IOA writer: %v", err)
		}
	}
	if p.rawWriter != nil {
		if err := p.rawWriter.Close(); err != nil {
			logger.Errorf("Failed to close raw writer: %v", err)
		}
	}
	if p.consumer != nil {
		return p.consumer.Close()
	}
	return nil
}

func (p *AdjacencyPipeline) readLoop(ctx context.Context, out chan<- []byte, rawOut chan<- []byte) {
	for {
		payload, err := p.consumer.Pop(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			if ctx.Err() != nil {
				return
			}
			logger.Errorf("Failed to pop input message: %v", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if payload == nil {
			continue
		}
		atomic.AddUint64(&p.consumedEvents, 1)
		metrics.EventsConsumed.Inc()
		if rawOut != nil {
			rawOut <- payload
		}
		out <- payload
	}
}

func (p *AdjacencyPipeline) rawWriteLoop(in <-chan []byte) {
	ticker := time.NewTicker(p.rawFlushIntvl)
	defer ticker.Stop()

	batch := make([][]byte, 0, p.rawBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		for attempt := 1; attempt <= 3; attempt++ {
			if err := p.rawWriter.WriteRawMessages(batch); err != nil {
				logger.Errorf("Failed to write raw messages (attempt %d/3): %v", attempt, err)
				if attempt == 3 {
					logger.Errorf("Dropping %d raw messages after retries", len(batch))
					batch = batch[:0]
					break
				}
				time.Sleep(1 * time.Second)
				continue
			}
			batch = batch[:0]
			break
		}
	}

	for {
		select {
		case <-ticker.C:
			flush()
		case payload, ok := <-in:
			if !ok {
				flush()
				return
			}
			if payload == nil {
				continue
			}
			batch = append(batch, payload)
			if len(batch) >= p.rawBatchSize {
				flush()
			}
		}
	}
}

func (p *AdjacencyPipeline) workerLoop(in <-chan []byte, out chan<- adjacencyWorkItem) {
	for payload := range in {
		event, err := sysmon.Parse(payload)
		if err != nil {
			atomic.AddUint64(&p.parseErrors, 1)
			metrics.EventsParseErrors.Inc()
			logger.Warnf("Failed to parse sysmon event: %v", err)
			continue
		}
		atomic.AddUint64(&p.parsedEvents, 1)
		metrics.EventsParsed.Inc()

		enrichDerivedFields(event)

		event.IoaTags = offlineEDRIOATags(event)

		rows := p.mapper.Map(event)
		ioaEvents := extractIOAEvents(rows)
		atomic.AddUint64(&p.mappedRows, uint64(len(rows)))
		metrics.AdjacencyRowsProduced.Add(float64(len(rows)))
		metrics.IOAEventsProduced.Add(float64(len(ioaEvents)))
		out <- adjacencyWorkItem{rows: rows, ioaEvents: ioaEvents}
	}
}

func offlineEDRIOATags(event *models.Event) []models.IoaTag {
	if event == nil {
		return nil
	}
	risk := strings.ToLower(strings.TrimSpace(rawString(event, "risk_level")))
	if risk == "" || risk == "notice" {
		return nil
	}
	name := strings.TrimSpace(rawString(event, "alert_name"))
	if name == "" {
		name = strings.TrimSpace(rawString(event, "name_key"))
	}
	if name == "" {
		name = "offline-edr-ioa"
	}
	ruleID := strings.TrimSpace(rawString(event, "ext_process_rule_id"))
	tactic := strings.TrimSpace(rawString(event, "attack.tactic"))
	technique := strings.TrimSpace(rawString(event, "attack.technique"))
	return []models.IoaTag{{
		ID:        ruleID,
		Name:      name,
		Severity:  risk,
		Tactic:    tactic,
		Technique: technique,
	}}
}

func rawString(event *models.Event, key string) string {
	if event == nil {
		return ""
	}
	if event.Lookup != nil {
		if v, ok := event.Lookup[key]; ok {
			return strings.TrimSpace(v)
		}
	}
	if event.Raw != nil {
		v, ok := event.Raw[key]
		if !ok || v == nil {
			return ""
		}
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	}
	return ""
}

func (p *AdjacencyPipeline) batchLoop(in <-chan adjacencyWorkItem, out chan<- writeBatch) {
	ticker := time.NewTicker(p.flushInterval)
	defer ticker.Stop()

	var batchRows []*models.AdjacencyRow
	var batchIOAEvents []*models.IOAEvent

	flush := func() {
		if len(batchRows) == 0 && len(batchIOAEvents) == 0 {
			return
		}
		metrics.BatchSize.Observe(float64(len(batchRows)))
		out <- writeBatch{rows: batchRows, ioaEvents: batchIOAEvents}
		batchRows = nil
		batchIOAEvents = nil
	}

	for {
		select {
		case <-ticker.C:
			flush()
		case item, ok := <-in:
			if !ok {
				flush()
				return
			}
			if len(item.rows) > 0 {
				batchRows = append(batchRows, item.rows...)
			}
			if len(item.ioaEvents) > 0 {
				batchIOAEvents = append(batchIOAEvents, item.ioaEvents...)
			}
			if len(batchRows) >= p.batchSize {
				flush()
			}
		}
	}
}

func (p *AdjacencyPipeline) writeLoop(in <-chan writeBatch) {
	for batch := range in {
		if len(batch.rows) > 0 {
			metrics.BatchWritesTotal.Inc()
			start := time.Now()
			var failed bool
			for attempt := 1; attempt <= 3; attempt++ {
				if err := p.writer.WriteRows(batch.rows); err != nil {
					logger.Errorf("Failed to write adjacency rows (attempt %d/3): %v", attempt, err)
					if attempt == 3 {
						logger.Errorf("Dropping %d adjacency rows after retries", len(batch.rows))
						metrics.BatchWriteErrors.Inc()
						metrics.BatchWriteDropped.Add(float64(len(batch.rows)))
						failed = true
						break
					}
					time.Sleep(1 * time.Second)
					continue
				}
				break
			}
			if !failed {
				atomic.AddUint64(&p.writtenRows, uint64(len(batch.rows)))
				metrics.BatchWriteDuration.Observe(time.Since(start).Seconds())
			}
		}
		if p.ioaWriter != nil && len(batch.ioaEvents) > 0 {
			for attempt := 1; attempt <= 3; attempt++ {
				if err := p.ioaWriter.WriteEvents(batch.ioaEvents); err != nil {
					logger.Errorf("Failed to write IOA events (attempt %d/3): %v", attempt, err)
					if attempt == 3 {
						logger.Errorf("Dropping %d IOA events after retries", len(batch.ioaEvents))
						break
					}
					time.Sleep(1 * time.Second)
					continue
				}
				break
			}
		}
	}
}

func (p *AdjacencyPipeline) progressLoop(done <-chan struct{}, startedAt time.Time) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var lastConsumed uint64
	var lastParsed uint64
	var lastRows uint64
	var lastWritten uint64

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			consumed, parsed, parseErr, rows, written := p.snapshotStats()
			deltaConsumed := consumed - lastConsumed
			deltaParsed := parsed - lastParsed
			deltaRows := rows - lastRows
			deltaWritten := written - lastWritten
			lastConsumed = consumed
			lastParsed = parsed
			lastRows = rows
			lastWritten = written
			logger.Infof(
				"Pipeline progress elapsed=%s pulled=%d (+%d) parsed=%d (+%d) mapped_rows=%d (+%d) written_rows=%d (+%d) parse_errors=%d",
				time.Since(startedAt).Truncate(time.Second),
				consumed, deltaConsumed,
				parsed, deltaParsed,
				rows, deltaRows,
				written, deltaWritten,
				parseErr,
			)
		}
	}
}

func (p *AdjacencyPipeline) snapshotStats() (consumed, parsed, parseErr, rows, written uint64) {
	consumed = atomic.LoadUint64(&p.consumedEvents)
	parsed = atomic.LoadUint64(&p.parsedEvents)
	parseErr = atomic.LoadUint64(&p.parseErrors)
	rows = atomic.LoadUint64(&p.mappedRows)
	written = atomic.LoadUint64(&p.writtenRows)
	return
}

func (p *AdjacencyPipeline) logRunSummary(elapsed time.Duration) {
	consumed, parsed, parseErr, rows, written := p.snapshotStats()
	logger.Infof(
		"Pipeline summary elapsed=%s pulled=%d parsed=%d mapped_rows=%d written_rows=%d parse_errors=%d",
		elapsed.Truncate(time.Millisecond),
		consumed,
		parsed,
		rows,
		written,
		parseErr,
	)
}

func extractIOAEvents(rows []*models.AdjacencyRow) []*models.IOAEvent {
	out := make([]*models.IOAEvent, 0, len(rows))
	for _, row := range rows {
		if row == nil || row.RecordType != "edge" || row.Timestamp.IsZero() {
			continue
		}
		names := rowNames(row)
		if len(names) == 0 {
			continue
		}
		host := row.Hostname
		if host == "" {
			host = row.AgentID
		}
		for _, name := range names {
			out = append(out, &models.IOAEvent{
				Timestamp:  row.Timestamp,
				Host:       host,
				AgentID:    row.AgentID,
				RecordID:   row.RecordID,
				EventID:    row.EventID,
				EdgeType:   row.Type,
				VertexID:   row.VertexID,
				AdjacentID: row.AdjacentID,
				Name:       name,
			})
		}
	}
	return out
}

func rowNames(row *models.AdjacencyRow) []string {
	// IOA time-series rows should only come from normalized ioa_tags
	// to avoid mixing edge/data-derived names from different pipelines.
	values := make([]string, 0, 4)
	for _, tag := range row.IoaTags {
		if n := strings.TrimSpace(tag.Name); n != "" {
			values = append(values, n)
		}
	}

	if len(values) == 0 {
		return nil
	}
	uniq := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, n := range values {
		if _, ok := uniq[n]; ok {
			continue
		}
		uniq[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func enrichDerivedFields(event *models.Event) {
	if event == nil || event.EventID != 7 || event.Fields == nil {
		return
	}

	image := eventFieldString(event.Fields, "Image")
	imageLoaded := eventFieldString(event.Fields, "ImageLoaded")
	if image == "" || imageLoaded == "" {
		return
	}

	imageDir := parentPath(image)
	imageLoadedDir := parentPath(imageLoaded)
	if imageDir == "" || imageLoadedDir == "" {
		return
	}

	event.Fields["ImageDir"] = imageDir
	event.Fields["ImageLoadedDir"] = imageLoadedDir
	event.Fields["SameParentDir"] = strings.EqualFold(imageDir, imageLoadedDir)
}

func eventFieldString(fields map[string]interface{}, key string) string {
	if fields == nil {
		return ""
	}
	v, ok := fields[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func parentPath(path string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "/", "\\")
	p = strings.TrimRight(p, "\\")
	idx := strings.LastIndex(p, "\\")
	if idx <= 0 {
		return ""
	}
	return p[:idx]
}
