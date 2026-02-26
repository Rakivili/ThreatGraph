package pipeline

import (
	"context"
	"strings"
	"sync"
	"time"

	"threatgraph/internal/alerts"
	"threatgraph/internal/graph/adjacency"
	inputredis "threatgraph/internal/input/redis"
	"threatgraph/internal/logger"
	"threatgraph/internal/rules"
	"threatgraph/internal/transform/sysmon"
	"threatgraph/pkg/models"
)

// RedisAdjacencyPipeline consumes Redis events and writes adjacency rows.
type RedisAdjacencyPipeline struct {
	consumer      *inputredis.Consumer
	engine        rules.Engine
	mapper        *adjacency.Mapper
	writer        AdjacencyWriter
	ioaWriter     IOAWriter
	rawWriter     RawWriter
	scorer        *alerts.Scorer
	alertWriter   AlertWriter
	workers       int
	batchSize     int
	flushInterval time.Duration
	rawBatchSize  int
	rawFlushIntvl time.Duration
}

type redisWorkItem struct {
	rows      []*models.AdjacencyRow
	ioaEvents []*models.IOAEvent
}

// NewRedisAdjacencyPipeline creates a pipeline for Redis adjacency output.
func NewRedisAdjacencyPipeline(consumer *inputredis.Consumer, engine rules.Engine, mapper *adjacency.Mapper, writer AdjacencyWriter, ioaWriter IOAWriter, rawWriter RawWriter, scorer *alerts.Scorer, alertWriter AlertWriter, workers, batchSize int, flushInterval time.Duration, rawBatchSize int, rawFlushInterval time.Duration) *RedisAdjacencyPipeline {
	return &RedisAdjacencyPipeline{
		consumer:      consumer,
		engine:        engine,
		mapper:        mapper,
		writer:        writer,
		ioaWriter:     ioaWriter,
		rawWriter:     rawWriter,
		scorer:        scorer,
		alertWriter:   alertWriter,
		workers:       workers,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		rawBatchSize:  rawBatchSize,
		rawFlushIntvl: rawFlushInterval,
	}
}

// Run starts the pipeline loop.
func (p *RedisAdjacencyPipeline) Run(ctx context.Context) error {
	logger.Infof("Redis adjacency pipeline started")

	if p.workers <= 0 {
		p.workers = 8
	}
	if p.batchSize <= 0 {
		p.batchSize = 1000
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
	workCh := make(chan redisWorkItem, p.workers*4)
	var rawCh chan []byte
	if p.rawWriter != nil {
		rawCh = make(chan []byte, p.workers*8)
	}

	var producerWG sync.WaitGroup
	var writerWG sync.WaitGroup

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
		p.writeLoop(workCh)
	}()
	if rawCh != nil {
		writerWG.Add(1)
		go func() {
			defer writerWG.Done()
			p.rawWriteLoop(rawCh)
		}()
	}

	<-ctx.Done()
	producerWG.Wait()
	close(workCh)
	writerWG.Wait()
	return ctx.Err()
}

// Close releases pipeline resources.
func (p *RedisAdjacencyPipeline) Close() error {
	if p.alertWriter != nil {
		if err := p.alertWriter.Close(); err != nil {
			logger.Errorf("Failed to close alert writer: %v", err)
		}
	}
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

func (p *RedisAdjacencyPipeline) readLoop(ctx context.Context, out chan<- []byte, rawOut chan<- []byte) {
	for {
		payload, err := p.consumer.Pop(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Errorf("Failed to pop redis message: %v", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if payload == nil {
			continue
		}
		if rawOut != nil {
			rawOut <- payload
		}
		out <- payload
	}
}

func (p *RedisAdjacencyPipeline) rawWriteLoop(in <-chan []byte) {
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

func (p *RedisAdjacencyPipeline) workerLoop(in <-chan []byte, out chan<- redisWorkItem) {
	for payload := range in {
		event, err := sysmon.Parse(payload)
		if err != nil {
			logger.Warnf("Failed to parse sysmon event: %v", err)
			continue
		}

		if p.engine != nil {
			event.IoaTags = p.engine.Apply(event)
		}

		rows := p.mapper.Map(event)
		out <- redisWorkItem{rows: rows, ioaEvents: extractIOAEvents(rows)}
	}
}

func (p *RedisAdjacencyPipeline) writeLoop(in <-chan redisWorkItem) {
	ticker := time.NewTicker(p.flushInterval)
	defer ticker.Stop()

	var batchRows []*models.AdjacencyRow
	var batchIOAEvents []*models.IOAEvent
	var batchAlerts []*models.Alert

	flush := func() {
		if len(batchRows) > 0 {
			for attempt := 1; attempt <= 3; attempt++ {
				if err := p.writer.WriteRows(batchRows); err != nil {
					logger.Errorf("Failed to write adjacency rows (attempt %d/3): %v", attempt, err)
					if attempt == 3 {
						logger.Errorf("Dropping %d adjacency rows after retries", len(batchRows))
						batchRows = nil
						break
					}
					time.Sleep(1 * time.Second)
					continue
				}
				batchRows = nil
				break
			}
		}
		if p.ioaWriter != nil && len(batchIOAEvents) > 0 {
			for attempt := 1; attempt <= 3; attempt++ {
				if err := p.ioaWriter.WriteEvents(batchIOAEvents); err != nil {
					logger.Errorf("Failed to write IOA events (attempt %d/3): %v", attempt, err)
					if attempt == 3 {
						logger.Errorf("Dropping %d IOA events after retries", len(batchIOAEvents))
						batchIOAEvents = nil
						break
					}
					time.Sleep(1 * time.Second)
					continue
				}
				batchIOAEvents = nil
				break
			}
		}
		if p.alertWriter != nil && len(batchAlerts) > 0 {
			for attempt := 1; attempt <= 3; attempt++ {
				if err := p.alertWriter.WriteAlerts(batchAlerts); err != nil {
					logger.Errorf("Failed to write alerts (attempt %d/3): %v", attempt, err)
					if attempt == 3 {
						logger.Errorf("Dropping %d alerts after retries", len(batchAlerts))
						batchAlerts = nil
						break
					}
					time.Sleep(1 * time.Second)
					continue
				}
				batchAlerts = nil
				break
			}
		}
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
				if p.scorer != nil {
					alertsOut := p.scorer.AddRows(item.rows)
					if len(alertsOut) > 0 {
						batchAlerts = append(batchAlerts, alertsOut...)
					}
				}
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
	values := make([]string, 0, 4)
	for _, tag := range row.IoaTags {
		if n := strings.TrimSpace(tag.Name); n != "" {
			values = append(values, n)
		}
	}

	appendName := func(v interface{}) {
		s, ok := v.(string)
		if !ok {
			return
		}
		for _, n := range splitNameParts(s) {
			n = strings.TrimSpace(n)
			if n != "" && n != "-" {
				values = append(values, n)
			}
		}
	}

	appendName(row.Data["name"])
	appendName(row.Data["rule_name"])
	appendName(row.Data["ruleName"])

	if fields, ok := row.Data["fields"].(map[string]interface{}); ok {
		appendName(fields["RuleName"])
		appendName(fields["rule_name"])
		appendName(fields["name"])
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

func splitNameParts(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	parts := strings.FieldsFunc(v, func(r rune) bool {
		switch r {
		case ';', '|':
			return true
		default:
			return false
		}
	})
	if len(parts) == 0 {
		parts = []string{v}
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "=") {
			kv := strings.SplitN(p, "=", 2)
			key := strings.ToLower(strings.TrimSpace(kv[0]))
			value := strings.TrimSpace(kv[1])
			if value != "" && (key == "name" || key == "rulename" || key == "rule_name") {
				out = append(out, value)
				continue
			}
		}
		out = append(out, p)
	}
	return out
}
