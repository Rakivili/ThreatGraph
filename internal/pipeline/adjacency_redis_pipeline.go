package pipeline

import (
	"context"
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
	scorer        *alerts.Scorer
	alertWriter   AlertWriter
	workers       int
	batchSize     int
	flushInterval time.Duration
}

type redisWorkItem struct {
	rows []*models.AdjacencyRow
}

// NewRedisAdjacencyPipeline creates a pipeline for Redis adjacency output.
func NewRedisAdjacencyPipeline(consumer *inputredis.Consumer, engine rules.Engine, mapper *adjacency.Mapper, writer AdjacencyWriter, scorer *alerts.Scorer, alertWriter AlertWriter, workers, batchSize int, flushInterval time.Duration) *RedisAdjacencyPipeline {
	return &RedisAdjacencyPipeline{
		consumer:      consumer,
		engine:        engine,
		mapper:        mapper,
		writer:        writer,
		scorer:        scorer,
		alertWriter:   alertWriter,
		workers:       workers,
		batchSize:     batchSize,
		flushInterval: flushInterval,
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

	msgCh := make(chan []byte, p.workers*4)
	workCh := make(chan redisWorkItem, p.workers*4)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		p.readLoop(ctx, msgCh)
		close(msgCh)
	}()

	for i := 0; i < p.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.workerLoop(msgCh, workCh)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		p.writeLoop(ctx, workCh)
	}()

	<-ctx.Done()
	close(workCh)
	wg.Wait()
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
	if p.consumer != nil {
		return p.consumer.Close()
	}
	return nil
}

func (p *RedisAdjacencyPipeline) readLoop(ctx context.Context, out chan<- []byte) {
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
		out <- payload
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
		out <- redisWorkItem{rows: rows}
	}
}

func (p *RedisAdjacencyPipeline) writeLoop(ctx context.Context, in <-chan redisWorkItem) {
	ticker := time.NewTicker(p.flushInterval)
	defer ticker.Stop()

	var batchRows []*models.AdjacencyRow
	var batchAlerts []*models.Alert

	flush := func() {
		if len(batchRows) > 0 {
			for {
				if err := p.writer.WriteRows(batchRows); err != nil {
					logger.Errorf("Failed to write adjacency rows: %v", err)
					select {
					case <-ctx.Done():
						return
					case <-time.After(1 * time.Second):
					}
					continue
				}
				batchRows = nil
				break
			}
		}
		if p.alertWriter != nil && len(batchAlerts) > 0 {
			for {
				if err := p.alertWriter.WriteAlerts(batchAlerts); err != nil {
					logger.Errorf("Failed to write alerts: %v", err)
					select {
					case <-ctx.Done():
						return
					case <-time.After(1 * time.Second):
					}
					continue
				}
				batchAlerts = nil
				break
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
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
			if len(batchRows) >= p.batchSize {
				flush()
			}
		}
	}
}
