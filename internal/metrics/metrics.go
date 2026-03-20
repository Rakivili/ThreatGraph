package metrics

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "threatgraph"

// ── Pipeline (produce) counters & histograms ────────────────────────

var (
	EventsConsumed = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "events_consumed_total",
		Help:      "Total events consumed from input source.",
	})
	EventsParsed = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "events_parsed_total",
		Help:      "Events successfully parsed.",
	})
	EventsParseErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "events_parse_errors_total",
		Help:      "Events that failed to parse.",
	})
	AdjacencyRowsProduced = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "adjacency_rows_produced_total",
		Help:      "Adjacency rows produced by mapper.",
	})
	IOAEventsProduced = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "ioa_events_produced_total",
		Help:      "IOA events extracted from adjacency rows.",
	})
	BatchWritesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "batch_writes_total",
		Help:      "Total batch write attempts.",
	})
	BatchWriteErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "batch_write_errors_total",
		Help:      "Batch writes that failed after all retries.",
	})
	BatchWriteDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "batch_write_dropped_total",
		Help:      "Rows dropped after exhausting retries.",
	})
	BatchWriteDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "batch_write_duration_seconds",
		Help:      "Batch write latency.",
		Buckets:   prometheus.DefBuckets,
	})
	BatchSize = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "batch_size",
		Help:      "Number of rows per write batch.",
		Buckets:   []float64{10, 50, 100, 250, 500, 1000, 2000, 5000},
	})
)

func init() {
	// Pipeline
	prometheus.MustRegister(
		EventsConsumed,
		EventsParsed,
		EventsParseErrors,
		AdjacencyRowsProduced,
		IOAEventsProduced,
		BatchWritesTotal,
		BatchWriteErrors,
		BatchWriteDropped,
		BatchWriteDuration,
		BatchSize,
	)
}

// ── HTTP metrics server ─────────────────────────────────────────────

var (
	mu     sync.Mutex
	server *http.Server
)

// StartServer starts the Prometheus /metrics HTTP endpoint.
func StartServer(addr string) {
	mu.Lock()
	defer mu.Unlock()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// logged once; callers already initialised the logger
			println("metrics: listen error:", err.Error())
		}
	}()
}

// StopServer gracefully shuts down the metrics HTTP server.
func StopServer() {
	mu.Lock()
	srv := server
	mu.Unlock()

	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
