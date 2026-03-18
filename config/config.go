package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration.
type Config struct {
	ThreatGraph ThreatGraphConfig `yaml:"threatgraph"`
}

// ThreatGraphConfig is the project configuration.
type ThreatGraphConfig struct {
	Input         InputConfig         `yaml:"input"`
	Pipeline      PipelineConfig      `yaml:"pipeline"`
	Graph         GraphConfig         `yaml:"graph"`
	Rules         RulesConfig         `yaml:"rules"`
	Output        OutputConfig        `yaml:"output"`
	IOA           IOAConfig           `yaml:"ioa"`
	ReplayCapture ReplayCaptureConfig `yaml:"replay_capture"`
	Logging       LoggingConfig       `yaml:"logging"`
	Serve         ServeConfig         `yaml:"serve"`
}

// GraphConfig controls raw adjacency graph emission.
type GraphConfig struct {
	WriteVertexRows bool `yaml:"write_vertex_rows"`
	IncludeEdgeData bool `yaml:"include_edge_data"`
}

// InputConfig controls the input reader.
type InputConfig struct {
	Mode          string              `yaml:"mode"`
	Redis         RedisConfig         `yaml:"redis"`
	Elasticsearch ElasticsearchConfig `yaml:"elasticsearch"`
}

// PipelineConfig controls pipeline behavior.
type PipelineConfig struct {
	Workers       int           `yaml:"workers"`
	WriteWorkers  int           `yaml:"write_workers"`
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
}

// RulesConfig controls IOA rules.
type RulesConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// RedisConfig controls Redis input.
type RedisConfig struct {
	Addr         string        `yaml:"addr"`
	Password     string        `yaml:"password"`
	DB           int           `yaml:"db"`
	Key          string        `yaml:"key"`
	BlockTimeout time.Duration `yaml:"block_timeout"`
}

type ElasticsearchConfig struct {
	URL              string            `yaml:"url"`
	Username         string            `yaml:"username"`
	Password         string            `yaml:"password"`
	Index            string            `yaml:"index"`
	Query            string            `yaml:"query"`
	Slices           int               `yaml:"slices"`
	TimeShards       int               `yaml:"time_shards"`
	TimeShardMinutes int               `yaml:"time_shard_minutes"`
	TimeShardWorkers int               `yaml:"time_shard_workers"`
	BatchSize        int               `yaml:"batch_size"`
	Scroll           time.Duration     `yaml:"scroll"`
	Timeout          time.Duration     `yaml:"timeout"`
	Headers          map[string]string `yaml:"headers"`
	CACertPath       string            `yaml:"ca_cert_path"`
	Insecure         bool              `yaml:"insecure"`
	RunOnce          bool              `yaml:"run_once"`
}

// OutputConfig controls output.
type OutputConfig struct {
	Mode       string                 `yaml:"mode"` // file|http|clickhouse
	File       FileOutputConfig       `yaml:"file"`
	HTTP       HTTPOutputConfig       `yaml:"http"`
	ClickHouse ClickHouseOutputConfig `yaml:"clickhouse"`
}

// IOAConfig controls lightweight IOA event output for prefiltering.
type IOAConfig struct {
	Enabled bool            `yaml:"enabled"`
	Output  IOAOutputConfig `yaml:"output"`
}

// IOAOutputConfig controls IOA event sink.
type IOAOutputConfig struct {
	Mode       string                 `yaml:"mode"` // file|clickhouse
	File       FileOutputConfig       `yaml:"file"`
	ClickHouse ClickHouseOutputConfig `yaml:"clickhouse"`
}

// ReplayCaptureConfig controls raw message capture for replay tests.
type ReplayCaptureConfig struct {
	Enabled       bool             `yaml:"enabled"`
	File          FileOutputConfig `yaml:"file"`
	BatchSize     int              `yaml:"batch_size"`
	FlushInterval time.Duration    `yaml:"flush_interval"`
}

// ClickHouseOutputConfig config for ClickHouse HTTP JSONEachRow writes.
type ClickHouseOutputConfig struct {
	URL      string            `yaml:"url"`
	Database string            `yaml:"database"`
	Table    string            `yaml:"table"`
	Format   string            `yaml:"format"`
	Username string            `yaml:"username"`
	Password string            `yaml:"password"`
	Timeout  time.Duration     `yaml:"timeout"`
	Headers  map[string]string `yaml:"headers"`
}

// FileOutputConfig config for local JSON output.
type FileOutputConfig struct {
	Path string `yaml:"path"`
}

// HTTPOutputConfig config for remote output.
type HTTPOutputConfig struct {
	URL     string            `yaml:"url"`
	Timeout time.Duration     `yaml:"timeout"`
	Headers map[string]string `yaml:"headers"`
}

// LoggingConfig controls logging output.
type LoggingConfig struct {
	Enabled bool   `yaml:"enabled"`
	Level   string `yaml:"level"`
	File    string `yaml:"file"`
	Console bool   `yaml:"console"`
}

// ServeConfig controls the near-real-time serve command.
type ServeConfig struct {
	Analyze  AnalyzeConfig        `yaml:"analyze"`
	Incident IncidentOutputConfig `yaml:"incident"`
}

// AnalyzeConfig controls incremental analysis polling.
type AnalyzeConfig struct {
	Window         time.Duration          `yaml:"window"`
	Interval       time.Duration          `yaml:"interval"`
	BatchSize      int                    `yaml:"batch_size"`
	MinSeq         int                    `yaml:"min_seq"`
	Workers        int                    `yaml:"workers"`
	AdjacencyTable string                 `yaml:"adjacency_table"`
	IOATable       string                 `yaml:"ioa_table"`
	ProcessedTable string                 `yaml:"processed_table"`
	ClickHouse     ClickHouseOutputConfig `yaml:"clickhouse"`
}

// IncidentOutputConfig controls incident output sink.
type IncidentOutputConfig struct {
	Mode string           `yaml:"mode"` // file|http
	File FileOutputConfig `yaml:"file"`
	HTTP HTTPOutputConfig `yaml:"http"`
}

// LoadConfig reads and parses a YAML config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
