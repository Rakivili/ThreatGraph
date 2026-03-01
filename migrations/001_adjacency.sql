CREATE TABLE IF NOT EXISTS threatgraph.adjacency (
    ts          DateTime64(3),
    record_type LowCardinality(String),
    type        LowCardinality(String),
    vertex_id   String,
    adjacent_id String,
    event_id    UInt16,
    host        LowCardinality(String),
    agent_id    LowCardinality(String),
    record_id   String,
    ioa_tags    String DEFAULT '[]'
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (host, ts, record_id)
TTL ts + INTERVAL 7 DAY;
