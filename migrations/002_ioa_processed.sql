CREATE TABLE IF NOT EXISTS threatgraph.ioa_processed (
    ts           DateTime64(3),
    host         LowCardinality(String),
    record_id    String,
    name         LowCardinality(String),
    iip_root     String,
    iip_ts       DateTime64(3),
    processed_at DateTime64(3) DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(processed_at)
PARTITION BY toYYYYMMDD(ts)
ORDER BY (host, record_id, name)
TTL ts + INTERVAL 7 DAY;
