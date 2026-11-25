-- +goose NO TRANSACTION
-- +goose Up
-- P5 3.5: the raw log. One database for every table, so that one row policy covers all of them. The policies
-- are made by the runner from access.sql before this file runs, so a table is under them from its first day
-- (migrations/clickhouse/README.md). goose's own version table is in ctrlz_meta, which the runner creates,
-- so every table of ctrlz has tenant_id.
CREATE DATABASE IF NOT EXISTS ctrlz;

-- A query is a row only at the Full level (3.1). The two TTL columns are set by the hub from the tenant at
-- judging time, and a partition holds one value of each, so `ttl_only_drop_parts` can drop a whole part when
-- its last row expires. An absent id is the zero UUID and an absent country is ''.
CREATE TABLE IF NOT EXISTS ctrlz.dns_raw (
  tenant_id          UUID,
  ts                 DateTime('UTC')        CODEC(Delta, ZSTD(1)),
  row_id             UInt64                 CODEC(ZSTD(1)),
  endpoint_id        UUID,
  client_id          UUID,
  profile_id         UUID,
  profile2_id        UUID,
  schedule_window_id UUID,
  qname_norm         String                 CODEC(ZSTD(3)),
  qtype              UInt16,
  rcode              UInt16,
  action             Enum8('none'=0,'block'=1,'bypass'=2,'redirect'=3),
  decision_stage     Enum8('rule'=1,'geo'=2,'service'=3,'filter'=4,'default'=5,'system'=6,'soft_disabled'=7),
  ref_kind           Enum8('none'=0,'rule'=1,'service'=2,'filter'=3,'exfiltration'=4,'default'=5,'system'=6,'degraded'=7),
  decision_ref       String                 CODEC(ZSTD(1)),
  location           UInt16,
  protocol           Enum8('udp'=1,'tcp'=2,'doh'=3,'dot'=4,'doq'=5,'doh3'=6),
  source_ip          IPv6                   CODEC(ZSTD(1)),
  source_country     LowCardinality(String),
  source_asn         UInt32,
  answer_country     LowCardinality(String),
  asn                UInt32,
  cname_chain        Array(String)          CODEC(ZSTD(3)),
  config_seq         UInt64                 CODEC(Delta, ZSTD(1)),
  catalog_version    UInt64                 CODEC(Delta, ZSTD(1)),
  traffic_cat        UInt16,
  latency_us         UInt32                 CODEC(ZSTD(1)),
  node_id            UUID,
  ingest_seq         UInt64                 CODEC(Delta, ZSTD(1)),
  in_domains         UInt8,
  ttl_days           UInt8,
  ttl_months         UInt8,
  INDEX i_profile  profile_id  TYPE bloom_filter(0.01) GRANULARITY 4,
  INDEX i_profile2 profile2_id TYPE bloom_filter(0.01) GRANULARITY 4,
  INDEX i_endpoint endpoint_id TYPE bloom_filter(0.01) GRANULARITY 4,
  INDEX i_client   client_id   TYPE bloom_filter(0.01) GRANULARITY 4,
  INDEX i_qname    qname_norm  TYPE ngrambf_v1(4, 32768, 2, 0) GRANULARITY 4
) ENGINE = MergeTree
PARTITION BY (ttl_days, toYYYYMMDD(ts))
ORDER BY (tenant_id, ts, row_id)
TTL ts + toIntervalDay(ttl_days)
SETTINGS non_replicated_deduplication_window = 10000, ttl_only_drop_parts = 1, min_free_disk_ratio_to_perform_insert = 0.1;

-- +goose Down
DROP TABLE IF EXISTS ctrlz.dns_raw;
