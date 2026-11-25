-- +goose NO TRANSACTION
-- +goose Up
-- P5 3.5: the two tables the hub writes from counters (counts_5m, agg_category) and the rollups that the
-- views of 0003 feed. Every sorting key starts with tenant_id. The TTL columns are in no sorting key: a
-- partition holds one value of them, so summing keeps it.

CREATE TABLE IF NOT EXISTS ctrlz.counts_5m (
  tenant_id   UUID,
  ts          DateTime('UTC')        CODEC(Delta, ZSTD(1)),
  endpoint_id UUID,
  client_id   UUID,
  profile_id  UUID,
  profile2_id UUID,
  protocol    Enum8('udp'=1,'tcp'=2,'doh'=3,'dot'=4,'doq'=5,'doh3'=6),
  action      Enum8('none'=0,'block'=1,'bypass'=2,'redirect'=3),
  refusal     Enum8('none'=0,'hard_disabled'=1,'not_authorized'=2,'revoked'=3),
  ttl_months  UInt8,
  queries     UInt64
) ENGINE = SummingMergeTree(queries)
PARTITION BY toYYYYMMDD(ts)
ORDER BY (tenant_id, ts, endpoint_id, client_id, profile_id, profile2_id, protocol, action, refusal)
TTL ts + toIntervalDay(3)
SETTINGS non_replicated_deduplication_window = 10000, ttl_only_drop_parts = 1, min_free_disk_ratio_to_perform_insert = 0.1;

CREATE TABLE IF NOT EXISTS ctrlz.agg_category (
  tenant_id   UUID,
  bucket      DateTime('UTC'),
  endpoint_id UUID,
  profile_id  UUID,
  profile2_id UUID,
  action      Enum8('none'=0,'block'=1,'bypass'=2,'redirect'=3),
  traffic_cat UInt16,
  ttl_months  UInt8,
  queries     UInt64
) ENGINE = SummingMergeTree(queries)
PARTITION BY (ttl_months, toYYYYMM(bucket))
ORDER BY (tenant_id, bucket, endpoint_id, profile_id, profile2_id, action, traffic_cat)
TTL bucket + toIntervalMonth(ttl_months)
SETTINGS non_replicated_deduplication_window = 10000, ttl_only_drop_parts = 1, min_free_disk_ratio_to_perform_insert = 0.1;

CREATE TABLE IF NOT EXISTS ctrlz.agg_counts (
  tenant_id   UUID,
  bucket      DateTime('UTC'),
  endpoint_id UUID,
  client_id   UUID,
  profile_id  UUID,
  profile2_id UUID,
  protocol    Enum8('udp'=1,'tcp'=2,'doh'=3,'dot'=4,'doq'=5,'doh3'=6),
  action      Enum8('none'=0,'block'=1,'bypass'=2,'redirect'=3),
  refusal     Enum8('none'=0,'hard_disabled'=1,'not_authorized'=2,'revoked'=3),
  ttl_months  UInt8,
  queries     UInt64
) ENGINE = SummingMergeTree(queries)
PARTITION BY (ttl_months, toYYYYMM(bucket))
ORDER BY (tenant_id, bucket, endpoint_id, client_id, profile_id, profile2_id, protocol, action, refusal)
TTL bucket + toIntervalMonth(ttl_months)
SETTINGS non_replicated_deduplication_window = 10000, ttl_only_drop_parts = 1, min_free_disk_ratio_to_perform_insert = 0.1;

-- Everything fed by raw rows ends at 90 days whatever the aggregate retention is (D4), so the three
-- rollups below carry ttl_full_days = min(90, 30 * ttl_months) and are partitioned by it and by the week.
CREATE TABLE IF NOT EXISTS ctrlz.agg_reason (
  tenant_id      UUID,
  ref_kind       Enum8('none'=0,'rule'=1,'service'=2,'filter'=3,'exfiltration'=4,'default'=5,'system'=6,'degraded'=7),
  bucket         DateTime('UTC'),
  endpoint_id    UUID,
  client_id      UUID,
  profile_id     UUID,
  profile2_id    UUID,
  protocol       Enum8('udp'=1,'tcp'=2,'doh'=3,'dot'=4,'doq'=5,'doh3'=6),
  action         Enum8('none'=0,'block'=1,'bypass'=2,'redirect'=3),
  decision_stage Enum8('rule'=1,'geo'=2,'service'=3,'filter'=4,'default'=5,'system'=6,'soft_disabled'=7),
  decision_ref   String                 CODEC(ZSTD(1)),
  ttl_full_days  UInt8,
  queries        UInt64
) ENGINE = SummingMergeTree(queries)
PARTITION BY (ttl_full_days, toMonday(bucket))
ORDER BY (tenant_id, ref_kind, bucket, endpoint_id, client_id, profile_id, profile2_id, protocol, action, decision_stage, decision_ref)
TTL bucket + toIntervalDay(ttl_full_days)
SETTINGS non_replicated_deduplication_window = 10000, ttl_only_drop_parts = 1, min_free_disk_ratio_to_perform_insert = 0.1;

CREATE TABLE IF NOT EXISTS ctrlz.agg_geo (
  tenant_id     UUID,
  dir           Enum8('src'=1,'dst'=2),
  bucket        DateTime('UTC'),
  endpoint_id   UUID,
  client_id     UUID,
  profile_id    UUID,
  profile2_id   UUID,
  protocol      Enum8('udp'=1,'tcp'=2,'doh'=3,'dot'=4,'doq'=5,'doh3'=6),
  action        Enum8('none'=0,'block'=1,'bypass'=2,'redirect'=3),
  country       LowCardinality(String),
  asn           UInt32,
  ttl_full_days UInt8,
  queries       UInt64
) ENGINE = SummingMergeTree(queries)
PARTITION BY (ttl_full_days, toMonday(bucket))
ORDER BY (tenant_id, dir, bucket, endpoint_id, client_id, profile_id, profile2_id, protocol, action, country, asn)
TTL bucket + toIntervalDay(ttl_full_days)
SETTINGS non_replicated_deduplication_window = 10000, ttl_only_drop_parts = 1, min_free_disk_ratio_to_perform_insert = 0.1;

-- The empty name is the "Other domains" row of R40 (5.4).
CREATE TABLE IF NOT EXISTS ctrlz.agg_domain (
  tenant_id     UUID,
  bucket        Date,
  endpoint_id   UUID,
  client_id     UUID,
  profile_id    UUID,
  profile2_id   UUID,
  action        Enum8('none'=0,'block'=1,'bypass'=2,'redirect'=3),
  name          String                 CODEC(ZSTD(3)),
  ttl_full_days UInt8,
  queries       UInt64
) ENGINE = SummingMergeTree(queries)
PARTITION BY (ttl_full_days, toMonday(bucket))
ORDER BY (tenant_id, bucket, endpoint_id, client_id, profile_id, profile2_id, action, name)
TTL bucket + toIntervalDay(ttl_full_days)
SETTINGS non_replicated_deduplication_window = 10000, ttl_only_drop_parts = 1, min_free_disk_ratio_to_perform_insert = 0.1;

-- +goose Down
DROP TABLE IF EXISTS ctrlz.agg_domain;
DROP TABLE IF EXISTS ctrlz.agg_geo;
DROP TABLE IF EXISTS ctrlz.agg_reason;
DROP TABLE IF EXISTS ctrlz.agg_counts;
DROP TABLE IF EXISTS ctrlz.agg_category;
DROP TABLE IF EXISTS ctrlz.counts_5m;
