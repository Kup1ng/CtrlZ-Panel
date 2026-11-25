-- +goose NO TRANSACTION
-- +goose Up
-- P5 3.5: the materialized views that feed the rollups. They run as their definer, ctrlz_migrator, so the
-- hub's user needs INSERT on the three tables it writes and on no rollup. Nobody is granted SELECT on a
-- view. A bucket is 30 minutes because an hour cannot hold the day boundary of UTC+3:30.

CREATE MATERIALIZED VIEW IF NOT EXISTS ctrlz.mv_counts TO ctrlz.agg_counts
DEFINER = ctrlz_migrator SQL SECURITY DEFINER
AS SELECT
  tenant_id,
  toStartOfInterval(ts, toIntervalMinute(30)) AS bucket,
  endpoint_id, client_id, profile_id, profile2_id, protocol, action, refusal, ttl_months,
  sum(queries) AS queries
FROM ctrlz.counts_5m
GROUP BY ALL;

CREATE MATERIALIZED VIEW IF NOT EXISTS ctrlz.mv_reason TO ctrlz.agg_reason
DEFINER = ctrlz_migrator SQL SECURITY DEFINER
AS SELECT
  tenant_id, ref_kind,
  toStartOfInterval(ts, toIntervalMinute(30)) AS bucket,
  endpoint_id, client_id, profile_id, profile2_id, protocol, action, decision_stage, decision_ref,
  toUInt8(least(90, 30 * ttl_months)) AS ttl_full_days,
  count() AS queries
FROM ctrlz.dns_raw
GROUP BY ALL;

CREATE MATERIALIZED VIEW IF NOT EXISTS ctrlz.mv_geo_src TO ctrlz.agg_geo
DEFINER = ctrlz_migrator SQL SECURITY DEFINER
AS SELECT
  tenant_id, 'src' AS dir,
  toStartOfInterval(ts, toIntervalMinute(30)) AS bucket,
  endpoint_id, client_id, profile_id, profile2_id, protocol, action,
  source_country AS country, source_asn AS asn,
  toUInt8(least(90, 30 * ttl_months)) AS ttl_full_days,
  count() AS queries
FROM ctrlz.dns_raw
GROUP BY ALL;

CREATE MATERIALIZED VIEW IF NOT EXISTS ctrlz.mv_geo_dst TO ctrlz.agg_geo
DEFINER = ctrlz_migrator SQL SECURITY DEFINER
AS SELECT
  tenant_id, 'dst' AS dir,
  toStartOfInterval(ts, toIntervalMinute(30)) AS bucket,
  endpoint_id, client_id, profile_id, profile2_id, protocol, action,
  answer_country AS country, asn,
  toUInt8(least(90, 30 * ttl_months)) AS ttl_full_days,
  count() AS queries
FROM ctrlz.dns_raw
WHERE answer_country != '' OR asn != 0
GROUP BY ALL;

-- The day is the Tehran day (UTC+3:30), the one a user reads. A name outside the first
-- 300,000 of the day's cost is the empty "Other domains" name (5.4).
CREATE MATERIALIZED VIEW IF NOT EXISTS ctrlz.mv_domain TO ctrlz.agg_domain
DEFINER = ctrlz_migrator SQL SECURITY DEFINER
AS SELECT
  tenant_id,
  toDate(ts, 'Asia/Tehran') AS bucket,
  endpoint_id, client_id, profile_id, profile2_id, action,
  if(in_domains = 1, qname_norm, '') AS name,
  toUInt8(least(90, 30 * ttl_months)) AS ttl_full_days,
  count() AS queries
FROM ctrlz.dns_raw
GROUP BY ALL;

-- +goose Down
DROP VIEW IF EXISTS ctrlz.mv_domain;
DROP VIEW IF EXISTS ctrlz.mv_geo_dst;
DROP VIEW IF EXISTS ctrlz.mv_geo_src;
DROP VIEW IF EXISTS ctrlz.mv_reason;
DROP VIEW IF EXISTS ctrlz.mv_counts;
