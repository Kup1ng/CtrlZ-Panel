# ClickHouse migrations

ClickHouse holds analytics only: `dns_raw`, the two tables the hub writes from counters and the five rollups
(P5 3.5). Migrations are goose files `NNNN_name.sql`, each `-- +goose NO TRANSACTION` because ClickHouse has none,
and are run by the Compose one-shot `migrate-analytics` (`ctrlz migrate-analytics`) as `ctrlz_migrator`.
goose's version table is `ctrlz_meta.schema_migrations`, so the database `ctrlz` holds data tables and views only
and every one of its tables has `tenant_id` first in its sorting key.

- 0001 and 0002: the raw table, the counter tables and the rollups.
- 0003: the materialized views, `SQL SECURITY DEFINER` with definer `ctrlz_migrator`.
- `access.sql`, which is not a migration: the row policies `tenant_only` and `maintenance` and the quota `reader`.
  The runner applies it before 0001 and again on every run, with OR REPLACE. A table with no policy at all is
  read without a filter, so the policies must exist before the first table, and they live in the server's access
  directory, which a restore of the data alone does not bring back.

The five users and their grants, profiles and constraints are `deploy/compose/clickhouse/users.xml`; the
passwords are written by the start wrapper of the `clickhouse` service from five Docker secrets.

Rules:

- Every statement is idempotent (`IF NOT EXISTS`), because a run that stopped half way is run again.
- A new table is added to the grants of `users.xml` in the same change (a lint compares the two), and its sorting
  key starts with `tenant_id`.
- Every query goes through one Go package that takes the tenant from the context (R6); the row policy is defence
  in depth, not the boundary.
- Expand-only in a release, contract one release later (R47). Sharding by `cityHash64(tenant_id)` arrives with
  stage C of the growth path (R37, R39).
