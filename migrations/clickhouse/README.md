# ClickHouse migrations

Empty on purpose. ClickHouse holds analytics only (`dns_raw` and its rollups) and arrives in P5.

What is already decided, so the first migration here follows it:

- Tables are `ORDER BY (tenant_id, ...)`, partitioned by retention class, and sharded by `cityHash64(tenant_id)` when stage C of the growth path arrives (R37, R39).
- Every query goes through one Go package that takes the tenant from the context, adds `WHERE tenant_id = {t:UUID}`, binds every parameter and allow-lists sort and filter columns (R6). A row policy on the database is defence in depth, not the boundary.
- Migrations here are numbered `NNNN_name.sql`, expand-only in a release, contract one release later (R47), and run by the same `ctrlz migrate` command once it learns a second target.
