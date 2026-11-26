-- P3, package D1 (docs/specs/p3-endpoints.md section 2.3): the Endpoint types and version 0 of the common
-- domains. The data lives in migrations/seed/*.json and is expanded here, as in 0071, so a reviewer reads
-- rows and the two cannot drift (genmig -check). A later change of either is a new migration; from P6 each
-- imported catalog version carries its own common domains, and version 0 is read only while no version
-- is current (7.3).
--
-- Nothing here is tenant data: both tables are global, and the migrator owns them.

-- +goose Up

SET LOCAL search_path = pg_catalog;

{{seed "endpoint_types"}}

{{seed "catalog_common_domains"}}
