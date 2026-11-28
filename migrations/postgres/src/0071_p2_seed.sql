-- P2, package B1 (docs/specs/p2-profiles.md section 2.3): the catalog seed. The data lives in
-- migrations/seed/*.json and is expanded here, so a reviewer reads rows, not INSERT text, and the
-- two cannot drift (genmig -check). P6's importer later upserts on the same keys; wire_id values
-- are fixed in the files and never reused (SC 9.5). A later change of the seed is a new migration.
--
-- Nothing here is tenant data: every table is global, and the migrator owns them.

-- +goose Up

SET LOCAL search_path = pg_catalog;

{{seed "catalog_filter"}}

{{seed "catalog_filter_mode"}}

{{seed "catalog_service_category"}}

{{seed "catalog_service"}}

{{seed "catalog_service_domain"}}

-- D42: the domains of the services above that must never be redirected and that the built-in
-- .ir and .ایران rule does not cover. The complete list is P6's (T-527).
{{seed "catalog_no_redirect_domain"}}

{{seed "profile_presets"}}
