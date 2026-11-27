-- P4, package R3 (docs/specs/p4-nodes.md 9.2): the impact of a change of zone.
--
-- GET /settings/domain/impact counts the Endpoints and, of them, those that have an Apple profile, which turn stale when
-- the zone changes (3.2 item 6). The admin could read neither the column nor a count of it: its SELECT on endpoints is a
-- list of seven columns. This grants the one more, a timestamp that says when a profile was last built and holds nothing
-- of the tenant's configuration. The admin still has no UPDATE on it, and no other column opens.
--
-- A new file and not an edit of 0100 (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

GRANT SELECT (apple_profile_generated_at) ON ctrlz.endpoints TO ctrlz_admin;
