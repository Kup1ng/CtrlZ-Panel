-- P2, package B3 review round 13 (p2-B3-r13-4, r13-8): indexes on the profile foreign keys of the tables P3 fills.
--
-- clients, schedule_windows and unblock_requests name a profile (profile_id, profile2_id) and had no index on it. Three
-- paths of P2 ask "who names this profile": the location set of a profile (and every write that sets a Redirect target,
-- through the allowed set), the lock of the clients before a profile delete, and the foreign keys of that delete
-- itself (ON DELETE SET NULL of clients, RESTRICT of schedule_windows, CASCADE of unblock_requests). Each walked every
-- client of the tenant (50 endpoints of 1,000 clients is 50,000 rows) to find none, up to three times in one delete, with
-- the profile's guard held. With these indexes each reads the rows that name the profile.
--
-- Partial where the column is nullable and mostly NULL, so the index holds only the rows that name a profile; the
-- planner uses a partial index for an equality on its column, which is how both the statements and the foreign key
-- checks ask. Every index leads with tenant_id, as every tenant query does (RULES). A new file and not an edit of an
-- applied one (README, Rules); plain CREATE INDEX, the migrator runs in a transaction and the tables are small until P3.

-- +goose Up

SET LOCAL search_path = pg_catalog;

CREATE INDEX clients_profile_idx ON ctrlz.clients (tenant_id, profile_id) WHERE profile_id IS NOT NULL;
CREATE INDEX clients_profile2_idx ON ctrlz.clients (tenant_id, profile2_id) WHERE profile2_id IS NOT NULL;
CREATE INDEX schedule_windows_profile_idx ON ctrlz.schedule_windows (tenant_id, profile_id);
CREATE INDEX schedule_windows_profile2_idx ON ctrlz.schedule_windows (tenant_id, profile2_id) WHERE profile2_id IS NOT NULL;
CREATE INDEX unblock_requests_profile_idx ON ctrlz.unblock_requests (tenant_id, profile_id);
