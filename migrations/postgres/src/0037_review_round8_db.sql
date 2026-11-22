-- P1 auth review round 8, database area (db-r8-1, db-r8-2).
--
-- db-r8-1: the lock order treats ctrlz.admin_users as inert (a key share on it is ignored) on the
-- premise that no statement locks it above NO KEY UPDATE. ctrlz_admin held UPDATE (username), a
-- plain UNIQUE column, and an UPDATE that changes a unique-index column takes a FOR UPDATE strength
-- lock that conflicts with the key share of every admin_sessions insert. No route renames an admin
-- (the first account is made by the key tool and nothing else changes a name), so the grant was
-- unused; it goes, and catalog check 21 now fails for any login role that holds UPDATE on a
-- unique-index column of an inert table, or DELETE on it, so the premise is read from the grants
-- and not from a sentence.
--
-- db-r8-2: ctrlz_compiler held table-level SELECT on authorized_ips and clients from P0, which
-- reaches the address and place of every tenant's client (authorized_ips.cidr, city, isp;
-- clients.hostname, mac, ip). The compiler writes ClientRecord (id, hash of the label, stack,
-- analytics override) and Prefix lists (policy.proto), none of which is a host name, a hardware
-- address, a client address, a city or a provider. It keeps the prefix itself and nothing else of
-- authorized_ips. ip_claims stays as it is: ClaimRecord carries the claimed prefix, so the compiler
-- is a declared reader of ip_claims.cidr.
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

REVOKE UPDATE (username) ON ctrlz.admin_users FROM ctrlz_admin;

REVOKE SELECT ON ctrlz.authorized_ips FROM ctrlz_compiler;
GRANT SELECT (tenant_id, id, endpoint_id, cidr) ON ctrlz.authorized_ips TO ctrlz_compiler;

REVOKE SELECT ON ctrlz.clients FROM ctrlz_compiler;
GRANT SELECT (tenant_id, id, endpoint_id, label, alias, profile_id, profile2_id, analytics_level, group_name,
              source, is_custom, first_seen_at, last_seen_at, created_at, updated_at)
  ON ctrlz.clients TO ctrlz_compiler;
