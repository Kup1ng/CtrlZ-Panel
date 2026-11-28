-- P4b, package B2 (docs/specs/p4b-proxy.md 3.2): the schema of the proxy, the Xray configs and the block page.
-- Every item of 3.2, in its order:
--
--  1. locations: the unique indexes fold the city and the label as SC 10.1 does, and the two names have a form.
--  2. node_location_configs: schema_version is the Xray release tag, last_good_fragment goes, accepted_unknown
--     comes, the CHECKs, and the trigger node_location_configs_limit that steps nodes.xray_rev and holds the
--     limits of D31.
--  3. The grants on node_location_configs: the compiler and the worker keep four columns, no role but the hub
--     and the admin sees a fragment.
--  4. location_availability follows the enabled configs (trigger location_availability_sync).
--  5. node_location_config_state: what a node reports of each config.
--  6. proxy_settings: the one row of the grant width and the probe addresses.
--  7. nodes: xray_fetch_version and xray_rev, and the admin's UPDATE of the two bind addresses and of those two.
--  8. block_roots: the account's block page root (a tenant table), and certificates without the two block kinds.
--  9. unblock_requests: the hub's reads, the forms of qname and message, the worker's read for the sweep, an index.
-- 10. The worker's reads for the sweep of 11, tenant_assets as PNG only, at most 20 rows a tenant.
-- 11. admin_jobs.kind gains locations_changed. Nothing else: job_outbox.kind is free text and the tenant holds
--     INSERT on it, and the worker already holds table-level U on the content tables (0070).
-- 12. ctrlz_fn.node_alert_close, for the hub alone.
-- 13. policy_artifacts.page_hash.
-- 14. Nothing: choosing branded makes its block_pages row in the same transaction (10.5), without a constraint.
--
-- Choices the spec leaves open, made here:
--  * The trigger functions run with the rights of the writer, like the others of the schema, because a SECURITY
--    DEFINER function may live in ctrlz_fn only (catalog check 10). The writer of node_location_configs is the
--    admin, which therefore keeps the table-level grants it has had on location_availability: nothing of the
--    application writes that table, the trigger does, and the admin cannot make a row it has no config for stay
--    there, since the trigger decides on the configs at each write. location_availability_sync takes the node's
--    row lock before it looks, as node_location_configs_limit does, so two writers of two configs of one
--    location cannot both see the other's config still enabled and leave a row that nothing justifies.
--  * schema_version had no code that wrote it, so an existing row has no tag to carry over. A database with a
--    row in node_location_configs stops here with a message, and nothing is guessed.
--  * qname is the text form that names.Name.String writes: lower case labels of [a-z0-9_-], a byte outside them
--    as \DDD, a dot inside a label as \., labels joined by dots, no trailing dot. The root is not a name a person
--    can be blocked from.
--  * A node's proxy_bind_ip had no form check (0100 holds the two DNS addresses to the five embedded-IPv4 forms),
--    and 3.2 item 7 says the bind addresses are covered; the CHECK is added here so that it is true.
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

-- 1. locations ----------------------------------------------------------------------------------

-- The fold of SC 10.1 is strings.TrimSpace and ToLower, so a city is trimmed of every character unicode.IsSpace
-- accepts, not only the ASCII spaces btrim removes. The form checks below refuse such a character at either end,
-- and with them the index on lower(btrim(...)) is the same fold as the Go one. Rows that hold one are trimmed
-- first, so the check for a pair below sees the folded form.
UPDATE ctrlz.locations SET
    city  = pg_catalog.regexp_replace(city,  '^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$', '', 'g'),
    label = pg_catalog.regexp_replace(label, '^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$', '', 'g')
  WHERE city ~ '^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]|[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]$'
     OR label ~ '^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]|[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]$';

-- Two rows that fold to one location would have two wire ids and the bitmap would miss the second. The index
-- below refuses them; a database that holds such a pair stops with a message instead of a bare 23505.
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM ctrlz.locations WHERE country_code IS NOT NULL
               GROUP BY country_code, pg_catalog.lower(pg_catalog.btrim(city)) HAVING pg_catalog.count(*) > 1)
     OR EXISTS (SELECT 1 FROM ctrlz.locations WHERE country_code IS NULL
               GROUP BY pg_catalog.lower(pg_catalog.btrim(label)) HAVING pg_catalog.count(*) > 1) THEN
    RAISE EXCEPTION 'two locations fold to one (SC 10.1): merge or remove one of each pair by hand, then run this migration again';
  END IF;
END
$$;
-- +goose StatementEnd

DROP INDEX ctrlz.locations_country_city_uq;
DROP INDEX ctrlz.locations_label_uq;
CREATE UNIQUE INDEX locations_country_city_uq ON ctrlz.locations (country_code, (pg_catalog.lower(pg_catalog.btrim(city))))
  NULLS NOT DISTINCT WHERE country_code IS NOT NULL;
CREATE UNIQUE INDEX locations_label_uq ON ctrlz.locations ((pg_catalog.lower(pg_catalog.btrim(label)))) WHERE country_code IS NULL;

ALTER TABLE ctrlz.locations
  ADD CONSTRAINT locations_city_form CHECK (city IS NULL OR (
    pg_catalog.char_length(city) BETWEEN 1 AND 64 AND city = pg_catalog.btrim(city) AND city !~ '[\u0001-\u001f\u007f-\u009f]'
    AND city !~ '^[\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]|[\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]$')),
  ADD CONSTRAINT locations_label_form CHECK (label IS NULL OR (
    pg_catalog.char_length(label) BETWEEN 1 AND 64 AND label = pg_catalog.btrim(label) AND label !~ '[\u0001-\u001f\u007f-\u009f]'
    AND label !~ '^[\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]|[\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]$'));

-- 7. nodes: the counter the trigger of item 2 steps ---------------------------------------------

-- Before item 2, whose trigger writes it.
ALTER TABLE ctrlz.nodes
  -- At most 32 bytes, as xrayschema.ValidReleaseTag holds it: a longer tag would pass here and then make the node's
  -- NodeConfig fail wire.ValidateNodeConfig, so that node could be sent no config at all.
  ADD COLUMN xray_fetch_version text CONSTRAINT nodes_xray_fetch_version_form CHECK (
    xray_fetch_version ~ '^v[0-9]+\.[0-9]+\.[0-9]+$' AND pg_catalog.char_length(xray_fetch_version) <= 32),
  ADD COLUMN xray_rev bigint NOT NULL DEFAULT 0 CONSTRAINT nodes_xray_rev_not_negative CHECK (xray_rev >= 0);

ALTER TABLE ctrlz.nodes ADD CONSTRAINT nodes_proxy_bind_ip_form CHECK (proxy_bind_ip IS NULL OR (
  pg_catalog.masklen(proxy_bind_ip) = (CASE pg_catalog.family(proxy_bind_ip) WHEN 4 THEN 32 ELSE 128 END)
  AND NOT (
    proxy_bind_ip <<= '::ffff:0:0/96'::pg_catalog.inet OR proxy_bind_ip <<= '64:ff9b::/96'::pg_catalog.inet
    OR proxy_bind_ip <<= '::/96'::pg_catalog.inet OR proxy_bind_ip <<= '2002::/16'::pg_catalog.inet
    OR proxy_bind_ip <<= '2001::/32'::pg_catalog.inet)));

GRANT UPDATE (dns_bind_ip, proxy_bind_ip, xray_fetch_version, xray_rev) ON ctrlz.nodes TO ctrlz_admin;

-- The hub reads the fragments again only when xray_rev moved, so a counter put back to the value it cached (the admin
-- holds UPDATE on the column, because the trigger of item 2 runs as the writer) would hide a removed credential. The
-- counter therefore never goes down, whoever writes it. Nor does it jump far: a counter set to the top of bigint would
-- make the step of the limit trigger overflow, so no config of that node could be written again, and nothing that can
-- write the counter could put it back (B2-r2-3). The trigger of item 2 steps by 1, so a step of a million is far above
-- any use, and the top of bigint is then out of reach of any number of writes.
-- +goose StatementBegin
CREATE FUNCTION ctrlz.nodes_xray_rev_forward() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  -- Two statements, not one OR: Postgres does not promise the order of the two sides, and the difference of a negative
  -- value from a large one would overflow.
  IF NEW.xray_rev < OLD.xray_rev THEN
    RAISE EXCEPTION 'nodes.xray_rev only moves forward'
      USING ERRCODE = 'check_violation', CONSTRAINT = 'nodes_xray_rev_forward';
  END IF;
  IF NEW.xray_rev - OLD.xray_rev > 1000000 THEN
    RAISE EXCEPTION 'nodes.xray_rev moves by at most a million at a time'
      USING ERRCODE = 'check_violation', CONSTRAINT = 'nodes_xray_rev_forward';
  END IF;
  RETURN NEW;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz.nodes_xray_rev_forward() FROM PUBLIC;
CREATE TRIGGER nodes_xray_rev_forward BEFORE UPDATE OF xray_rev ON ctrlz.nodes
  FOR EACH ROW EXECUTE FUNCTION ctrlz.nodes_xray_rev_forward();

-- 2 and 3. node_location_configs ----------------------------------------------------------------

-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM ctrlz.node_location_configs) THEN
    RAISE EXCEPTION 'node_location_configs holds rows, and schema_version was an integer that named no Xray release: remove them, then run this migration again';
  END IF;
END
$$;
-- +goose StatementEnd

ALTER TABLE ctrlz.node_location_configs DROP COLUMN last_good_fragment;
ALTER TABLE ctrlz.node_location_configs ALTER COLUMN schema_version DROP DEFAULT;
ALTER TABLE ctrlz.node_location_configs ALTER COLUMN schema_version TYPE text USING schema_version::pg_catalog.text;
ALTER TABLE ctrlz.node_location_configs
  ADD COLUMN accepted_unknown text[] NOT NULL DEFAULT '{}',
  ADD CONSTRAINT node_location_configs_schema_version_form CHECK (
    schema_version ~ '^v[0-9]+\.[0-9]+\.[0-9]+$' AND pg_catalog.char_length(schema_version) <= 32),
  ADD CONSTRAINT node_location_configs_fragment_size CHECK (pg_catalog.octet_length(fragment::pg_catalog.text) <= 32768),
  ADD CONSTRAINT node_location_configs_note_len CHECK (pg_catalog.char_length(note) <= 500),
  ADD CONSTRAINT node_location_configs_tag_form CHECK (tag ~ '^[a-z0-9][a-z0-9-]{0,31}$'),
  ADD CONSTRAINT node_location_configs_priority_range CHECK (priority BETWEEN 0 AND 99),
  -- The bounds of wire.ValidateNodeConfig (64 paths of at most 256 bytes), so that one bad write cannot make
  -- the config of a whole node unreadable or unsendable. The elements are joined with a control character that no
  -- path holds, so one pattern bounds each of them; the form of a path is the route's and the validator's. A run of
  -- 257 is written as 255 and 2: Postgres refuses a repetition count above 255 (SQLSTATE 2201B). The limit is in bytes
  -- (xrayschema.ValidPath), a regular expression counts characters, and a path is ASCII only, so every element is held to
  -- the printable ASCII characters: then a character is a byte (B2-r2-1).
  ADD CONSTRAINT node_location_configs_accepted_unknown_bounds CHECK (
    pg_catalog.cardinality(accepted_unknown) <= 64
    AND pg_catalog.array_position(accepted_unknown, NULL::pg_catalog.text) IS NULL
    AND pg_catalog.array_to_string(accepted_unknown, pg_catalog.chr(1)) !~ ('[^ -~' || pg_catalog.chr(1) || ']')
    AND pg_catalog.array_to_string(accepted_unknown, pg_catalog.chr(1)) !~ ('[^' || pg_catalog.chr(1) || ']{255}[^' || pg_catalog.chr(1) || ']{2}'));

-- Every write of a config steps the counter of its node: the node row's lock orders the writers of one node, and
-- the hub reads the fragments again only when the counter moved (11). The limits are D31's: 64 configs and 2 MiB
-- of fragments a node, counted after the write, under that lock. A statement that moves a config to another node
-- steps both.
-- +goose StatementBegin
CREATE FUNCTION ctrlz.node_location_configs_limit() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_a     uuid;
  v_b     uuid;
  v_rows  bigint;
  v_bytes bigint;
BEGIN
  IF TG_OP = 'INSERT' THEN
    v_a := NEW.node_id;
    v_b := NEW.node_id;
  ELSIF TG_OP = 'DELETE' THEN
    v_a := OLD.node_id;
    v_b := OLD.node_id;
  ELSE
    v_a := OLD.node_id;
    v_b := NEW.node_id;
  END IF;
  UPDATE ctrlz.nodes SET xray_rev = xray_rev + 1 WHERE id = v_a;
  IF v_b <> v_a THEN
    UPDATE ctrlz.nodes SET xray_rev = xray_rev + 1 WHERE id = v_b;
  END IF;
  IF TG_OP <> 'DELETE' THEN
    SELECT pg_catalog.count(*), COALESCE(pg_catalog.sum(pg_catalog.octet_length(fragment::pg_catalog.text)), 0)
      INTO v_rows, v_bytes
      FROM ctrlz.node_location_configs WHERE node_id = NEW.node_id;
    IF v_rows > 64 OR v_bytes > 2097152 THEN
      RAISE EXCEPTION 'a node holds at most 64 configs and 2 MiB of fragments'
        USING ERRCODE = 'check_violation', CONSTRAINT = 'node_location_configs_limit';
    END IF;
  END IF;
  RETURN NULL;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz.node_location_configs_limit() FROM PUBLIC;
CREATE TRIGGER node_location_configs_limit AFTER INSERT OR UPDATE OR DELETE ON ctrlz.node_location_configs
  FOR EACH ROW EXECUTE FUNCTION ctrlz.node_location_configs_limit();

-- The compiler and the worker read which config is enabled where and nothing of it; the table-level SELECT of
-- 0007 gave them the fragment too. A column grant is not narrowed by a column REVOKE, so the table-level one goes.
REVOKE SELECT ON ctrlz.node_location_configs FROM ctrlz_compiler, ctrlz_worker;
GRANT SELECT (id, node_id, location_id, enabled) ON ctrlz.node_location_configs TO ctrlz_compiler, ctrlz_worker;

-- 4. location_availability ----------------------------------------------------------------------

-- A row exists exactly while an enabled config exists for (node, location). The node's row is locked first, so
-- two transactions that each switch off one of two configs of a location wait for each other and the second
-- sees the first's write; without it both would still see the other's config enabled and neither would delete.
-- The rows of the nodes are locked in id order.
-- +goose StatementBegin
CREATE FUNCTION ctrlz.location_availability_sync() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_a uuid;
  v_b uuid;
BEGIN
  IF TG_OP = 'INSERT' THEN
    v_a := NEW.node_id;
    v_b := NEW.node_id;
  ELSIF TG_OP = 'DELETE' THEN
    v_a := OLD.node_id;
    v_b := OLD.node_id;
  ELSE
    v_a := OLD.node_id;
    v_b := NEW.node_id;
  END IF;
  PERFORM 1 FROM ctrlz.nodes WHERE id IN (v_a, v_b) ORDER BY id FOR NO KEY UPDATE;
  IF TG_OP <> 'INSERT' THEN
    IF EXISTS (SELECT 1 FROM ctrlz.node_location_configs WHERE node_id = OLD.node_id AND location_id = OLD.location_id AND enabled) THEN
      INSERT INTO ctrlz.location_availability (node_id, location_id) VALUES (OLD.node_id, OLD.location_id) ON CONFLICT DO NOTHING;
    ELSE
      DELETE FROM ctrlz.location_availability WHERE node_id = OLD.node_id AND location_id = OLD.location_id;
    END IF;
  END IF;
  IF TG_OP <> 'DELETE' THEN
    IF EXISTS (SELECT 1 FROM ctrlz.node_location_configs WHERE node_id = NEW.node_id AND location_id = NEW.location_id AND enabled) THEN
      INSERT INTO ctrlz.location_availability (node_id, location_id) VALUES (NEW.node_id, NEW.location_id) ON CONFLICT DO NOTHING;
    ELSE
      DELETE FROM ctrlz.location_availability WHERE node_id = NEW.node_id AND location_id = NEW.location_id;
    END IF;
  END IF;
  RETURN NULL;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz.location_availability_sync() FROM PUBLIC;
CREATE TRIGGER location_availability_sync AFTER INSERT OR UPDATE OF node_id, location_id, enabled OR DELETE ON ctrlz.node_location_configs
  FOR EACH ROW EXECUTE FUNCTION ctrlz.location_availability_sync();

-- Whatever the table held before the trigger is made to say what the configs say.
INSERT INTO ctrlz.location_availability (node_id, location_id)
  SELECT DISTINCT node_id, location_id FROM ctrlz.node_location_configs WHERE enabled
  ON CONFLICT DO NOTHING;
DELETE FROM ctrlz.location_availability a WHERE NOT EXISTS (
  SELECT 1 FROM ctrlz.node_location_configs c WHERE c.node_id = a.node_id AND c.location_id = a.location_id AND c.enabled);

-- 5. node_location_config_state -----------------------------------------------------------------

-- What a node reports of each config (Heartbeat.xray_configs). node_id is not a foreign key: a report names the
-- node that sent it, and the hub drops one for a config of another node. A removed config takes its state.
CREATE TABLE ctrlz.node_location_config_state (
  config_id       uuid PRIMARY KEY REFERENCES ctrlz.node_location_configs (id) ON DELETE CASCADE,
  node_id         uuid NOT NULL,
  fragment_sha256 bytea CHECK (pg_catalog.octet_length(fragment_sha256) = 32),
  state           text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'applied', 'refused', 'last_good')),
  error           text CHECK (pg_catalog.char_length(error) <= 500),
  healthy         boolean,
  latency_ms      integer CHECK (latency_ms >= 0),
  reported_at     timestamptz NOT NULL DEFAULT pg_catalog.now()
);
CREATE INDEX node_location_config_state_node_idx ON ctrlz.node_location_config_state (node_id);
GRANT SELECT, INSERT, UPDATE ON ctrlz.node_location_config_state TO ctrlz_hub;
GRANT SELECT ON ctrlz.node_location_config_state TO ctrlz_admin;

-- 6. proxy_settings -----------------------------------------------------------------------------

CREATE TABLE ctrlz.proxy_settings (
  singleton   boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  grant_width text NOT NULL DEFAULT 'exact' CHECK (grant_width IN ('exact', 'prefix24', 'carrier')),
  probe_urls  text[] NOT NULL DEFAULT ARRAY['http://www.gstatic.com/generate_204', 'http://cp.cloudflare.com/generate_204']::pg_catalog.text[]
    CONSTRAINT proxy_settings_probe_urls_count CHECK (
      pg_catalog.cardinality(probe_urls) BETWEEN 1 AND 2 AND pg_catalog.array_position(probe_urls, NULL::pg_catalog.text) IS NULL)
    -- http or https, printable ASCII without a space, at most 256 bytes (wire.ValidateNodeConfig refuses the rest, and
    -- the row is global: one bad value would stop every node's config).
    CONSTRAINT proxy_settings_probe_urls_form CHECK (
      pg_catalog.array_to_string(probe_urls, pg_catalog.chr(1)) ~ ('^https?://[!-~]+(' || pg_catalog.chr(1) || 'https?://[!-~]+)?$')
      AND pg_catalog.array_to_string(probe_urls, pg_catalog.chr(1)) !~ '[!-~]{255}[!-~]{2}'),  -- 257 in a row; a count above 255 is refused
  updated_at  timestamptz NOT NULL DEFAULT pg_catalog.now()
);
CREATE TRIGGER touch_updated_at BEFORE UPDATE ON ctrlz.proxy_settings
  FOR EACH ROW EXECUTE FUNCTION ctrlz.touch_updated_at();
INSERT INTO ctrlz.proxy_settings DEFAULT VALUES;
GRANT SELECT ON ctrlz.proxy_settings TO ctrlz_hub;
GRANT SELECT, UPDATE (grant_width, probe_urls) ON ctrlz.proxy_settings TO ctrlz_admin;

-- 8. block_roots and certificates ---------------------------------------------------------------

-- The account's block page root. The row is empty until the hub gives it a certificate (10.3); the key is
-- derived from block_root_key at each use and kept nowhere, so no column holds one. Every writer of a block_pages
-- row adds the empty row (10.5), and the tenant may insert nothing but the key of it.
CREATE TABLE ctrlz.block_roots (
  tenant_id    uuid PRIMARY KEY REFERENCES ctrlz.tenants (id) ON DELETE CASCADE,
  cert_der     bytea,
  spki_sha256  bytea,
  not_before   timestamptz,
  not_after    timestamptz,
  created_at   timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT block_roots_cert_together CHECK (
    (cert_der IS NULL) = (spki_sha256 IS NULL) AND (cert_der IS NULL) = (not_before IS NULL) AND (cert_der IS NULL) = (not_after IS NULL)),
  CONSTRAINT block_roots_cert_form CHECK (
    (cert_der IS NULL OR pg_catalog.octet_length(cert_der) BETWEEN 1 AND 4096)
    AND (spki_sha256 IS NULL OR pg_catalog.octet_length(spki_sha256) = 32)
    AND (not_after IS NULL OR not_after > not_before))
);
{{rls "ctrlz.block_roots"}}
-- The pass of every 5 s looks only for rows with no certificate; the partial index keeps that read to them however
-- many accounts have a certificate. The pass at start reads every row for the SPKI comparison.
CREATE INDEX block_roots_empty_idx ON ctrlz.block_roots (tenant_id) WHERE cert_der IS NULL;
GRANT SELECT, INSERT (tenant_id) ON ctrlz.block_roots TO ctrlz_tenant;
GRANT SELECT, UPDATE (cert_der, spki_sha256, not_before, not_after) ON ctrlz.block_roots TO ctrlz_hub;
-- The hub serves every account, so it sees and writes every row, as the compiler's drain does for the outbox.
CREATE POLICY hub_read ON ctrlz.block_roots AS PERMISSIVE FOR SELECT TO ctrlz_hub USING (true);
CREATE POLICY hub_issue ON ctrlz.block_roots AS PERMISSIVE FOR UPDATE TO ctrlz_hub USING (true) WITH CHECK (true);

-- Nothing writes a block root as a certificate row (the root is a column of block_roots and the key is
-- derived), so the two kinds go from the list.
ALTER TABLE ctrlz.certificates DROP CONSTRAINT certificates_kind_check;
ALTER TABLE ctrlz.certificates ADD CONSTRAINT certificates_kind_check
  CHECK (kind IN ('wildcard', 'panel', 'admin', 'node_ca', 'zone_ca'));

-- 9. unblock_requests ---------------------------------------------------------------------------

ALTER TABLE ctrlz.unblock_requests
  ADD CONSTRAINT unblock_requests_qname_form CHECK (
    pg_catalog.char_length(qname) BETWEEN 1 AND 253
    AND qname ~ '^([a-z0-9_-]|\\[0-9]{3}|\\\.)+(\.([a-z0-9_-]|\\[0-9]{3}|\\\.)+)*$'),
  ADD CONSTRAINT unblock_requests_message_len CHECK (pg_catalog.char_length(message) <= 500);
CREATE INDEX unblock_requests_status_idx ON ctrlz.unblock_requests (tenant_id, status, created_at);
-- The hub looks for an equal (Endpoint, name) still open and counts the open rows, inside the tenant of the
-- request (the policy bounds the rows); the worker's sweep filters on the age.
GRANT SELECT (endpoint_id, qname, status, created_at) ON ctrlz.unblock_requests TO ctrlz_hub;
GRANT SELECT (created_at) ON ctrlz.unblock_requests TO ctrlz_worker;

-- 10. tenant_assets -----------------------------------------------------------------------------

-- assets.Store (10.5) decodes a logo and writes it again as PNG, so a row of any other type is not its work.
-- Validated, as the catalog check 28 requires of every constraint. 0003 allowed JPEG and WebP, but nothing on main wrote a
-- row of this table (assets.Store is its first writer), so the table is empty on any installed database and the scan
-- finds nothing; a row of another type would stop the migration with a check violation, which is the loud answer.
ALTER TABLE ctrlz.tenant_assets ADD CONSTRAINT tenant_assets_png_only CHECK (mime = 'image/png');

-- At most 20 rows a tenant (D31). assets.Store decides it first under the quota lock of the tenant; this takes the
-- same lock before it counts, so two writers of one tenant meet here even when one of them skipped QuotaLock (the lock
-- is re-entrant inside one transaction). In READ COMMITTED the count then runs on a snapshot taken after the wait. A
-- writer that holds no tenant setting (the seed, a superuser) locks nothing: the function answers false for it.
-- +goose StatementBegin
CREATE FUNCTION ctrlz.tenant_assets_limit() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  PERFORM ctrlz_fn.profile_tenant_lock();
  IF (SELECT pg_catalog.count(*) FROM ctrlz.tenant_assets WHERE tenant_id = NEW.tenant_id) >= 20 THEN
    RAISE EXCEPTION 'a tenant holds at most 20 assets'
      USING ERRCODE = 'check_violation', CONSTRAINT = 'tenant_assets_limit';
  END IF;
  RETURN NEW;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz.tenant_assets_limit() FROM PUBLIC;
CREATE TRIGGER tenant_assets_limit BEFORE INSERT ON ctrlz.tenant_assets
  FOR EACH ROW EXECUTE FUNCTION ctrlz.tenant_assets_limit();

-- The sweep of 11 deletes an asset older than a day that no block_pages row names.
GRANT SELECT (id, created_at) ON ctrlz.tenant_assets TO ctrlz_worker;
GRANT SELECT (logo_asset_id) ON ctrlz.block_pages TO ctrlz_worker;

-- 11. admin_jobs --------------------------------------------------------------------------------

ALTER TABLE ctrlz.admin_jobs DROP CONSTRAINT admin_jobs_kind_check;
ALTER TABLE ctrlz.admin_jobs ADD CONSTRAINT admin_jobs_kind_check
  CHECK (kind IN ('registration_transition', 'webauthn_rp_change', 'pair_change', 'domain_change', 'node_revoked', 'locations_changed'));

-- 13. policy_artifacts --------------------------------------------------------------------------

-- On the row of a profile blob: the block page it names (6.2). Nobody reads it but the compiler, which writes it
-- (table-level grants), and the hub, which serves the blobs.
ALTER TABLE ctrlz.policy_artifacts
  ADD COLUMN page_hash bytea CONSTRAINT policy_artifacts_page_hash_len CHECK (pg_catalog.octet_length(page_hash) = 32);

-- 12. ctrlz_fn.node_alert_close -----------------------------------------------------------------

-- The hub raises an alert with INSERT only and, when the condition is gone, closes it here: the one UPDATE of
-- alerts it has, which sets resolved_at of the open row of one kind and one node, for the kinds of 11 and no other.
-- The row is named by params.key, the node's id as text (alerts_open_key_uq, 0011). It answers how many rows it
-- closed, which is one or none. ctrlz_auth owns it because it is not about a tenant and needs UPDATE on alerts.
GRANT SELECT (id, kind, params, resolved_at), UPDATE (resolved_at) ON ctrlz.alerts TO ctrlz_auth;

SET ROLE ctrlz_auth;
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.node_alert_close(p_kind text, p_node uuid) RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_closed integer;
BEGIN
  -- The ordered shape of every multi-row writer (db-r16-19): the open row of a kind and a node is one by
  -- alerts_open_key_uq, but that index is partial, so the statement names its rows by id, locked in id order.
  UPDATE ctrlz.alerts SET resolved_at = pg_catalog.now()
  WHERE id = ANY (ARRAY(
    SELECT s.id FROM ctrlz.alerts s
    WHERE s.resolved_at IS NULL AND s.kind = p_kind AND (s.params ->> 'key') = p_node::pg_catalog.text
      AND s.kind = ANY (ARRAY['nft_failed', 'xray_down', 'block_key_missing', 'grants_full', 'xray_stuck',
                              'location_down', 'xray_upgrade_blocked', 'proxy_unreachable']::pg_catalog.text[])
    ORDER BY s.id FOR NO KEY UPDATE));
  GET DIAGNOSTICS v_closed = ROW_COUNT;
  RETURN v_closed;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.node_alert_close(text, uuid) FROM PUBLIC;
-- The schema first: EXECUTE alone is refused with 42501 when the role cannot reach the schema. The hub holds no
-- other function of ctrlz_fn, so USAGE grants nothing else.
GRANT USAGE ON SCHEMA ctrlz_fn TO ctrlz_hub;
GRANT EXECUTE ON FUNCTION ctrlz_fn.node_alert_close(text, uuid) TO ctrlz_hub;
RESET ROLE;
