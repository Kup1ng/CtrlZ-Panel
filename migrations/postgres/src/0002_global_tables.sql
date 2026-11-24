-- Global tables: no tenant_id, no RLS, reach by explicit grant only.
-- Spec section 5. No global table references a tenant row with an FK.
-- `announcements.tenant_id` and `invites.accepted_tenant_id` are plain values.

-- +goose Up

SET LOCAL search_path = ctrlz, pg_catalog;

-- Nodes and pairs ----------------------------------------------------------

CREATE TABLE nodes (
  id                  uuid PRIMARY KEY DEFAULT uuidv7(),
  -- slot makes a fifth node impossible in the database itself (D25).
  slot                smallint NOT NULL UNIQUE CONSTRAINT nodes_slot_range CHECK (slot BETWEEN 1 AND 4),
  name                text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
  status              text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'draining', 'revoked')),
  dns_bind_ip         inet,
  dns_advertised_ip   inet,
  proxy_bind_ip       inet,
  proxy_advertised_ip inet,
  cert_serial         text,
  spki_sha256         bytea CHECK (spki_sha256 IS NULL OR octet_length(spki_sha256) = 32),
  resolve_mode        text NOT NULL DEFAULT 'recursive' CHECK (resolve_mode IN ('recursive', 'upstream', 'mixed')),
  last_heartbeat_at   timestamptz,
  version_info        jsonb NOT NULL DEFAULT '{}',
  applied_seq         bigint NOT NULL DEFAULT 0,
  proxy_blocked       boolean NOT NULL DEFAULT false,
  {{ts}}
);
{{touch "nodes"}}

CREATE TABLE node_pairs (
  id               uuid PRIMARY KEY DEFAULT uuidv7(),
  primary_node_id  uuid NOT NULL REFERENCES nodes (id),
  fallback_node_id uuid NOT NULL REFERENCES nodes (id),
  {{ts}},
  CONSTRAINT node_pairs_distinct CHECK (primary_node_id <> fallback_node_id)
);
{{touch "node_pairs"}}

-- Singletons -----------------------------------------------------------------

-- Only global_pair_id lives here, so tenants can read the pair without a grant
-- on settings (R4).
CREATE TABLE public_settings (
  singleton      boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  global_pair_id uuid REFERENCES node_pairs (id),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
{{touch "public_settings"}}
INSERT INTO public_settings DEFAULT VALUES;

CREATE TABLE system_settings (
  singleton          boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  registration_mode  text NOT NULL DEFAULT 'closed' CHECK (registration_mode IN ('closed', 'invite', 'open')),
  open_grace_days    integer NOT NULL DEFAULT 14 CHECK (open_grace_days BETWEEN 1 AND 365),
  takeover_idle_days integer NOT NULL DEFAULT 7 CHECK (takeover_idle_days BETWEEN 1 AND 365),
  updated_at         timestamptz NOT NULL DEFAULT now()
);
{{touch "system_settings"}}
INSERT INTO system_settings DEFAULT VALUES;

CREATE TABLE domain_settings (
  singleton        boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  dns_zone         text,
  panel_host       text,
  admin_host       text,
  prev_dns_zone    text,
  transition_until timestamptz,
  updated_at       timestamptz NOT NULL DEFAULT now()
);
{{touch "domain_settings"}}
INSERT INTO domain_settings DEFAULT VALUES;

CREATE TABLE webauthn_config (
  singleton       boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  rp_id           text,
  allowed_origins text[] NOT NULL DEFAULT '{}',
  enabled         boolean NOT NULL DEFAULT false,
  updated_at      timestamptz NOT NULL DEFAULT now()
);
{{touch "webauthn_config"}}
INSERT INTO webauthn_config DEFAULT VALUES;

-- Same columns as tenant_entitlements, but never NULL. The numbers are
-- provisional until the P4 load test (D31).
CREATE TABLE entitlement_defaults (
  singleton                 boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  max_profiles              integer NOT NULL DEFAULT 20    CHECK (max_profiles >= 0),
  max_endpoints             integer NOT NULL DEFAULT 50    CHECK (max_endpoints >= 0),
  max_clients_per_endpoint  integer NOT NULL DEFAULT 1000  CHECK (max_clients_per_endpoint >= 0),
  max_authorized_ips        integer NOT NULL DEFAULT 50    CHECK (max_authorized_ips >= 0),
  max_api_tokens            integer NOT NULL DEFAULT 10    CHECK (max_api_tokens >= 0),
  max_rules_per_request     integer NOT NULL DEFAULT 1000  CHECK (max_rules_per_request >= 0),
  max_rules_per_profile     integer NOT NULL DEFAULT 10000 CHECK (max_rules_per_profile >= 0),
  max_wildcards_per_profile integer NOT NULL DEFAULT 1000  CHECK (max_wildcards_per_profile >= 0),
  max_realtime_sessions     integer NOT NULL DEFAULT 3     CHECK (max_realtime_sessions >= 0),
  max_publishes_per_hour    integer NOT NULL DEFAULT 120   CHECK (max_publishes_per_hour >= 0),
  updated_at                timestamptz NOT NULL DEFAULT now()
);
{{touch "entitlement_defaults"}}
INSERT INTO entitlement_defaults DEFAULT VALUES;

-- Coordination ---------------------------------------------------------------

CREATE TABLE leases (
  name       text PRIMARY KEY,
  holder     text NOT NULL,
  expires_at timestamptz NOT NULL
);

-- Admin ---------------------------------------------------------------------

CREATE TABLE admin_users (
  id                   uuid PRIMARY KEY DEFAULT uuidv7(),
  username             text NOT NULL UNIQUE CHECK (char_length(username) BETWEEN 1 AND 64),
  password_hash        text NOT NULL,
  totp_secret_ct       bytea,
  totp_last_step       bigint,
  must_change_password boolean NOT NULL DEFAULT true,
  disabled_at          timestamptz,
  {{ts}}
);
{{touch "admin_users"}}

CREATE TABLE admin_sessions (
  id                  uuid PRIMARY KEY DEFAULT uuidv7(),
  admin_id            uuid NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
  token_hash          bytea NOT NULL UNIQUE,
  idle_expires_at     timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  totp_verified_at    timestamptz,
  revoked_at          timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now()
);

-- Insert only. The chain is prev_hash -> entry_hash (R44).
CREATE TABLE audit_log (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  at         timestamptz NOT NULL DEFAULT now(),
  admin_id   uuid,
  action     text NOT NULL,
  target     text,
  params     jsonb NOT NULL DEFAULT '{}',
  prev_hash  bytea,
  entry_hash bytea NOT NULL
);

CREATE TABLE alerts (
  id          uuid PRIMARY KEY DEFAULT uuidv7(),
  severity    text NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
  kind        text NOT NULL,
  params      jsonb NOT NULL DEFAULT '{}',
  resolved_at timestamptz,
  {{ts}}
);
{{touch "alerts"}}

CREATE TABLE announcements (
  id        uuid PRIMARY KEY DEFAULT uuidv7(),
  audience  text NOT NULL CHECK (audience IN ('all', 'tenant')),
  -- A value, not an FK: no global table references a tenant row.
  tenant_id uuid,
  body      text NOT NULL,
  starts_at timestamptz NOT NULL DEFAULT now(),
  ends_at   timestamptz,
  {{ts}},
  CONSTRAINT announcements_audience_tenant CHECK ((audience = 'tenant') = (tenant_id IS NOT NULL))
);
{{touch "announcements"}}

-- Invites and OTP -------------------------------------------------------------

CREATE TABLE invites (
  id                 uuid PRIMARY KEY DEFAULT uuidv7(),
  token_hash         bytea NOT NULL UNIQUE,
  phone_e164         text NOT NULL CHECK (phone_e164 ~ '^\+[1-9][0-9]{7,14}$'),
  created_by         uuid REFERENCES admin_users (id) ON DELETE SET NULL,
  expires_at         timestamptz NOT NULL,
  -- A value, not an FK: invites exist before any tenant does.
  accepted_tenant_id uuid,
  used_at            timestamptz,
  revoked_at         timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE otp_challenges (
  id          uuid PRIMARY KEY DEFAULT uuidv7(),
  phone_e164  text NOT NULL CHECK (phone_e164 ~ '^\+[1-9][0-9]{7,14}$'),
  purpose     text NOT NULL CHECK (purpose IN ('login', 'signup', 'invite', 'reset', 'phone_old', 'phone_new')),
  code_hash   bytea NOT NULL,
  -- The code under the KEK until the gateway accepts it, then NULL. River
  -- args hold only the id (R21).
  delivery_ct bytea,
  attempts    integer NOT NULL DEFAULT 0,
  expires_at  timestamptz NOT NULL,
  consumed_at timestamptz,
  ip          inet,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Daily caps and spend live in Postgres, not Valkey (R44).
CREATE TABLE sms_counters (
  day   date NOT NULL,
  scope text NOT NULL CHECK (scope IN ('phone', 'ip', 'global')),
  key   text NOT NULL,
  count integer NOT NULL DEFAULT 0,
  cost  numeric(14, 4) NOT NULL DEFAULT 0,
  PRIMARY KEY (day, scope, key)
);

CREATE TABLE sms_gateways (
  id             uuid PRIMARY KEY DEFAULT uuidv7(),
  provider       text NOT NULL CHECK (provider IN ('sms_ir', 'melipayamak', 'noop')),
  role           text NOT NULL DEFAULT 'disabled' CHECK (role IN ('primary', 'fallback', 'disabled')),
  credentials_ct bytea,
  sender         text,
  {{ts}}
);
{{touch "sms_gateways"}}
-- At most one primary and one fallback (D23).
CREATE UNIQUE INDEX sms_gateways_role_uq ON sms_gateways (role) WHERE role IN ('primary', 'fallback');

CREATE TABLE sms_templates (
  key    text NOT NULL,
  locale text NOT NULL CHECK (locale IN ('fa', 'en')),
  body   text NOT NULL,
  {{ts}},
  PRIMARY KEY (key, locale)
);
{{touch "sms_templates"}}

-- Node side -------------------------------------------------------------------

CREATE TABLE node_enrollments (
  id              uuid PRIMARY KEY DEFAULT uuidv7(),
  token_hash      bytea NOT NULL UNIQUE,
  expires_at      timestamptz NOT NULL,
  bound_ip        inet,
  node_id         uuid REFERENCES nodes (id) ON DELETE CASCADE,
  key_fingerprint text,
  state           text NOT NULL DEFAULT 'issued' CHECK (state IN ('issued', 'pending_approval', 'approved', 'rejected', 'expired')),
  approved_by     uuid REFERENCES admin_users (id) ON DELETE SET NULL,
  approved_at     timestamptz,
  {{ts}}
);
{{touch "node_enrollments"}}

CREATE TABLE node_certs (
  serial     text PRIMARY KEY,
  node_id    uuid NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  not_before timestamptz NOT NULL,
  not_after  timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (not_after > not_before)
);

CREATE TABLE locations (
  id           uuid PRIMARY KEY DEFAULT uuidv7(),
  wire_id      integer NOT NULL UNIQUE CHECK (wire_id BETWEEN 1 AND 65535),
  country_code char(2) CHECK (country_code ~ '^[A-Z]{2}$'),
  city         text,
  label        text,
  {{ts}},
  CONSTRAINT locations_country_or_label CHECK (country_code IS NOT NULL OR label IS NOT NULL)
);
{{touch "locations"}}
CREATE UNIQUE INDEX locations_country_city_uq ON locations (country_code, city) NULLS NOT DISTINCT WHERE country_code IS NOT NULL;
CREATE UNIQUE INDEX locations_label_uq ON locations (label) WHERE country_code IS NULL;

CREATE TABLE node_upstreams (
  id                uuid PRIMARY KEY DEFAULT uuidv7(),
  node_id           uuid NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  group_name        text NOT NULL,
  position          integer NOT NULL CHECK (position >= 0),
  kind              text NOT NULL CHECK (kind IN ('udp', 'doh', 'dot', 'doq')),
  address           text NOT NULL,
  bootstrap_ip      inet,
  tls_name          text,
  timeout_ms        integer NOT NULL DEFAULT 2000 CHECK (timeout_ms > 0),
  health_interval_s integer NOT NULL DEFAULT 30 CHECK (health_interval_s > 0),
  trusted           boolean NOT NULL DEFAULT false,
  via_location_id   uuid REFERENCES locations (id) ON DELETE SET NULL,
  {{ts}},
  UNIQUE (node_id, group_name, position),
  -- DoH, DoT and DoQ need a bootstrap address: the node cannot resolve the
  -- name of its own upstream through that upstream.
  CONSTRAINT node_upstreams_bootstrap CHECK (kind = 'udp' OR bootstrap_ip IS NOT NULL)
);
{{touch "node_upstreams"}}

CREATE TABLE node_resolver_rules (
  id            uuid PRIMARY KEY DEFAULT uuidv7(),
  node_id       uuid NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  position      integer NOT NULL CHECK (position >= 0),
  match_type    text NOT NULL CHECK (match_type IN ('domain', 'suffix', 'geosite', 'qtype', 'tld')),
  match_value   text,
  target_group  text NOT NULL,
  final_default boolean NOT NULL DEFAULT false,
  {{ts}},
  UNIQUE (node_id, position),
  CONSTRAINT node_resolver_rules_value CHECK (final_default OR match_value IS NOT NULL)
);
{{touch "node_resolver_rules"}}

CREATE TABLE node_location_configs (
  id                 uuid PRIMARY KEY DEFAULT uuidv7(),
  node_id            uuid NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  location_id        uuid NOT NULL REFERENCES locations (id),
  tag                text NOT NULL,
  priority           integer NOT NULL DEFAULT 0,
  enabled            boolean NOT NULL DEFAULT true,
  fragment           jsonb NOT NULL,
  last_good_fragment jsonb,
  note               text,
  schema_version     integer NOT NULL DEFAULT 1,
  {{ts}},
  UNIQUE (node_id, tag)
);
{{touch "node_location_configs"}}

-- Derived and ids only: the input for AllowedLocations.
CREATE TABLE location_availability (
  node_id     uuid NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  location_id uuid NOT NULL REFERENCES locations (id) ON DELETE CASCADE,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (node_id, location_id)
);
{{touch "location_availability"}}

CREATE TABLE node_quarantine (
  id          uuid PRIMARY KEY DEFAULT uuidv7(),
  node_id     uuid NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  seq         bigint NOT NULL,
  item        text NOT NULL,
  reason      text NOT NULL,
  reported_at timestamptz NOT NULL DEFAULT now(),
  cleared_at  timestamptz
);

-- Config log and artifacts -------------------------------------------------------

-- Hash chained. seq is written by one leased writer under an advisory lock.
CREATE TABLE config_log (
  seq        bigint PRIMARY KEY,
  class      text NOT NULL,
  prev_hash  bytea,
  entry_hash bytea NOT NULL,
  payload    bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Content addressed, behind a store interface (R37). No tenant_id by design
-- (R18): an artifact is shared by every tenant with the same content.
CREATE TABLE policy_artifacts (
  hash         bytea PRIMARY KEY,
  kind         text NOT NULL,
  size         bigint NOT NULL CHECK (size >= 0),
  store_ref    text NOT NULL,
  first_seq    bigint NOT NULL,
  gc_after_seq bigint,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE config_snapshot (
  seq        bigint PRIMARY KEY,
  entry_hash bytea NOT NULL,
  store_ref  text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Certificates and updates -------------------------------------------------------

CREATE TABLE certificates (
  id             uuid PRIMARY KEY DEFAULT uuidv7(),
  kind           text NOT NULL CHECK (kind IN ('wildcard', 'panel', 'admin', 'node_ca', 'block_root', 'block_intermediate')),
  chain_pem      text NOT NULL,
  wrapped_key_ct bytea,
  not_before     timestamptz NOT NULL,
  not_after      timestamptz NOT NULL,
  state          text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'active', 'retired', 'revoked')),
  {{ts}},
  CHECK (not_after > not_before)
);
{{touch "certificates"}}

CREATE TABLE update_status (
  class      text PRIMARY KEY,
  version    text,
  age        interval,
  last_error text,
  checked_at timestamptz
);

CREATE TABLE bundles (
  id        uuid PRIMARY KEY DEFAULT uuidv7(),
  kind      text NOT NULL,
  version   text NOT NULL,
  sha256    bytea NOT NULL CHECK (octet_length(sha256) = 32),
  store_ref text NOT NULL,
  state     text NOT NULL DEFAULT 'staged' CHECK (state IN ('staged', 'active', 'previous', 'failed')),
  {{ts}}
);
{{touch "bundles"}}

CREATE TABLE geoip_versions (
  id      uuid PRIMARY KEY DEFAULT uuidv7(),
  kind    text NOT NULL CHECK (kind IN ('country', 'asn', 'city')),
  version text NOT NULL,
  sha256  bytea NOT NULL CHECK (octet_length(sha256) = 32),
  active  boolean NOT NULL DEFAULT false,
  {{ts}}
);
{{touch "geoip_versions"}}
CREATE UNIQUE INDEX geoip_versions_active_uq ON geoip_versions (kind) WHERE active;

-- Catalog ------------------------------------------------------------------------

CREATE TABLE catalog_versions (
  version          bigint PRIMARY KEY,
  key              bytea NOT NULL,
  sysnames_version bigint,
  state            text NOT NULL DEFAULT 'staged' CHECK (state IN ('staged', 'current', 'previous', 'failed')),
  {{ts}}
);
{{touch "catalog_versions"}}

CREATE TABLE catalog_filter (
  id          text PRIMARY KEY,
  wire_id     integer NOT NULL UNIQUE CHECK (wire_id BETWEEN 1 AND 65535),
  kind        text NOT NULL CHECK (kind IN ('native', 'third_party')),
  category_id text,
  name_en     text NOT NULL,
  name_fa     text NOT NULL,
  state       text NOT NULL DEFAULT 'available' CHECK (state IN ('available', 'unavailable', 'deprecated')),
  {{ts}}
);
{{touch "catalog_filter"}}

CREATE TABLE catalog_filter_mode (
  filter_id text NOT NULL REFERENCES catalog_filter (id) ON DELETE CASCADE,
  mode      text NOT NULL,
  wire_id   integer NOT NULL UNIQUE CHECK (wire_id BETWEEN 0 AND 65535),
  version   bigint NOT NULL DEFAULT 0,
  sources   jsonb NOT NULL DEFAULT '[]',
  {{ts}},
  PRIMARY KEY (filter_id, mode)
);
{{touch "catalog_filter_mode"}}

CREATE TABLE catalog_filter_table (
  filter_id text NOT NULL,
  mode      text NOT NULL,
  version   bigint NOT NULL,
  hash      bytea NOT NULL,
  store_ref text NOT NULL,
  state     text NOT NULL CHECK (state IN ('current', 'previous')),
  {{ts}},
  PRIMARY KEY (filter_id, mode, version),
  FOREIGN KEY (filter_id, mode) REFERENCES catalog_filter_mode (filter_id, mode) ON DELETE CASCADE
);
{{touch "catalog_filter_table"}}

CREATE TABLE catalog_service_category (
  id      text PRIMARY KEY,
  name_en text NOT NULL,
  name_fa text NOT NULL
);

CREATE TABLE catalog_service (
  slug            text PRIMARY KEY,
  wire_id         integer NOT NULL UNIQUE CHECK (wire_id BETWEEN 1 AND 65535),
  category_id     text NOT NULL REFERENCES catalog_service_category (id),
  name_en         text NOT NULL,
  name_fa         text NOT NULL,
  source          text,
  license         text,
  logo_ref        text,
  risk_flag       boolean NOT NULL DEFAULT false,
  -- NULL means no regional limit.
  allowed_regions text[],
  -- A deprecated service stays, so profiles that use it keep their rows.
  state           text NOT NULL DEFAULT 'available' CHECK (state IN ('available', 'deprecated')),
  version         bigint NOT NULL DEFAULT 0,
  {{ts}}
);
{{touch "catalog_service"}}

CREATE TABLE catalog_service_domain (
  slug    text NOT NULL REFERENCES catalog_service (slug) ON DELETE CASCADE,
  pattern text NOT NULL,
  kind    text NOT NULL CHECK (kind IN ('domain', 'full')),
  PRIMARY KEY (slug, pattern)
);

CREATE TABLE catalog_service_alias (
  alias text PRIMARY KEY,
  slug  text NOT NULL REFERENCES catalog_service (slug) ON DELETE CASCADE
);

CREATE TABLE catalog_protected_domains (pattern text PRIMARY KEY);
CREATE TABLE catalog_infra_denylist (pattern text PRIMARY KEY);

CREATE TABLE catalog_common_domains (
  version bigint NOT NULL,
  pattern text NOT NULL,
  PRIMARY KEY (version, pattern)
);

CREATE TABLE catalog_rewrites (
  version bigint NOT NULL,
  name    text NOT NULL,
  target  text NOT NULL,
  kind    text NOT NULL,
  PRIMARY KEY (version, name)
);

CREATE TABLE endpoint_types (
  key      text PRIMARY KEY,
  name_en  text NOT NULL,
  name_fa  text NOT NULL,
  position integer NOT NULL DEFAULT 0
);

CREATE TABLE profile_presets (
  kind           text PRIMARY KEY CHECK (kind IN ('custom', 'developer', 'gaming', 'kids', 'privacy', 'productivity', 'vpn_replacement')),
  content        jsonb NOT NULL DEFAULT '{}',
  schema_version integer NOT NULL DEFAULT 1,
  {{ts}}
);
{{touch "profile_presets"}}
