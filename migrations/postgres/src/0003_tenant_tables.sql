-- Tenant tables. Spec sections 1, 3 and 4.
--
-- Every table here has tenant_id, PRIMARY KEY (tenant_id, ...), FORCE ROW
-- LEVEL SECURITY with the one tenant_isolation policy, and composite foreign
-- keys that carry tenant_id, so a child can never point at another tenant's
-- parent. Macros (double-brace calls) expand at build time (tools/genmig) so every table
-- has identical text.

-- +goose Up

SET LOCAL search_path = ctrlz, pg_catalog;

-- Account -------------------------------------------------------------------------

-- The tenant is the row; its key column is id, not tenant_id.
CREATE TABLE tenants (
  id                         uuid PRIMARY KEY DEFAULT uuidv7(),
  status                     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleting')),
  admin_hold                 boolean NOT NULL DEFAULT false,
  home_countries             char(2)[] NOT NULL DEFAULT '{}' CONSTRAINT tenants_home_countries_max CHECK (cardinality(home_countries) <= 3),
  raw_retention_days         integer NOT NULL DEFAULT 7 CHECK (raw_retention_days IN (1, 3, 7, 30)),
  aggregate_retention_months integer NOT NULL DEFAULT 12 CHECK (aggregate_retention_months IN (1, 3, 6, 12)),
  deleted_at                 timestamptz,
  {{ts}}
);
{{rls_tenants}}
{{touch "tenants"}}

CREATE TABLE users (
  {{tid}},
  id                  uuid NOT NULL DEFAULT uuidv7(),
  phone_e164          text NOT NULL CONSTRAINT users_phone_e164_key UNIQUE CONSTRAINT users_phone_format CHECK (phone_e164 ~ '^\+[1-9][0-9]{7,14}$'),
  phone_verified_at   timestamptz,
  password_hash       text,
  totp_secret_ct      bytea,
  totp_enabled_at     timestamptz,
  totp_last_step      bigint,
  enforce_passkey     boolean NOT NULL DEFAULT false,
  role                text NOT NULL DEFAULT 'owner' CHECK (role IN ('owner')),
  locale              text NOT NULL DEFAULT 'fa' CHECK (locale IN ('fa', 'en')),
  theme               text NOT NULL DEFAULT 'system' CHECK (theme IN ('system', 'light', 'dark')),
  onboarding_hints    jsonb NOT NULL DEFAULT '{}',
  onboarding_state    jsonb NOT NULL DEFAULT '{}',
  must_reset          boolean NOT NULL DEFAULT false,
  last_login_at       timestamptz,
  {{ts}},
  PRIMARY KEY (tenant_id, id)
);
-- v1 has one user per tenant, and D32 (members) stays open.
CREATE UNIQUE INDEX users_one_owner_uq ON users (tenant_id) WHERE role = 'owner';
{{rls "users"}}
{{touch "users"}}

CREATE TABLE recovery_codes (
  {{tid}},
  id        uuid NOT NULL DEFAULT uuidv7(),
  user_id   uuid NOT NULL,
  code_hash bytea NOT NULL,
  used_at   timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX recovery_codes_user_idx ON recovery_codes (tenant_id, user_id);
{{rls "recovery_codes"}}

CREATE TABLE sessions (
  {{tid}},
  id                  uuid NOT NULL DEFAULT uuidv7(),
  user_id             uuid NOT NULL,
  token_hash          bytea NOT NULL CONSTRAINT sessions_token_hash_key UNIQUE,
  remember_me         boolean NOT NULL DEFAULT false,
  idle_expires_at     timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  revoked_at          timestamptz,
  last_seen_at        timestamptz NOT NULL DEFAULT now(),
  {{ts}},
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX sessions_user_idx ON sessions (tenant_id, user_id);
{{rls "sessions"}}
{{touch "sessions"}}

CREATE TABLE refresh_tokens (
  {{tid}},
  id                uuid NOT NULL DEFAULT uuidv7(),
  user_id           uuid NOT NULL,
  session_id        uuid NOT NULL,
  family_id         uuid NOT NULL,
  token_hash        bytea NOT NULL CONSTRAINT refresh_tokens_token_hash_key UNIQUE,
  rotated_at        timestamptz,
  reuse_grace_until timestamptz,
  expires_at        timestamptz NOT NULL,
  revoked_at        timestamptz,
  {{ts}},
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, session_id) REFERENCES sessions (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (tenant_id, family_id);
{{rls "refresh_tokens"}}
{{touch "refresh_tokens"}}

CREATE TABLE api_tokens (
  {{tid}},
  id           uuid NOT NULL DEFAULT uuidv7(),
  user_id      uuid NOT NULL,
  name         text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
  kind         text NOT NULL CHECK (kind IN ('read', 'write')),
  token_hash   bytea NOT NULL CONSTRAINT api_tokens_token_hash_key UNIQUE,
  token_prefix text NOT NULL,
  allowed_ips  cidr[] NOT NULL DEFAULT '{}',
  last_used_at timestamptz,
  revoked_at   timestamptz,
  {{ts}},
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
{{rls "api_tokens"}}
{{touch "api_tokens"}}

CREATE TABLE webauthn_credentials (
  {{tid}},
  id            uuid NOT NULL DEFAULT uuidv7(),
  user_id       uuid NOT NULL,
  credential_id bytea NOT NULL CONSTRAINT webauthn_credentials_credential_id_key UNIQUE,
  public_key    bytea NOT NULL,
  sign_count    bigint NOT NULL DEFAULT 0,
  transports    text[] NOT NULL DEFAULT '{}',
  name          text NOT NULL DEFAULT '',
  rp_id         text NOT NULL,
  stale_at      timestamptz,
  last_used_at  timestamptz,
  {{ts}},
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
{{rls "webauthn_credentials"}}
{{touch "webauthn_credentials"}}

CREATE TABLE phone_change_requests (
  {{tid}},
  id              uuid NOT NULL DEFAULT uuidv7(),
  user_id         uuid NOT NULL,
  new_phone_e164  text NOT NULL CHECK (new_phone_e164 ~ '^\+[1-9][0-9]{7,14}$'),
  -- Values, not FKs: OTP rows are global and short lived.
  old_otp_id      uuid NOT NULL,
  new_otp_id      uuid NOT NULL,
  expires_at      timestamptz NOT NULL,
  completed_at    timestamptz,
  {{ts}},
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
{{rls "phone_change_requests"}}
{{touch "phone_change_requests"}}

-- NULL in an override column means the global default.
CREATE TABLE tenant_entitlements (
  tenant_id                 uuid PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
  max_profiles              integer CHECK (max_profiles >= 0),
  max_endpoints             integer CHECK (max_endpoints >= 0),
  max_clients_per_endpoint  integer CHECK (max_clients_per_endpoint >= 0),
  max_authorized_ips        integer CHECK (max_authorized_ips >= 0),
  max_api_tokens            integer CHECK (max_api_tokens >= 0),
  max_rules_per_request     integer CHECK (max_rules_per_request >= 0),
  max_rules_per_profile     integer CHECK (max_rules_per_profile >= 0),
  max_wildcards_per_profile integer CHECK (max_wildcards_per_profile >= 0),
  max_realtime_sessions     integer CHECK (max_realtime_sessions >= 0),
  max_publishes_per_hour    integer CHECK (max_publishes_per_hour >= 0),
  {{ts}}
);
{{rls "tenant_entitlements"}}
{{touch "tenant_entitlements"}}

CREATE TABLE notifications (
  {{tid}},
  id       uuid NOT NULL DEFAULT uuidv7(),
  kind     text NOT NULL,
  severity text NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
  params   jsonb NOT NULL DEFAULT '{}',
  link     text,
  read_at  timestamptz,
  {{ts}},
  PRIMARY KEY (tenant_id, id)
);
{{rls "notifications"}}
{{touch "notifications"}}

CREATE TABLE announcement_reads (
  {{tid}},
  announcement_id uuid NOT NULL REFERENCES announcements (id) ON DELETE CASCADE,
  user_id         uuid NOT NULL,
  read_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, announcement_id, user_id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
{{rls "announcement_reads"}}

CREATE TABLE feedback_items (
  {{tid}},
  id          uuid NOT NULL DEFAULT uuidv7(),
  kind        text NOT NULL CHECK (kind IN ('false_positive', 'false_negative', 'feature', 'contact')),
  body        text NOT NULL CHECK (char_length(body) <= 4000),
  context     jsonb NOT NULL DEFAULT '{}',
  status      text NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'read', 'replied', 'closed')),
  admin_reply text,
  replied_at  timestamptz,
  {{ts}},
  PRIMARY KEY (tenant_id, id)
);
{{rls "feedback_items"}}
{{touch "feedback_items"}}

-- Insert only. user_id is a value: the log outlives the user row.
CREATE TABLE tenant_audit_log (
  {{tid}},
  id      uuid NOT NULL DEFAULT uuidv7(),
  user_id uuid,
  action  text NOT NULL,
  target  text,
  params  jsonb NOT NULL DEFAULT '{}',
  ip      inet,
  at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);
{{rls "tenant_audit_log"}}

CREATE TABLE idempotency_keys (
  {{tid}},
  key          text NOT NULL,
  route        text NOT NULL,
  request_hash bytea NOT NULL,
  status_code  integer,
  response     jsonb,
  expires_at   timestamptz NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, key)
);
{{rls "idempotency_keys"}}

CREATE TABLE tenant_assets (
  {{tid}},
  id         uuid NOT NULL DEFAULT uuidv7(),
  kind       text NOT NULL CHECK (kind IN ('logo')),
  sha256     bytea NOT NULL CHECK (octet_length(sha256) = 32),
  mime       text NOT NULL CHECK (mime IN ('image/png', 'image/jpeg', 'image/webp')),
  size       integer NOT NULL CONSTRAINT tenant_assets_size_max CHECK (size BETWEEN 1 AND 262144),
  -- Uploaded, never a URL (D28).
  bytes      bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT tenant_assets_size_matches CHECK (octet_length(bytes) = size)
);
{{rls "tenant_assets"}}

-- Profiles --------------------------------------------------------------------------

CREATE TABLE profiles (
  {{tid}},
  id                 uuid NOT NULL DEFAULT uuidv7(),
  name               text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
  kind               text NOT NULL DEFAULT 'custom' CHECK (kind IN ('custom', 'developer', 'gaming', 'kids', 'privacy', 'productivity', 'vpn_replacement')),
  version            bigint NOT NULL DEFAULT 1,
  disabled_until     timestamptz,
  lock_state         text NOT NULL DEFAULT 'unlocked' CHECK (lock_state IN ('unlocked', 'locked')),
  lock_message       text,
  lock_password_hash text,
  locked_by          uuid,
  locked_at          timestamptz,
  compiled_hash      bytea,
  {{ts}},
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, locked_by) REFERENCES users (tenant_id, id) ON DELETE SET NULL (locked_by),
  CONSTRAINT profiles_lock_needs_password CHECK (lock_state <> 'locked' OR lock_password_hash IS NOT NULL)
);
{{rls "profiles"}}
{{touch "profiles"}}

-- Every option is nullable: NULL means not set (R27). compatibility_mode is
-- stored but not compiled (D9).
CREATE TABLE profile_options (
  {{tid}},
  profile_id         uuid NOT NULL,
  {{actionset "profile_options" "default_" "null"}}
  default_location_unavailable boolean NOT NULL DEFAULT false,
  block_exfiltration boolean,
  rebind_protection  boolean,
  disable_dnssec     boolean,
  block_ttl          integer CHECK (block_ttl BETWEEN 1 AND 86400),
  redirect_ttl       integer CHECK (redirect_ttl BETWEEN 1 AND 86400),
  bypass_ttl         integer CHECK (bypass_ttl BETWEEN 1 AND 86400),
  block_response     text CHECK (block_response IN ('zero', 'nxdomain', 'refused', 'custom', 'branded')),
  block_custom_v4    inet,
  block_custom_v6    inet,
  ecs_mode           text CHECK (ecs_mode IN ('none', 'auto', 'custom')),
  ecs_v4             cidr,
  ecs_v6             cidr,
  dns64              boolean,
  cname_flattening   boolean,
  safe_search        boolean,
  restricted_youtube boolean,
  compatibility_mode boolean,
  {{ts}},
  PRIMARY KEY (tenant_id, profile_id),
  FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT profile_options_block_custom CHECK (block_response IS DISTINCT FROM 'custom' OR block_custom_v4 IS NOT NULL OR block_custom_v6 IS NOT NULL),
  CONSTRAINT profile_options_block_custom_family CHECK ((block_custom_v4 IS NULL OR family(block_custom_v4) = 4) AND (block_custom_v6 IS NULL OR family(block_custom_v6) = 6)),
  CONSTRAINT profile_options_ecs_custom CHECK (ecs_mode IS DISTINCT FROM 'custom' OR ecs_v4 IS NOT NULL OR ecs_v6 IS NOT NULL),
  CONSTRAINT profile_options_ecs_family CHECK ((ecs_v4 IS NULL OR family(ecs_v4) = 4) AND (ecs_v6 IS NULL OR family(ecs_v6) = 6))
);
{{rls "profile_options"}}
{{touch "profile_options"}}

CREATE TABLE profile_filters (
  {{tid}},
  profile_id uuid NOT NULL,
  filter_id  text NOT NULL REFERENCES catalog_filter (id),
  -- NULL for a filter with one mode. The composite FK below is then skipped
  -- (MATCH SIMPLE), and the single-column FK above still validates filter_id.
  mode       text,
  enabled    boolean NOT NULL DEFAULT true,
  {{ts}},
  PRIMARY KEY (tenant_id, profile_id, filter_id),
  FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (filter_id, mode) REFERENCES catalog_filter_mode (filter_id, mode)
);
{{rls "profile_filters"}}
{{touch "profile_filters"}}

-- An absent row or enabled = false is not Bypass.
CREATE TABLE profile_services (
  {{tid}},
  profile_id           uuid NOT NULL,
  service_slug         text NOT NULL REFERENCES catalog_service (slug),
  enabled              boolean NOT NULL DEFAULT true,
  {{actionset "profile_services" "" ""}}
  location_unavailable boolean NOT NULL DEFAULT false,
  {{ts}},
  PRIMARY KEY (tenant_id, profile_id, service_slug),
  FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles (tenant_id, id) ON DELETE CASCADE
);
{{rls "profile_services"}}
{{touch "profile_services"}}

CREATE TABLE rule_folders (
  {{tid}},
  id         uuid NOT NULL DEFAULT uuidv7(),
  profile_id uuid NOT NULL,
  name       text NOT NULL CONSTRAINT rule_folders_name_len CHECK (char_length(name) BETWEEN 1 AND 31),
  kind       text NOT NULL DEFAULT 'standard' CHECK (kind IN ('standard', 'bypass', 'do_not_log')),
  {{actionset "rule_folders" "" "null"}}
  position   integer NOT NULL DEFAULT 0,
  {{ts}},
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, profile_id, id),
  FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles (tenant_id, id) ON DELETE CASCADE
);
{{rls "rule_folders"}}
{{touch "rule_folders"}}

CREATE TABLE rules (
  {{tid}},
  id                   uuid NOT NULL DEFAULT uuidv7(),
  profile_id           uuid NOT NULL,
  folder_id            uuid,
  rule_key             text NOT NULL,
  match_kind           text NOT NULL CHECK (match_kind IN ('domain', 'subdomains', 'glob', 'dest_cc', 'dest_as', 'src_cc')),
  negated              boolean NOT NULL DEFAULT false,
  {{actionset "rules" "" "inherit"}}
  enabled              boolean NOT NULL DEFAULT true,
  expires_at           timestamptz,
  comment              text CONSTRAINT rules_comment_len CHECK (char_length(comment) <= 64),
  location_unavailable boolean NOT NULL DEFAULT false,
  {{ts}},
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, profile_id, rule_key),
  FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles (tenant_id, id) ON DELETE CASCADE,
  -- Deleting a folder deletes its rules, as the confirm dialog says. A NULL
  -- folder_id skips the check (MATCH SIMPLE): the rule is at the top level.
  FOREIGN KEY (tenant_id, profile_id, folder_id) REFERENCES rule_folders (tenant_id, profile_id, id) ON DELETE CASCADE,
  CONSTRAINT rules_inherit_needs_folder CHECK (action <> 'inherit' OR folder_id IS NOT NULL)
);
CREATE INDEX rules_profile_idx ON rules (tenant_id, profile_id);
{{rls "rules"}}
{{touch "rules"}}

CREATE TABLE block_pages (
  {{tid}},
  profile_id    uuid NOT NULL,
  logo_asset_id uuid,
  title         text,
  message       text,
  unblock_mode  text NOT NULL DEFAULT 'none' CHECK (unblock_mode IN ('none', 'default', 'custom')),
  unblock_url   text,
  {{ts}},
  PRIMARY KEY (tenant_id, profile_id),
  FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, logo_asset_id) REFERENCES tenant_assets (tenant_id, id) ON DELETE SET NULL (logo_asset_id)
);
{{rls "block_pages"}}
{{touch "block_pages"}}

-- Endpoints -----------------------------------------------------------------------

CREATE TABLE endpoint_groups (
  {{tid}},
  id   uuid NOT NULL DEFAULT uuidv7(),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
  {{ts}},
  PRIMARY KEY (tenant_id, id)
);
{{rls "endpoint_groups"}}
{{touch "endpoint_groups"}}

CREATE TABLE endpoints (
  {{tid}},
  id                        uuid NOT NULL DEFAULT uuidv7(),
  name                      text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
  type                      text NOT NULL REFERENCES endpoint_types (key),
  group_id                  uuid,
  comment                   text CONSTRAINT endpoints_comment_len CHECK (char_length(comment) <= 255),
  -- A routing label, not a secret (R7).
  resolver_id               text NOT NULL CONSTRAINT endpoints_resolver_id_key UNIQUE CONSTRAINT endpoints_resolver_id_format CHECK (resolver_id ~ '^[a-z2-7]{26}$'),
  doh_token_ct              bytea,
  doh_token_hash            bytea,
  profile_id                uuid NOT NULL,
  profile2_id               uuid,
  analytics_level           text NOT NULL DEFAULT 'full' CHECK (analytics_level IN ('none', 'some', 'full')),
  admin_state               text NOT NULL DEFAULT 'enabled' CHECK (admin_state IN ('enabled', 'soft_disabled', 'hard_disabled')),
  admin_hold                boolean NOT NULL DEFAULT false,
  legacy_dns                boolean NOT NULL DEFAULT false,
  authorize_secure_dns      boolean NOT NULL DEFAULT false,
  authorize_ddns            boolean NOT NULL DEFAULT false,
  expose_ip                 boolean NOT NULL DEFAULT false,
  -- Hidden until the app exists (D8).
  prevent_deactivation      boolean NOT NULL DEFAULT false,
  require_authorized_ips    boolean NOT NULL DEFAULT false,
  schedule_timezone         text NOT NULL DEFAULT 'Asia/Tehran',
  -- Always NULL in v1, with no route and no UI (D30).
  pair_override_node_a      uuid REFERENCES nodes (id),
  pair_override_node_b      uuid REFERENCES nodes (id),
  pair_version              bigint NOT NULL DEFAULT 0,
  first_query_at            timestamptz,
  last_query_at             timestamptz,
  apple_profile_generated_at timestamptz,
  {{ts}},
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT endpoints_id_key UNIQUE (id),
  FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, profile2_id) REFERENCES profiles (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, group_id) REFERENCES endpoint_groups (tenant_id, id) ON DELETE SET NULL (group_id),
  CONSTRAINT endpoints_profiles_differ CHECK (profile2_id IS NULL OR profile2_id <> profile_id),
  CONSTRAINT endpoints_pair_override CHECK (
    (pair_override_node_a IS NULL AND pair_override_node_b IS NULL)
    OR (pair_override_node_a IS NOT NULL AND pair_override_node_b IS NOT NULL AND pair_override_node_a <> pair_override_node_b))
);
{{rls "endpoints"}}
{{touch "endpoints"}}

CREATE TABLE endpoint_ddns_hosts (
  {{tid}},
  id               uuid NOT NULL DEFAULT uuidv7(),
  endpoint_id      uuid NOT NULL,
  hostname         text NOT NULL,
  last_resolved_at timestamptz,
  last_ips         inet[] NOT NULL DEFAULT '{}',
  last_error       text,
  {{ts}},
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, endpoint_id, hostname),
  FOREIGN KEY (tenant_id, endpoint_id) REFERENCES endpoints (tenant_id, id) ON DELETE CASCADE
);
{{rls "endpoint_ddns_hosts"}}
{{touch "endpoint_ddns_hosts"}}

-- minutes is a week in 30 minute steps. Minute 0 is Sunday 00:00 local time.
CREATE TABLE schedule_windows (
  {{tid}},
  id          uuid NOT NULL DEFAULT uuidv7(),
  endpoint_id uuid NOT NULL,
  minutes     int4range NOT NULL,
  profile_id  uuid NOT NULL,
  profile2_id uuid,
  {{ts}},
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, endpoint_id) REFERENCES endpoints (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, profile2_id) REFERENCES profiles (tenant_id, id) ON DELETE RESTRICT,
  CONSTRAINT schedule_windows_grid CHECK (
    NOT isempty(minutes) AND lower_inc(minutes) AND NOT upper_inc(minutes)
    AND lower(minutes) >= 0 AND upper(minutes) <= 10080
    AND lower(minutes) % 30 = 0 AND upper(minutes) % 30 = 0
    AND upper(minutes) - lower(minutes) >= 30),
  CONSTRAINT schedule_windows_no_overlap EXCLUDE USING gist (tenant_id WITH =, endpoint_id WITH =, minutes WITH &&)
);
{{rls "schedule_windows"}}
{{touch "schedule_windows"}}

CREATE TABLE clients (
  {{tid}},
  id              uuid NOT NULL DEFAULT uuidv7(),
  endpoint_id     uuid NOT NULL,
  -- Appears on the network in the hostname, so the grammar is strict (R7).
  label           text NOT NULL CONSTRAINT clients_label_grammar CHECK (label ~ '^[a-z0-9]([a-z0-9-]{0,34}[a-z0-9])?$'),
  alias           text,
  profile_id      uuid,
  profile2_id     uuid,
  analytics_level text CHECK (analytics_level IN ('none', 'some', 'full')),
  group_name      text,
  hostname        text,
  mac             macaddr,
  ip              inet,
  source          text NOT NULL DEFAULT 'auto' CHECK (source IN ('auto', 'manual')),
  is_custom       boolean NOT NULL DEFAULT false,
  first_seen_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at    timestamptz NOT NULL DEFAULT now(),
  {{ts}},
  PRIMARY KEY (tenant_id, id),
  -- Overflow goes to the row with label 'default' (R8).
  UNIQUE (tenant_id, endpoint_id, label),
  FOREIGN KEY (tenant_id, endpoint_id) REFERENCES endpoints (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles (tenant_id, id) ON DELETE SET NULL (profile_id),
  FOREIGN KEY (tenant_id, profile2_id) REFERENCES profiles (tenant_id, id) ON DELETE SET NULL (profile2_id)
);
{{rls "clients"}}
{{touch "clients"}}

CREATE TABLE authorized_ips (
  {{tid}},
  id              uuid NOT NULL DEFAULT uuidv7(),
  endpoint_id     uuid NOT NULL,
  cidr            cidr NOT NULL,
  source          text NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'secure_dns', 'ddns')),
  ddns_host_id    uuid,
  cleanup_opt_in  boolean NOT NULL DEFAULT false,
  city            text,
  isp             text,
  last_seen_at    timestamptz,
  {{ts}},
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, endpoint_id, cidr),
  FOREIGN KEY (tenant_id, endpoint_id) REFERENCES endpoints (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, ddns_host_id) REFERENCES endpoint_ddns_hosts (tenant_id, id) ON DELETE CASCADE
);
{{rls "authorized_ips"}}
{{touch "authorized_ips"}}

-- Source IP is identity for plain DNS, so a claim is global in effect: the
-- exclusion constraint spans tenants and does not depend on RLS. Only active
-- and grace rows exclude each other; pending_proof rows may overlap. IPv4
-- only, because nodes serve IPv4 (spec section 13, item 7).
CREATE TABLE ip_claims (
  {{tid}},
  id                uuid NOT NULL DEFAULT uuidv7(),
  endpoint_id       uuid NOT NULL,
  cidr              cidr NOT NULL CONSTRAINT ip_claims_ipv4 CHECK (family(cidr) = 4),
  state             text NOT NULL CHECK (state IN ('active', 'pending_proof', 'grace', 'suspended', 'released')),
  proof_method      text CHECK (proof_method IN ('verify_tcp', 'verify_udp_txt', 'browser_ip', 'secure_dns')),
  proven_at         timestamptz,
  grace_until       timestamptz,
  first_grace_at    timestamptz,
  source            text NOT NULL CHECK (source IN ('manual', 'browser', 'secure_dns', 'ddns')),
  last_seen_at      timestamptz,
  approved_by_admin boolean NOT NULL DEFAULT false,
  displaced_at      timestamptz,
  {{ts}},
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, endpoint_id) REFERENCES endpoints (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT ip_claims_no_overlap EXCLUDE USING gist (cidr inet_ops WITH &&) WHERE (state IN ('active', 'grace'))
);
CREATE INDEX ip_claims_endpoint_idx ON ip_claims (tenant_id, endpoint_id);
{{rls "ip_claims"}}
{{touch "ip_claims"}}

CREATE TABLE ip_proof_challenges (
  {{tid}},
  id            uuid NOT NULL DEFAULT uuidv7(),
  claim_id      uuid NOT NULL,
  -- The only thing a ProofObservation carries from the node.
  label         text NOT NULL CONSTRAINT ip_proof_challenges_label_key UNIQUE,
  txt_code_hash bytea,
  observed_at   timestamptz,
  observed_ip   inet,
  expires_at    timestamptz NOT NULL,
  consumed_at   timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, claim_id) REFERENCES ip_claims (tenant_id, id) ON DELETE CASCADE
);
{{rls "ip_proof_challenges"}}

CREATE TABLE setup_share_tokens (
  {{tid}},
  id          uuid NOT NULL DEFAULT uuidv7(),
  endpoint_id uuid NOT NULL,
  client      text,
  token_hash  bytea NOT NULL CONSTRAINT setup_share_tokens_token_hash_key UNIQUE,
  expires_at  timestamptz NOT NULL,
  max_uses    integer NOT NULL DEFAULT 10 CHECK (max_uses > 0),
  uses        integer NOT NULL DEFAULT 0 CHECK (uses >= 0),
  revoked_at  timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, endpoint_id) REFERENCES endpoints (tenant_id, id) ON DELETE CASCADE
);
{{rls "setup_share_tokens"}}

CREATE TABLE profile_download_tokens (
  {{tid}},
  id          uuid NOT NULL DEFAULT uuidv7(),
  endpoint_id uuid NOT NULL,
  params_hash bytea NOT NULL,
  token_hash  bytea NOT NULL CONSTRAINT profile_download_tokens_token_hash_key UNIQUE,
  expires_at  timestamptz NOT NULL,
  max_uses    integer NOT NULL DEFAULT 1 CHECK (max_uses > 0),
  uses        integer NOT NULL DEFAULT 0 CHECK (uses >= 0),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, endpoint_id) REFERENCES endpoints (tenant_id, id) ON DELETE CASCADE
);
{{rls "profile_download_tokens"}}

CREATE TABLE unblock_requests (
  {{tid}},
  id          uuid NOT NULL DEFAULT uuidv7(),
  profile_id  uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  qname       text NOT NULL,
  message     text,
  status      text NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'read', 'handled', 'dismissed')),
  {{ts}},
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, endpoint_id) REFERENCES endpoints (tenant_id, id) ON DELETE CASCADE
);
{{rls "unblock_requests"}}
{{touch "unblock_requests"}}

CREATE TABLE filter_preview_jobs (
  {{tid}},
  id              uuid NOT NULL DEFAULT uuidv7(),
  profile_id      uuid NOT NULL,
  filter_id       text NOT NULL REFERENCES catalog_filter (id),
  from_mode       text,
  to_mode         text,
  window_days     integer NOT NULL CHECK (window_days > 0),
  catalog_version bigint,
  profile_version bigint,
  status          text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed', 'cancelled')),
  covered_share   numeric(5, 4) CHECK (covered_share BETWEEN 0 AND 1),
  result_ref      text,
  {{ts}},
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles (tenant_id, id) ON DELETE CASCADE
);
-- One active job per tenant.
CREATE UNIQUE INDEX filter_preview_jobs_active_uq ON filter_preview_jobs (tenant_id) WHERE status IN ('queued', 'running');
{{rls "filter_preview_jobs"}}
{{touch "filter_preview_jobs"}}

CREATE TABLE batch_jobs (
  {{tid}},
  id         uuid NOT NULL DEFAULT uuidv7(),
  kind       text NOT NULL,
  profile_id uuid,
  state      text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'done', 'failed')),
  progress   integer NOT NULL DEFAULT 0 CHECK (progress >= 0),
  total      integer NOT NULL DEFAULT 0 CHECK (total >= 0),
  result     jsonb,
  {{ts}},
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles (tenant_id, id) ON DELETE CASCADE
);
{{rls "batch_jobs"}}
{{touch "batch_jobs"}}

-- A row with a NULL endpoint_id is the tenant-wide floor (Clear Analytics).
CREATE TABLE analytics_read_floors (
  {{tid}},
  id          uuid NOT NULL DEFAULT uuidv7(),
  endpoint_id uuid,
  cleared_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE NULLS NOT DISTINCT (tenant_id, endpoint_id),
  FOREIGN KEY (tenant_id, endpoint_id) REFERENCES endpoints (tenant_id, id) ON DELETE CASCADE
);
{{rls "analytics_read_floors"}}

-- Outboxes ---------------------------------------------------------------------------

-- aggregate_id is the profile id for 'profile' and the tenant id for
-- 'endpoint_set', so it is a value, not an FK. One row per profile per
-- transaction, never per rule; lock changes make no row.
CREATE TABLE policy_outbox (
  {{tid}},
  id             uuid NOT NULL DEFAULT uuidv7(),
  aggregate_type text NOT NULL CHECK (aggregate_type IN ('profile', 'endpoint_set')),
  aggregate_id   uuid NOT NULL,
  batch_id       uuid NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT policy_outbox_dedupe UNIQUE (tenant_id, aggregate_type, aggregate_id, batch_id)
);
-- The compiler drains across tenants in age order, so this index cannot lead
-- with tenant_id. It is on the allow-list in spec section 6.3.
CREATE INDEX policy_outbox_created_at_idx ON policy_outbox (created_at);
{{rls "policy_outbox"}}

-- Args never hold an OTP or a secret (R21).
CREATE TABLE job_outbox (
  {{tid}},
  id         uuid NOT NULL DEFAULT uuidv7(),
  kind       text NOT NULL,
  args       jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);
{{rls "job_outbox"}}
