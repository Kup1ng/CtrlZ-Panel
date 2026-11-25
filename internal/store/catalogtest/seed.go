package catalogtest

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"text/template"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// globalSeed creates the global rows that tenant rows point at. It runs once.
const globalSeed = `
INSERT INTO ctrlz.endpoint_types (key, name_en, name_fa, position, icon) VALUES ('doh_client', 'DoH client', 'DoH', 99, 'network');
INSERT INTO ctrlz.locations (id, wire_id, country_code, city) VALUES ('00000000-0000-7000-8000-0000000000a1', 1, 'DE', 'Frankfurt');
-- The catalog rows tenant rows point at ('ads-trackers' with its mode 'strict', the service 'youtube')
-- come from the P2 seed migration (0071), not from here: a fixture row with the same key or wire id
-- would collide with it, and a test that uses the real rows also tests the seed.
INSERT INTO ctrlz.announcements (id, audience, body) VALUES ('00000000-0000-7000-8000-0000000000b1', 'all', 'hello');
INSERT INTO ctrlz.nodes (id, slot, name, status, dns_advertised_ip) VALUES
  ('00000000-0000-7000-8000-0000000000c1', 1, 'node-1', 'active', '192.0.2.1'),
  ('00000000-0000-7000-8000-0000000000c2', 2, 'node-2', 'active', '192.0.2.2');
INSERT INTO ctrlz.node_pairs (id, primary_node_id, fallback_node_id) VALUES
  ('00000000-0000-7000-8000-0000000000d1', '00000000-0000-7000-8000-0000000000c1', '00000000-0000-7000-8000-0000000000c2');
UPDATE ctrlz.public_settings SET global_pair_id = '00000000-0000-7000-8000-0000000000d1';
-- P1 (0011). A row in each new global table, a real OTP row and a decoy.
-- A console one-time password with its 24 hours: must_change_password with no expiry is not a
-- state the code makes, and ctrlz.credential_state reads it as an expired one (rule one-time-state).
INSERT INTO ctrlz.admin_users (id, username, password_hash, password_expires_at) VALUES ('00000000-0000-7000-8000-0000000000e1', 'seed-admin', 'argon2id$seed', now() + interval '24 hours');
INSERT INTO ctrlz.sms_gateways (id, provider, role) VALUES ('00000000-0000-7000-8000-0000000000f1', 'noop', 'primary');
INSERT INTO ctrlz.auth_tickets (token_hash, kind, subject_tenant, subject_user, expires_at)
  VALUES (decode(repeat('01', 32), 'hex'), 'mfa', '00000000-0000-7000-8000-000000000001', '00000000-0000-7000-8000-000000000002', now() + interval '5 minutes');
INSERT INTO ctrlz.auth_throttle (scope, key, window_start, count) VALUES ('login_net', decode(repeat('02', 32), 'hex'), now(), 1);
INSERT INTO ctrlz.admin_jobs (kind, created_by) VALUES ('registration_transition', '00000000-0000-7000-8000-0000000000e1');
INSERT INTO ctrlz.sms_outbox (kind, gateway_id, phone_e164, template_key, locale, created_by)
  VALUES ('test', '00000000-0000-7000-8000-0000000000f1', '+989120000099', 'otp', 'fa', '00000000-0000-7000-8000-0000000000e1');
INSERT INTO ctrlz.sms_deliveries (source, source_id, gateway_id, provider, template_key, outcome)
  VALUES ('otp', gen_random_uuid(), '00000000-0000-7000-8000-0000000000f1', 'noop', 'otp', 'accepted');
INSERT INTO ctrlz.sms_provider_templates (gateway_id, key, locale, provider_template_id, param_names)
  VALUES ('00000000-0000-7000-8000-0000000000f1', 'otp', 'fa', '123456', '{CODE}');
INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, delivery_ct, expires_at, ip)
  VALUES ('+989120000098', 'login', '', '', now() + interval '5 minutes', '198.51.100.9');
INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, delivery_ct, expires_at, ip)
  VALUES ('+989120000097', 'login', '', NULL, now() + interval '5 minutes', '198.51.100.9');
`

// SeedIDs are the ids a test needs to find the seeded rows again.
type SeedIDs struct {
	Tenant    uuid.UUID
	User      uuid.UUID
	Profile   uuid.UUID // the first profile; the second is Profile2
	Profile2  uuid.UUID
	Endpoint  uuid.UUID
	Claim     uuid.UUID
	Index     int // 1 or 2
	Phone     string
	Session   string // the plain text whose bytes are sessions.token_hash
	APIToken  string
	Refresh   string
	Passkey   string
	Share     string
	Download  string
	Invite    string
	Prefix    string // the seeded active claim, e.g. 10.1.0.1/32
	ResolveID string
}

// tenantSeed inserts exactly one row into every tenant table. Every nullable
// foreign key column is filled in, so the foreign key tests have something to
// break. Values that must be globally unique carry the tenant index.
var tenantSeedTmpl = template.Must(template.New("seed").Parse(`
INSERT INTO ctrlz.tenants (id, plan_id) SELECT '{{.Tenant}}', p.id FROM ctrlz.plans p WHERE p.is_default;
INSERT INTO ctrlz.users (tenant_id, id, phone_e164, password_hash) VALUES ('{{.Tenant}}', '{{.User}}', '{{.Phone}}', 'argon2id$seed');
INSERT INTO ctrlz.recovery_codes (tenant_id, user_id, code_hash) VALUES ('{{.Tenant}}', '{{.User}}', 'rc{{.Index}}');
INSERT INTO ctrlz.sessions (tenant_id, id, user_id, token_hash, idle_expires_at, absolute_expires_at, last_seen_at)
  VALUES ('{{.Tenant}}', '00000000-0000-7000-8000-0000000{{.Index}}0001', '{{.User}}', convert_to('{{.Session}}', 'UTF8'), now() + interval '1 hour', now() + interval '8 hours', now());
INSERT INTO ctrlz.refresh_tokens (tenant_id, user_id, session_id, family_id, token_hash, expires_at)
  VALUES ('{{.Tenant}}', '{{.User}}', '00000000-0000-7000-8000-0000000{{.Index}}0001', '00000000-0000-7000-8000-0000000{{.Index}}00f1', convert_to('{{.Refresh}}', 'UTF8'), now() + interval '30 days');
INSERT INTO ctrlz.api_tokens (tenant_id, user_id, name, kind, token_hash, token_prefix, allowed_ips, expires_at)
  VALUES ('{{.Tenant}}', '{{.User}}', 'ci', 'read', convert_to('{{.APIToken}}', 'UTF8'), 'czt_{{.Index}}', '{198.51.100.0/24}', now() + interval '365 days');
INSERT INTO ctrlz.webauthn_credentials (tenant_id, user_id, credential_id, public_key, rp_id)
  VALUES ('{{.Tenant}}', '{{.User}}', convert_to('{{.Passkey}}', 'UTF8'), '\x01'::bytea, 'example.test');
INSERT INTO ctrlz.phone_change_requests (tenant_id, user_id, new_phone_e164, old_otp_id, new_otp_id, expires_at)
  VALUES ('{{.Tenant}}', '{{.User}}', '+98913000000{{.Index}}', gen_random_uuid(), gen_random_uuid(), now() + interval '10 minutes');
INSERT INTO ctrlz.tenant_entitlements (tenant_id) VALUES ('{{.Tenant}}');
INSERT INTO ctrlz.notifications (tenant_id, kind) VALUES ('{{.Tenant}}', 'welcome');
INSERT INTO ctrlz.announcement_reads (tenant_id, announcement_id, user_id)
  VALUES ('{{.Tenant}}', '00000000-0000-7000-8000-0000000000b1', '{{.User}}');
INSERT INTO ctrlz.feedback_items (tenant_id, kind, body) VALUES ('{{.Tenant}}', 'contact', 'hi');
INSERT INTO ctrlz.tenant_audit_log (tenant_id, user_id, action) VALUES ('{{.Tenant}}', '{{.User}}', 'login');
INSERT INTO ctrlz.idempotency_keys (tenant_id, key, route, request_hash, expires_at)
  VALUES ('{{.Tenant}}', 'k{{.Index}}', '/x', '\x01', now() + interval '1 day');
INSERT INTO ctrlz.tenant_assets (tenant_id, id, kind, sha256, mime, size, bytes)
  VALUES ('{{.Tenant}}', '00000000-0000-7000-8000-0000000{{.Index}}0a01', 'logo', decode(repeat('ab', 32), 'hex'), 'image/png', 4, '\x89504e47');

INSERT INTO ctrlz.profiles (tenant_id, id, name, locked_by) VALUES ('{{.Tenant}}', '{{.Profile}}', 'one', '{{.User}}');
INSERT INTO ctrlz.profiles (tenant_id, id, name) VALUES ('{{.Tenant}}', '{{.Profile2}}', 'two');
INSERT INTO ctrlz.profile_options (tenant_id, profile_id, default_action, default_target_kind, default_target_location_id, block_response, block_custom_v4)
  VALUES ('{{.Tenant}}', '{{.Profile}}', 'redirect', 'location', '00000000-0000-7000-8000-0000000000a1', 'custom', '203.0.113.9');
INSERT INTO ctrlz.profile_filters (tenant_id, profile_id, filter_id, mode) VALUES ('{{.Tenant}}', '{{.Profile}}', 'ads-trackers', 'strict');
INSERT INTO ctrlz.profile_services (tenant_id, profile_id, service_slug, action, target_kind, target_host)
  VALUES ('{{.Tenant}}', '{{.Profile}}', 'youtube', 'redirect', 'host', 'proxy.example.test');
INSERT INTO ctrlz.rule_folders (tenant_id, id, profile_id, name) VALUES ('{{.Tenant}}', '00000000-0000-7000-8000-0000000{{.Index}}0b01', '{{.Profile}}', 'work');
INSERT INTO ctrlz.rules (tenant_id, profile_id, folder_id, rule_key, match_kind, action, target_kind, target_ipv4)
  VALUES ('{{.Tenant}}', '{{.Profile}}', '00000000-0000-7000-8000-0000000{{.Index}}0b01', 'example.test', 'domain', 'redirect', 'ip', '203.0.113.7');
INSERT INTO ctrlz.block_pages (tenant_id, profile_id, logo_asset_id, title) VALUES ('{{.Tenant}}', '{{.Profile}}', '00000000-0000-7000-8000-0000000{{.Index}}0a01', 'Blocked');

INSERT INTO ctrlz.endpoint_groups (tenant_id, id, name) VALUES ('{{.Tenant}}', '00000000-0000-7000-8000-0000000{{.Index}}0c01', 'home');
INSERT INTO ctrlz.endpoints (tenant_id, id, name, type, group_id, resolver_id, profile_id, profile2_id)
  VALUES ('{{.Tenant}}', '{{.Endpoint}}', 'laptop', 'doh_client', '00000000-0000-7000-8000-0000000{{.Index}}0c01', '{{.ResolveID}}', '{{.Profile}}', '{{.Profile2}}');
INSERT INTO ctrlz.endpoint_ddns_hosts (tenant_id, id, endpoint_id, hostname)
  VALUES ('{{.Tenant}}', '00000000-0000-7000-8000-0000000{{.Index}}0d01', '{{.Endpoint}}', 'home{{.Index}}.example.test');
INSERT INTO ctrlz.schedule_windows (tenant_id, endpoint_id, minutes, profile_id, profile2_id)
  VALUES ('{{.Tenant}}', '{{.Endpoint}}', int4range(0, 60), '{{.Profile2}}', '{{.Profile}}');
INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, profile_id, profile2_id)
  VALUES ('{{.Tenant}}', '{{.Endpoint}}', 'default', '{{.Profile}}', '{{.Profile2}}');
INSERT INTO ctrlz.authorized_ips (tenant_id, endpoint_id, cidr, ddns_host_id)
  VALUES ('{{.Tenant}}', '{{.Endpoint}}', '198.51.{{.Index}}.0/24', '00000000-0000-7000-8000-0000000{{.Index}}0d01');
INSERT INTO ctrlz.ip_claims (tenant_id, id, endpoint_id, cidr, state, source)
  VALUES ('{{.Tenant}}', '{{.Claim}}', '{{.Endpoint}}', '{{.Prefix}}', 'active', 'manual');
INSERT INTO ctrlz.ip_proof_challenges (tenant_id, claim_id, label, expires_at)
  VALUES ('{{.Tenant}}', '{{.Claim}}', 'label{{.Index}}', now() + interval '10 minutes');
INSERT INTO ctrlz.setup_share_tokens (tenant_id, endpoint_id, client, token_hash, expires_at)
  VALUES ('{{.Tenant}}', '{{.Endpoint}}', 'default', convert_to('{{.Share}}', 'UTF8'), now() + interval '1 day');
INSERT INTO ctrlz.profile_download_tokens (tenant_id, endpoint_id, params, params_hash, token_hash, expires_at, via_share_id)
  VALUES ('{{.Tenant}}', '{{.Endpoint}}', '{}'::jsonb, '\x01', convert_to('{{.Download}}', 'UTF8'), now() + interval '15 minutes',
    (SELECT s.id FROM ctrlz.setup_share_tokens s WHERE s.tenant_id = '{{.Tenant}}' AND s.token_hash = convert_to('{{.Share}}', 'UTF8')));
INSERT INTO ctrlz.unblock_requests (tenant_id, profile_id, endpoint_id, qname) VALUES ('{{.Tenant}}', '{{.Profile}}', '{{.Endpoint}}', 'example.test');
INSERT INTO ctrlz.filter_preview_jobs (tenant_id, profile_id, filter_id, window_days) VALUES ('{{.Tenant}}', '{{.Profile}}', 'ads-trackers', 7);
INSERT INTO ctrlz.batch_jobs (tenant_id, kind, profile_id) VALUES ('{{.Tenant}}', 'import', '{{.Profile}}');
INSERT INTO ctrlz.analytics_read_floors (tenant_id, endpoint_id) VALUES ('{{.Tenant}}', '{{.Endpoint}}');
INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id) VALUES ('{{.Tenant}}', 'profile', '{{.Profile}}', gen_random_uuid());
INSERT INTO ctrlz.job_outbox (tenant_id, kind) VALUES ('{{.Tenant}}', 'welcome');
`))

// NewSeedIDs makes the ids of tenant number n (1 or 2).
func NewSeedIDs(n int) SeedIDs {
	return SeedIDs{
		Tenant:    uuid.Must(uuid.NewV7()),
		User:      uuid.Must(uuid.NewV7()),
		Profile:   uuid.Must(uuid.NewV7()),
		Profile2:  uuid.Must(uuid.NewV7()),
		Endpoint:  uuid.Must(uuid.NewV7()),
		Claim:     uuid.Must(uuid.NewV7()),
		Index:     n,
		Phone:     fmt.Sprintf("+98912000000%d", n),
		Session:   fmt.Sprintf("session-token-%d", n),
		APIToken:  fmt.Sprintf("api-token-%d", n),
		Refresh:   fmt.Sprintf("refresh-token-%d", n),
		Passkey:   fmt.Sprintf("credential-%d", n),
		Share:     fmt.Sprintf("share-token-%d", n),
		Download:  fmt.Sprintf("download-token-%d", n),
		Prefix:    fmt.Sprintf("10.%d.0.1/32", n),
		ResolveID: strings.Repeat("a", 25) + fmt.Sprint(n+1),
	}
}

// SeedGlobal inserts the global rows the tenant seed refers to.
func SeedGlobal(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, globalSeed)
	return err
}

// SeedTenant inserts one row into every tenant table for the tenant in ids.
// It runs as the superuser, which bypasses RLS: the migrator and every
// service role are blocked from writing without a tenant, and that is the
// point of the schema.
func SeedTenant(ctx context.Context, conn *pgx.Conn, ids SeedIDs) error {
	var b bytes.Buffer
	if err := tenantSeedTmpl.Execute(&b, ids); err != nil {
		return err
	}
	// Split so that an error names its statement, and so each row is its own
	// round trip in the log.
	for _, stmt := range strings.Split(b.String(), ";\n") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := conn.Exec(ctx, stmt); err != nil {
			first := stmt
			if len(first) > 80 {
				first = first[:80]
			}
			return fmt.Errorf("seed %q: %w", first, err)
		}
	}
	return nil
}
