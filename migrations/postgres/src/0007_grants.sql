-- Grants. Spec sections 6 and 7: the matrix and the column limits.
--
-- Notation in the grant lines: S select, I insert, U update, D delete. A
-- letter alone is a table-level grant. S(a,b) is column-level on a and b.
-- S(-a-b) is column-level on every column except a and b, resolved here at
-- migration time, so a column added later is NOT readable until a migration
-- grants it (fail closed). Omitted privileges are denied.
--
-- The exact same strings are in migrations/catalog/grants.yaml, and the
-- catalog test compares what Postgres holds with that file in both directions.
-- Nothing is ever granted to PUBLIC.

-- +goose Up

SET LOCAL search_path = ctrlz, pg_catalog;

-- Helper that exists only for this migration (pg_temp), so it is not part of
-- the schema and the function checks never see it.
-- +goose StatementBegin
CREATE FUNCTION pg_temp.grant_dsl(p_table text, p_role text, p_spec text) RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  tok    text[];
  v_priv text;
  v_args text;
  v_cols text;
BEGIN
  FOR tok IN SELECT m FROM regexp_matches(p_spec, '([SIUD])(?:\(([^)]*)\))?', 'g') AS m LOOP
    v_priv := CASE tok[1] WHEN 'S' THEN 'SELECT' WHEN 'I' THEN 'INSERT' WHEN 'U' THEN 'UPDATE' ELSE 'DELETE' END;
    v_args := tok[2];
    IF v_args IS NULL THEN
      EXECUTE format('GRANT %s ON ctrlz.%I TO %I', v_priv, p_table, p_role);
    ELSE
      IF left(v_args, 1) = '-' THEN
        SELECT string_agg(quote_ident(a.attname), ', ' ORDER BY a.attnum) INTO v_cols
        FROM pg_attribute a
        WHERE a.attrelid = format('ctrlz.%I', p_table)::regclass
          AND a.attnum > 0 AND NOT a.attisdropped
          AND a.attname <> ALL (string_to_array(substr(v_args, 2), '-'));
      ELSE
        SELECT string_agg(quote_ident(btrim(c)), ', ') INTO v_cols
        FROM unnest(string_to_array(v_args, ',')) AS c;
      END IF;
      EXECUTE format('GRANT %s (%s) ON ctrlz.%I TO %I', v_priv, v_cols, p_table, p_role);
    END IF;
  END LOOP;
END
$$;
-- +goose StatementEnd

-- Tenant tables ----------------------------------------------------------------------

{{grant "tenants" "tenant" "S(-admin_hold) U(home_countries,raw_retention_days,aggregate_retention_months)"}}
{{grant "tenants" "compiler" "S(id,status,admin_hold)"}}
{{grant "tenants" "worker" "S(id,status,deleted_at,raw_retention_days,aggregate_retention_months) U(status,deleted_at) D"}}
{{grant "tenants" "admin" "S U(status,admin_hold)"}}
{{grant "tenants" "auth" "S(id,status) I"}}

{{grant "users" "tenant" "S(-password_hash-totp_secret_ct) U(locale,theme,onboarding_hints,onboarding_state,password_hash,totp_secret_ct,totp_enabled_at,totp_last_step,enforce_passkey,phone_e164,phone_verified_at,last_login_at,must_reset)"}}
{{grant "users" "worker" "S(tenant_id,id,phone_e164,locale) U(enforce_passkey)"}}
{{grant "users" "admin" "S(-password_hash-totp_secret_ct) U(must_reset,password_hash,totp_secret_ct,totp_enabled_at,enforce_passkey)"}}
{{grant "users" "auth" "S(tenant_id,id,phone_e164,password_hash,totp_secret_ct,totp_enabled_at,enforce_passkey,must_reset) I"}}

{{grant "recovery_codes" "tenant" "S I U D"}}
{{grant "recovery_codes" "admin" "D"}}

{{grant "sessions" "tenant" "S I U D"}}
{{grant "sessions" "worker" "D"}}
{{grant "sessions" "admin" "S(tenant_id,id,user_id,created_at,last_seen_at,revoked_at) U"}}
{{grant "sessions" "auth" "S(tenant_id,id,user_id,token_hash,idle_expires_at,absolute_expires_at,revoked_at)"}}

{{grant "refresh_tokens" "tenant" "S I U D"}}
{{grant "refresh_tokens" "worker" "D"}}
{{grant "refresh_tokens" "admin" "U"}}
{{grant "refresh_tokens" "auth" "S(tenant_id,id,user_id,token_hash,family_id,rotated_at,reuse_grace_until,expires_at,revoked_at)"}}

{{grant "api_tokens" "tenant" "S I U(name,allowed_ips,last_used_at,revoked_at) D"}}
{{grant "api_tokens" "admin" "U"}}
{{grant "api_tokens" "auth" "S(tenant_id,id,user_id,token_hash,kind,allowed_ips,revoked_at)"}}

{{grant "webauthn_credentials" "tenant" "S I U(name,sign_count,last_used_at) D"}}
{{grant "webauthn_credentials" "admin" "U"}}
{{grant "webauthn_credentials" "auth" "S(tenant_id,id,user_id,credential_id,public_key,sign_count,rp_id,stale_at)"}}

{{grant "phone_change_requests" "tenant" "S I U"}}
{{grant "phone_change_requests" "worker" "D"}}

{{grant "tenant_entitlements" "tenant" "S"}}
{{grant "tenant_entitlements" "compiler" "S"}}
{{grant "tenant_entitlements" "worker" "S"}}
{{grant "tenant_entitlements" "admin" "S I U"}}
{{grant "tenant_entitlements" "auth" "I"}}

{{grant "notifications" "tenant" "S U(read_at)"}}
{{grant "notifications" "worker" "I D"}}
{{grant "notifications" "admin" "I"}}

{{grant "announcement_reads" "tenant" "S I"}}
{{grant "announcement_reads" "worker" "D"}}

{{grant "feedback_items" "tenant" "S I"}}
{{grant "feedback_items" "admin" "S U(status,admin_reply,replied_at)"}}

{{grant "tenant_audit_log" "tenant" "S I"}}
{{grant "tenant_audit_log" "worker" "D"}}

{{grant "idempotency_keys" "tenant" "S I U"}}
{{grant "idempotency_keys" "worker" "D"}}

{{grant "batch_jobs" "tenant" "S I"}}
{{grant "batch_jobs" "worker" "S U D"}}

{{grant "analytics_read_floors" "tenant" "S I U"}}
{{grant "analytics_read_floors" "worker" "S"}}

{{grant "tenant_assets" "tenant" "S I D"}}
{{grant "tenant_assets" "compiler" "S"}}
{{grant "tenant_assets" "worker" "D"}}

{{grant "profiles" "tenant" "S I U(-id-tenant_id-compiled_hash) D"}}
{{grant "profiles" "compiler" "S"}}
{{grant "profiles" "worker" "S U(version,updated_at)"}}
{{grant "profiles" "admin" "S(tenant_id,id,name,kind,lock_state,locked_at) U(lock_state,lock_message,lock_password_hash,locked_by,locked_at)"}}

{{grant "profile_options" "tenant" "S I U D"}}
{{grant "profile_options" "compiler" "S"}}
{{grant "profile_options" "worker" "S U(default_location_unavailable)"}}

{{grant "profile_filters" "tenant" "S I U D"}}
{{grant "profile_filters" "compiler" "S"}}
{{grant "profile_filters" "worker" "S"}}

{{grant "profile_services" "tenant" "S I U D"}}
{{grant "profile_services" "compiler" "S"}}
{{grant "profile_services" "worker" "S U(location_unavailable)"}}

{{grant "rule_folders" "tenant" "S I U D"}}
{{grant "rule_folders" "compiler" "S"}}
{{grant "rule_folders" "worker" "S"}}

{{grant "rules" "tenant" "S I U D"}}
{{grant "rules" "compiler" "S"}}
{{grant "rules" "worker" "S U(location_unavailable) D"}}

{{grant "block_pages" "tenant" "S I U D"}}
{{grant "block_pages" "compiler" "S"}}

{{grant "unblock_requests" "tenant" "S U(status)"}}
{{grant "unblock_requests" "hub" "I"}}
{{grant "unblock_requests" "worker" "D"}}

{{grant "filter_preview_jobs" "tenant" "S I"}}
{{grant "filter_preview_jobs" "worker" "S U D"}}

{{grant "endpoint_groups" "tenant" "S I U D"}}
{{grant "endpoint_groups" "compiler" "S"}}

{{grant "endpoints" "tenant" "S(-doh_token_hash) I(tenant_id,id,name,type,group_id,comment,resolver_id,doh_token_ct,doh_token_hash,profile_id,profile2_id,analytics_level,admin_state,legacy_dns,authorize_secure_dns,authorize_ddns,expose_ip,prevent_deactivation,require_authorized_ips,schedule_timezone,apple_profile_generated_at) U(name,type,group_id,comment,profile_id,profile2_id,analytics_level,admin_state,legacy_dns,authorize_secure_dns,authorize_ddns,expose_ip,prevent_deactivation,require_authorized_ips,schedule_timezone,resolver_id,doh_token_ct,doh_token_hash,apple_profile_generated_at) D"}}
{{grant "endpoints" "hub" "S(id,tenant_id,pair_override_node_a,pair_override_node_b,pair_version,first_query_at,last_query_at) U(first_query_at,last_query_at)"}}
{{grant "endpoints" "compiler" "S(-doh_token_ct)"}}
{{grant "endpoints" "worker" "S(tenant_id,id,legacy_dns,authorize_ddns,require_authorized_ips,last_query_at) U(pair_version)"}}
{{grant "endpoints" "admin" "S(tenant_id,id,type,admin_state,admin_hold,first_query_at,last_query_at) U(admin_hold)"}}
{{grant "endpoints" "auth" "S(tenant_id,id,pair_override_node_a,pair_override_node_b,admin_state)"}}

{{grant "endpoint_ddns_hosts" "tenant" "S I U D"}}
{{grant "endpoint_ddns_hosts" "worker" "S U(last_resolved_at,last_ips,last_error)"}}

{{grant "schedule_windows" "tenant" "S I U D"}}
{{grant "schedule_windows" "compiler" "S"}}

{{grant "clients" "tenant" "S I U(alias,profile_id,profile2_id,analytics_level,group_name,is_custom) D"}}
{{grant "clients" "hub" "S(tenant_id,id,endpoint_id,label) I(tenant_id,endpoint_id,label,source,first_seen_at,last_seen_at) U(last_seen_at)"}}
{{grant "clients" "compiler" "S"}}
{{grant "clients" "worker" "S D"}}

{{grant "authorized_ips" "tenant" "S I U(cleanup_opt_in) D"}}
{{grant "authorized_ips" "hub" "S(tenant_id,id,endpoint_id,cidr) U(last_seen_at)"}}
{{grant "authorized_ips" "compiler" "S"}}
{{grant "authorized_ips" "worker" "S I U(last_seen_at) D"}}

{{grant "ip_claims" "tenant" "S"}}
{{grant "ip_claims" "hub" "S(tenant_id,id,endpoint_id) U(last_seen_at)"}}
{{grant "ip_claims" "compiler" "S"}}
{{grant "ip_claims" "worker" "S U(state,grace_until,first_grace_at)"}}
{{grant "ip_claims" "admin" "S U(state,approved_by_admin)"}}
{{grant "ip_claims" "auth" "S I U"}}

{{grant "ip_proof_challenges" "tenant" "S I U(consumed_at)"}}
{{grant "ip_proof_challenges" "hub" "S(tenant_id,id,label) U(observed_at,observed_ip)"}}
{{grant "ip_proof_challenges" "worker" "D"}}

{{grant "setup_share_tokens" "tenant" "S I U(revoked_at,uses) D"}}
{{grant "setup_share_tokens" "worker" "D"}}
{{grant "setup_share_tokens" "auth" "S(tenant_id,id,endpoint_id,token_hash,expires_at,max_uses,uses,client,revoked_at)"}}

{{grant "profile_download_tokens" "tenant" "S I U(uses) D"}}
{{grant "profile_download_tokens" "worker" "D"}}
{{grant "profile_download_tokens" "auth" "S(tenant_id,id,endpoint_id,token_hash,expires_at,max_uses,uses,params_hash)"}}

{{grant "policy_outbox" "tenant" "I"}}
{{grant "policy_outbox" "compiler" "S D"}}
{{grant "policy_outbox" "worker" "I"}}
{{grant "policy_outbox" "admin" "I"}}

{{grant "job_outbox" "tenant" "I"}}
{{grant "job_outbox" "hub" "I"}}
{{grant "job_outbox" "worker" "S D"}}
{{grant "job_outbox" "admin" "I"}}

-- Global tables ----------------------------------------------------------------------

{{grant "public_settings" "tenant" "S"}}
{{grant "public_settings" "hub" "S"}}
{{grant "public_settings" "compiler" "S"}}
{{grant "public_settings" "worker" "S"}}
{{grant "public_settings" "admin" "S U"}}
{{grant "public_settings" "auth" "S"}}

{{grant "system_settings" "worker" "S"}}
{{grant "system_settings" "admin" "S U"}}
{{grant "system_settings" "auth" "S"}}

{{grant "domain_settings" "tenant" "S"}}
{{grant "domain_settings" "hub" "S"}}
{{grant "domain_settings" "compiler" "S"}}
{{grant "domain_settings" "worker" "S"}}
{{grant "domain_settings" "admin" "S U"}}

{{grant "webauthn_config" "tenant" "S"}}
{{grant "webauthn_config" "admin" "S U"}}

{{grant "entitlement_defaults" "tenant" "S"}}
{{grant "entitlement_defaults" "compiler" "S"}}
{{grant "entitlement_defaults" "worker" "S"}}
{{grant "entitlement_defaults" "admin" "S U"}}

{{grant "leases" "hub" "S I U"}}
{{grant "leases" "compiler" "S I U"}}
{{grant "leases" "worker" "S I U"}}

{{grant "invites" "worker" "D"}}
{{grant "invites" "admin" "S I U"}}
{{grant "invites" "auth" "S(id,token_hash,phone_e164,expires_at,used_at,revoked_at) U(used_at,accepted_tenant_id)"}}

{{grant "otp_challenges" "worker" "S(id,phone_e164,purpose,delivery_ct) U(delivery_ct) D"}}
{{grant "otp_challenges" "auth" "S I U"}}

{{grant "sms_counters" "worker" "S I U D"}}
{{grant "sms_counters" "admin" "S"}}
{{grant "sms_counters" "auth" "S I U"}}

{{grant "sms_gateways" "worker" "S"}}
{{grant "sms_gateways" "admin" "S I U"}}

{{grant "sms_templates" "worker" "S"}}
{{grant "sms_templates" "admin" "S I U"}}

{{grant "admin_users" "admin" "S I U D"}}
{{grant "admin_sessions" "admin" "S I U D"}}

{{grant "audit_log" "admin" "S I"}}

{{grant "alerts" "hub" "I"}}
{{grant "alerts" "compiler" "I"}}
{{grant "alerts" "worker" "I"}}
{{grant "alerts" "admin" "S U"}}

{{grant "announcements" "tenant" "S"}}
{{grant "announcements" "worker" "S"}}
{{grant "announcements" "admin" "S I U D"}}

{{grant "nodes" "hub" "S U(last_heartbeat_at,version_info,applied_seq,cert_serial)"}}
{{grant "nodes" "compiler" "S"}}
{{grant "nodes" "worker" "S"}}
{{grant "nodes" "admin" "S I U"}}
{{grant "nodes" "auth" "S(id,dns_advertised_ip)"}}

{{grant "node_enrollments" "hub" "S I U"}}
{{grant "node_enrollments" "worker" "D"}}
{{grant "node_enrollments" "admin" "S I U"}}

{{grant "node_certs" "hub" "S I U"}}
{{grant "node_certs" "admin" "S U"}}

-- Tenants see the pair by id only, never an address.
{{grant "node_pairs" "tenant" "S(id,primary_node_id,fallback_node_id)"}}
{{grant "node_pairs" "hub" "S"}}
{{grant "node_pairs" "compiler" "S"}}
{{grant "node_pairs" "worker" "S"}}
{{grant "node_pairs" "admin" "S I U"}}
{{grant "node_pairs" "auth" "S"}}

{{grant "node_upstreams" "hub" "S"}}
{{grant "node_upstreams" "compiler" "S"}}
{{grant "node_upstreams" "admin" "S I U D"}}
{{grant "node_resolver_rules" "hub" "S"}}
{{grant "node_resolver_rules" "compiler" "S"}}
{{grant "node_resolver_rules" "admin" "S I U D"}}

{{grant "locations" "tenant" "S"}}
{{grant "locations" "hub" "S"}}
{{grant "locations" "compiler" "S"}}
{{grant "locations" "worker" "S"}}
{{grant "locations" "admin" "S I U"}}

{{grant "node_location_configs" "hub" "S"}}
{{grant "node_location_configs" "compiler" "S"}}
{{grant "node_location_configs" "worker" "S"}}
{{grant "node_location_configs" "admin" "S I U D"}}

{{grant "location_availability" "tenant" "S"}}
{{grant "location_availability" "hub" "S"}}
{{grant "location_availability" "compiler" "S"}}
{{grant "location_availability" "worker" "S"}}
{{grant "location_availability" "admin" "S I U D"}}

{{grant "config_log" "hub" "S"}}
{{grant "config_log" "compiler" "S I"}}
{{grant "config_log" "worker" "D"}}
{{grant "config_log" "admin" "S"}}

{{grant "policy_artifacts" "hub" "S"}}
{{grant "policy_artifacts" "compiler" "S I U"}}
{{grant "policy_artifacts" "worker" "D"}}
{{grant "policy_artifacts" "admin" "S"}}

{{grant "config_snapshot" "hub" "S"}}
{{grant "config_snapshot" "compiler" "S I D"}}
{{grant "config_snapshot" "admin" "S"}}

{{grant "node_quarantine" "hub" "S I U"}}
{{grant "node_quarantine" "compiler" "S"}}
{{grant "node_quarantine" "admin" "S U"}}

-- A node gets the wrapped key bundle only (R5).
{{grant "certificates" "hub" "S(id,kind,chain_pem,wrapped_key_ct,not_after,state)"}}
{{grant "certificates" "worker" "S I U"}}
{{grant "certificates" "admin" "S I U"}}

{{grant "update_status" "hub" "S"}}
{{grant "update_status" "compiler" "S"}}
{{grant "update_status" "worker" "S I U"}}
{{grant "update_status" "admin" "S I U"}}
{{grant "bundles" "hub" "S"}}
{{grant "bundles" "compiler" "S"}}
{{grant "bundles" "worker" "S I U"}}
{{grant "bundles" "admin" "S I U"}}
{{grant "geoip_versions" "hub" "S"}}
{{grant "geoip_versions" "compiler" "S"}}
{{grant "geoip_versions" "worker" "S I U"}}
{{grant "geoip_versions" "admin" "S I U"}}

-- Catalog and seed tables. The tenant role gets only what a route reads.
{{grant "catalog_filter" "tenant" "S"}}
{{grant "catalog_filter_mode" "tenant" "S"}}
{{grant "catalog_service" "tenant" "S"}}
{{grant "catalog_service_domain" "tenant" "S"}}
{{grant "catalog_service_category" "tenant" "S"}}
{{grant "catalog_versions" "tenant" "S(version)"}}
{{grant "endpoint_types" "tenant" "S"}}
{{grant "profile_presets" "tenant" "S"}}

{{catalog_grants}}

-- Views ------------------------------------------------------------------------------

GRANT SELECT ON hub_endpoint_index TO ctrlz_hub;
GRANT SELECT ON tenant_endpoint_status TO ctrlz_tenant;
GRANT SELECT ON tenant_profile_counts TO ctrlz_tenant;
GRANT SELECT ON admin_tenant_summary TO ctrlz_admin;
