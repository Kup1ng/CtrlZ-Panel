import type {components as Admin} from "../generated/admin";

// Typed fixtures of the admin API for the mock mode of the e2e tests (spec 17.1, apps/admin/e2e). Each one is the schema of
// the generated document, so an API change that breaks a fixture breaks `tsc` and not a test at run time. Numbers and ids
// are invented.

type A = Admin["schemas"];

export type AdminUserRow = A["AdminUserRow"];
export type InviteRow = A["InviteRow"];
export type SmsGatewayRow = A["SmsGatewayRow"];
export type SmsTemplateRow = A["SmsTemplateRow"];
export type SmsLimits = A["SmsLimits"];
export type SmsStats = A["SmsStats"];
export type AuditRow = A["AuditRow"];
export type AlertRow = A["AlertRow"];

let counter = 0;
const uuid = () => `00000000-0000-4000-8000-${String(++counter).padStart(12, "0")}`;

export function adminUserFixture(over: Partial<AdminUserRow> = {}): AdminUserRow {
  const n = counter + 1;
  return {
    tenant_id: uuid(),
    user_id: uuid(),
    phone_e164: `+98912000${String(1000 + n).slice(-4)}`,
    tenant_status: "active",
    created_at: "2026-11-10T08:00:00Z",
    last_login_at: "2026-11-15T09:30:00Z",
    ...over,
  };
}

export function inviteFixture(over: Partial<InviteRow> = {}): InviteRow {
  const n = counter + 1;
  return {
    id: uuid(),
    phone_e164: `+98935000${String(1000 + n).slice(-4)}`,
    locale: "fa",
    state: "pending",
    expires_at: "2026-11-25T08:00:00Z",
    created_at: "2026-11-12T08:00:00Z",
    ...over,
  };
}

export function gatewayFixture(over: Partial<SmsGatewayRow> = {}): SmsGatewayRow {
  return {provider: "sms_ir", role: "primary", configured: true, hint: "…a9f2", cost_per_message: "420", last_ok_at: "2026-11-16T07:00:00Z", ...over};
}

export function templateFixture(over: Partial<SmsTemplateRow> = {}): SmsTemplateRow {
  return {key: "otp", locale: "fa", body: "کد ورود شما: {code}", mappings: [], ...over};
}

export function limitsFixture(over: Partial<SmsLimits> = {}): SmsLimits {
  return {
    otp_cap_phone: 5,
    otp_cap_phone_net: 8,
    otp_cap_ip: 20,
    otp_cap_net24: 60,
    otp_cap_phone_trusted: 10,
    otp_cap_net48: 120,
    otp_cap_global: 2000,
    otp_cooldown_s: 60,
    otp_soft_pct: 80,
    sms_outbox_cap_daily: 500,
    ...over,
  };
}

export function statsFixture(over: Partial<SmsStats> = {}): SmsStats {
  return {
    days: [
      {day: "2026-11-16", otp_count: 120, outbox_count: 8, cost: "53760"},
      {day: "2026-11-15", otp_count: 98, outbox_count: 3, cost: "42420"},
    ],
    gateways: [
      {provider: "sms_ir", accepted: 214, failed: 4},
      {provider: "melipayamak", accepted: 3, failed: 1},
    ],
    ...over,
  };
}

let auditId = 0;
export function auditFixture(over: Partial<AuditRow> = {}): AuditRow {
  return {id: ++auditId, at: "2026-11-16T10:00:00Z", action: "admin.login", target: "admin", params: {method: "password"}, ip: "203.0.113.5", ...over};
}

export function alertFixture(over: Partial<AlertRow> = {}): AlertRow {
  return {id: uuid(), severity: "critical", kind: "sms_gateway", params: {provider: "sms_ir", class: "credit", code: "no_credit"}, created_at: "2026-11-16T06:00:00Z", ...over};
}

// ---- P4 (p4-nodes 9.2): nodes, pairs, enrolments, free DNS, domain and certificates -------------------------------------------------
// The documentation addresses are RFC 5737 (203.0.113.0/24, 198.51.100.0/24), so no fixture names a real host.

export type NodeView = A["NodeView"];
export type PairView = A["PairView"];
export type NodeEnrollmentRow = A["NodeEnrollmentRow"];
export type AddressGivenUp = A["AddressGivenUp"];
export type TakenClaim = A["TakenClaim"];
export type KeptRow = A["KeptRow"];
export type Overview = A["Overview"];
export type FreeDnsSettings = A["FreeDnsSettings"];
export type FreeCounterRow = A["FreeCounterRow"];
export type DomainSettings = A["DomainSettings"];
export type CertificateView = A["CertificateView"];

const NOW = "2026-11-24T10:00:00Z";

/** An active node that has just sent a Heartbeat and is at the head of the configuration. `slot` picks its addresses. */
export function nodeFixture(over: Partial<NodeView> = {}): NodeView {
  const slot = over.slot ?? 1;
  return {
    id: uuid(),
    slot,
    name: `node-${slot}`,
    status: "active",
    resolve_mode: "recursive",
    proxy_blocked: false,
    dns_bind_ip: `203.0.113.${10 + slot}`,
    dns_advertised_ip: `203.0.113.${10 + slot}`,
    proxy_bind_ip: `198.51.100.${10 + slot}`,
    proxy_advertised_ip: `198.51.100.${10 + slot}`,
    key_fingerprint: hexFingerprint(slot),
    created_at: "2026-11-10T08:00:00Z",
    last_heartbeat_at: new Date(Date.now() - 20_000).toISOString(),
    node_version: "0.4.2",
    unbound_version: "1.22.0",
    catalog_version: "2026.11.20",
    applied_seq: 120,
    config_head: 120,
    applied_seq_lag: 0,
    dns_withdrawn: false,
    dns_hold: false,
    pending_requests: 0,
    ...over,
  };
}

/**
 * A key fingerprint as the contract writes it: 64 lower-case hex digits (`^[0-9a-f]*$`), made from a number so that each fixture has its own.
 * A text such as "SHA256:fixture1" is not one, so a mock test with it would never notice a change in the form the page sends (PG-r1-11).
 */
export function hexFingerprint(seed: number): string {
  return `${seed.toString(16).padStart(2, "0")}ab`.repeat(16);
}

export function pairFixture(primary: NodeView, fallback: NodeView, over: Partial<PairView> = {}): PairView {
  return {id: uuid(), primary_node_id: primary.id, fallback_node_id: fallback.id, is_global: true, created_at: "2026-11-11T08:00:00Z", ...over};
}

export function enrollmentFixture(over: Partial<NodeEnrollmentRow> = {}): NodeEnrollmentRow {
  return {
    id: uuid(),
    state: "pending_approval",
    created_at: NOW,
    expires_at: "2026-11-24T10:15:00Z",
    key_fingerprint: hexFingerprint(90),
    dns_bind_ip: "203.0.113.20",
    dns_advertised_ip: "203.0.113.20",
    proxy_bind_ip: "198.51.100.20",
    proxy_advertised_ip: "198.51.100.20",
    hostname: "host-1",
    node_version: "0.4.2",
    ...over,
  };
}

export function givenUpFixture(over: Partial<AddressGivenUp> = {}): AddressGivenUp {
  return {address: "203.0.113.50", kind: "dns", node_name: "node-old", given_up_at: "2026-11-20T09:00:00Z", safe_from: "2026-12-20T09:00:00Z", ...over};
}

/** A claim taken on a node's proof observation. `n` makes the ids distinct and the time `n` minutes back from the fixed moment. */
export function claimFixture(n: number, over: Partial<TakenClaim> = {}): TakenClaim {
  const hex = (v: number, w: number) => v.toString(16).padStart(w, "0");
  return {
    tenant_id: `0000000a-0000-4000-8000-${hex(n % 3, 12)}`,
    endpoint_id: `0000000b-0000-4000-8000-${hex(n, 12)}`,
    claim_id: `0000000c-0000-4000-8000-${hex(n, 12)}`,
    cidr: `198.51.${100 + (n % 100)}.0/24`,
    consumed_at: new Date(Date.parse("2026-11-24T10:00:00Z") - n * 60_000).toISOString(),
    ...over,
  };
}

export function freeDnsFixture(over: Partial<FreeDnsSettings> = {}): FreeDnsSettings {
  return {enabled: true, qps: 1000, version: 1_763_000_000_000, ...over};
}

export function freeCounterFixture(node: NodeView, over: Partial<FreeCounterRow> = {}): FreeCounterRow {
  return {node_id: node.id, bucket_start: "2026-11-24T09:00:00Z", transport: "udp", outcome: "answered", rcode: 0, count: 1200, ...over};
}

export function overviewFixture(nodes: NodeView[], over: Partial<Overview> = {}): Overview {
  return {nodes, config_head: 120, qps: 340, cache_hit_permille: 912, free_dns: freeDnsFixture(), ...over};
}

export function domainFixture(over: Partial<DomainSettings> = {}): DomainSettings {
  return {dns_zone: "dns.example.ir", panel_host: "panel.example.ir", admin_host: "admin.example.ir", apply_pending: false, ...over};
}

export function certificateFixture(over: Partial<CertificateView> = {}): CertificateView {
  return {
    id: uuid(),
    kind: "wildcard",
    source: "uploaded",
    state: "active",
    names: ["*.dns.example.ir", "dns.example.ir"],
    not_before: "2026-10-01T00:00:00Z",
    not_after: "2027-01-01T00:00:00Z",
    created_at: "2026-10-02T08:00:00Z",
    ...over,
  };
}
