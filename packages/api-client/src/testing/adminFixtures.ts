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
