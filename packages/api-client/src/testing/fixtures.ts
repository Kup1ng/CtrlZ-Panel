import type {components as Admin} from "../generated/admin";
import type {components as Panel} from "../generated/panel";

// Typed fixtures for the mock mode of the e2e tests (spec 17.1). Each one is the
// schema of the generated document, so an API change that breaks a fixture breaks
// `tsc`, not a test at run time. Phone numbers and ids here are invented.

type P = Panel["schemas"];
type A = Admin["schemas"];

export type Me = P["Me"];
export type Notification = P["Notification"];
export type Announcement = P["Announcement"];

const USER_ID = "00000000-0000-4000-8000-000000000001";
const TENANT_ID = "00000000-0000-4000-8000-0000000000a1";

/** A signed-in, ready user in Persian, with a password and no second factor. */
export function meFixture(over: {user?: Partial<Me["user"]>; security?: Partial<Me["security"]>; tenant?: Partial<Me["tenant"]>} = {}): Me {
  return {
    user: {
      id: USER_ID,
      phone_masked: "+98912***4567",
      phone_verified: true,
      locale: "fa",
      theme: "system",
      onboarding_hints: {enabled: true},
      onboarding_state: {},
      has_password: true,
      must_reset: false,
      ...over.user,
    },
    security: {
      totp_enabled: false,
      recovery_codes_left: 0,
      passkeys: 0,
      enforce_passkey: false,
      passkey_review_required: false,
      ...over.security,
    },
    tenant: {id: TENANT_ID, status: "active", home_countries: ["IR"], ...over.tenant},
  };
}

let counter = 0;
const uuid = () => `00000000-0000-4000-8000-${String(++counter).padStart(12, "0")}`;

export function notificationFixture(over: Partial<Notification> = {}): Notification {
  return {
    id: uuid(),
    kind: "password_reset",
    severity: "info",
    params: {},
    created_at: "2026-11-10T08:00:00Z",
    ...over,
  };
}

export function announcementFixture(over: Partial<Announcement> = {}): Announcement {
  return {id: uuid(), body: "Planned maintenance tonight.", starts_at: "2026-11-01T00:00:00Z", read: false, ...over};
}

export function publicConfigFixture(over: Partial<P["PublicConfig"]> = {}): P["PublicConfig"] {
  return {registration_mode: "invite", sms_available: true, passkey_enabled: false, ...over};
}

export function sessionRowFixture(over: Partial<P["SessionRow"]> = {}): P["SessionRow"] {
  return {
    id: uuid(),
    current: false,
    created_at: "2026-11-09T10:00:00Z",
    last_seen_at: "2026-11-10T10:00:00Z",
    auth_method: "password",
    ip: "203.0.113.7",
    user_agent: "Mozilla/5.0 (fixture)",
    ...over,
  };
}

export function passkeyRowFixture(over: Partial<P["PasskeyRow"]> = {}): P["PasskeyRow"] {
  return {id: uuid(), name: "Passkey 1", created_at: "2026-11-01T10:00:00Z", stale: false, backup_eligible: true, ...over};
}

export function adminMeFixture(over: Partial<A["AdminMe"]> = {}): A["AdminMe"] {
  return {username: "admin", must_change_password: false, totp_enrolled: true, notices: [], ...over};
}

export function errorBody(code: string, over: Partial<P["Error"]> = {}): P["Error"] {
  return {code, request_id: "req-fixture-1", ...over};
}

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * The challenge id that `POST /auth/otp/request` answers with: 64 characters of base64url, not a UUID, so an id that
 * was never issued looks like one that was (OtpIssued in api/openapi.yaml; only the signed-in reauthentication
 * challenge, SessionOtpIssued, is a UUID). The alphabet is walked with a stride of 7, so every id holds `-` and `_`
 * and the screens are tested with the characters a real id carries.
 */
export function otpChallengeId(seed: number): string {
  return Array.from({length: 64}, (_, i) => B64URL[(i * 7 + seed * 13 + 5) % 64]).join("");
}
