import {describe, expect, it} from "vitest";

import {FRESH_WINDOW_MS, freshUntil} from "./fresh.ts";
import {noticesOf, unresolvedAlerts, type AlertRow} from "./hooks/alerts.ts";
import {AUDIT_ACTION_RE} from "./hooks/audit.ts";

// The pure rules of the admin hooks (spec 11.3, 13.5, 13.6): the fresh-TOTP window as the indicator reads it, the order of the
// banners, and the shape of the audit filter. The calls themselves are covered in the browser (apps/admin/e2e).

const NOW = Date.parse("2026-11-17T10:00:00Z");
const at = (ms: number) => new Date(NOW + ms).toISOString();

describe("freshUntil", () => {
  it("is the end of the window while it is open", () => {
    expect(freshUntil({fresh_until: at(120_000)}, NOW)?.toISOString()).toBe(at(120_000));
  });
  it("is nothing when there is no window, it ended, or the date is not one", () => {
    expect(freshUntil(undefined, NOW)).toBeUndefined();
    expect(freshUntil({}, NOW)).toBeUndefined();
    expect(freshUntil({fresh_until: at(-1)}, NOW)).toBeUndefined();
    expect(freshUntil({fresh_until: at(0)}, NOW)).toBeUndefined();
    expect(freshUntil({fresh_until: "not a date"}, NOW)).toBeUndefined();
  });
  it("does not trust a window longer than the five minutes there is (a wrong clock)", () => {
    expect(freshUntil({fresh_until: at(FRESH_WINDOW_MS)}, NOW)).toBeDefined();
    expect(freshUntil({fresh_until: at(FRESH_WINDOW_MS + 30_000)}, NOW)).toBeDefined();
    expect(freshUntil({fresh_until: at(FRESH_WINDOW_MS + 2 * 60_000)}, NOW)).toBeUndefined();
  });
});

const alert = (over: Partial<AlertRow>): AlertRow => ({id: "a", severity: "info", kind: "sms_down", params: {}, created_at: at(0), ...over});

describe("unresolvedAlerts", () => {
  it("drops the resolved ones, puts critical first and the newest first inside a severity", () => {
    const rows = [
      alert({id: "old-warning", severity: "warning", created_at: at(-3000)}),
      alert({id: "resolved", severity: "critical", resolved_at: at(-10)}),
      alert({id: "new-warning", severity: "warning", created_at: at(-1000)}),
      alert({id: "critical", severity: "critical", created_at: at(-5000)}),
      alert({id: "info", severity: "info", created_at: at(-10)}),
    ];
    expect(unresolvedAlerts(rows).map((a) => a.id)).toEqual(["critical", "new-warning", "old-warning", "info"]);
  });
  it("does not change the list it is given", () => {
    const rows = [alert({id: "b", severity: "info"}), alert({id: "a", severity: "critical"})];
    unresolvedAlerts(rows);
    expect(rows.map((a) => a.id)).toEqual(["b", "a"]);
  });
  it("reads nothing as nothing", () => {
    expect(unresolvedAlerts(undefined)).toEqual([]);
  });
});

describe("noticesOf", () => {
  it("is newest first and does not change /me", () => {
    const me = {notices: [{kind: "password_reset" as const, at: at(-2000)}, {kind: "totp_reset" as const, at: at(-1000)}]};
    expect(noticesOf(me).map((n) => n.kind)).toEqual(["totp_reset", "password_reset"]);
    expect(me.notices[0]!.kind).toBe("password_reset");
    expect(noticesOf(undefined)).toEqual([]);
  });
});

describe("AUDIT_ACTION_RE", () => {
  it("takes the names the API pattern takes, and refuses everything else", () => {
    for (const ok of ["admin.login", "sms.gateway_put", "a", "x-y.z_1"]) expect(AUDIT_ACTION_RE.test(ok), ok).toBe(true);
    for (const bad of ["", "Admin.Login", "1abc", "has space", "a/b", "x".repeat(65), ".start"]) expect(AUDIT_ACTION_RE.test(bad), bad).toBe(false);
  });
});
