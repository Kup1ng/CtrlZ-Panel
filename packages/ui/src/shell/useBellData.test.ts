import {describe, expect, it} from "vitest";

import {announcementFixture, notificationFixture, securityNoticeFixture} from "@ctrlz/api-client/testing/fixtures.ts";

import {accountRowOf, ACCOUNT_ROW_FRAGMENTS, securityActions} from "./securityNotice.ts";
import {bellModel, safeInternalPath} from "./useBellData.ts";

const BACKSLASH = String.fromCharCode(92);

describe("safeInternalPath", () => {
  it("follows an app path", () => {
    expect(safeInternalPath("/preferences/account")).toBe("/preferences/account");
    expect(safeInternalPath("/profiles?x=1#y")).toBe("/profiles?x=1#y");
    expect(safeInternalPath("/endpoints/abc.def")).toBe("/endpoints/abc.def");
    expect(safeInternalPath("/analytics")).toBe("/analytics");
  });

  it("ignores anything that could leave the app", () => {
    for (const link of [
      "//evil.example/x",
      "https://evil.example",
      "javascript:alert(1)",
      `/${BACKSLASH}evil.example`,
      `${BACKSLASH}${BACKSLASH}evil.example`,
      "profiles",
      "/ok\nHeader: x",
      "/ok\u0000",
      // Dot segments: the URL parser removes them and what is left is protocol-relative (wp4-r17-1).
      "/..//x.example/a",
      "/profiles/..//x.example",
      "/%2e%2e//x.example",
      "/%2E%2E/x",
      "/a/../..//x.example",
      "/profiles/../preferences",
      "/profiles/./x",
      "/profiles/%2e%2e/x",
      "/profiles/%252e%252e/x",
      // A trailing space is trimmed by the URL parser, which then folds the dot segment (wp4-r18-1).
      "/profiles/.. ",
      "/profiles/%2e%2e ",
      "/preferences/.%2E ",
      "/profiles/%2f%2fx.example",
      "/profiles/%5cx.example",
      // Outside every known panel prefix.
      "/unknown/page",
      "/",
      "",
      undefined,
      null,
    ]) {
      expect(safeInternalPath(link as string | undefined | null), String(link)).toBeUndefined();
    }
  });
});

describe("bellModel (Question 19)", () => {
  it("puts the unread security notices apart, one entry per kind and newest first, and keeps them out of the list", () => {
    const older = securityNoticeFixture({created_at: "2026-11-10T08:00:00Z"});
    const newer = securityNoticeFixture({kind: "recovery_codes_regenerated", created_at: "2026-11-12T08:00:00Z", markable: false});
    const plain = notificationFixture();
    const model = bellModel({items: [plain], securityItems: [older, newer]}, []);
    expect(model.security.map((e) => e.id)).toEqual([newer.id, older.id]);
    expect(model.security.map((e) => e.markable)).toEqual([false, true]);
    expect(model.entries.map((e) => e.id)).toEqual([plain.id]);
  });

  it("shows a read security notice in the list like any read notice", () => {
    const read = securityNoticeFixture({read_at: "2026-11-13T08:00:00Z"});
    const model = bellModel({items: [read], securityItems: []}, []);
    expect(model.security).toEqual([]);
    expect(model.entries.map((e) => [e.id, e.security, e.read, e.markable])).toEqual([[read.id, true, true, true]]);
  });

  // webi-r1-6: the API leaves an unread security notice older than the newest 50 in `items`; it is still a security notice.
  it("puts an unread security notice that the API left in the list into the block", () => {
    const past = securityNoticeFixture({created_at: "2026-01-01T00:00:00Z", markable: false});
    const plain = notificationFixture();
    const model = bellModel({items: [plain, past], securityItems: []}, []);
    expect(model.security.map((e) => [e.id, e.markable, e.count])).toEqual([[past.id, false, 1]]);
    expect(model.entries.map((e) => e.id)).toEqual([plain.id]);
  });

  it("drops a notice from the list when the block already holds it, so it is never in both places", () => {
    const n = securityNoticeFixture();
    const model = bellModel({items: [n], securityItems: [n]}, []);
    expect(model.security.map((e) => e.id)).toEqual([n.id]);
    expect(model.entries).toEqual([]);
  });

  // webi-r1-6 and -7: a flood of one kind is one entry, so the other kind stays in the block and in the two banners.
  it("makes one entry per kind: the newest text, a count, and the ids one press clears", () => {
    const passkey = securityNoticeFixture({created_at: "2026-11-01T08:00:00Z"});
    const flood = Array.from({length: 60}, (_, i) =>
      securityNoticeFixture({kind: "recovery_codes_regenerated", created_at: new Date(Date.UTC(2026, 10, 2, 8, i)).toISOString()}),
    );
    const model = bellModel({items: [], securityItems: [...flood.slice(10).reverse()]}, []);
    expect(model.security.map((e) => [e.kind, e.count])).toEqual([["recovery_codes_regenerated", 50]]);
    // The passkey notice is on a later page of the list: once that page is loaded it is a second entry, not lost.
    const later = bellModel({items: [passkey, ...flood.slice(0, 10)], securityItems: [...flood.slice(10).reverse()]}, []);
    expect(later.security.map((e) => [e.kind, e.count])).toEqual([
      ["recovery_codes_regenerated", 60],
      ["passkey_added", 1],
    ]);
    const group = later.security[0]!;
    expect(group.id).toBe(flood[59]!.id);
    expect(new Set(group.memberIds)).toEqual(new Set(flood.map((n) => n.id)));
    expect(later.security[1]!.memberIds).toEqual([passkey.id]);
  });

  // webi-r2-7: a group shows the newest text, so the date of its oldest notice has to come from the group, not be lost.
  it("a group keeps the date of its oldest notice, and one notice has its own", () => {
    const first = securityNoticeFixture({kind: "passkey_added", created_at: "2026-11-12T09:00:00Z"});
    const second = securityNoticeFixture({kind: "passkey_added", created_at: "2026-11-12T10:00:00Z"});
    const [group] = bellModel({items: [], securityItems: [second, first]}, []).security;
    expect(group!.createdAt).toBe("2026-11-12T10:00:00Z");
    expect(group!.oldestAt).toBe("2026-11-12T09:00:00Z");
    expect(group!.count).toBe(2);
    const [single] = bellModel({items: [], securityItems: [first]}, []).security;
    expect(single!.oldestAt).toBe(single!.createdAt);
  });

  it("merges announcements into the list only, always markable and never security", () => {
    const a = announcementFixture();
    const model = bellModel({items: [], securityItems: []}, [a]);
    expect(model.entries.map((e) => [e.source, e.security, e.markable])).toEqual([["announcement", false, true]]);
  });

  it("makes a group markable only when every notice in it is", () => {
    const old = securityNoticeFixture({created_at: "2026-11-10T08:00:00Z", markable: true});
    const fresh = securityNoticeFixture({created_at: "2026-11-12T08:00:00Z", markable: false});
    expect(bellModel({items: [], securityItems: [fresh, old]}, []).security.map((e) => e.markable)).toEqual([false]);
    expect(bellModel({items: [], securityItems: [old]}, []).security.map((e) => e.markable)).toEqual([true]);
  });
});

describe("the links of a security notice", () => {
  // webi-r1-5: a password change keeps every passkey and the recovery codes, so the links name what evicts a thief.
  it("depend on the kind and name only rows of the account page, through the one validator", () => {
    expect(securityActions("passkey_added").map((a) => [a.id, a.href])).toEqual([
      ["passkeys", "/preferences/account#passkeys"],
      ["password", "/preferences/account#password"],
      ["sessions", "/preferences/account#sessions"],
    ]);
    expect(securityActions("recovery_codes_regenerated").map((a) => [a.id, a.href])).toEqual([
      ["totp", "/preferences/account#totp"],
      // A passkey signs in with no code, so the new-codes notice must lead to the passkeys too (webi-r2-6).
      ["passkeys", "/preferences/account#passkeys"],
      ["password", "/preferences/account#password"],
      ["sessions", "/preferences/account#sessions"],
    ]);
    expect(securityActions("something_new").map((a) => a.id)).toEqual(["passkeys", "password", "sessions"]);
    expect(securityActions(undefined).map((a) => a.id)).toEqual(["passkeys", "password", "sessions"]);
    // A kind is a string from the API and must not find a member of Object.prototype.
    expect(securityActions("constructor").map((a) => a.id)).toEqual(["passkeys", "password", "sessions"]);
    for (const kind of ["passkey_added", "recovery_codes_regenerated", undefined]) {
      for (const a of securityActions(kind)) expect(safeInternalPath(a.href)).toBe(a.href);
    }
  });

  it("accept only those four fragments on the account page", () => {
    expect(ACCOUNT_ROW_FRAGMENTS).toEqual(["passkeys", "totp", "password", "sessions"]);
    expect(accountRowOf("#password")).toBe("password");
    expect(accountRowOf("sessions")).toBe("sessions");
    expect(accountRowOf("#passkeys")).toBe("passkeys");
    expect(accountRowOf("#totp")).toBe("totp");
    for (const hash of ["", "#", "#phone", "#password]", "#sessions, #x", "#PASSWORD", "# password", "#constructor", "#__proto__"]) expect(accountRowOf(hash), hash).toBeUndefined();
  });
});
