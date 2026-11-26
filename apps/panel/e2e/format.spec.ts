import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {acc, gotoAccount, open, row} from "./account-support.ts";

// Spec 17.3 `format.spec.ts` (T-466), panel: a date drawn by the app is Jalali with Persian digits in `fa`, and Gregorian with Latin digits in
// `en`. The formatter itself is `packages/i18n/src/format.test.ts` and `digits.test.ts` (vitest); what a unit test cannot say is that the
// screens go through it, so this reads dates off a real page: the sessions of the Account page (a date and time) and a passkey (a date).
// The sessions of `sessionsFixture` are made on 1, 10 and 12 November 2026, which is 10, 19 and 21 Aban 1405.

const PERSIAN_DIGITS = /[۰-۹]/;
const LATIN_DIGITS = /[0-9]/;

test.describe("fa", () => {
  test.use({viewport: {width: 1280, height: 800}});

  test("a rendered date has a Jalali year and Persian digits, and no Gregorian year or Latin digit", async ({page, context, baseURL}) => {
    await open(context, baseURL, {me: {security: {passkeys: 1}}, handlers: {"GET /account/passkeys": {body: {passkeys: [{id: "20000000-0000-4000-8000-0000000000aa", name: "Laptop", created_at: "2026-11-01T10:00:00Z", stale: false, backup_eligible: true}]}}}});
    await gotoAccount(page, "fa");
    await row(page, "sessions").getByRole("button", {name: acc("fa", "sessions.manageAria")}).click();
    const sessions = row(page, "sessions").getByRole("listitem");
    await expect(sessions).toHaveCount(3);
    const created = (await sessions.allInnerTexts()).map((t) => t.split("\n").find((l) => l.includes("۱۴۰۵")) ?? "");
    expect(created.every((line) => line !== ""), `each session shows its creation date with a Jalali year: ${JSON.stringify(created)}`).toBe(true);
    for (const line of created) {
      expect(line).toMatch(PERSIAN_DIGITS);
      expect(line, "no Gregorian year").not.toContain("2026");
      expect(line, "no Latin digit in a Persian date line").not.toMatch(LATIN_DIGITS);
    }
    // The month is a Persian month name: 10 November 2026 is in Aban.
    await expect(sessions.filter({hasText: "آبان"}).first()).toBeVisible();

    // The date of a passkey (`f.date`, no time) is the same calendar.
    const passkey = row(page, "passkeys");
    await expect(passkey).toContainText("۱۴۰۵");
    expect(await passkey.innerText()).not.toContain("2026");
  });
});

test.describe("en", () => {
  test.use({viewport: {width: 1280, height: 800}});

  test("a rendered date has a Gregorian year and Latin digits, and no Jalali year or Persian digit", async ({page, context, baseURL}) => {
    await open(context, baseURL, {me: {security: {passkeys: 1}}, handlers: {"GET /account/passkeys": {body: {passkeys: [{id: "20000000-0000-4000-8000-0000000000aa", name: "Laptop", created_at: "2026-11-01T10:00:00Z", stale: false, backup_eligible: true}]}}}});
    await gotoAccount(page, "en");
    await row(page, "sessions").getByRole("button", {name: acc("en", "sessions.manageAria")}).click();
    const sessions = row(page, "sessions").getByRole("listitem");
    await expect(sessions).toHaveCount(3);
    const created = (await sessions.allInnerTexts()).map((t) => t.split("\n").find((l) => l.includes("2026")) ?? "");
    expect(created.every((line) => line !== ""), `each session shows its creation date with a Gregorian year: ${JSON.stringify(created)}`).toBe(true);
    for (const line of created) {
      expect(line).toMatch(LATIN_DIGITS);
      expect(line, "no Jalali year").not.toContain("1405");
      expect(line, "no Persian digit in an English date line").not.toMatch(PERSIAN_DIGITS);
    }
    await expect(sessions.filter({hasText: "Nov"}).first()).toBeVisible();
    const passkey = row(page, "passkeys");
    await expect(passkey).toContainText("2026");
    expect(await passkey.innerText()).not.toContain("1405");
  });
});
