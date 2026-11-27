import {adminUserFixture, auditFixture} from "@ctrlz/api-client/testing/adminFixtures.ts";
import type {Locator} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {adm, allowAdminErrors, gotoShell, openAdmin, type Lang} from "./admin-support.ts";

// Spec 17.3 `format.spec.ts` (T-466), admin: a date drawn by the admin is Jalali with Persian digits in `fa`, and Gregorian with Latin digits
// in `en`. The formatter is `packages/i18n/src/format.test.ts` (vitest); what a unit test cannot say is that the screens go through it, so
// this reads the dates of the Users and Audit tables off a real page. A phone number and an IP address are technical tokens and keep their
// Latin digits in both languages (`<Tech>`), so they are taken out before the text is read.

test.beforeEach(({guard}) => allowAdminErrors(guard));

const PERSIAN_DIGITS = /[۰-۹]/;
const LATIN_DIGITS = /[0-9]/;

// 10 November 2026, 08:00 UTC, is 19 Aban 1405, 11:30 in Tehran.
const CREATED = "2026-11-10T08:00:00Z";
const LAST_LOGIN = "2026-11-15T09:30:00Z";
const AUDIT_AT = "2026-11-16T10:00:00Z";

/** The text of a table row without its technical tokens (`bdi dir="ltr"`: phones, addresses, identifiers). */
const proseOf = (row: Locator) =>
  row.evaluate((el) => {
    const copy = el.cloneNode(true) as HTMLElement;
    copy.querySelectorAll("bdi").forEach((b) => b.remove());
    return copy.textContent ?? "";
  });

for (const [lang, year, other, digits, otherDigits, month] of [
  ["fa", "۱۴۰۵", "2026", PERSIAN_DIGITS, LATIN_DIGITS, "آبان"],
  ["en", "2026", "1405", LATIN_DIGITS, PERSIAN_DIGITS, "Nov"],
] as const) {
  test.describe(`${lang}`, () => {
    test.use({viewport: {width: 1280, height: 900}});

    test(`a rendered date has a ${lang === "fa" ? "Jalali" : "Gregorian"} year and ${lang === "fa" ? "Persian" : "Latin"} digits, and nothing of the other calendar`, async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {
        handlers: {
          "GET /users": {body: {items: [adminUserFixture({phone_e164: "+989120001001", created_at: CREATED, last_login_at: LAST_LOGIN})]}},
          "GET /audit": {body: {items: [auditFixture({at: AUDIT_AT})]}},
        },
      });

      for (const [path, title, grid] of [
        ["/users", adm(lang, "pages.users.title"), adm(lang, "users.gridLabel")],
        ["/audit", adm(lang, "pages.audit.title"), adm(lang, "audit.gridLabel")],
      ] as const) {
        await gotoShell(page, lang as Lang, path, title);
        const row = page.getByRole("grid", {name: grid}).getByRole("row").nth(1);
        await expect(row).toBeVisible();
        const prose = await proseOf(row);
        const where = `${path} in ${lang}: ${JSON.stringify(prose)}`;
        expect(prose, `the year, ${where}`).toContain(year);
        expect(prose, `the month, ${where}`).toContain(month);
        expect(prose, `the other calendar's year, ${where}`).not.toContain(other);
        expect(prose, `the language's digits, ${where}`).toMatch(digits);
        expect(prose, `the other language's digits, ${where}`).not.toMatch(otherDigits);
      }
    });
  });
}
