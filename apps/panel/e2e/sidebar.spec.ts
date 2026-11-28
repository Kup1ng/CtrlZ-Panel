import type {Locator, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {LAB, signIn} from "./feedback-support.ts";
import {shell} from "./notices-support.ts";

// Spec 17.3 `shell.spec.ts` rows T-113 and T-124, in mock mode, for what P1 has no real screen to show:
//
//  - T-113, the sidebar counters. P2 and P3 build the lists that Profiles and Endpoints count, so until then `useShellCounts` returns null and
//    no route shows a chip. The (lab) layout gives it fixed numbers (spec question 10), and these cases read the chips in both languages, in
//    the desktop sidebar and in the full-screen panel of a phone, and that a real route still shows none.
//  - T-124, the version in the logo menu. It is `NEXT_PUBLIC_CTRLZ_VERSION`, fixed when the bundle is built (scripts/ctrlz-version.mjs gives
//    the value, ci-web.sh passes it), so the case is told the value that its build was given in `E2E_CTRLZ_VERSION`. A run that was not told
//    holds the shape of what the script may produce.

const LANGS = [
  {lang: "fa", dir: "rtl", profiles: "۳", endpoints: "۱٬۲۰۴"},
  {lang: "en", dir: "ltr", profiles: "3", endpoints: "1,204"},
] as const;

// What scripts/ctrlz-version.mjs lets through: letters, digits and `._+-`, at most 64, starting with a letter or digit; `dev` when nothing was set.
const SAFE_VERSION = /^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$/;

const chips = (scope: Page | Locator) => scope.locator(".sidebar__menu-chip");

for (const {lang, dir, profiles, endpoints} of LANGS) {
  test.describe(`${lang} (${dir})`, () => {
    test.describe("at 1280px", () => {
      test.use({viewport: {width: 1280, height: 800}});

      test("Profiles and Endpoints carry their counts, in the language's digits, and no other item does (T-113)", async ({page, context, baseURL}) => {
        await signIn(context, baseURL);
        await page.goto(LAB(lang));
        await expect(page.locator("aside.sidebar")).toBeVisible();
        const sidebar = page.locator("aside.sidebar");
        await expect(chips(sidebar)).toHaveText([profiles, endpoints]);
        // Each chip sits in the row of its own item.
        await expect(sidebar.getByRole("row", {name: shell(lang, "nav.profiles")}).locator(".sidebar__menu-chip")).toHaveText(profiles);
        await expect(sidebar.getByRole("row", {name: shell(lang, "nav.endpoints")}).locator(".sidebar__menu-chip")).toHaveText(endpoints);
        // The chip is at the inline end of its row, whichever way the page is written, and inside the sidebar.
        const [row, chip] = await Promise.all([
          sidebar.getByRole("row", {name: shell(lang, "nav.endpoints")}).boundingBox(),
          sidebar.getByRole("row", {name: shell(lang, "nav.endpoints")}).locator(".sidebar__menu-chip").boundingBox(),
        ]);
        if (dir === "ltr") expect(chip!.x + chip!.width).toBeLessThanOrEqual(row!.x + row!.width + 1);
        else expect(chip!.x).toBeGreaterThanOrEqual(row!.x - 1);
        const label = (await sidebar.getByRole("row", {name: shell(lang, "nav.endpoints")}).locator(".sidebar__menu-label").boundingBox())!;
        if (dir === "ltr") expect(chip!.x).toBeGreaterThanOrEqual(label.x);
        else expect(chip!.x + chip!.width).toBeLessThanOrEqual(label.x + label.width + 1);
      });

      test("a real route has no chip until P2 and P3 give it counts (T-113)", async ({page, context, baseURL}) => {
        await signIn(context, baseURL);
        await page.goto(`/${lang}/profiles`);
        await expect(page.locator("aside.sidebar")).toBeVisible();
        await expect(chips(page)).toHaveCount(0);
      });

      test("the logo menu names the version it was built with (T-124)", async ({page, context, baseURL}) => {
        await signIn(context, baseURL);
        await page.goto(`/${lang}/profiles`);
        await page.locator(".shell-logo-trigger").first().click();
        // The line is "Version <v>1.2.3</v>": the word of the language, then the value in its own left-to-right island.
        const line = page.getByText(lang === "fa" ? /^نسخه/ : /^Version/);
        await expect(line).toBeVisible();
        const shown = (await line.locator("bdi").innerText()).trim();
        await expect(line.locator("bdi")).toHaveAttribute("dir", "ltr");
        const told = process.env.E2E_CTRLZ_VERSION;
        if (told) expect(shown, "the version this build was given").toBe(told);
        else expect(shown, "a version the script could have produced").toMatch(SAFE_VERSION);
      });
    });

    test.describe("at 375px", () => {
      test.use({viewport: {width: 375, height: 812}});

      test("the full-screen panel shows the counts too, and fits (T-113)", async ({page, context, baseURL}) => {
        await signIn(context, baseURL);
        await page.goto(LAB(lang));
        await page.getByRole("button", {name: shell(lang, "sidebar.openMenu")}).click();
        const panel = page.getByRole("dialog");
        await expect(chips(panel)).toHaveText([profiles, endpoints]);
        const box = (await chips(panel).last().boundingBox())!;
        expect(box.x).toBeGreaterThanOrEqual(0);
        expect(box.x + box.width).toBeLessThanOrEqual(375);
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), "no sideways scroll").toBe(true);
      });
    });
  });
}
