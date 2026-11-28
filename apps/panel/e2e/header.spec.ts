import type {Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import enFeedback from "../../../packages/i18n/messages/en/feedback.json";
import faFeedback from "../../../packages/i18n/messages/fa/feedback.json";
import {shell} from "./notices-support.ts";
import {LAB, signIn} from "./feedback-support.ts";

// Spec 17.3 `header.spec.ts` (T-115, T-116, T-123), in mock mode. The stubs of P1 have no search, menu or plus, so their cases are in
// `shell.spec.ts`; the page that has every control of spec 8.4 is the header of the feedback lab (a fixture, spec question 10), and these are
// the cases of its buttons: the search, the three-dot menu and "+" at the end of the row, the always visible search at 375px, and the profile
// switcher in the `leading` slot with its jump list above ten entries.

const LANGS = [
  {lang: "fa", dir: "rtl"},
  {lang: "en", dir: "ltr"},
] as const;
const FEEDBACK = {fa: faFeedback, en: enFeedback} as const;

const echo = (page: Page) => page.getByTestId("header-echo");
const header = (page: Page) => page.locator(".page-header");

for (const {lang, dir} of LANGS) {
  const S = (path: keyof typeof enFeedback.showcase) => FEEDBACK[lang].showcase[path] as string;
  const searchName = shell(lang, "header.search");
  const moreName = shell(lang, "header.more");

  test.describe(`${lang} (${dir}) at 1280px`, () => {
    test.use({viewport: {width: 1280, height: 800}});

    test("the row has the icon, title, subtitle and help, then search, the three-dot menu and + at the end (T-116)", async ({page, context, baseURL}) => {
      await signIn(context, baseURL);
      await page.goto(LAB(lang));
      await expect(header(page)).toBeVisible();
      await expect(header(page).getByRole("heading", {level: 1})).toHaveText(S("title"));
      await expect(header(page).locator(".page-header__subtitle")).toHaveText(S("subtitle"));
      await expect(header(page).getByRole("button", {name: shell(lang, "header.help")})).toBeVisible();

      const search = header(page).getByRole("button", {name: searchName, exact: true});
      const more = header(page).getByRole("button", {name: moreName});
      const create = header(page).getByRole("button", {name: S("createSample")});
      await expect(search).toBeVisible();
      await expect(more).toBeVisible();
      await expect(create).toBeVisible();

      // The three sit in that order at the inline end, whichever way the page is written: search, then the menu, then +.
      const [s, m, c] = await Promise.all([search.boundingBox(), more.boundingBox(), create.boundingBox()]);
      const centres = [s!, m!, c!].map((b) => b.x + b.width / 2);
      const sign = dir === "ltr" ? 1 : -1;
      expect(sign * (centres[1]! - centres[0]!), "the menu follows the search").toBeGreaterThan(0);
      expect(sign * (centres[2]! - centres[1]!), "+ follows the menu").toBeGreaterThan(0);
      // The group is at the inline end of the row: the last button is nearer that edge than the title is.
      const title = (await header(page).getByRole("heading", {level: 1}).boundingBox())!;
      if (dir === "ltr") expect(c!.x).toBeGreaterThan(title.x);
      else expect(c!.x).toBeLessThan(title.x);
      // 24px is the least a target may be (DESIGN.md).
      for (const box of [s!, m!, c!]) expect(Math.min(box.width, box.height)).toBeGreaterThanOrEqual(24);
    });

    test("the search button opens a field that takes focus, and what is typed reaches the page (T-116)", async ({page, context, baseURL}) => {
      await signIn(context, baseURL);
      await page.goto(LAB(lang));
      const button = header(page).getByRole("button", {name: searchName, exact: true});
      await expect(button).toHaveAttribute("aria-expanded", "false");
      await expect(header(page).locator(".page-header__search-inline")).toHaveCount(0);
      await button.click();
      await expect(button).toHaveAttribute("aria-expanded", "true");
      const field = header(page).locator(".page-header__search-inline").getByRole("searchbox");
      await expect(field).toBeFocused();
      await page.keyboard.type("ads");
      await expect(echo(page)).toHaveAttribute("data-query", "ads");
      // A second press folds it again.
      await button.click();
      await expect(header(page).locator(".page-header__search-inline")).toHaveCount(0);
    });

    test("the three-dot menu lists its actions, runs the one chosen, and + runs its own (T-116)", async ({page, context, baseURL}) => {
      await signIn(context, baseURL);
      await page.goto(LAB(lang));
      await header(page).getByRole("button", {name: moreName}).click();
      const menu = page.getByRole("menu", {name: moreName});
      await expect(menu.getByRole("menuitem")).toHaveText([S("copy"), S("remove")]);
      await menu.getByRole("menuitem", {name: S("remove")}).click();
      await expect(menu).toHaveCount(0);
      await expect(echo(page)).toHaveAttribute("data-action", "remove");

      await expect(echo(page)).toHaveAttribute("data-created", "0");
      await header(page).getByRole("button", {name: S("createSample")}).click();
      await expect(echo(page)).toHaveAttribute("data-created", "1");
    });

    test("the profile switcher in the leading slot: a menu of three, the current one marked, a choice changes the page (T-123)", async ({page, context, baseURL}) => {
      await signIn(context, baseURL);
      await page.goto(LAB(lang));
      const trigger = header(page).getByRole("button", {name: shell(lang, "profileSwitcher.label")});
      await expect(trigger).toContainText(S("profileOne"));
      // It comes first in the row, ahead of the title, at the inline start.
      const [t, h] = [(await trigger.boundingBox())!, (await header(page).getByRole("heading", {level: 1}).boundingBox())!];
      if (dir === "ltr") expect(t.x).toBeLessThan(h.x);
      else expect(t.x).toBeGreaterThan(h.x);

      await trigger.click();
      const menu = page.getByRole("menu", {name: shell(lang, "profileSwitcher.label")});
      const items = menu.getByRole("menuitemradio");
      await expect(items).toHaveText([S("profileOne"), S("profileTwo"), S("profileNew")]);
      await expect(items.nth(0)).toHaveAttribute("aria-checked", "true");
      await items.nth(1).click();
      await expect(echo(page)).toHaveAttribute("data-profile", "office");
      await expect(trigger).toContainText(S("profileTwo"));
      // The choice is kept when the menu is opened again.
      await trigger.click();
      await expect(page.getByRole("menuitemradio").nth(1)).toHaveAttribute("aria-checked", "true");
    });

    test("above ten profiles the switcher is a jump list: type to narrow it, choose one (T-123)", async ({page, context, baseURL}) => {
      await signIn(context, baseURL);
      await page.goto(LAB(lang));
      const many = page.getByTestId("switcher-many");
      await expect(many).toHaveAttribute("data-value", "p1");
      // The label of the trigger is the current profile's name, in the language's digits.
      await expect(many.getByRole("button")).toContainText(lang === "fa" ? "پروفایل ۱" : "Profile 1");
      await many.getByRole("button").click();

      const jump = page.getByRole("dialog", {name: shell(lang, "profileSwitcher.label")});
      await expect(jump).toBeVisible();
      await expect(jump.getByRole("searchbox")).toBeFocused();
      // Command lists its entries as menu items.
      await expect(jump.getByRole("menuitem")).toHaveCount(12);
      // Latin digits find the Persian-digit name (normalizeFaSearch); the list narrows to the names that hold a 7.
      await page.keyboard.type("7");
      await expect(jump.getByRole("menuitem")).toHaveCount(1);
      await jump.getByRole("menuitem").click();
      await expect(jump).toHaveCount(0);
      await expect(many).toHaveAttribute("data-value", "p7");
      await expect(many.getByRole("button")).toContainText(lang === "fa" ? "پروفایل ۷" : "Profile 7");
    });
  });

  test.describe(`${lang} (${dir}) at 375px`, () => {
    test.use({viewport: {width: 375, height: 812}});

    test("the search field is always on screen under the title, the button is gone, and the other two stay in the row (T-115)", async ({page, context, baseURL}) => {
      await signIn(context, baseURL);
      await page.goto(LAB(lang));
      await expect(header(page)).toBeVisible();
      // No press needed: the field is there, the search button is not.
      const field = header(page).locator(".page-header__search-mobile").getByRole("searchbox");
      await expect(field).toBeVisible();
      await expect(header(page).getByRole("button", {name: searchName, exact: true})).toBeHidden();
      await expect(header(page).locator(".page-header__search-inline")).toHaveCount(0);

      const [f, h] = [(await field.boundingBox())!, (await header(page).getByRole("heading", {level: 1}).boundingBox())!];
      expect(f.y, "the field is below the title").toBeGreaterThan(h.y + h.height - 1);
      expect(f.x).toBeGreaterThanOrEqual(0);
      expect(f.x + f.width).toBeLessThanOrEqual(375);
      // The menu and + keep their place in the row, on screen.
      for (const name of [moreName, S("createSample")]) {
        const box = (await header(page).getByRole("button", {name}).boundingBox())!;
        expect(box.x, name).toBeGreaterThanOrEqual(0);
        expect(box.x + box.width, name).toBeLessThanOrEqual(375);
        expect(box.y, `${name} is in the title's row, above the field`).toBeLessThan(f.y);
      }

      await field.click();
      await page.keyboard.type("cdn");
      await expect(echo(page)).toHaveAttribute("data-query", "cdn");
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), "no sideways scroll").toBe(true);
    });
  });

  // The switcher in the leading slot took the title's room on a phone (the title was cut to three letters beside it), so below md it has its own line above the row.
  test.describe(`${lang} (${dir}) at 375px with the switcher`, () => {
    test.use({viewport: {width: 375, height: 812}});

    test("the profile switcher has a line above the title, and the title keeps room to be read (T-123)", async ({page, context, baseURL}) => {
      await signIn(context, baseURL);
      await page.goto(LAB(lang));
      const trigger = header(page).getByRole("button", {name: shell(lang, "profileSwitcher.label")});
      await expect(trigger).toBeVisible();
      const [t, h] = [(await trigger.boundingBox())!, (await header(page).getByRole("heading", {level: 1}).boundingBox())!];
      expect(t.y + t.height, "the switcher ends above the title").toBeLessThanOrEqual(h.y + 1);
      expect(h.width, "the title has room for more than a few letters").toBeGreaterThanOrEqual(120);
      for (const name of [moreName, S("createSample")]) {
        const box = (await header(page).getByRole("button", {name}).boundingBox())!;
        expect(box.y, `${name} stays on the title's line`).toBeGreaterThanOrEqual(h.y - 20);
        expect(box.y + box.height, name).toBeLessThanOrEqual(h.y + h.height + 40);
      }
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), "no sideways scroll").toBe(true);
    });
  });

  test.describe(`${lang} (${dir}) at 768px`, () => {
    test.use({viewport: {width: 768, height: 900}});

    // md is 768: from there the button is back and the field under the title is gone.
    test("from 768px the field folds into the button again (T-115)", async ({page, context, baseURL}) => {
      await signIn(context, baseURL);
      await page.goto(LAB(lang));
      await expect(header(page).getByRole("button", {name: searchName, exact: true})).toBeVisible();
      await expect(header(page).locator(".page-header__search-mobile").getByRole("searchbox")).toBeHidden();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), "no sideways scroll").toBe(true);
    });
  });
}
