import {expect, test, type Page} from "@playwright/test";

// Spec 17.3 `shell.spec.ts`, 8.2 and the shell rows of `header.spec.ts`,
// `states.spec.ts` and the URL cases of `dialogs.spec.ts`, for what exists in P1.
//
// `baseURL` is the panel on any origin. The shared Playwright config, the guard
// that fails on external requests and CSP violations, and the Caddy setup are
// WP12's (spec 17.1); until they land this file runs with a config of its own
// that sets `baseURL` and `channel: "msedge"`.

const LOCALES = [
  {lang: "fa", dir: "rtl"},
  {lang: "en", dir: "ltr"},
] as const;

test.beforeEach(async ({context, baseURL}) => {
  // The proxy only checks that a session cookie exists (spec 15.4). The API is
  // the real gate, and there is none in P1.
  await context.addCookies([
    {name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true},
  ]);
});

const sidebar = (page: Page) => page.locator("aside.sidebar");
const width = async (page: Page) => Math.round((await sidebar(page).boundingBox())!.width);

for (const {lang, dir} of LOCALES) {
  test.describe(`${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});

    test("the sidebar is at the inline start and the rail is on the content side", async ({page}) => {
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator("html")).toHaveAttribute("dir", dir);
      const aside = (await sidebar(page).boundingBox())!;
      const main = (await page.locator(".shell-page").boundingBox())!;
      if (dir === "rtl") expect(aside.x).toBeGreaterThan(main.x);
      else expect(aside.x).toBeLessThan(main.x);

      // Stock `.sidebar--right { order: 1 }` would flip an RTL sidebar to the visual left.
      const rail = (await page.locator(".sidebar__rail").boundingBox())!;
      const railCentre = rail.x + rail.width / 2;
      // Measured: the rail is centred 6.5px inside the content-side edge in both directions.
      if (dir === "rtl") expect(Math.abs(railCentre - aside.x)).toBeLessThanOrEqual(8);
      else expect(Math.abs(railCentre - (aside.x + aside.width))).toBeLessThanOrEqual(8);
    });

    test("collapse persists after a reload, and the Persian B key toggles it", async ({page}) => {
      await page.goto(`/${lang}/profiles`);
      expect(await width(page)).toBe(280);
      await page.getByRole("button", {name: lang === "fa" ? /جمع کردن/ : /Collapse or expand/}).click();
      await expect.poll(() => width(page)).toBe(48);
      await page.reload();
      expect(await width(page)).toBe(48);
      // The key listener is attached on hydration, after the server HTML is already painted.
      await page.waitForLoadState("networkidle");

      // On a Persian layout the B key types "ذ". The Sidebar's own shortcut reads
      // `event.key` and does nothing there, so the shell binds `event.code`.
      await page.evaluate(() =>
        document.dispatchEvent(new KeyboardEvent("keydown", {key: "ذ", code: "KeyB", ctrlKey: true, bubbles: true, cancelable: true})),
      );
      await expect.poll(() => width(page)).toBe(280);
      await page.keyboard.press("Control+b");
      await expect.poll(() => width(page)).toBe(48);
    });

    test("a collapsed item shows one tooltip, on the content side", async ({page}) => {
      await page.goto(`/${lang}/profiles`);
      await page.getByRole("button", {name: lang === "fa" ? /جمع کردن/ : /Collapse or expand/}).click();
      await expect.poll(() => width(page)).toBe(48);
      const icon = (await page.locator(".sidebar__menu-item .sidebar__menu-icon").first().boundingBox())!;
      await page.mouse.move(icon.x + icon.width / 2, icon.y + icon.height / 2);
      const tip = page.locator(".tooltip");
      await expect(tip).toHaveCount(1);
      const t = (await tip.boundingBox())!;
      if (dir === "rtl") expect(t.x + t.width).toBeLessThanOrEqual(icon.x + 1);
      else expect(t.x).toBeGreaterThanOrEqual(icon.x + icon.width - 1);
    });

    test("the sidebar reaches every route of the stubs", async ({page}) => {
      await page.goto(`/${lang}/profiles`);
      const names = lang === "fa"
        ? {endpoints: /اندپوینت‌ها/, analytics: /تحلیل/, statistics: /آمار/, activity: /گزارش فعالیت/, domain: /آزمون دامنه/, prefs: /تنظیمات/, api: /^API/}
        : {endpoints: /Endpoints/, analytics: /Analytics/, statistics: /Statistics/, activity: /Activity log/, domain: /Domain test/, prefs: /Preferences/, api: /^API/};
      const row = (n: RegExp) => page.getByRole("row", {name: n}).first();
      await row(names.endpoints).click();
      await expect(page).toHaveURL(/\/endpoints$/);
      await row(names.analytics).click();
      await row(names.statistics).click();
      await expect(page).toHaveURL(/\/analytics\/statistics$/);
      await row(names.activity).click();
      await expect(page).toHaveURL(/\/analytics\/activity-log$/);
      await row(names.domain).click();
      await expect(page).toHaveURL(/\/analytics\/domain-test$/);
      await row(names.prefs).click();
      await row(names.api).click();
      await expect(page).toHaveURL(/\/preferences\/api$/);
    });

    test("a stub has its icon, title, subtitle and help button, and no search, menu or plus", async ({page}) => {
      await page.goto(`/${lang}/endpoints`);
      const header = page.locator(".page-header");
      await expect(header.locator("h1")).toBeVisible();
      await expect(header.locator(".page-header__subtitle")).toBeVisible();
      await expect(header.locator(".page-header__icon svg")).toBeVisible();
      await expect(header.getByRole("button")).toHaveCount(1);
      await expect(header.getByRole("button")).toHaveAttribute("aria-label", lang === "fa" ? "راهنمای این بخش" : "Help for this section");
    });

    test("the desktop has no top bar", async ({page}) => {
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".app-layout__header")).toBeHidden();
    });

    test("dialogs bound to the URL: direct link, Back, reload, Escape, focus", async ({page}) => {
      const bell = page.getByRole("button", {name: lang === "fa" ? /^اعلان‌ها/ : /^Notifications/}).first();
      await page.goto(`/${lang}/profiles?notificationsDialog=1`);
      await expect(page.getByRole("dialog")).toBeVisible();
      await page.reload();
      await expect(page.getByRole("dialog")).toBeVisible();
      await page.keyboard.press("Escape");
      await expect(page.getByRole("dialog")).toBeHidden();
      await expect(page).not.toHaveURL(/notificationsDialog/);

      await bell.click();
      await expect(page).toHaveURL(/notificationsDialog=1/);
      await page.goBack();
      await expect(page.getByRole("dialog")).toBeHidden();
      await expect(page).not.toHaveURL(/notificationsDialog/);

      await bell.click();
      await page.keyboard.press("Escape");
      await expect(page.getByRole("dialog")).toBeHidden();
      await expect(bell).toBeFocused();
    });

    test("the help dialog opens from the header, about 440px wide", async ({page}) => {
      await page.goto(`/${lang}/profiles`);
      await page.getByRole("button", {name: lang === "fa" ? "راهنمای این بخش" : "Help for this section"}).click();
      await expect(page).toHaveURL(/helpPane=profiles/);
      const dialog = page.getByRole("dialog");
      await expect(dialog).toBeVisible();
      await expect.poll(async () => Math.round((await dialog.boundingBox())!.width)).toBe(440);
    });

    test("hiding the onboarding card needs a confirmation", async ({page}) => {
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".onboarding")).toBeVisible();
      await page.getByRole("button", {name: lang === "fa" ? "پنهان کردن" : "Hide", exact: true}).click();
      await expect(page.getByRole("alertdialog")).toBeVisible();
      await expect(page.locator(".onboarding")).toBeVisible();
      await page.getByRole("button", {name: lang === "fa" ? "انصراف" : "Cancel"}).click();
      await expect(page.locator(".onboarding")).toBeVisible();
      await page.getByRole("button", {name: lang === "fa" ? "پنهان کردن" : "Hide", exact: true}).click();
      await page.getByRole("button", {name: lang === "fa" ? "پنهان کن" : "Hide it", exact: true}).click();
      await expect(page.locator(".onboarding")).toHaveCount(0);
    });

    test("Log out asks first", async ({page}) => {
      await page.goto(`/${lang}/profiles`);
      await page.getByRole("row", {name: lang === "fa" ? /تنظیمات/ : /Preferences/}).first().click();
      await page.getByRole("row", {name: lang === "fa" ? /خروج/ : /Log out/}).first().click();
      await expect(page.getByRole("alertdialog")).toBeVisible();
      await page.getByRole("button", {name: lang === "fa" ? "انصراف" : "Cancel"}).click();
      await expect(page.getByRole("alertdialog")).toBeHidden();
      await expect(page).toHaveURL(/\/profiles$/);
    });

    test("an unknown path is a 404 inside the shell with a session cookie", async ({page}) => {
      const res = await page.goto(`/${lang}/no/such/page`);
      expect(res?.status()).toBe(404);
      await expect(sidebar(page)).toBeVisible();
      await expect(page.locator(".empty-state__title")).toBeVisible();
    });

    test("an unknown path is a 404 on its own without one", async ({browser, baseURL}) => {
      const context = await browser.newContext({baseURL});
      const page = await context.newPage();
      const res = await page.goto(`/${lang}/no/such/page`);
      expect(res?.status()).toBe(404);
      await expect(page.locator("aside.sidebar")).toHaveCount(0);
      await expect(page.locator(".empty-state__title")).toBeVisible();
      await context.close();
    });

    test("an offline browser gets a banner and the layout keeps its height", async ({page, context}) => {
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".banner-stack")).toHaveCount(0);
      await context.setOffline(true);
      await expect(page.locator(".banner-stack")).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollHeight <= innerHeight)).toBe(true);
      await context.setOffline(false);
      await expect(page.locator(".banner-stack")).toHaveCount(0);
    });
  });

  test.describe(`${lang} (${dir}) on a phone`, () => {
    test.use({viewport: {width: 375, height: 812}});

    test("the menu is a full-screen panel from the inline start", async ({page}) => {
      await page.goto(`/${lang}/profiles`);
      await expect(sidebar(page)).toBeHidden();
      await page.getByRole("button", {name: lang === "fa" ? "باز کردن منو" : "Open menu"}).click();
      const sheet = page.locator(".sidebar__mobile-sheet");
      await expect(sheet).toBeVisible();
      await expect(sheet).toHaveAttribute("data-placement", dir === "rtl" ? "right" : "left");
      expect(await sheet.evaluate((el) => getComputedStyle(el).width)).toBe("375px");
      // Items start at the inline start of the panel.
      const item = (await page.locator(".sidebar__mobile-sheet .sidebar__menu-item").first().boundingBox())!;
      if (dir === "rtl") expect(item.x + item.width).toBeGreaterThan(300);
      else expect(item.x).toBeLessThan(75);
    });

    test("the full-screen panel has its own close button", async ({page}) => {
      await page.goto(`/${lang}/profiles`);
      await page.getByRole("button", {name: lang === "fa" ? "باز کردن منو" : "Open menu"}).click();
      const sheet = page.locator(".sidebar__mobile-sheet");
      await expect(sheet).toBeVisible();
      await sheet.getByRole("button", {name: lang === "fa" ? "بستن" : "Close"}).click();
      await expect(sheet).toBeHidden();
    });

    test("the page has no horizontal scroll", async ({page}) => {
      await page.goto(`/${lang}/profiles`);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    });
  });
}
