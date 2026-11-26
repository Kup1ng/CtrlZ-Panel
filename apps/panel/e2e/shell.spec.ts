import type {Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {installApiMock} from "@ctrlz/api-client/testing/mock.ts";

// Spec 17.3 `shell.spec.ts`, 8.2 and the shell rows of `header.spec.ts`,
// `states.spec.ts` and the URL cases of `dialogs.spec.ts`, for what exists in P1.
//
// `baseURL` is the panel on any origin. The config is the shared one of spec 17.1
// (packages/ui/src/testing/config.ts), and the guard of 17.2 fails the test on an
// external request, a CSP violation or a console error.

const LOCALES = [
  {lang: "fa", dir: "rtl"},
  {lang: "en", dir: "ltr"},
] as const;

test.beforeEach(async ({context, baseURL}) => {
  // The proxy only checks that a session cookie exists (spec 15.4). The shell's
  // SessionGate asks /me, which the mock answers with a ready, signed-in user
  // (WP4, spec 17.1 mock mode); the API is the real gate.
  await installApiMock(context);
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
      // The key listener is attached by an effect, after hydration, and the server HTML is painted long
      // before that: "networkidle" does not mean hydrated, and under load (two workers) one run of this
      // test sent its key before the listener existed. A dispatch is a toggle, so it cannot simply be
      // retried. The handler calls preventDefault on a key it took, and dispatchEvent then returns
      // false, so the key is sent again only while nothing has taken it.
      //
      // On a Persian layout the B key types "ذ". The Sidebar's own shortcut reads `event.key` and does
      // nothing there, so the shell binds `event.code`.
      await expect
        .poll(() =>
          page.evaluate(
            () => !document.dispatchEvent(new KeyboardEvent("keydown", {key: "ذ", code: "KeyB", ctrlKey: true, bubbles: true, cancelable: true})),
          ),
        )
        .toBe(true);
      await expect.poll(() => width(page)).toBe(280);
      await page.keyboard.press("Control+b");
      await expect.poll(() => width(page)).toBe(48);
    });

    // gate-r6-1. The jump palette is HeroUI Pro's Command overlay, mounted on every signed-in page. Spec 15.2 and 17.2 rest the run-time half of
    // the CSP on the idea that a library that creates a style or an element when a screen opens is caught by the guard because some test opens
    // that screen. This one opens the one Pro overlay of the shell, with the key, and the guard fails the test on a CSP violation, a console
    // error or an external request while it is open, typed into and closed (a style element without the nonce, a data: or blob: asset).
    test("mod+k opens the jump palette, it filters, takes Escape and jumps to a page, with no CSP violation (gate-r6-1)", async ({page}) => {
      const label = lang === "fa" ? "پرش به صفحه" : "Jump to a page";
      const search = lang === "fa" ? "اندپوینت" : "Endpoints";
      await page.goto(`/${lang}/profiles`);
      const palette = page.getByRole("dialog", {name: label});
      await expect(palette).toHaveCount(0);
      // The listener is attached after hydration (see the Control+B case). Opening is not a toggle, so sending the key again is harmless;
      // it stops when a handler took the key (preventDefault makes dispatchEvent answer false).
      await expect
        .poll(() =>
          page.evaluate(
            () => !document.dispatchEvent(new KeyboardEvent("keydown", {key: "k", code: "KeyK", ctrlKey: true, bubbles: true, cancelable: true})),
          ),
        )
        .toBe(true);
      await expect(palette).toBeVisible();
      // The nonce'd style that the overlay adds has a sheet: a style element that the policy refused has none.
      expect(await page.evaluate(() => Array.from(document.querySelectorAll("style[nonce]")).every((s) => (s as HTMLStyleElement).sheet !== null))).toBe(true);

      const input = palette.getByRole("searchbox", {name: lang === "fa" ? "رفتن به…" : "Go to…"});
      await input.fill(search);
      await expect(palette.getByRole("menuitem").first()).toBeVisible();
      await input.fill("zzzz-nothing");
      await expect(palette.getByText(lang === "fa" ? "نتیجه‌ای پیدا نشد" : "No results found")).toBeVisible();
      // The first Escape of a search field with text in it clears the text (the library's behaviour); the dialog closes on the one that follows.
      await page.keyboard.press("Escape");
      await expect(input).toHaveValue("");
      await page.keyboard.press("Escape");
      await expect(palette).toHaveCount(0);

      // The real key, on a hydrated page, then a jump with Enter.
      await page.keyboard.press("Control+k");
      await expect(palette).toBeVisible();
      await palette.getByRole("searchbox").fill(search);
      await page.keyboard.press("Enter");
      await expect(page).toHaveURL(/\/endpoints$/);
      await expect(palette).toHaveCount(0);
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
      // Escape before the dialog is open does nothing, and "hidden" is then true at once while the dialog opens behind it and takes the focus
      // (a failure of the full run under load, gate-r7: the bell was not focused). The dialog is waited for first.
      await expect(page.getByRole("dialog")).toBeVisible();
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

    test("an unknown path is a 404 inside the shell with a session cookie", async ({page, guard}) => {
      // The browser logs the 404 document as a console error: it is what this test asks for.
      guard.allowConsole(/status of 404/);
      const res = await page.goto(`/${lang}/no/such/page`);
      expect(res?.status()).toBe(404);
      await expect(sidebar(page)).toBeVisible();
      await expect(page.locator(".empty-state__title")).toBeVisible();
    });

    test("an unknown path is a 404 on its own without one", async ({guard}) => {
      // The visitor with no session is a second context of the guard, so this page is under the three checks of spec 17.2 too.
      guard.allowConsole(/status of 404/);
      const context = await guard.newContext();
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

    // gate-r35-1 to 7. The nav sheet is a role=dialog itself: the key that opened it has to close it, and Ctrl+K has to work with it open.
    test("Control+B opens the nav sheet and closes it again, and Control+K opens the palette over it (gate-r35-1)", async ({page}) => {
      await page.goto(`/${lang}/profiles`);
      const sheet = page.locator(".sidebar__mobile-sheet");
      // The listener is attached after hydration (see the Persian B key case): send the key until a handler takes it.
      await expect
        .poll(() =>
          page.evaluate(
            () => !document.dispatchEvent(new KeyboardEvent("keydown", {key: "b", code: "KeyB", ctrlKey: true, bubbles: true, cancelable: true})),
          ),
        )
        .toBe(true);
      await expect(sheet).toBeVisible();
      await page.keyboard.press("Control+b");
      await expect(sheet).toHaveCount(0);
      await page.keyboard.press("Control+b");
      await expect(sheet).toBeVisible();
      await page.keyboard.press("Control+k");
      await expect(page.getByRole("dialog", {name: lang === "fa" ? "پرش به صفحه" : "Jump to a page"})).toBeVisible();
    });

    test("the page has no horizontal scroll", async ({page}) => {
      await page.goto(`/${lang}/profiles`);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    });
  });
}
