import {errorBody, notificationFixture, securityNoticeFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {badge, banners, LANGS, openBell, openWith, reads, securityBlock, shell} from "./notices-support.ts";

// Question 19 (spec 8.5, 8.8, 12.3): the notice of a passkey that was added or recovery codes that were replaced stands in its
// own block of the bell and as a warning banner, is never read by being opened, and is cleared only by its own button, which is
// there only when this session may clear it (`markable`). Mock mode: the mock plays the server's split and its 409.

const digits = (lang: string, n: number) => (lang === "fa" ? String(n).replace(/[0-9]/g, (d) => "۰۱۲۳۴۵۶۷۸۹"[Number(d)]!) : String(n));

for (const {lang} of LANGS) {
  test.describe(`${lang}`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const title = shell(lang, "bell.kinds.passkey_added.title");

    test("an unread security notice is in its own block, the badge adds it, and opening the bell reads nothing", async ({page, context, baseURL}) => {
      const sec = securityNoticeFixture();
      const plain = notificationFixture({kind: "phone_changed", created_at: "2026-11-09T08:00:00Z"});
      const mock = await openWith(context, baseURL, {notifications: [sec, plain], announcements: true});
      await page.goto(`/${lang}/profiles`);
      // 1 security + 1 ordinary + 1 announcement. Persian digits in fa.
      await expect(badge(page)).toHaveText(digits(lang, 3));
      await openBell(page);
      const block = securityBlock(page);
      await expect(block).toBeVisible();
      await expect(block.getByRole("heading", {name: shell(lang, "bell.security.title")})).toBeVisible();
      await expect(block).toContainText(title);
      // Never inside the accordion: no trigger button carries its title, the ordinary notice has one.
      const dialog = page.getByRole("dialog");
      await expect(dialog.locator("button[aria-expanded]").filter({hasText: title})).toHaveCount(0);
      await expect(dialog.locator("button[aria-expanded]").filter({hasText: shell(lang, "bell.kinds.phone_changed.title")})).toHaveCount(1);
      expect(reads(mock)).toEqual([]);
    });

    test("Mark as read clears it: the block and the badge drop, and the notice joins the list as a read one", async ({page, context, baseURL}) => {
      const sec = securityNoticeFixture();
      const mock = await openWith(context, baseURL, {notifications: [sec]});
      await page.goto(`/${lang}/profiles`);
      await expect(badge(page)).toHaveText(digits(lang, 1));
      await openBell(page);
      await securityBlock(page).getByRole("button", {name: shell(lang, "bell.security.markReadAria", {title})}).click();
      await expect.poll(() => reads(mock)).toEqual([sec.id]);
      await expect(securityBlock(page)).toHaveCount(0);
      await expect(badge(page)).toHaveCount(0);
      // The refetch brings it back as a read notice of the ordinary list, with no unread mark.
      const item = page.getByRole("dialog").locator("button[aria-expanded]").filter({hasText: title});
      await expect(item).toHaveCount(1);
      await expect(item).not.toContainText(shell(lang, "bell.unreadMark"));
    });

    test("a session that may not clear it (markable false) has no button, says so, and the banner cannot be closed", async ({page, context, baseURL}) => {
      const sec = securityNoticeFixture({markable: false});
      const mock = await openWith(context, baseURL, {notifications: [sec]});
      await page.goto(`/${lang}/profiles`);
      await expect(badge(page)).toHaveText(digits(lang, 1));
      const banner = banners(page);
      await expect(banner).toHaveCount(1);
      await expect(banner).toContainText(shell(lang, "bell.security.notMarkable"));
      await expect(banner.getByRole("button")).toHaveCount(0);
      await openBell(page);
      const block = securityBlock(page);
      await expect(block.getByTestId("not-markable")).toHaveText(shell(lang, "bell.security.notMarkable"));
      await expect(block.getByRole("button")).toHaveCount(0);
      // The links to the places that undo the change are still there.
      await expect(block.getByRole("link")).toHaveCount(3);
      expect(reads(mock)).toEqual([]);
    });

    test("a 409 on the mark asks the list again and shows no error of its own", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 409/);
      const sec = securityNoticeFixture();
      const mock = await openWith(context, baseURL, {
        notifications: [sec],
        // The server says the session existed when the notice was made, whatever the list said a moment ago.
        handlers: {"POST /notifications/{id}/read": {status: 409, body: errorBody("conflict")}},
      });
      await page.goto(`/${lang}/profiles`);
      await openBell(page);
      const before = mock.count("GET /notifications");
      await securityBlock(page).getByRole("button", {name: shell(lang, "bell.security.markReadAria", {title})}).click();
      await expect.poll(() => reads(mock)).toEqual([sec.id]);
      await expect.poll(() => mock.count("GET /notifications")).toBeGreaterThan(before);
      // Let the mutation settle and the page draw twice before the toast is counted: the mutation's own callbacks run after the list is
      // asked again, so a count taken at once would pass before a wrong toast could come (webi-r3-4).
      await page.evaluate(() => new Promise<void>((done) => requestAnimationFrame(() => requestAnimationFrame(() => done()))));
      // Still unread and still in the block; no toast, no alert in the dialog, no field text.
      await expect(securityBlock(page)).toContainText(title);
      await expect(page.getByRole("dialog").getByRole("alert")).toHaveCount(0);
      await expect(page.locator("[data-slot='toast'], .toast")).toHaveCount(0);
      await expect(badge(page)).toHaveText(digits(lang, 1));
    });

    // webi-r1-6: 51 unread of one kind: the API keeps 50 apart and leaves the oldest in the list. They are one entry with a count,
    // the oldest is not a closed row of the accordion, and one press of Mark as read clears all of them.
    test("a flood of one kind is one entry with a count, and Mark as read clears every notice of it", async ({page, context, baseURL}) => {
      const all = Array.from({length: 51}, (_, i) =>
        securityNoticeFixture({created_at: new Date(Date.UTC(2026, 10, 12, 8, 0, 0) - i * 60_000).toISOString()}),
      );
      const mock = await openWith(context, baseURL, {notifications: all});
      await page.goto(`/${lang}/profiles`);
      await expect(badge(page)).toHaveText(digits(lang, 51));
      await openBell(page);
      const block = securityBlock(page);
      await expect(block.getByRole("listitem")).toHaveCount(1);
      // The count, and the date of the first notice of the group (webi-r2-7).
      await expect(block).toContainText(digits(lang, 51));
      await expect(page.getByRole("dialog").locator("button[aria-expanded]").filter({hasText: title})).toHaveCount(0);
      expect(reads(mock)).toEqual([]);
      // One press sends at most 40 marks, one after another (webi-r2-3, webi-r2-8): the rest stay a group and the next press clears them.
      await block.getByRole("button", {name: shell(lang, "bell.security.markReadAria", {title})}).click();
      await expect.poll(() => reads(mock).length).toBe(40);
      await expect(block).toContainText(digits(lang, 11));
      await block.getByRole("button", {name: shell(lang, "bell.security.markReadAria", {title})}).click();
      await expect.poll(() => reads(mock).length).toBe(51);
      expect(new Set(reads(mock))).toEqual(new Set(all.map((n) => n.id)));
    });

    // webi-r1-6 and -7: a thief regenerates the codes over and over after adding a passkey. The passkey notice is older than the
    // newest 50 and on the second page of the list; the panel finds it by itself, and it stays a banner of its own.
    test("a flood of recovery-code notices does not hide the passkey notice: it is found on a later page and keeps its banner", async ({page, context, baseURL}) => {
      const passkey = securityNoticeFixture({created_at: "2026-11-01T08:00:00Z"});
      const flood = Array.from({length: 130}, (_, i) =>
        securityNoticeFixture({kind: "recovery_codes_regenerated", created_at: new Date(Date.UTC(2026, 10, 2, 8, 0, 0) + i * 60_000).toISOString()}),
      );
      const mock = await openWith(context, baseURL, {notifications: [passkey, ...flood]});
      await page.goto(`/${lang}/profiles`);
      await expect.poll(() => mock.calls.filter((c) => c.path === "/notifications" && c.query.get("cursor") !== null).length).toBeGreaterThan(0);
      const banner = banners(page);
      await expect(banner).toHaveCount(2);
      await expect(banner.filter({hasText: shell(lang, "bell.kinds.passkey_added.title")})).toHaveCount(1);
      await expect(banner.filter({hasText: shell(lang, "bell.kinds.recovery_codes_regenerated.title")})).toHaveCount(1);
      await openBell(page);
      await expect(securityBlock(page).getByRole("listitem")).toHaveCount(2);
    });

    test("the passkey notice leads to the passkeys, the recovery notice to the codes, and each text says what evicts a thief", async ({page, context, baseURL}) => {
      const passkey = securityNoticeFixture();
      const codes = securityNoticeFixture({kind: "recovery_codes_regenerated", created_at: "2026-11-13T08:00:00Z"});
      await openWith(context, baseURL, {notifications: [passkey, codes]});
      await page.goto(`/${lang}/profiles`);
      const passkeyBanner = banners(page).filter({hasText: shell(lang, "bell.kinds.passkey_added.title")});
      // A password change keeps every passkey, so the text must send the person to remove it, and must not stop at the password.
      await expect(passkeyBanner.getByRole("link").first()).toHaveAttribute("href", /\/preferences\/account#passkeys$/);
      await expect(passkeyBanner).toContainText(lang === "fa" ? "حذف کنید" : "remove it under Passkeys");
      const codesBanner = banners(page).filter({hasText: shell(lang, "bell.kinds.recovery_codes_regenerated.title")});
      await expect(codesBanner.getByRole("link").first()).toHaveAttribute("href", /\/preferences\/account#totp$/);
      await expect(codesBanner).toContainText(lang === "fa" ? "کدهای تازه بسازید" : "make new codes");
      await passkeyBanner.getByRole("link").first().click();
      await expect(page).toHaveURL(/\/preferences\/account#passkeys$/);
      await expect(page.locator('[data-row-id="passkeys"] h2')).toBeFocused();
    });

    // webi-r1-1: the fragment stays in the address bar, and the bell opens and closes by changing the search parameters.
    test("a fragment is acted on once: opening and closing the bell on the account page does not take the focus back to the row", async ({page, context, baseURL}) => {
      await openWith(context, baseURL, {notifications: []});
      await page.goto(`/${lang}/preferences/account#sessions`);
      const rowButton = page.locator('[data-row-id="sessions"] button').first();
      await expect(rowButton).toBeFocused();
      await openBell(page);
      expect(await page.evaluate(() => document.querySelector("[role=dialog]")?.contains(document.activeElement) ?? false)).toBe(true);
      await page.keyboard.press("Escape");
      await expect(page.getByRole("dialog")).toHaveCount(0);
      await expect(rowButton).not.toBeFocused();
    });

    test("the banner is a warning that is announced, has the two links, and closing it clears the notice", async ({page, context, baseURL}) => {
      const sec = securityNoticeFixture({kind: "recovery_codes_regenerated"});
      const mock = await openWith(context, baseURL, {notifications: [sec]});
      await page.goto(`/${lang}/profiles`);
      const banner = banners(page);
      await expect(banner).toHaveCount(1);
      await expect(banner).toHaveAttribute("role", "alert");
      await expect(banner).toContainText(shell(lang, "bell.kinds.recovery_codes_regenerated.title"));
      // The text says when: the date of the notice is in the sentence, not the placeholder.
      await expect(banner).not.toContainText("{when}");
      const links = banner.getByRole("link");
      // Recovery codes that were replaced stay valid after a password change, so the first link is where new ones are made (webi-r1-5).
      // A passkey signs in with no code, so the passkeys are the second link (webi-r2-6).
      await expect(links).toHaveCount(4);
      await expect(links.nth(0)).toHaveAttribute("href", /\/preferences\/account#totp$/);
      await expect(links.nth(1)).toHaveAttribute("href", /\/preferences\/account#passkeys$/);
      await expect(links.nth(2)).toHaveAttribute("href", /\/preferences\/account#password$/);
      await expect(links.nth(3)).toHaveAttribute("href", /\/preferences\/account#sessions$/);
      // The banner does not take the focus by itself.
      await expect(banner.locator(":focus")).toHaveCount(0);
      await banner.getByRole("button", {name: shell(lang, "banners.dismiss")}).click();
      await expect.poll(() => reads(mock)).toEqual([sec.id]);
      await expect(banners(page)).toHaveCount(0);
    });

    test("a link leads to the account page and puts the focus on the row it names", async ({page, context, baseURL}) => {
      await openWith(context, baseURL, {notifications: [securityNoticeFixture()]});
      await page.goto(`/${lang}/profiles`);
      await banners(page).getByRole("link", {name: shell(lang, "bell.security.reviewSessions")}).click();
      await expect(page).toHaveURL(/\/preferences\/account#sessions$/);
      await expect(page.locator('[data-row-id="sessions"] button').first()).toBeFocused();
      // The same from the bell: the dialog goes with its address parameter, and the password row takes the focus.
      await openBell(page);
      await securityBlock(page).getByRole("link", {name: shell(lang, "bell.security.changePassword")}).click();
      await expect(page).toHaveURL(/\/preferences\/account#password$/);
      await expect(page.getByRole("dialog")).toHaveCount(0);
      await expect(page.locator('[data-row-id="password"] button').first()).toBeFocused();
    });

    // webi-r2-6: the panel pages by itself up to a cap. Past it, an unread passkey notice can still be unloaded, and the page says so.
    test("a flood longer than the pages the panel loads by itself says that more unread notices are further back", async ({page, context, baseURL}) => {
      const recent = Array.from({length: 50}, (_, i) =>
        securityNoticeFixture({kind: "recovery_codes_regenerated", created_at: new Date(Date.UTC(2026, 10, 20, 8, 0, 0) - i * 60_000).toISOString()}),
      );
      const plain = Array.from({length: 520}, (_, i) =>
        notificationFixture({kind: "phone_changed", created_at: new Date(Date.UTC(2026, 10, 10, 8, 0, 0) - i * 60_000).toISOString()}),
      );
      const passkey = securityNoticeFixture({created_at: "2026-11-01T08:00:00Z"});
      await openWith(context, baseURL, {notifications: [...recent, ...plain, passkey]});
      await page.goto(`/${lang}/profiles`);
      await expect(banners(page).first()).toContainText(shell(lang, "bell.moreUnread"));
      await openBell(page);
      await expect(page.getByTestId("more-unread")).toHaveText(shell(lang, "bell.moreUnread"));
    });

    // webi-r2-2: the fragment stays in the address, so a second press on the same link changes nothing there and fires no hashchange.
    test("pressing the link to the row the page is already at moves to it again, from the bell and from the banner", async ({page, context, baseURL}) => {
      await openWith(context, baseURL, {notifications: [securityNoticeFixture()]});
      await page.goto(`/${lang}/preferences/account#password`);
      const password = page.locator('[data-row-id="password"] button').first();
      await expect(password).toBeFocused();
      await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
      await expect(password).not.toBeFocused();
      await openBell(page);
      await securityBlock(page).getByRole("link", {name: shell(lang, "bell.security.changePassword")}).click();
      await expect(page.getByRole("dialog")).toHaveCount(0);
      await expect(password).toBeFocused();
      // The banner: no dialog, the address does not change at all.
      await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
      await banners(page).getByRole("link", {name: shell(lang, "bell.security.changePassword")}).click();
      await expect(password).toBeFocused();
    });
  });
}
