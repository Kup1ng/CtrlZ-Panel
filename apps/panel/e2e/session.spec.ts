import type {BrowserContext, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {announcementFixture, meFixture, notificationFixture, publicConfigFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import {defaultHandlers, installApiMock, type ApiMock} from "@ctrlz/api-client/testing/mock.ts";

import {allowAuthErrors, field, gotoForm, signedIn, submit} from "./auth-support.ts";

// WP4: the session gate, refresh, logout and the bell and banner data, in mock mode
// (spec 17.1). Spec 17.3 rows `bell.spec.ts`, `banners.spec.ts` and `onboarding.spec.ts`
// meet here for the part that depends on the API client; their screens are WP6's.

// The browser logs every failed response as a console error, and the shared guard fails a test on one
// (spec 17.2). These are the three the tests below cause on purpose, and each test names the ones it
// causes, so an unrelated 401, 404 or 503 in any other test of this file still fails it (wp12-r1-10).
//   gone         a 401: the refresh that is refused, or the session that has ended
//   loginPage    a 404: the login page the session leaves for, which WP8 has not built yet; when it
//                exists, drop this one and the calls that name it
//   unavailable  a 503: a /me, a mutation or a logout that fails
const CAUSES = {
  gone: /status of 401/,
  loginPage: /status of 404/,
  unavailable: /status of 503/,
};
const allow = (guard: {allowConsole(pattern: RegExp): void}, ...causes: (keyof typeof CAUSES)[]) => causes.forEach((c) => guard.allowConsole(CAUSES[c]));

type Setup = NonNullable<Parameters<typeof installApiMock>[1]>;

async function open(context: BrowserContext, baseURL: string | undefined, setup: Setup = {}): Promise<ApiMock> {
  await context.addCookies([
    {name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true},
  ]);
  return installApiMock(context, setup);
}

const LANGS = [
  {lang: "fa", dir: "rtl"},
  {lang: "en", dir: "ltr"},
] as const;

const bell = (page: Page) => page.locator(".shell-bell").first();
const badge = (page: Page) => bell(page).locator(".badge");

for (const {lang} of LANGS) {
  test.describe(`${lang}`, () => {
    test.use({viewport: {width: 1280, height: 800}});

    test("a ready session shows the page, and asks /me and nothing the API has not got", async ({page, context, baseURL}) => {
      const mock = await open(context, baseURL);
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".shell-page")).toBeVisible();
      await expect(page.getByRole("status")).toHaveCount(0);
      expect(mock.count("GET /me")).toBeGreaterThanOrEqual(1);
      expect(mock.unhandled).toEqual([]);
    });

    // wp4-r5-7. Chrome evicts a page from the back/forward cache on its own, so a real Back cannot show the
    // handler working; a synthetic pageshow does exercise the real handler of the built page. Safari, which
    // does restore it, is a manual check (spec 14.7).
    test("a gated page restored from the back/forward cache is hidden and loaded again", async ({page, context, baseURL}) => {
      const mock = await open(context, baseURL);
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".shell-page")).toBeVisible();
      await page.evaluate(() => {
        (window as unknown as {restoredMarker: number}).restoredMarker = 1;
      });
      const before = mock.count("GET /me");
      await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pageshow", {persisted: false})));
      await page.waitForTimeout(300);
      expect(await page.evaluate(() => (window as unknown as {restoredMarker?: number}).restoredMarker)).toBe(1);
      const reloaded = page.waitForEvent("load");
      await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pageshow", {persisted: true})));
      await reloaded;
      await expect(page.locator(".shell-page")).toBeVisible();
      expect(await page.evaluate(() => (window as unknown as {restoredMarker?: number}).restoredMarker)).toBeUndefined();
      expect(mock.count("GET /me")).toBeGreaterThan(before);
    });

    test("no session: refresh refused, then the login page with next", async ({page, context, baseURL, guard}) => {
      allow(guard, "gone", "loginPage");
      const mock = await open(context, baseURL);
      mock.expire(401);
      await page.goto(`/${lang}/profiles`);
      await page.waitForURL(`**/${lang}/login?next=%2Fprofiles`);
      // One probe and one refresh, however many requests were waiting, and the original is not repeated after it.
      // (The login page is not built yet; the 404 that stands in for it asks /me again, so count what /profiles asked.)
      const fromProfiles = mock.calls.filter((c) => c.pageUrl.endsWith("/profiles"));
      expect(fromProfiles.filter((c) => c.path === "/auth/refresh")).toHaveLength(1);
      // The page's own /me and the client's probe, which asks whether the session is alive before it refreshes.
      expect(fromProfiles.filter((c) => c.path === "/me")).toHaveLength(2);
    });

    // gate-r15-5. currentNext() builds the `next` of every client-side end of a session. The case above only ever loads the bare path, so a
    // query, a nested path or the locale being cut at the wrong segment would have changed nothing here. These are the shapes that matter:
    // the query of a URL dialog (useUrlDialog) and a nested page. The visitor must come back to exactly that page, with the dialog open.
    for (const path of ["/preferences/account?helpPane=account", "/profiles?notificationsDialog=1"]) {
      test(`a session that ends on ${path} leaves with it as next, and sign-in lands on it again (gate-r15-5)`, async ({page, context, baseURL, guard}) => {
        allow(guard, "gone");
        allowAuthErrors(guard);
        const mock = await open(context, baseURL);
        mock.on("GET /auth/config", {body: publicConfigFixture()});
        // Signing in ends the expiry of the mock, as a new session would.
        const session = signedIn(context, baseURL);
        mock.on("POST /auth/login/password", async (call, state) => {
          state.expired = false;
          return session(call, state);
        });
        mock.expire(401);
        await page.goto(`/${lang}${path}`);
        await page.waitForURL((url) => url.pathname === `/${lang}/login`);
        const login = new URL(page.url());
        expect(login.searchParams.get("next")).toBe(path);
        expect(login.search).toBe(`?next=${encodeURIComponent(path)}`);

        await gotoForm(page, page.url());
        await field(page, "phone").fill("09123456789");
        await field(page, "password").fill("correct horse battery");
        await submit(page).click();
        await page.waitForURL((url) => url.pathname + url.search === `/${lang}${path}`);
        // The dialog that the query names is open: the page was restored, not only the path.
        await expect(page.getByRole("dialog")).toBeVisible();
        expect(mock.unhandled).toEqual([]);
      });
    }

    test("only the refresh cookie left: one refresh brings the session back", async ({page, context, baseURL, guard}) => {
      allow(guard, "gone");
      const mock = await open(context, baseURL);
      mock.expire(204);
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".shell-page")).toBeVisible();
      expect(mock.count("POST /auth/refresh")).toBe(1);
      // The page's /me (401), the probe (401), the repeat after the refresh (200). A fourth would be TanStack
      // Query retrying a failed repeat, which is what a client that cannot call fetch looks like.
      expect(mock.count("GET /me")).toBe(3);
      expect(page.url()).toMatch(new RegExp(`/${lang}/profiles$`));
    });

    test("a session that ends while the page is open leaves for the login page, once", async ({page, context, baseURL, guard}) => {
      allow(guard, "gone", "loginPage");
      const mock = await open(context, baseURL, {notifications: [notificationFixture()]});
      await page.clock.install();
      await page.goto(`/${lang}/profiles`);
      await expect(badge(page)).toBeVisible();
      mock.expire(401);
      // The bell's poll is what finds out, a minute later.
      await page.clock.fastForward(61_000);
      await page.waitForURL(`**/${lang}/login?next=%2Fprofiles`);
      expect(mock.calls.filter((c) => c.pageUrl.endsWith("/profiles") && c.path === "/auth/refresh")).toHaveLength(1);
    });

    test("a user who must change the password is sent to /change-password and sees nothing of the shell content", async ({page, context, baseURL}) => {
      const mock = await open(context, baseURL, {me: meFixture({user: {must_reset: true}})});
      await page.goto(`/${lang}/profiles`);
      await page.waitForURL(`**/${lang}/change-password`);
      // A restricted session is refused every other route, so none is asked for.
      expect(mock.count("GET /notifications")).toBe(0);
      expect(mock.count("GET /announcements")).toBe(0);
    });

    test("a suspended tenant is sent to /suspended", async ({page, context, baseURL}) => {
      const mock = await open(context, baseURL, {me: meFixture({tenant: {status: "suspended"}})});
      await page.goto(`/${lang}/profiles`);
      await page.waitForURL(`**/${lang}/suspended`);
      expect(mock.count("GET /notifications")).toBe(0);
    });

    // gate-r22-7: the gate cuts at a segment. /change-password-x and /suspended-x are no page, they fall to the catch-all inside the shell,
    // and a restricted account must still be sent on, not shown the shell around a 404.
    for (const {name, me, target, strays} of [
      {name: "a user who must change the password", me: meFixture({user: {must_reset: true}}), target: "change-password", strays: ["change-password-x", "change-password/x", "change-password/x/y"]},
      {name: "a suspended tenant", me: meFixture({tenant: {status: "suspended"}}), target: "suspended", strays: ["suspended-x", "suspended/x", "suspended/x/y"]},
    ]) {
      // gate-r23-6: a path below the page has no page either, and used to leave the skeleton for good.
      for (const stray of strays) {
        test(`${name} who opens /${stray} is sent to /${target}, as the gate matches the page itself (gate-r22-7, gate-r23-6)`, async ({page, context, baseURL, guard}) => {
          allow(guard, "loginPage");
          await open(context, baseURL, {me});
          await page.goto(`/${lang}/${stray}`);
          await page.waitForURL(`**/${lang}/${target}`);
        });
      }
    }

    test("a /me that fails with 503 shows an error with Retry, and Retry recovers", async ({page, context, baseURL, guard}) => {
      allow(guard, "unavailable");
      const mock = await open(context, baseURL);
      mock.on("GET /me", {status: 503, body: {code: "service_unavailable", retry_after_s: 2}});
      await page.goto(`/${lang}/profiles`);
      const alert = page.getByRole("alert").filter({has: page.getByRole("button")});
      await expect(alert).toBeVisible({timeout: 15_000});
      mock.on("GET /me", {body: meFixture({user: {locale: lang}})});
      await alert.getByRole("button", {name: lang === "fa" ? "تلاش دوباره" : "Try again"}).click();
      await expect(page.locator(".shell-page")).toBeVisible();
      expect(page.url()).toMatch(new RegExp(`/${lang}/profiles$`));
    });

    test("the saved language is applied once per tab session", async ({page, context, baseURL}) => {
      const other = lang === "fa" ? "en" : "fa";
      const mock = await open(context, baseURL, {me: meFixture({user: {locale: other}})});
      mock.state.followPageLocale = false;
      await page.goto(`/${lang}/profiles`);
      await page.waitForURL(`**/${other}/profiles`);
      await expect(page.locator(".shell-page")).toBeVisible();
      // The user then picks the first language by hand: it stays.
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".shell-page")).toBeVisible();
      await page.waitForTimeout(500);
      expect(page.url()).toMatch(new RegExp(`/${lang}/profiles$`));
    });

    test("two quick theme switches end on the last choice, and the writes go out one at a time (wp4-r6-2)", async ({page, context, baseURL}) => {
      const base = defaultHandlers()["PATCH /account/preferences"]!;
      const order: string[] = [];
      const mock = await open(context, baseURL, {
        me: meFixture({user: {theme: "system"}}),
        handlers: {
          // The answer to Dark is slow, so Light is chosen while it is still in flight.
          "PATCH /account/preferences": async (call, state) => {
            const theme = (call.body as {theme?: string}).theme;
            order.push(`start ${theme}`);
            if (theme === "dark") await new Promise((r) => setTimeout(r, 700));
            const reply = await base(call, state);
            order.push(`end ${theme}`);
            return reply;
          },
        },
      });
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".shell-page")).toBeVisible();
      const pick = async (index: number) => {
        await page.locator(".shell-logo-trigger").first().click();
        // Language items first, then Light, Dark, System.
        await page.getByRole("menuitemradio").nth(index).click();
      };
      await pick(3);
      await expect(page.locator("html")).toHaveClass(/\bdark\b/);
      await pick(2);
      await expect(page.locator("html")).not.toHaveClass(/\bdark\b/);
      // Watch the page while the slow answer to Dark comes in: it must never go back to dark.
      const seen = await page.evaluate(async () => {
        const classes: string[] = [];
        const until = Date.now() + 1_800;
        while (Date.now() < until) {
          classes.push(document.documentElement.className);
          await new Promise((r) => setTimeout(r, 40));
        }
        return classes;
      });
      expect(seen.filter((c) => /\bdark\b/.test(c))).toEqual([]);
      await expect.poll(() => mock.state.me.user.theme).toBe("light");
      expect(order).toEqual(["start dark", "end dark", "start light", "end light"]);
    });

    test("the theme the server holds wins over the cookie", async ({page, context, baseURL}) => {
      await open(context, baseURL, {me: meFixture({user: {theme: "dark"}})});
      await context.addCookies([{name: "ctrlz_theme", value: "light", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator("html")).toHaveClass(/\bdark\b/);
    });

    test("the bell badge adds notifications and announcements, and opening an item reads it", async ({page, context, baseURL}) => {
      const [a, b] = [notificationFixture({kind: "password_reset"}), notificationFixture({kind: "phone_changed", created_at: "2026-11-09T08:00:00Z"})];
      const mock = await open(context, baseURL, {notifications: [a, b], announcements: [announcementFixture()]});
      await page.goto(`/${lang}/profiles`);
      // Persian digits in fa and ASCII in en (spec 4.4): one form each, so a lost format.number fails here.
      await expect(badge(page)).toHaveText(lang === "fa" ? /^۳$/ : /^3$/);

      await bell(page).getByRole("button").click();
      const dialog = page.getByRole("dialog");
      await expect(dialog).toBeVisible();
      await dialog.getByRole("button").filter({hasText: lang === "fa" ? "رمز عبور شما بازنشانی شد" : "Your password was reset"}).click();
      await expect.poll(() => mock.count("POST /notifications/{id}/read")).toBe(1);
      expect(mock.calls.find((c) => c.method === "POST")!.path).toBe(`/notifications/${a.id}/read`);
      await expect(badge(page)).toHaveText(/^[2۲]$/);
    });

    test("a notification link that could leave the origin shows no Open button, a safe one does (wp4-r17-1)", async ({page, context, baseURL}) => {
      const evil = notificationFixture({kind: "password_reset", link: "/..//127.0.0.1:1/x"});
      const safe = notificationFixture({kind: "phone_changed", link: "/preferences/account", created_at: "2026-11-09T08:00:00Z"});
      await open(context, baseURL, {notifications: [evil, safe]});
      await page.goto(`/${lang}/profiles`);
      await bell(page).getByRole("button").click();
      const dialog = page.getByRole("dialog");
      await expect(dialog).toBeVisible();
      const openLabel = lang === "fa" ? "باز کردن" : "Open";
      // Expand both rows. A row's panel is mounted only while open, so each button is counted after its own expand.
      const rows = dialog.getByRole("button").filter({hasText: lang === "fa" ? "رمز عبور شما بازنشانی شد" : "Your password was reset"});
      await rows.click();
      await expect(dialog.getByRole("button", {name: openLabel, exact: true})).toHaveCount(0);
      await dialog.getByRole("button").filter({hasText: lang === "fa" ? "شماره تلفن" : "phone"}).first().click();
      await expect(dialog.getByRole("button", {name: openLabel, exact: true})).toHaveCount(1);
      expect(new URL(page.url()).origin).toBe(new URL(baseURL!).origin);
    });

    test("a notification link ending in a dot-dot and a space shows no Open button (wp4-r18-1)", async ({page, context, baseURL}) => {
      const spaced = notificationFixture({kind: "password_reset", link: "/profiles/.. "});
      await open(context, baseURL, {notifications: [spaced]});
      await page.goto(`/${lang}/profiles`);
      await bell(page).getByRole("button").click();
      const dialog = page.getByRole("dialog");
      await expect(dialog).toBeVisible();
      await dialog.getByRole("button").filter({hasText: lang === "fa" ? "رمز عبور شما بازنشانی شد" : "Your password was reset"}).click();
      await expect(dialog.getByRole("button", {name: lang === "fa" ? "باز کردن" : "Open", exact: true})).toHaveCount(0);
    });

    test("the bell polls every minute while the tab is visible", async ({page, context, baseURL}) => {
      const mock = await open(context, baseURL);
      await page.clock.install();
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".shell-page")).toBeVisible();
      await expect(badge(page)).toHaveCount(0);
      const before = mock.count("GET /notifications");
      mock.state.notifications = [notificationFixture()];
      await page.clock.fastForward(61_000);
      await expect(badge(page)).toBeVisible();
      expect(mock.count("GET /notifications")).toBeGreaterThan(before);
    });

    test("the bell stops polling after half an hour without input, and the next input takes it up again (wp4-r2-2)", async ({page, context, baseURL}) => {
      const mock = await open(context, baseURL);
      await page.clock.install();
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".shell-page")).toBeVisible();
      await expect.poll(() => mock.count("GET /notifications")).toBeGreaterThanOrEqual(1);
      // A minute at a time, with the answer in between: the interval is read again after every fetch.
      // The next timer is set when the answer to a poll arrives, not when the request leaves, so a fixed 80 ms wait was a race: under load the
      // answer came after the next minute had begun, that minute ended just before the timer was due, and the count was 0 (gate-r8, seen at the
      // last line of this test with two workers). The answer is waited for, and the poll that went out is the one that is counted.
      const minute = async () => {
        const seen = mock.count("GET /notifications");
        const answer = page.waitForResponse((r) => r.url().includes("/notifications"), {timeout: 3000}).catch(() => null);
        await page.clock.runFor(60_000);
        if (mock.count("GET /notifications") > seen) await answer;
        await page.waitForTimeout(50);
        return mock.count("GET /notifications") - seen;
      };
      expect(await minute()).toBe(1);
      for (let i = 0; i < 31; i++) await minute();
      // 32 minutes without input: the poll has stopped, so the idle limit of the session can run.
      const stopped = mock.count("GET /notifications");
      for (let i = 0; i < 5; i++) await minute();
      expect(mock.count("GET /notifications")).toBe(stopped);
      // A link that drops and comes back with nobody there must not fetch either (wp4-r3-7): "online" refetches
      // every stale query, and each request slides the idle limit. /me and the feeds are all stale by now.
      const meBefore = mock.count("GET /me");
      await context.setOffline(true);
      await page.waitForTimeout(100);
      await context.setOffline(false);
      await page.waitForTimeout(400);
      expect(mock.count("GET /notifications")).toBe(stopped);
      expect(mock.count("GET /me")).toBe(meBefore);
      // The browser's own scroll, with nobody there (wp4-r8-1, r8-3): a banner that goes away, a row that
      // changes height or an image that loads makes the scroller clamp or anchor, and Chrome fires a trusted
      // `scroll` for it. A tall spacer and a programmatic scrollTop make the same kind of event. It must not
      // reopen presence, and neither must a script's own click (isTrusted false).
      await page.evaluate(() => {
        const w = window as unknown as {__scrolls: number};
        w.__scrolls = 0;
        window.addEventListener("scroll", () => w.__scrolls++, {capture: true});
        const spacer = document.createElement("div");
        spacer.style.height = "4000px";
        document.querySelector(".shell-page")!.append(spacer);
        for (let el: Element | null = spacer; el; el = el.parentElement) {
          if (el.scrollHeight > el.clientHeight) el.scrollTop = el.scrollHeight;
        }
        window.scrollTo(0, document.body.scrollHeight);
      });
      await page.waitForTimeout(300);
      expect(await page.evaluate(() => (window as unknown as {__scrolls: number}).__scrolls)).toBeGreaterThan(0);
      await page.evaluate(() => document.body.dispatchEvent(new Event("click", {bubbles: true})));
      await page.waitForTimeout(150);
      expect(mock.count("GET /notifications")).toBe(stopped);
      expect(mock.count("GET /me")).toBe(meBefore);
      // Someone comes back: one refetch at once, then the poll goes on. A click is enough, with no pointer
      // movement or key before it (wp4-r7-1). It is a trusted one: page.mouse.click is real input.
      await page.mouse.click(2, 2);
      await expect.poll(() => mock.count("GET /notifications")).toBe(stopped + 1);
      // The poll goes on: the refetch above set the next timer when its answer came, which can be a moment after the minute below began, so it is
      // due in this minute or the next, and then once a minute.
      let resumed = 0;
      for (let i = 0; i < 2 && resumed === 0; i += 1) resumed = await minute();
      expect(resumed, "the poll went on within two minutes of the click").toBe(1);
      expect(await minute()).toBe(1);
    });

    test("past the session's idle limit with no input the page shows no account and sends nothing; only the Continue button brings it back (wp4-r6-3, wp4-r7-1)", async ({page, context, baseURL}) => {
      const mock = await open(context, baseURL);
      await page.clock.install();
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".shell-page")).toBeVisible();
      await expect.poll(() => mock.count("GET /notifications")).toBeGreaterThanOrEqual(1);
      // A minute at a time past the presence pause (30 min), so every poll that is due has run.
      for (let i = 0; i < 32; i++) {
        await page.clock.runFor(60_000);
        await page.waitForTimeout(40);
      }
      const settled = {me: mock.count("GET /me"), notifications: mock.count("GET /notifications"), announcements: mock.count("GET /announcements")};
      // 32 + 87 = 119 minutes: still on screen.
      await page.clock.runFor(87 * 60_000);
      await expect(page.locator(".shell-page")).toBeVisible();
      // 121 minutes, past 2 h: nothing of the account is in the DOM, and no request went out meanwhile.
      await page.clock.runFor(2 * 60_000);
      await expect(page.locator(".shell-page")).toHaveCount(0);
      await expect(page.locator(".shell-bell")).toHaveCount(0);
      await expect(page.getByRole("alertdialog")).toContainText(lang === "fa" ? "برای امنیت شما پنهان شد" : "Hidden for your security");
      // The button has the focus, so a keyboard or screen-reader user lands on the one thing to do.
      const continueButton = page.getByRole("button", {name: lang === "fa" ? "ادامه" : "Continue"});
      await expect(continueButton).toBeFocused();
      expect({me: mock.count("GET /me"), notifications: mock.count("GET /notifications"), announcements: mock.count("GET /announcements")}).toEqual(settled);
      // A mouse that jitters, a key, a stray tap: none of it brings the account back or asks /me (wp4-r7-1).
      await page.mouse.move(40, 40);
      await page.mouse.move(80, 90);
      await page.keyboard.press("Shift");
      await page.waitForTimeout(150);
      await expect(page.locator(".shell-page")).toHaveCount(0);
      expect(mock.count("GET /me")).toBe(settled.me);
      // Someone asks to continue: the page mounts again and asks /me, as on a first load.
      await continueButton.click();
      await expect(page.locator(".shell-page")).toBeVisible();
      expect(mock.count("GET /me")).toBe(settled.me + 1);
      // The Continue button went with the cover, so focus would be on <body>: it moves to the page region
      // once the page is back, for a keyboard or screen-reader user (wp4-r9-1).
      await expect.poll(() => page.evaluate(() => document.activeElement?.id)).toBe("main-content");
    });

    test("another tab signing in as someone else clears this tab and loads it again (wp4-r2-1)", async ({page, context, baseURL}) => {
      const mock = await open(context, baseURL, {notifications: [notificationFixture()]});
      await page.goto(`/${lang}/profiles`);
      await expect(badge(page)).toBeVisible();
      await page.evaluate(() => ((window as unknown as {__same: boolean}).__same = true));
      // Tenant 2's user signs in elsewhere: the cookie changes, /me answers for them, and so does the poll.
      mock.on("GET /me", {body: meFixture({user: {id: "00000000-0000-4000-8000-0000000000b2", locale: lang}, tenant: {id: "00000000-0000-4000-8000-0000000000c3"}})});
      mock.state.notifications = [];
      await page.evaluate(() => new BroadcastChannel("ctrlz-session").postMessage("login"));
      // The marker is on the old document: it is gone once the page was loaded again (an evaluate that
      // meets the navigation throws, which is the same answer).
      await expect
        .poll(() => page.evaluate(() => (window as unknown as {__same?: boolean}).__same).catch(() => undefined))
        .toBeUndefined();
      await expect(page.locator(".shell-page")).toBeVisible();
      // The first user's notification does not survive the reload, and the new user's page is the one on show.
      await expect(badge(page)).toHaveCount(0);
      expect(page.url()).toMatch(new RegExp(`/${lang}/profiles$`));
    });

    test("a signing-in of the same account in another tab changes nothing here (wp4-r2-1)", async ({page, context, baseURL}) => {
      const mock = await open(context, baseURL, {notifications: [notificationFixture()]});
      await page.goto(`/${lang}/profiles`);
      await expect(badge(page)).toBeVisible();
      await page.evaluate(() => ((window as unknown as {__same: boolean}).__same = true));
      const before = mock.count("GET /me");
      await page.evaluate(() => new BroadcastChannel("ctrlz-session").postMessage("login"));
      await expect.poll(() => mock.count("GET /me")).toBeGreaterThan(before);
      await page.waitForTimeout(400);
      expect(await page.evaluate(() => (window as unknown as {__same?: boolean}).__same)).toBe(true);
      await expect(badge(page)).toBeVisible();
    });

    test("a critical notification is a banner; dismissing it reads it", async ({page, context, baseURL}) => {
      const critical = notificationFixture({kind: "passkey_stale", severity: "critical"});
      const mock = await open(context, baseURL, {notifications: [critical, notificationFixture({kind: "password_reset", severity: "warning"})]});
      await page.goto(`/${lang}/profiles`);
      const stack = page.locator(".banner-stack");
      await expect(stack.locator(".banner-stack__item")).toHaveCount(1);
      await stack.getByRole("button", {name: lang === "fa" ? "بستن اعلان" : "Dismiss notice"}).click();
      await expect(stack).toHaveCount(0);
      expect(mock.calls.some((c) => c.method === "POST" && c.path === `/notifications/${critical.id}/read`)).toBe(true);
      await page.reload();
      await expect(page.locator(".shell-page")).toBeVisible();
      await expect(page.locator(".banner-stack")).toHaveCount(0);
    });

    test("banners keep their priority, show two, and an announcement outside its window stays out", async ({page, context, baseURL}) => {
      await open(context, baseURL, {
        me: meFixture({user: {has_password: false}}),
        notifications: [notificationFixture({kind: "passkey_stale", severity: "critical"})],
        announcements: [
          announcementFixture({body: "Live announcement"}),
          announcementFixture({body: "Over", ends_at: "2026-11-02T00:00:00Z"}),
          announcementFixture({body: "Not yet", starts_at: "2099-01-01T00:00:00Z"}),
        ],
        handlers: {"GET /auth/config": {body: {registration_mode: "closed", sms_available: false, passkey_enabled: false}}},
      });
      await page.goto(`/${lang}/profiles`);
      const items = page.locator(".banner-stack__item");
      await expect(items).toHaveCount(2);
      // 1 critical notification, then the live announcement; the password warning is third, behind "more".
      await expect(items.nth(0)).toContainText(lang === "fa" ? "پاسکی" : "passkey");
      await expect(items.nth(1)).toContainText("Live announcement");
      await expect(page.locator(".banner-stack")).not.toContainText("Over");
      await expect(page.locator(".banner-stack")).not.toContainText("Not yet");
      await page.locator(".banner-stack").getByRole("button", {name: lang === "fa" ? /اعلان دیگر/ : /more notice/}).click();
      await expect(items).toHaveCount(3);
      await expect(items.nth(2)).toContainText(lang === "fa" ? "رمز عبور" : "password");
    });

    // wp4-r12-1: the window was judged once per render, and the poll of an unchanged feed renders nothing.
    test("an announcement leaves at its ends_at and another comes at its starts_at, with the data unchanged", async ({page, context, baseURL}) => {
      const minutes = (n: number) => new Date(Date.now() + n * 60_000).toISOString();
      await open(context, baseURL, {
        announcements: [
          announcementFixture({body: "Ends soon", ends_at: minutes(2)}),
          announcementFixture({body: "Starts later", starts_at: minutes(3)}),
        ],
      });
      await page.clock.install();
      await page.goto(`/${lang}/profiles`);
      const stack = page.locator(".banner-stack");
      await expect(stack).toContainText("Ends soon");
      await expect(stack).not.toContainText("Starts later");
      // Past the end and before the start: no new data may be needed for the page to change.
      await page.clock.fastForward(2 * 60_000 + 5_000);
      await expect(stack).toHaveCount(0);
      await page.clock.fastForward(60_000);
      await expect(stack).toContainText("Starts later");
    });

    test("announcement text is shown as text, in the direction of its own language", async ({page, context, baseURL}) => {
      await open(context, baseURL, {announcements: [announcementFixture({body: "<img src=x onerror=alert(1)> سلام"})]});
      await page.goto(`/${lang}/profiles`);
      const text = page.locator(".banner-stack").getByText("<img src=x onerror=alert(1)>");
      await expect(text).toBeVisible();
      await expect(page.locator(".banner-stack img")).toHaveCount(0);
      await expect(text).toHaveAttribute("dir", "auto");
    });

    test("the onboarding card is dismissed through the API and stays gone after a reload", async ({page, context, baseURL}) => {
      const mock = await open(context, baseURL);
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".onboarding")).toBeVisible();
      await page.getByRole("button", {name: lang === "fa" ? "پنهان کردن" : "Hide", exact: true}).click();
      await page.getByRole("button", {name: lang === "fa" ? "پنهان کن" : "Hide it", exact: true}).click();
      await expect(page.locator(".onboarding")).toHaveCount(0);
      // The Hide button that had focus is gone with the card: focus goes to the page region, not to <body> (wp4-r3-3).
      await expect.poll(() => page.evaluate(() => document.activeElement?.id)).toBe("main-content");
      const patch = mock.calls.find((c) => c.method === "PATCH" && c.path === "/account/preferences")!;
      const sent = (patch.body as {onboarding_state: Record<string, unknown>}).onboarding_state;
      expect(sent.v).toBe(1);
      expect(typeof sent.dismissed_at).toBe("string");
      await page.reload();
      await expect(page.locator(".shell-page")).toBeVisible();
      await expect(page.locator(".onboarding")).toHaveCount(0);
    });

    test("hints off hide the card without a dismissal", async ({page, context, baseURL}) => {
      const mock = await open(context, baseURL, {me: meFixture({user: {onboarding_hints: {enabled: false}}})});
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".shell-page")).toBeVisible();
      await expect(page.locator(".onboarding")).toHaveCount(0);
      expect(mock.count("PATCH /account/preferences")).toBe(0);
    });

    test("Log out: POST /auth/logout, then the login page; the other tab follows", async ({page, context, baseURL, guard}) => {
      allow(guard, "loginPage");
      const mock = await open(context, baseURL);
      const second = await context.newPage();
      await second.goto(`/${lang}/profiles`);
      await expect(second.locator(".shell-page")).toBeVisible();
      await page.goto(`/${lang}/profiles`);
      await page.getByRole("row", {name: lang === "fa" ? /تنظیمات/ : /Preferences/}).first().click();
      await page.getByRole("row", {name: lang === "fa" ? /خروج/ : /Log out/}).first().click();
      await page.getByRole("button", {name: lang === "fa" ? "خروج" : "Log out", exact: true}).click();
      await page.waitForURL(`**/${lang}/login`);
      expect(mock.count("POST /auth/logout")).toBe(1);
      await second.waitForURL(`**/${lang}/login`);
      // Hearing it does not log out again.
      expect(mock.count("POST /auth/logout")).toBe(1);
    });

    // gate-r20-6. /<lang>/login/<anything> has no page; with a session cookie the catch-all renders the signed-in shell with the 404 in it. It is
    // not the login page, so a session that ends elsewhere must clear it: the bell's notifications are in the query cache and stay rendered
    // otherwise, for the next person at the PC. Before the fix isOnLoginPath() matched every path below /login and the 'logout' message was ignored.
    test("a signed-in 404 under /login/ is not taken for the login page: another tab's logout clears it (gate-r20-6)", async ({page, context, baseURL, guard}) => {
      allow(guard, "loginPage");
      const mock = await open(context, baseURL, {notifications: [notificationFixture({kind: "password_reset"})]});
      await page.goto(`/${lang}/login/x`);
      await expect(badge(page)).toHaveText(lang === "fa" ? /^۱$/ : /^1$/);
      expect(mock.count("GET /me")).toBeGreaterThanOrEqual(1);
      // What another tab's logout sends. A message goes to every other channel object, this tab's included.
      await page.evaluate(() => new BroadcastChannel("ctrlz-session").postMessage("logout"));
      await page.waitForURL((url) => url.pathname === `/${lang}/login`);
      // The login page is a plain document: no shell, no bell and none of the previous account's entries.
      await expect(page.locator(".shell-bell")).toHaveCount(0);
      await expect(page.getByText(lang === "fa" ? "رمز عبور شما بازنشانی شد" : "Your password was reset")).toHaveCount(0);
      // Hearing it does not log out again.
      expect(mock.count("POST /auth/logout")).toBe(0);
    });

    test("a mutation that meets an expired session is repeated once after the refresh, with no query retry to hide behind", async ({page, context, baseURL, guard}) => {
      allow(guard, "gone");
      const errors: string[] = [];
      page.on("pageerror", (e) => errors.push(e.message));
      const mock = await open(context, baseURL);
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".onboarding")).toBeVisible();
      mock.expire(204);
      await page.getByRole("button", {name: lang === "fa" ? "پنهان کردن" : "Hide", exact: true}).click();
      await page.getByRole("button", {name: lang === "fa" ? "پنهان کن" : "Hide it", exact: true}).click();
      await expect(page.locator(".onboarding")).toHaveCount(0);
      // A mutation is never retried by TanStack Query, so a second PATCH is the client's own repeat.
      expect(mock.count("PATCH /account/preferences")).toBe(2);
      expect(mock.count("POST /auth/refresh")).toBe(1);
      expect(errors).toEqual([]);
    });

    test("a 401 that raced a rotation is repeated after /me says the session is alive, and nothing is refreshed", async ({page, context, baseURL, guard}) => {
      allow(guard, "gone");
      const mock = await open(context, baseURL);
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".onboarding")).toBeVisible();
      // The first PATCH went out with the cookie from before a rotation; the browser holds the new one by now.
      let first = true;
      mock.on("PATCH /account/preferences", (call, state) => {
        if (first) {
          first = false;
          return {status: 401, body: {code: "session_expired"}};
        }
        const sent = (call.body as {onboarding_state: Record<string, string | number>}).onboarding_state;
        state.me = {...state.me, user: {...state.me.user, onboarding_state: sent}};
        return {body: state.me};
      });
      await page.getByRole("button", {name: lang === "fa" ? "پنهان کردن" : "Hide", exact: true}).click();
      await page.getByRole("button", {name: lang === "fa" ? "پنهان کن" : "Hide it", exact: true}).click();
      await expect(page.locator(".onboarding")).toHaveCount(0);
      expect(mock.count("PATCH /account/preferences")).toBe(2);
      // A refresh without a refresh cookie would have cleared the live session cookie (AUTH 3.5).
      expect(mock.count("POST /auth/refresh")).toBe(0);
      expect(page.url()).toMatch(new RegExp(`/${lang}/profiles$`));
    });

    test("a dismissal the server did not take keeps the card and says why", async ({page, context, baseURL, guard}) => {
      allow(guard, "unavailable");
      const mock = await open(context, baseURL);
      mock.on("PATCH /account/preferences", {status: 503, body: {code: "service_unavailable"}});
      await page.goto(`/${lang}/profiles`);
      await page.getByRole("button", {name: lang === "fa" ? "پنهان کردن" : "Hide", exact: true}).click();
      await page.getByRole("button", {name: lang === "fa" ? "پنهان کن" : "Hide it", exact: true}).click();
      await expect(page.getByText(lang === "fa" ? /سرویس فعلاً در دسترس نیست/ : /service is not available/i)).toBeVisible();
      await expect(page.locator(".onboarding")).toBeVisible();
    });

    async function openLogout(page: Page) {
      await page.getByRole("row", {name: lang === "fa" ? /تنظیمات/ : /Preferences/}).first().click();
      await page.getByRole("row", {name: lang === "fa" ? /خروج/ : /Log out/}).first().click();
      await page.getByRole("button", {name: lang === "fa" ? "خروج" : "Log out", exact: true}).click();
    }

    test("Log out with a dead session cookie asks for a refresh first, and ends the session it brings back", async ({page, context, baseURL, guard}) => {
      allow(guard, "gone", "loginPage");
      // The refresh cookie of Remember me outlives the session cookie, and the 401 of a dead session clears nothing.
      const mock = await open(context, baseURL);
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".shell-page")).toBeVisible();
      let live = false;
      mock.on("POST /auth/refresh", () => {
        live = true;
        return {status: 204};
      });
      mock.on("POST /auth/logout", () => (live ? {status: 204} : {status: 401, body: {code: "session_expired"}}));
      await openLogout(page);
      await page.waitForURL(`**/${lang}/login`);
      const order = mock.calls.filter((c) => c.path === "/auth/logout" || c.path === "/auth/refresh").map((c) => `${c.method} ${c.path}`);
      expect(order).toEqual(["POST /auth/logout", "POST /auth/refresh", "POST /auth/logout"]);
    });

    test("Log out with nothing behind the dead session: the refresh says 401 and the user leaves", async ({page, context, baseURL, guard}) => {
      allow(guard, "gone", "loginPage");
      const mock = await open(context, baseURL);
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".shell-page")).toBeVisible();
      mock.on("POST /auth/refresh", {status: 401, body: {code: "session_expired"}});
      mock.on("POST /auth/logout", {status: 401, body: {code: "session_expired"}});
      await openLogout(page);
      await page.waitForURL(`**/${lang}/login`);
      const order = mock.calls.filter((c) => c.path === "/auth/logout" || c.path === "/auth/refresh").map((c) => `${c.method} ${c.path}`);
      expect(order).toEqual(["POST /auth/logout", "POST /auth/refresh"]);
    });

    test("Log out that the server did not take stays on the page and says why", async ({page, context, baseURL, guard}) => {
      allow(guard, "unavailable");
      const mock = await open(context, baseURL);
      mock.on("POST /auth/logout", {status: 503, body: {code: "service_unavailable"}});
      await page.goto(`/${lang}/profiles`);
      await page.getByRole("row", {name: lang === "fa" ? /تنظیمات/ : /Preferences/}).first().click();
      await page.getByRole("row", {name: lang === "fa" ? /خروج/ : /Log out/}).first().click();
      await page.getByRole("button", {name: lang === "fa" ? "خروج" : "Log out", exact: true}).click();
      await expect(page.getByText(lang === "fa" ? /سرویس فعلاً در دسترس نیست/ : /service is not available/i)).toBeVisible();
      expect(page.url()).toMatch(new RegExp(`/${lang}/profiles$`));
    });
  });
}

test.describe("on a phone", () => {
  test.use({viewport: {width: 375, height: 812}});

  for (const {lang} of LANGS) {
    test(`${lang}: the gate and the banner fit 375px with no horizontal scroll`, async ({page, context, baseURL}) => {
      await open(context, baseURL, {announcements: [announcementFixture({body: "A long announcement ".repeat(12)})]});
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".banner-stack")).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    });

    // An admin writes the text, and a link has no place to break (wp4-r3-1).
    test(`${lang}: an announcement with one 120-character token does not widen the page`, async ({page, context, baseURL}) => {
      const token = `https://example.com/${"a".repeat(100)}?x=1`;
      await open(context, baseURL, {announcements: [announcementFixture({body: `See ${token}`})]});
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".banner-stack")).toBeVisible();
      expect(await page.evaluate(() => [document.documentElement.scrollWidth, innerWidth])).toEqual([375, 375]);
      const alert = await page.locator(".banner-stack .alert").first().boundingBox();
      expect(alert!.width).toBeLessThanOrEqual(375);
    });
  }
});

// gate-r2-13. Every auth page may hold what a visitor typed or a reset ticket, so a page of this layout that the back/forward cache
// restores is reloaded (gate-r1-19), and the one line that arranges it is <LoginSessionReset /> in the (auth) layout. The hook has
// a unit test; nothing else ties it to the six pages, so a layout that dropped the line would pass every other test. A synthetic
// pageshow, as for the gated page above: Chrome evicts a real page from the cache on its own.
test.describe("a page of the (auth) layout restored from the back/forward cache", () => {
  // The last two are for a signed-in visitor: with no session the proxy sends them away before the layout is reached. They also reload
  // through their own session gate, so only the first four fail when the line is removed from the layout (checked by removing it).
  const restricted = {"change-password": meFixture({user: {must_reset: true}}), suspended: meFixture({tenant: {status: "suspended"}})} as const;
  for (const path of ["login", "register", "invite", "forgot-password", "change-password", "suspended"] as const) {
    test(`/${path} is reloaded, and a restore that is not from the cache changes nothing`, async ({page, context, baseURL, guard}) => {
      // Whatever the page asks the API while it opens is of no interest here, and the mock answers it with an error status.
      guard.allowConsole(/status of (401|404|503)/);
      const me = path === "change-password" || path === "suspended" ? restricted[path] : undefined;
      if (me) await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
      await installApiMock(context, me ? {me} : {});
      await page.goto(`/fa/${path}`);
      await expect(page.locator("main#main")).toBeVisible();
      await page.evaluate(() => {
        (window as unknown as {restoredMarker: number}).restoredMarker = 1;
      });
      await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pageshow", {persisted: false})));
      await page.waitForTimeout(300);
      expect(await page.evaluate(() => (window as unknown as {restoredMarker?: number}).restoredMarker), "a pageshow that is not a restore").toBe(1);
      const reloaded = page.waitForEvent("load");
      await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pageshow", {persisted: true})));
      await reloaded;
      expect(await page.evaluate(() => (window as unknown as {restoredMarker?: number}).restoredMarker), "the page was reloaded").toBeUndefined();
    });
  }
});
