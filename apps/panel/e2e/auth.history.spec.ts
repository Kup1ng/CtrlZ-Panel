import type {Page} from "@playwright/test";
import {otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {INVITE_TOKEN, allowAuthErrors, callsTo, field, gotoForm, inviteInfoFixture, lastBody, LANGS, openAnonymous, text} from "./auth-support.ts";

// gate-r21-1, -6, -7, -9 (a regression of wp8-r1-5, whose own test passed only by timing).
//
// The invite page and the login page write the address bar from a mount effect. React runs a child's effects before its parent's, so on
// the first load that write reached the browser's native `history.replaceState`, before the router had installed its own. The entry lost
// the router's marker (`__NA`), a Back to it showed the URL of one page on the screen of another, and the router kept the address with the
// invite code in it. And a link pasted into a tab that is already on /invite is a `popstate` and then a `hashchange`: the code was read
// from `location.hash` in the second, after the router had written its canonical URL, which has no fragment, over the first.

test.beforeEach(({guard}) => allowAuthErrors(guard));
test.use({viewport: {width: 1280, height: 800}});

const CODE = INVITE_TOKEN;
const routerMarker = (page: Page) => page.evaluate(() => (history.state as {__NA?: boolean} | null)?.__NA === true);

for (const {lang} of LANGS) {
  test.describe(`the address bar and the router, ${lang}`, () => {
    test("a link pasted into a tab already on /invite is read when the router rewrites the address between popstate and hashchange", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": {body: inviteInfoFixture()}});
      await page.goto(`/${lang}/invite`);
      await expect(field(page, "token")).toBeVisible();
      // The order is held by the test and not left to timing: what the router's own write does between the two events is done here,
      // from a popstate listener that was added after the page's own. Chrome fires popstate and then hashchange for a fragment navigation.
      const order = await page.evaluate(
        (code) =>
          new Promise<string[]>((resolve) => {
            const seen: string[] = [];
            window.addEventListener("popstate", () => {
              seen.push("popstate");
              history.replaceState(history.state, "", location.pathname + location.search);
            });
            window.addEventListener("hashchange", () => {
              seen.push(`hashchange:${JSON.stringify(location.hash)}`);
              setTimeout(() => resolve(seen), 0);
            });
            location.hash = `#${code}`;
          }),
        CODE,
      );
      // The condition of the failure, asserted: the fragment is already gone from the address when hashchange runs.
      expect(order).toEqual(["popstate", 'hashchange:""']);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(text(lang, "invite.lookupTitle"));
      await expect.poll(() => lastBody(mock, "POST", "/auth/invites/lookup")).toEqual({token: CODE});
      expect(callsTo(mock, "POST", "/auth/invites/lookup")).toHaveLength(1);
      expect(new URL(page.url()).hash).toBe("");
    });

    test("the same link twice, and a mangled link between them, are each read", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": {body: inviteInfoFixture()}});
      await page.goto(`/${lang}/invite`);
      await expect(field(page, "token")).toBeVisible();
      for (const hash of ["---", CODE]) {
        await page.evaluate((value) => void (location.hash = `#${value}`), hash);
        await expect.poll(() => page.evaluate(() => location.hash)).toBe("");
      }
      // The mangled one is the invalid state with no lookup, and the real one after it is still read.
      await expect(page.getByRole("heading", {level: 1})).toHaveText(text(lang, "invite.lookupTitle"));
      expect(callsTo(mock, "POST", "/auth/invites/lookup")).toHaveLength(1);
    });

    // webi-r1-8: the bad link supersedes the lookup of the earlier one, so a late answer cannot put that invite's number on a page that holds no token.
    test("a mangled link pasted while a lookup is slow ends that lookup: its late answer does not open the info step", async ({page, context}) => {
      let release: () => void = () => undefined;
      const gate = new Promise<void>((resolve) => void (release = resolve));
      const mock = await openAnonymous(context, {
        "POST /auth/invites/lookup": async () => {
          await gate;
          return {body: inviteInfoFixture()};
        },
      });
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect.poll(() => callsTo(mock, "POST", "/auth/invites/lookup").length).toBe(1);
      await page.evaluate(() => void (location.hash = "#---"));
      await expect(page.getByRole("heading", {level: 1})).toHaveText(text(lang, "invite.invalidTitle"));
      release();
      await page.waitForTimeout(600);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(text(lang, "invite.invalidTitle"));
      expect(callsTo(mock, "POST", "/auth/otp/request")).toHaveLength(0);
    });

    // webi-r3-5: "Send code" is on the wire when the visitor leaves the invite; its late answer must not open the confirm step of a page
    // that no longer holds that token.
    test("Try another link while the code is being sent: the late answer does not open the confirm step", async ({page, context}) => {
      let release: () => void = () => undefined;
      const gate = new Promise<void>((resolve) => void (release = resolve));
      const mock = await openAnonymous(context, {
        "POST /auth/invites/lookup": {body: inviteInfoFixture()},
        "POST /auth/otp/request": async () => {
          await gate;
          return {status: 202, body: {challenge_id: otpChallengeId(1), expires_in_s: 300, resend_after_s: 60}};
        },
      });
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(text(lang, "invite.lookupTitle"));
      await page.getByRole("button", {name: text(lang, "invite.send")}).click();
      await expect.poll(() => callsTo(mock, "POST", "/auth/otp/request").length).toBe(1);
      await page.getByRole("button", {name: text(lang, "invite.another")}).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(text(lang, "invite.title"));
      release();
      await page.waitForTimeout(600);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(text(lang, "invite.title"));
      await expect(field(page, "token")).toBeVisible();
    });

    test("/invite#TOKEN: the strip goes through the router, the entry keeps its marker, and Back from a link is the invite page", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/invites/lookup": {body: inviteInfoFixture()}});
      // A mangled link: no token in it, so the page is the invalid state (no lookup) and its sign-in link is there to follow.
      await page.goto(`/${lang}/invite#---`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(text(lang, "invite.invalidTitle"));
      await expect.poll(() => page.evaluate(() => location.hash)).toBe("");
      expect(await routerMarker(page), "the entry still belongs to the router").toBe(true);
      await page.getByRole("link", {name: text(lang, "invite.signIn")}).click();
      await expect(page).toHaveURL(new RegExp(`/${lang}/login$`));
      await page.goBack();
      await expect(page).toHaveURL(new RegExp(`/${lang}/invite$`));
      // The page that is shown is the one the address names (it was the login form before the fix).
      await expect(field(page, "token")).toBeVisible();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(text(lang, "invite.title"));
    });

    test("a token in the link is gone from the address bar and from what the router holds, also after a refresh of the page's data", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/invites/lookup": {body: inviteInfoFixture()}});
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(text(lang, "invite.lookupTitle"));
      await expect.poll(() => page.evaluate(() => location.hash)).toBe("");
      expect(await routerMarker(page)).toBe(true);
      // A router action that commits without changing the address makes the router write its canonical URL again. If it still held the
      // fragment, this would put the token back (latent today: nothing on the page refreshes).
      const refreshed = await page.evaluate(() => {
        const router = (window as unknown as {next?: {router?: {refresh?: () => void}}}).next?.router;
        router?.refresh?.();
        return typeof router?.refresh === "function";
      });
      expect(refreshed, "Next exposes its router for this check").toBe(true);
      await page.waitForTimeout(500);
      expect(await page.evaluate(() => location.href)).not.toContain(CODE.slice(0, 8));
      expect(await page.evaluate(() => JSON.stringify(history.state))).not.toContain(CODE.slice(0, 8));
    });

    test("the login page's ?step= mirror keeps the router's marker, and Back from Forgot password is the login page", async ({page, context}) => {
      await openAnonymous(context);
      // A step that needs a ticket the page does not have: the mirror puts the address back on the first step, on the first load.
      await gotoForm(page, `/${lang}/login?step=otp&next=%2Fprofiles`);
      await expect.poll(() => page.evaluate(() => location.search)).toBe("?next=%2Fprofiles");
      expect(await routerMarker(page), "the entry still belongs to the router").toBe(true);
      await page.getByRole("link", {name: text(lang, "login.forgot")}).click();
      await expect(page).toHaveURL(new RegExp(`/${lang}/forgot-password`));
      await page.goBack();
      await expect(page).toHaveURL(new RegExp(`/${lang}/login[?]next=%2Fprofiles$`));
      await expect(field(page, "phone")).toBeVisible();
    });
  });
}
