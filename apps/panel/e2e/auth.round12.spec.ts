import {meFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import {installApiMock} from "@ctrlz/api-client/testing/mock.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {
  allowAuthErrors,
  callsTo,
  err,
  errorText,
  field,
  gotoForm,
  lastBody,
  LANGS,
  meReady,
  openAnonymous,
  signedIn,
  STRONG_PASSWORD,
  submit,
  text,
} from "./auth-support.ts";

// Round 12 of the review of WP8: a slow route change after a sign-in is not a redirect back to /login
// (wp8-r12-1, r12-3), and the reauth stage of the forced password change takes a recovery code (wp8-r12-2).

test.beforeEach(({guard}) => allowAuthErrors(guard));

const PHONE = "09123456789";

for (const {lang, dir} of LANGS) {
  test.describe(`round 12, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    // The soft navigation (an RSC fetch) is held for ever, as on a link too slow to deliver it. A full page load of
    // the same path (what the page falls back to) is let through.
    async function holdSoftNavigation(context: Parameters<typeof signedIn>[0], guard: {allowConsole(pattern: RegExp): void}) {
      // The full load that ends the wait tears the held fetch down, and Next writes that to the console of the document that
      // is going away. The guard keeps what a document writes from pagehide on across a navigation (gate-r23-2), so the
      // message is now seen. It is what the app does when a soft navigation fails, and this test holds one on purpose.
      guard.allowConsole(/Failed to fetch RSC payload for .* Falling back to browser navigation/);
      let held = 0;
      await context.route(`**/${lang}/profiles**`, (route) => {
        if (new URL(route.request().url()).searchParams.has("_rsc")) {
          held++;
          return; // never answered: the page is "still loading"
        }
        return route.fallback();
      });
      return () => held;
    }

    async function signInWith(page: Parameters<typeof gotoForm>[0]) {
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill(STRONG_PASSWORD);
      await submit(page).click();
    }

    // wp8-r12-1, r12-3: the 12 s bound cannot tell a slow healthy route change from a redirect to /login. It asks
    // /me first: a live session is never called ended, and the move is made again as a full load.
    test("wp8-r12-1/3: a slow route change with a live session shows no 'session ended' notice and finishes the move", async ({
      page,
      context,
      baseURL,
      guard,
    }) => {
      test.setTimeout(90_000);
      const held = await holdSoftNavigation(context, guard);
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": signedIn(context, baseURL),
        "GET /me": meReady(),
        "POST /auth/logout": {status: 204},
      });
      await signInWith(page);
      await expect.poll(() => held(), {timeout: 15_000}).toBeGreaterThan(0);
      await expect(field(page, "password")).toBeDisabled();
      // The bound passes, the probe says the session is live, and the page is loaded for real.
      await page.waitForURL(`**/${lang}/profiles`, {timeout: 40_000});
      await expect(page.getByText(errorText(lang, "session_expired"), {exact: true})).toHaveCount(0);
      expect(callsTo(mock, "GET", "/me").length).toBeGreaterThan(0);
      expect(callsTo(mock, "POST", "/auth/login/password")).toHaveLength(1);
      expect(callsTo(mock, "POST", "/auth/logout")).toHaveLength(0);
    });

    // An answer that says nothing about the session (a 503) is not read as its end either.
    test("wp8-r12-1/3: a /me that fails with a 503 is not read as a dead session", async ({page, context, baseURL, guard}) => {
      test.setTimeout(90_000);
      const held = await holdSoftNavigation(context, guard);
      let probes = 0;
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": signedIn(context, baseURL),
        // The first look is the probe after the bound, and it fails. The shell of the page that is loaded for real
        // then asks again and gets the user.
        "GET /me": (call, state) => (++probes === 1 ? err(503, "service_unavailable") : meReady()(call, state)),
        "POST /auth/logout": {status: 204},
      });
      await signInWith(page);
      await expect.poll(() => held(), {timeout: 15_000}).toBeGreaterThan(0);
      await page.waitForURL(`**/${lang}/profiles`, {timeout: 40_000});
      await expect(page.getByText(errorText(lang, "session_expired"), {exact: true})).toHaveCount(0);
      expect(callsTo(mock, "POST", "/auth/logout")).toHaveLength(0);
    });

    // wp8-r12-2: the reauth stage takes a recovery code, like the sign-in page; before the server asks for a reauth
    // the API takes only the authenticator code, so the page has no switch there and says what to do when the
    // authenticator is lost.
    test("wp8-r12-2: the reauth stage offers a recovery code, and the page says Forgot Password is the way out", async ({
      page,
      context,
      baseURL,
    }) => {
      await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
      let fresh = false;
      const mock = await installApiMock(context, {
        me: meFixture({user: {must_reset: true}, security: {totp_enabled: true}}),
        handlers: {
          "POST /account/password": (_c, s) => {
            if (!fresh) return err(403, "reauth_required");
            s.me = {...s.me, user: {...s.me.user, must_reset: false}};
            return {status: 204};
          },
          "POST /auth/reauth": () => {
            fresh = true;
            return {status: 204};
          },
        },
      });
      await gotoForm(page, `/${lang}/change-password`);
      // Before the server asks for a reauth: the hint, and no switch (/account/password takes no recovery code).
      await expect(page.getByText(T("changePassword.lostAuthenticator"), {exact: true})).toBeVisible();
      await expect(page.getByRole("button", {name: T("login.twoFactor.useRecovery")})).toHaveCount(0);

      await field(page, "new_password").fill(STRONG_PASSWORD);
      await field(page, "totp_code").focus();
      await page.keyboard.type("123456");
      await expect(field(page, "reauth_password")).toBeFocused();
      // Now the reauth is what takes the code, and it takes a recovery code in its place.
      await page.getByRole("button", {name: T("login.twoFactor.useRecovery")}).click();
      await expect(field(page, "recovery_code")).toBeFocused();
      await expect(field(page, "totp_code")).toHaveCount(0);
      await field(page, "reauth_password").fill("OneTime-pass-1");
      // A short code is refused before anything is sent.
      await field(page, "recovery_code").fill("ABCD");
      await submit(page).click();
      await expect(page.getByText(T("fields.recovery.required"))).toBeVisible();
      expect(callsTo(mock, "POST", "/auth/reauth")).toHaveLength(0);
      await field(page, "recovery_code").fill("abcd-efgh-2345-6789");
      await submit(page).click();
      await page.waitForURL(`**/${lang}/profiles`);
      expect(lastBody(mock, "POST", "/auth/reauth")).toEqual({password: "OneTime-pass-1", recovery_code: "ABCDEFGH23456789"});
      expect(callsTo(mock, "POST", "/account/password").map((c) => c.body)).toEqual([
        {new_password: STRONG_PASSWORD, totp_code: "123456"},
        {new_password: STRONG_PASSWORD},
      ]);
    });

    test("wp8-r12-2: an account without an authenticator sees neither the hint nor a code field", async ({page, context, baseURL}) => {
      await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
      await installApiMock(context, {me: meFixture({user: {must_reset: true}, security: {totp_enabled: false}}), handlers: {}});
      await gotoForm(page, `/${lang}/change-password`);
      await expect(page.getByText(T("changePassword.lostAuthenticator"), {exact: true})).toHaveCount(0);
      await expect(field(page, "totp_code")).toHaveCount(0);
    });
  });
}
