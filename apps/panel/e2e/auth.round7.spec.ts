import type {Page} from "@playwright/test";
import {otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {
  allowAuthErrors,
  callsTo,
  err,
  field,
  gotoForm,
  LANGS,
  meReady,
  openAnonymous,
  signedIn,
  submit,
  text,
  typeWhenFocused,
} from "./auth-support.ts";

// Round 7 of the review of WP8: a sign-in call that is still running when the visitor leaves the page never acts
// on the page they chose (wp8-r7-3, r7-7), and a passkey prompt does not outlive its step (r7-6). Also the
// suspended notice on the two steps that had only a unit test (r7-1).

test.beforeEach(({guard}) => allowAuthErrors(guard));

const PHONE = "09123456789";
const PASSWORD = "correct horse battery";
const OTP_ID = otpChallengeId(12);
const issued = {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 60}};

/** A gate a handler waits on, opened by `release`. */
function gate() {
  let release!: () => void;
  const opened = new Promise<void>((resolve) => {
    release = resolve;
  });
  return {opened, release};
}

const passkeyOptions = (rpId: string) => ({
  publicKey: {challenge: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", rpId, timeout: 60000, userVerification: "preferred"},
});

async function fillPassword(page: Page) {
  await field(page, "phone").fill(PHONE);
  await field(page, "password").fill(PASSWORD);
}

for (const {lang, dir} of LANGS) {
  test.describe(`round 7, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);
    const link = (page: Page, key: string) => page.getByText(T(key), {exact: true});

    // wp8-r7-1: account_suspended on the SMS code and the second factor, in place, as on the password step.
    test("wp8-r7-1: account_suspended from the SMS code is explained on the login page", async ({page, context}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/login/otp": err(403, "account_suspended"),
        "POST /auth/refresh": err(401, "session_expired"),
      });
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await typeWhenFocused(page, "123456");
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("suspended.title"));
      await expect(page.getByText(T("suspended.text"))).toBeVisible();
      expect(new URL(page.url()).pathname).toBe(`/${lang}/login`);
      expect(callsTo(mock, "GET", "/me")).toHaveLength(0);
      await page.getByRole("button", {name: T("suspended.back")}).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.title"));
    });

    test("wp8-r7-1: account_suspended from the second factor is explained on the login page", async ({page, context}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": {body: {status: "mfa_required", ticket: "t", methods: ["totp"]}},
        "POST /auth/login/totp": err(403, "account_suspended"),
        "POST /auth/refresh": err(401, "session_expired"),
      });
      await gotoForm(page, `/${lang}/login`);
      await fillPassword(page);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.twoFactor.title"));
      await typeWhenFocused(page, "123456");
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("suspended.title"));
      expect(new URL(page.url()).pathname).toBe(`/${lang}/login`);
      expect(callsTo(mock, "GET", "/me")).toHaveLength(0);
      await page.getByRole("button", {name: T("suspended.back")}).click();
      await expect(field(page, "password")).toBeVisible();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.title"));
    });

    // wp8-r7-3 and r7-7: the links under the form are off while a call runs, like the tabs.
    test("wp8-r7-3: the links under the form are off while the password call runs, and the answer lands on /profiles", async ({page, context, baseURL}) => {
      const held = gate();
      const sign = signedIn(context, baseURL);
      const mock = await openAnonymous(
        context,
        {
          "POST /auth/login/password": async (c, s) => {
            await held.opened;
            return sign(c, s);
          },
          "GET /me": meReady(),
        },
        {registration_mode: "open"},
      );
      await gotoForm(page, `/${lang}/login`);
      await fillPassword(page);
      await submit(page).click();
      await expect.poll(() => callsTo(mock, "POST", "/auth/login/password").length).toBe(1);
      for (const key of ["login.forgot", "login.register"]) {
        await expect(link(page, key)).toHaveAttribute("aria-disabled", "true");
        // A forced click is what a slow hand does between the press and the answer.
        await link(page, key).click({force: true});
        expect(new URL(page.url()).pathname).toBe(`/${lang}/login`);
        await expect(field(page, "password")).toBeVisible();
      }
      held.release();
      await page.waitForURL(`**/${lang}/profiles`);
      expect(callsTo(mock, "POST", "/auth/logout")).toHaveLength(0);
    });

    test("wp8-r7-3: the invite link is off too, and all links are back after a failed call", async ({page, context}) => {
      const held = gate();
      await openAnonymous(
        context,
        {
          "POST /auth/login/password": async () => {
            await held.opened;
            return err(401, "invalid_credentials");
          },
        },
        {registration_mode: "invite"},
      );
      await gotoForm(page, `/${lang}/login`);
      await fillPassword(page);
      await submit(page).click();
      await expect(link(page, "login.invite")).toHaveAttribute("aria-disabled", "true");
      held.release();
      await expect(link(page, "login.invite")).not.toHaveAttribute("aria-disabled", "true");
      await expect(link(page, "login.forgot")).not.toHaveAttribute("aria-disabled", "true");
      await link(page, "login.invite").click();
      await page.waitForURL(`**/${lang}/invite`);
    });

    // The answer of a call whose page has gone: the visitor left by the browser's Back, which nothing can disable.
    test("wp8-r7-3: a sign-in answer that arrives after the visitor left ends the session and moves nobody", async ({page, context, baseURL}) => {
      const held = gate();
      const sign = signedIn(context, baseURL);
      const mock = await openAnonymous(
        context,
        {
          "POST /auth/login/password": async (c, s) => {
            await held.opened;
            return sign(c, s);
          },
          "POST /auth/logout": {status: 204},
          "GET /me": meReady(),
        },
        {registration_mode: "open"},
      );
      await gotoForm(page, `/${lang}/register`);
      // A client-side move, so that Back is one too and the sign-in form is unmounted without a page load.
      await page.getByRole("link", {name: T("register.signIn")}).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.title"));
      await expect(submit(page)).toBeEnabled();
      await fillPassword(page);
      await submit(page).click();
      await expect.poll(() => callsTo(mock, "POST", "/auth/login/password").length).toBe(1);
      await page.goBack();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("register.title"));
      held.release();
      // The session the call opened is ended, since the page that asked for it cannot show it.
      await expect.poll(() => callsTo(mock, "POST", "/auth/logout").length).toBe(1);
      await page.waitForTimeout(300);
      expect(new URL(page.url()).pathname).toBe(`/${lang}/register`);
    });

    // wp8-r7-3, second part: the ticket ends while a code is on its way.
    test("wp8-r7-3: the second factor is not left under a code that is on its way, when the ticket ends", async ({page, context, baseURL}) => {
      await page.clock.install();
      const held = gate();
      const sign = signedIn(context, baseURL);
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": {body: {status: "mfa_required", ticket: "t", ticket_expires_in_s: 20, methods: ["totp"]}},
        "POST /auth/login/totp": async (c, s) => {
          await held.opened;
          return sign(c, s);
        },
        "GET /me": meReady(),
      });
      await gotoForm(page, `/${lang}/login`);
      await fillPassword(page);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.twoFactor.title"));
      await typeWhenFocused(page, "123456");
      await expect.poll(() => callsTo(mock, "POST", "/auth/login/totp").length).toBe(1);
      await page.clock.fastForward(21_000);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.twoFactor.title"));
      held.release();
      await page.waitForURL(`**/${lang}/profiles`);
    });

    test("wp8-r7-3: when that code is refused, the page starts over at once, with the ticket notice", async ({page, context}) => {
      await page.clock.install();
      const held = gate();
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": {body: {status: "mfa_required", ticket: "t", ticket_expires_in_s: 20, methods: ["totp"]}},
        "POST /auth/login/totp": async () => {
          await held.opened;
          return err(401, "totp_invalid");
        },
      });
      await gotoForm(page, `/${lang}/login`);
      await fillPassword(page);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.twoFactor.title"));
      await typeWhenFocused(page, "123456");
      await expect.poll(() => callsTo(mock, "POST", "/auth/login/totp").length).toBe(1);
      await page.clock.fastForward(21_000);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.twoFactor.title"));
      held.release();
      await expect(field(page, "password")).toBeVisible();
      await expect(page.locator(".alert")).toBeVisible();
    });

    // wp8-r7-6: the passkey prompt is aborted when the step is left by any way, not only by its Back button.
    test("wp8-r7-6: the Forgot Password link is off while the prompt is open, and leaving by Back aborts the ceremony", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(
        context,
        {"POST /auth/passkey/login/begin": {body: {ticket: "pk-ticket", options: passkeyOptions(new URL(baseURL!).hostname)}}},
        {passkey_enabled: true, registration_mode: "open"},
      );
      await page.addInitScript(() => {
        const mark = window as unknown as {__pkSignal?: AbortSignal | null; __pkAborted?: boolean};
        // The prompt stays open until it is aborted, as a browser's does while the visitor decides.
        navigator.credentials.get = (options) =>
          new Promise((_, reject) => {
            mark.__pkSignal = options?.signal ?? null;
            options?.signal?.addEventListener("abort", () => {
              mark.__pkAborted = true;
              reject(new DOMException("aborted", "AbortError"));
            });
          });
      });
      await gotoForm(page, `/${lang}/register`);
      await page.getByRole("link", {name: T("register.signIn")}).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.title"));
      await page.getByRole("button", {name: T("login.passkey")}).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.passkeyStep.title"));
      await expect.poll(() => page.evaluate(() => (window as unknown as {__pkSignal?: unknown}).__pkSignal != null)).toBe(true);
      await expect(link(page, "login.forgot")).toHaveAttribute("aria-disabled", "true");
      await link(page, "login.forgot").click({force: true});
      expect(new URL(page.url()).pathname).toBe(`/${lang}/login`);
      // The browser's Back is not something the page can disable: the step unmounts, and the prompt must go.
      await page.goBack();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("register.title"));
      await expect.poll(() => page.evaluate(() => (window as unknown as {__pkAborted?: boolean}).__pkAborted === true)).toBe(true);
      expect(callsTo(mock, "POST", "/auth/passkey/login/finish")).toHaveLength(0);
    });
  });
}
