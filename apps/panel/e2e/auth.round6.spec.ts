import type {Page} from "@playwright/test";
import {otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {
  allowAuthErrors,
  callsTo,
  err,
  field,
  gotoForm,
  inviteInfoFixture,
  lastBody,
  LANGS,
  meReady,
  openAnonymous,
  signedIn,
  submit,
  text,
} from "./auth-support.ts";

// Round 6 of the review of WP8: the sign-in step cannot be left while its call runs, so a late answer never acts
// on a step the visitor moved to (wp8-r6-1); a second invite link pasted during a lookup is not mixed up with the
// first (r6-2); and a shown password stays shown when the form stops at its own check (r6-4).

test.beforeEach(({guard}) => allowAuthErrors(guard));

const PHONE = "09123456789";
const PASSWORD = "correct horse battery";
const OTP_ID = otpChallengeId(11);
const issued = {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 60}};
const INVITE_A = "ABCDEFGHJKMNPQRSTVWX";
const INVITE_B = "BCDEFGHJKMNPQRSTVWXY";

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

for (const {lang, dir} of LANGS) {
  test.describe(`round 6, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);
    const tab = (page: Page, name: "tabPassword" | "tabOtp") => page.getByRole("tab", {name: T(`login.${name}`)});

    // wp8-r6-1: the tab list unmounted the form that had a call running, and the late answer then signed in, or
    // flipped to the second factor, under a visitor who had gone to the other tab.
    test("wp8-r6-1: the SMS tab is off while the password call runs, and the answer lands on the password form", async ({page, context, baseURL}) => {
      const held = gate();
      const sign = signedIn(context, baseURL);
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": async (c, s) => {
          await held.opened;
          return sign(c, s);
        },
        "GET /me": meReady(),
      });
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill(PASSWORD);
      await submit(page).click();
      await expect.poll(() => callsTo(mock, "POST", "/auth/login/password").length).toBe(1);
      await expect(tab(page, "tabOtp")).toHaveAttribute("aria-disabled", "true");
      // A forced click is what a slow hand does between the press and the answer.
      await tab(page, "tabOtp").click({force: true});
      await expect(tab(page, "tabPassword")).toHaveAttribute("aria-selected", "true");
      await expect(field(page, "password")).toBeVisible();
      held.release();
      await page.waitForURL(`**/${lang}/profiles`);
    });

    test("wp8-r6-1: the password tab is off while the SMS request runs, and the code step follows the answer", async ({page, context}) => {
      const held = gate();
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": async () => {
          await held.opened;
          return issued;
        },
      });
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect.poll(() => callsTo(mock, "POST", "/auth/otp/request").length).toBe(1);
      await expect(tab(page, "tabPassword")).toHaveAttribute("aria-disabled", "true");
      await tab(page, "tabPassword").click({force: true});
      await expect(field(page, "phone")).toBeVisible();
      held.release();
      await expect(field(page, "code")).toBeVisible();
    });

    test("wp8-r6-1: the tabs are free again after a failed call, and the passkey button is off while it runs", async ({page, context}) => {
      const held = gate();
      await openAnonymous(
        context,
        {
          "POST /auth/login/password": async () => {
            await held.opened;
            return err(401, "invalid_credentials");
          },
        },
        {passkey_enabled: true},
      );
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill(PASSWORD);
      await submit(page).click();
      const passkey = page.getByRole("button", {name: T("login.passkey")});
      await expect(passkey).toBeDisabled();
      held.release();
      await expect(passkey).toBeEnabled();
      await expect(tab(page, "tabOtp")).not.toHaveAttribute("aria-disabled", "true");
      await tab(page, "tabOtp").click();
      await expect(tab(page, "tabOtp")).toHaveAttribute("aria-selected", "true");
    });

    // The passkey step: Back ends the ceremony, so a prompt that is completed afterwards signs nobody in.
    test("wp8-r6-1: Back to sign in aborts the passkey ceremony", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(
        context,
        {"POST /auth/passkey/login/begin": {body: {ticket: "pk-ticket", options: passkeyOptions(new URL(baseURL!).hostname)}}},
        {passkey_enabled: true},
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
      await gotoForm(page, `/${lang}/login`);
      await page.getByRole("button", {name: T("login.passkey")}).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.passkeyStep.title"));
      await expect.poll(() => callsTo(mock, "POST", "/auth/passkey/login/begin").length).toBe(1);
      await expect.poll(() => page.evaluate(() => (window as unknown as {__pkSignal?: unknown}).__pkSignal != null)).toBe(true);
      await page.getByRole("button", {name: T("login.passkeyStep.back")}).click();
      await expect.poll(() => page.evaluate(() => (window as unknown as {__pkAborted?: boolean}).__pkAborted === true)).toBe(true);
      await expect(field(page, "password")).toBeVisible();
      // The abort is the visitor's own doing: it is not an error to show.
      await expect(page.locator(".alert")).toHaveCount(0);
      expect(callsTo(mock, "POST", "/auth/passkey/login/finish")).toHaveLength(0);
    });

    // wp8-r6-2: a second link pasted while the first lookup runs.
    test("wp8-r6-2: a second invite link during the first lookup is the one that is shown and sent", async ({page, context}) => {
      const first = gate();
      const mock = await openAnonymous(context, {
        "POST /auth/invites/lookup": async (c) => {
          const token = (c.body as {token: string}).token;
          if (token === INVITE_A) {
            await first.opened;
            return {body: {...inviteInfoFixture(), phone_masked: "0912***1111"}};
          }
          return {body: {...inviteInfoFixture(), phone_masked: "0912***2222"}};
        },
        "POST /auth/otp/request": issued,
      });
      await page.goto(`/${lang}/invite#${INVITE_A}`);
      await expect.poll(() => callsTo(mock, "POST", "/auth/invites/lookup").length).toBe(1);
      await page.evaluate((code) => {
        location.hash = `#${code}`;
      }, INVITE_B);
      await expect.poll(() => callsTo(mock, "POST", "/auth/invites/lookup").length).toBe(2);
      await expect(page.locator("bdi", {hasText: "0912***2222"})).toBeVisible();
      // The first answer arrives late and changes nothing.
      first.release();
      await page.waitForTimeout(300);
      await expect(page.locator("bdi", {hasText: "0912***1111"})).toHaveCount(0);
      await expect(page.locator("bdi", {hasText: "0912***2222"})).toBeVisible();
      await submit(page).click();
      expect(lastBody(mock, "POST", "/auth/otp/request")).toEqual({purpose: "invite", invite_token: INVITE_B, locale: lang});
    });

    test("wp8-r6-2: the first lookup answered before the second link keeps working as before", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": {body: inviteInfoFixture()}});
      await page.goto(`/${lang}/invite#${INVITE_A}`);
      await expect(page.locator("bdi", {hasText: "+98912***4567"})).toBeVisible();
      await page.evaluate((code) => {
        location.hash = `#${code}`;
      }, INVITE_B);
      await expect.poll(() => callsTo(mock, "POST", "/auth/invites/lookup").length).toBe(2);
      await expect(page.locator("bdi", {hasText: "+98912***4567"})).toBeVisible();
    });

    // wp8-r6-4: the submit event is not what hides a shown password; sending is.
    test("wp8-r6-4: Enter that stops at an empty phone keeps a shown password shown, and sending hides it", async ({page, context}) => {
      const held = gate();
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": async () => {
          await held.opened;
          return err(503, "service_unavailable");
        },
      });
      await gotoForm(page, `/${lang}/login`);
      await field(page, "password").fill(PASSWORD);
      await page.getByRole("button", {name: T("fields.password.showLabel")}).click();
      await expect(field(page, "password")).toHaveAttribute("type", "text");
      await field(page, "password").press("Enter");
      await expect(field(page, "phone")).toHaveAttribute("aria-invalid", "true");
      expect(callsTo(mock, "POST", "/auth/login/password")).toHaveLength(0);
      await expect(field(page, "password")).toHaveAttribute("type", "text");
      await expect(page.getByRole("button", {name: T("fields.password.hideLabel")})).toBeVisible();
      // Now a send: hidden before the answer.
      await field(page, "phone").fill(PHONE);
      await field(page, "password").press("Enter");
      await expect.poll(() => callsTo(mock, "POST", "/auth/login/password").length).toBe(1);
      await expect(field(page, "password")).toHaveAttribute("type", "password");
      held.release();
      await expect(page.locator(".alert")).toHaveCount(1);
      await expect(field(page, "password")).toHaveAttribute("type", "password");
    });
  });
}
