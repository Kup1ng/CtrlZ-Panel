import type {Page} from "@playwright/test";
import {otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {
  allowAuthErrors,
  callsTo,
  err,
  field,
  formAlert,
  gotoForm,
  inviteInfoFixture,
  LANGS,
  liveRegionsInsertedWithText,
  openAnonymous,
  submit,
  text,
  watchLiveRegions,
} from "./auth-support.ts";

// Round 1 of the review of WP8 (wp8-r1-4 to r1-8): where the focus goes when a step is left, whether the
// notice of the step we came back to is announced, the stale notice of Register, the invite link that carries
// no code, what the sixth digit does during a wait or offline, and the passkey step's Forgot Password link.
// Each test names the finding it holds.

test.beforeEach(({guard}) => allowAuthErrors(guard));

const PHONE = "09123456789";
const OTP_ID = otpChallengeId(14);
const issued = {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 60}};
const mfa = {body: {status: "mfa_required", ticket: "t", ticket_expires_in_s: 300, methods: ["totp"]}};
const CODE = "ABCDEFGHJKMNPQRSTVWX";

const options = (rpId: string) => ({
  publicKey: {challenge: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", rpId, timeout: 60000, userVerification: "preferred"},
});

/**
 * Types into whatever has the focus: the OTP slots take it from the page's own focus. It waits for a field to
 * have it first: a key typed before the new step has put the focus on its field goes nowhere, and a test that
 * relied on the race failed one run in the full suite (wp8-r4, found with the regression run of r4-2).
 */
async function typeCode(page: Page, code = "123456") {
  await expect(page.locator("form input:focus")).toHaveCount(1);
  await page.keyboard.type(code);
}

for (const {lang, dir} of LANGS) {
  test.describe(`states after going back, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);
    const EXPIRED = lang === "fa" ? "منقضی" : "expired";

    test("wp8-r1-4: an expired SMS code returns to the number with the focus on it, and the notice reaches a live region that was already there", async ({page, context}) => {
      await watchLiveRegions(page);
      await openAnonymous(context, {"POST /auth/otp/request": issued, "POST /auth/login/otp": err(401, "otp_expired")});
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeCode(page);
      await expect(formAlert(page)).toContainText(EXPIRED);
      await expect(field(page, "phone")).toBeFocused();
      expect(await liveRegionsInsertedWithText(page)).toEqual([]);
    });

    test("wp8-r1-4: Use a different number returns to the number with the focus on it", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/otp/request": issued});
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.getByRole("button", {name: T("login.otpCode.change")}).click();
      await expect(field(page, "phone")).toBeFocused();
      await expect(field(page, "phone")).toHaveValue(PHONE);
    });

    test("wp8-r1-4: a ticket that ended returns to the password with the focus on it, notice announced", async ({page, context}) => {
      await watchLiveRegions(page);
      await openAnonymous(context, {"POST /auth/login/password": mfa, "POST /auth/login/totp": err(401, "ticket_invalid")});
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill("x");
      await submit(page).click();
      await typeCode(page);
      await expect(formAlert(page)).toContainText(EXPIRED);
      await expect(field(page, "password")).toBeFocused();
      expect(await liveRegionsInsertedWithText(page)).toEqual([]);
    });

    test("wp8-r1-4: the Back button of the second factor returns to the password with the focus on it", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/login/password": mfa});
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill("x");
      await submit(page).click();
      await expect(field(page, "totp_code")).toBeFocused();
      await page.getByRole("button", {name: T("login.twoFactor.back")}).click();
      await expect(field(page, "password")).toBeFocused();
    });

    test("wp8-r1-4: Back to sign in from the passkey prompt returns with the focus on the password", async ({page, context, baseURL}) => {
      await openAnonymous(
        context,
        {
          "POST /auth/login/password": {body: {status: "passkey_required"}},
          "POST /auth/passkey/login/begin": {body: {ticket: "pk", options: options(new URL(baseURL!).hostname)}},
        },
        {passkey_enabled: true},
      );
      // The prompt is closed: the step stays, silent, with Back and Try again.
      await page.addInitScript(() => {
        navigator.credentials.get = () => Promise.reject(new DOMException("closed", "NotAllowedError"));
      });
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill("x");
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.passkeyStep.title"));
      await page.getByRole("button", {name: T("login.passkeyStep.back")}).click();
      await expect(field(page, "password")).toBeFocused();
    });

    test("wp8-r1-8: the passkey prompt offers Forgot Password only while SMS works", async ({page, context, baseURL}) => {
      for (const sms of [true, false]) {
        await openAnonymous(
          context,
          {"POST /auth/passkey/login/begin": {body: {ticket: "pk", options: options(new URL(baseURL!).hostname)}}},
          {passkey_enabled: true, sms_available: sms},
        );
        await page.addInitScript(() => {
          navigator.credentials.get = () => Promise.reject(new DOMException("closed", "NotAllowedError"));
        });
        await gotoForm(page, `/${lang}/login`);
        await page.getByRole("button", {name: T("login.passkey")}).click();
        await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.passkeyStep.title"));
        await expect(page.getByRole("link", {name: T("login.forgot")})).toHaveCount(sms ? 1 : 0);
      }
    });

    test("wp8-r1-4 and wp8-r1-6: Register's expired-code notice is announced, goes when the number is edited, and does not come back", async ({page, context}) => {
      await watchLiveRegions(page);
      await openAnonymous(
        context,
        {"POST /auth/otp/request": issued, "POST /auth/register": err(401, "otp_expired")},
        {registration_mode: "open"},
      );
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await typeCode(page);
      await expect(field(page, "password")).toBeFocused();
      await submit(page).click();
      // Back on the number step: the focus is on it and the notice is in a region that was there before it.
      await expect(formAlert(page)).toContainText(EXPIRED);
      await expect(field(page, "phone")).toBeFocused();
      expect(await liveRegionsInsertedWithText(page)).toEqual([]);

      // Sending the number again clears it at once, and it does not return when the code step is left.
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.getByRole("button", {name: T("register.change")}).click();
      await expect(field(page, "phone")).toBeFocused();
      await expect(formAlert(page)).toHaveCount(0);
    });

    test("wp8-r1-6: editing the number drops the notice", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/otp/request": issued, "POST /auth/register": err(401, "otp_expired")}, {registration_mode: "open"});
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeCode(page);
      await submit(page).click();
      await expect(formAlert(page)).toContainText(EXPIRED);
      await field(page, "phone").press("Backspace");
      await expect(formAlert(page)).toHaveCount(0);
    });

    test("wp8-r1-4: the invite step after an expired code has the focus on its heading and shows the notice", async ({page, context}) => {
      await watchLiveRegions(page);
      await openAnonymous(context, {
        "POST /auth/invites/lookup": {body: inviteInfoFixture()},
        "POST /auth/otp/request": issued,
        "POST /auth/register": err(401, "otp_expired"),
      });
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(submit(page)).toBeEnabled();
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await typeCode(page);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.lookupTitle"));
      await expect(page.getByRole("heading", {level: 1})).toBeFocused();
      await expect(formAlert(page)).toContainText(EXPIRED);
      expect(await liveRegionsInsertedWithText(page)).toEqual([]);
    });

    test("wp8-r1-4: Forgot Password starts again at the number with the focus on it after an expired code", async ({page, context}) => {
      await watchLiveRegions(page);
      await openAnonymous(context, {"POST /auth/otp/request": issued, "POST /auth/password/reset/verify": err(401, "otp_expired")});
      await gotoForm(page, `/${lang}/forgot-password`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeCode(page);
      await expect(formAlert(page)).toContainText(EXPIRED);
      await expect(field(page, "phone")).toBeFocused();
      expect(await liveRegionsInsertedWithText(page)).toEqual([]);
    });

    test("the probe itself: a region inserted with its text is reported", async ({page, context}) => {
      await watchLiveRegions(page);
      await openAnonymous(context);
      await gotoForm(page, `/${lang}/login`);
      await page.evaluate(() => {
        const region = document.createElement("div");
        region.setAttribute("aria-live", "polite");
        const alert = document.createElement("div");
        alert.className = "alert";
        region.append(alert);
        document.body.appendChild(region);
      });
      expect((await liveRegionsInsertedWithText(page)).length).toBe(1);
    });
  });

  test.describe(`invite link without a code, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    test("wp8-r1-5: a fragment of punctuation asks for the code by hand and the page does not wait", async ({page, context}) => {
      const mock = await openAnonymous(context);
      await page.goto(`/${lang}/invite#---`);
      await expect(field(page, "token")).toBeVisible();
      await expect(page.locator('[aria-busy="true"]')).toHaveCount(0);
      expect(new URL(page.url()).hash).toBe("");
      expect(callsTo(mock, "POST", "/auth/invites/lookup")).toHaveLength(0);
    });

    test("wp8-r1-5: a hashchange to such a fragment, and then to a real code, is read each time", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": {body: inviteInfoFixture()}});
      await page.goto(`/${lang}/invite`);
      await expect(field(page, "token")).toBeVisible();
      await page.evaluate(() => {
        location.hash = "#---";
      });
      await expect(field(page, "token")).toBeVisible();
      await expect(page.locator('[aria-busy="true"]')).toHaveCount(0);
      await page.evaluate((code) => {
        location.hash = `#${code}`;
      }, CODE);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.lookupTitle"));
      expect(callsTo(mock, "POST", "/auth/invites/lookup")).toHaveLength(1);
    });
  });

  test.describe(`the wait and offline, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});

    async function toCodeWith429(page: Page, context: Parameters<typeof openAnonymous>[0]) {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/login/otp": err(429, "too_many_attempts", {retry_after_s: 60}),
      });
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeCode(page);
      await expect(submit(page)).toBeDisabled();
      expect(callsTo(mock, "POST", "/auth/login/otp")).toHaveLength(1);
      return mock;
    }

    test("wp8-r1-7: retyping the sixth digit during a 429 wait sends nothing", async ({page, context}) => {
      const mock = await toCodeWith429(page, context);
      await field(page, "code").focus();
      await page.keyboard.press("End");
      await page.keyboard.press("Backspace");
      await page.keyboard.type("6");
      // Give a wrong submit the time it would need to reach the mock.
      await page.waitForTimeout(500);
      expect(callsTo(mock, "POST", "/auth/login/otp")).toHaveLength(1);
      await expect(submit(page)).toBeDisabled();
    });

    test("wp8-r1-7: Retry of a busy server waits out retry_after_s too", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/login/password": err(503, "server_busy", {retry_after_s: 60})});
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill("x");
      await submit(page).click();
      const retry = formAlert(page).getByRole("button");
      await expect(retry).toBeVisible();
      await expect(retry).toBeDisabled();
      expect(callsTo(mock, "POST", "/auth/login/password")).toHaveLength(1);
    });

    test("wp8-r1-7: offline, the sixth digit does not start a request", async ({page, context, guard}) => {
      // The browser may ask for the tab icon again while it is offline; that is not a request of the page.
      guard.allowConsole(/ERR_INTERNET_DISCONNECTED/);
      const mock = await openAnonymous(context, {"POST /auth/otp/request": issued, "POST /auth/login/otp": err(401, "otp_invalid")});
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      const failed: string[] = [];
      page.on("requestfailed", (r) => failed.push(r.url()));
      await context.setOffline(true);
      await expect(submit(page)).toBeDisabled();
      await typeCode(page);
      await page.waitForTimeout(500);
      // Nothing is pending and nothing failed: no spinner on the button, no error line.
      await expect(formAlert(page)).toHaveCount(0);
      await context.setOffline(false);
      expect(failed.filter((url) => url.includes("/api/"))).toEqual([]);
      expect(callsTo(mock, "POST", "/auth/login/otp")).toHaveLength(0);
    });
  });

  test.describe(`login tabs by keyboard, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    test("wp8-r1-9: the arrow that points to the next tab follows the direction of the page", async ({page, context}) => {
      await openAnonymous(context);
      await gotoForm(page, `/${lang}/login`);
      const password = page.getByRole("tab", {name: T("login.tabPassword")});
      const sms = page.getByRole("tab", {name: T("login.tabOtp")});
      // In Persian the list runs right to left, so the second tab is to the left of the first.
      const forward = dir === "rtl" ? "ArrowLeft" : "ArrowRight";
      const backward = dir === "rtl" ? "ArrowRight" : "ArrowLeft";
      await password.focus();
      await page.keyboard.press(forward);
      await expect(sms).toHaveAttribute("aria-selected", "true");
      await expect(sms).toBeFocused();
      await page.keyboard.press(backward);
      await expect(password).toHaveAttribute("aria-selected", "true");
    });
  });
}

// wp8-r21-1. /auth/config cannot be read (the first answer and its retries fail): the card shows the 503 with Retry,
// and it must still lead to the sign-in page like every other gated state, so a flaky API is not a dead end.
for (const {lang, dir} of LANGS) {
  test.describe(`failed /auth/config, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    for (const [path, key] of [
      ["register", "register.signIn"],
      ["forgot-password", "forgot.back"],
    ] as const) {
      test(`wp8-r21-1: /${path} with /auth/config failing keeps a way to sign in`, async ({page, context}) => {
        await page.clock.install();
        let asked = 0;
        await openAnonymous(context, {
          "GET /auth/config": () => {
            asked += 1;
            return err(503, "service_unavailable");
          },
        });
        await page.goto(`/${lang}/${path}`);
        // The client's retries wait 1 s and 2 s on the page's clock.
        await expect
          .poll(async () => {
            await page.clock.fastForward(2_500);
            return asked;
          })
          .toBeGreaterThanOrEqual(3);
        await expect(formAlert(page)).toBeVisible();
        const link = page.getByRole("link", {name: T(key)});
        await expect(link).toBeVisible();
        await expect(link).toHaveAttribute("href", /\/login/);
      });
    }
  });
}
