import {meFixture, otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
import {installApiMock} from "@ctrlz/api-client/testing/mock.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {
  allowAuthErrors,
  callsTo,
  err,
  errorText,
  field,
  gotoForm,
  LANGS,
  openAnonymous,
  STRONG_PASSWORD,
  submit,
  text,
} from "./auth-support.ts";

// Round 24 of the review of WP8: the API answers a wrong recovery code with the authenticator's `totp_invalid`, and
// the line under the recovery-code field must not name an app the visitor no longer has (wp8-r24-1). The line of a
// wrong authenticator code is unchanged. The Forgot Password passkey line is asserted in forgot.spec.ts.

test.beforeEach(({guard}) => allowAuthErrors(guard));

const PHONE = "09123456789";
const OTP_ID = otpChallengeId(7);
const RECOVERY = "ABCD-EFGH-JKMN-PQRS";

for (const {lang, dir} of LANGS) {
  test.describe(`round 24, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);


    test("wp8-r24-1: login 2FA, a wrong recovery code has its own line and a wrong app code keeps the old one", async ({page, context}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": {body: {status: "mfa_required", ticket: "t-24", ticket_expires_in_s: 300, methods: ["totp", "recovery_code"]}},
        "POST /auth/login/totp": err(401, "totp_invalid"),
      });
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill(STRONG_PASSWORD);
      await submit(page).click();
      await expect(field(page, "totp_code")).toBeFocused();
      await page.keyboard.type("123456");
      await expect(page.getByText(errorText(lang, "totp_invalid"), {exact: true})).toBeVisible();

      await page.getByRole("button", {name: T("login.twoFactor.useRecovery")}).click();
      await field(page, "recovery_code").fill(RECOVERY);
      await field(page, "recovery_code").press("Enter");
      await expect.poll(() => callsTo(mock, "POST", "/auth/login/totp").length).toBe(2);
      await expect(page.getByText(T("fields.recovery.invalid"), {exact: true})).toBeVisible();
      await expect(page.getByText(errorText(lang, "totp_invalid"), {exact: true})).toHaveCount(0);
    });

    test("wp8-r24-1: Forgot Password step 3, a wrong recovery code has its own line", async ({page, context}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 60}},
        "POST /auth/password/reset/verify": {body: {ticket: "reset-ticket-24", second_factor: "totp"}},
        "POST /auth/password/reset/complete": err(401, "totp_invalid"),
      });
      await gotoForm(page, `/${lang}/forgot-password`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("123456");
      await field(page, "new_password").fill(STRONG_PASSWORD);
      await page.getByRole("button", {name: T("login.twoFactor.useRecovery")}).click();
      await field(page, "recovery_code").fill(RECOVERY);
      await submit(page).click();
      await expect.poll(() => callsTo(mock, "POST", "/auth/password/reset/complete").length).toBe(1);
      await expect(page.getByText(T("fields.recovery.invalid"), {exact: true})).toBeVisible();
      await expect(page.getByText(errorText(lang, "totp_invalid"), {exact: true})).toHaveCount(0);
    });

    test("wp8-r24-1: forced change, a wrong recovery code and a wrong current password each have their own line", async ({
      page,
      context,
      baseURL,
    }) => {
      await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
      const mock = await installApiMock(context, {
        me: meFixture({user: {must_reset: true}, security: {totp_enabled: true}}),
        handlers: {
          "POST /account/password": err(403, "reauth_required"),
          "POST /auth/reauth": (call) => {
            const body = call.body as {password?: string; recovery_code?: string};
            return body.password === "wrong-current-1" ? err(401, "invalid_credentials") : err(401, "totp_invalid");
          },
        },
      });
      await gotoForm(page, `/${lang}/change-password`);
      await field(page, "new_password").fill(STRONG_PASSWORD);
      await field(page, "totp_code").focus();
      await page.keyboard.type("123456");
      await expect(field(page, "reauth_password")).toBeFocused();
      await page.getByRole("button", {name: T("login.twoFactor.useRecovery")}).click();
      await field(page, "reauth_password").fill("OneTime-pass-1");
      await field(page, "recovery_code").fill("abcd-efgh-2345-6789");
      await submit(page).click();
      await expect.poll(() => callsTo(mock, "POST", "/auth/reauth").length).toBe(1);
      await expect(page.getByText(T("fields.recovery.invalid"), {exact: true})).toBeVisible();

      await field(page, "reauth_password").fill("wrong-current-1");
      await field(page, "recovery_code").fill("abcd-efgh-2345-6789");
      await submit(page).click();
      await expect.poll(() => callsTo(mock, "POST", "/auth/reauth").length).toBe(2);
      await expect(page.getByText(T("changePassword.reauth.invalid"), {exact: true})).toBeVisible();
    });
  });
}
