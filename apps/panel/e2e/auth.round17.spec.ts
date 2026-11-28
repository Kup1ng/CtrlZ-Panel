import {meFixture, publicConfigFixture, otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
import {installApiMock} from "@ctrlz/api-client/testing/mock.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {
  INVITE_TOKEN,
  allowAuthErrors,
  callsTo,
  err,
  errorText,
  field,
  formAlert,
  gotoForm,
  inviteInfoFixture,
  lastBody,
  LANGS,
  openAnonymous,
  STRONG_PASSWORD,
  submit,
  text,
} from "./auth-support.ts";

// Round 17 of the review of WP8: a typed authenticator code goes out as ASCII digits on the sign-in and on Forgot
// Password (wp8-r17-1), `sms_unavailable` gives each flow its own advice (r17-2), the waiting screens say they wait
// and are not silent offline (r17-3, r17-4), and the two forms that set a new password name the account for the
// password manager (r17-5).

test.beforeEach(({guard}) => allowAuthErrors(guard));

const PHONE = "09123456789";
const OTP_ID = otpChallengeId(5);
const CODE = INVITE_TOKEN;
const issued = {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 1}};

function gate() {
  let release!: () => void;
  const opened = new Promise<void>((resolve) => {
    release = resolve;
  });
  return {opened, release};
}

for (const {lang, dir} of LANGS) {
  test.describe(`round 17, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    // wp8-r17-1: Persian digits typed into the authenticator code slots reach the server as ASCII, on the login page
    // and in step 3 of Forgot Password (the unit test pins every route of authApi; these two prove the screens use it).
    test("wp8-r17-1: a Persian-digit authenticator code is sent as ASCII on the login page", async ({page, context}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": {body: {status: "mfa_required", ticket: "mfa-ticket-17", ticket_expires_in_s: 300, methods: ["totp"]}},
        "POST /auth/login/totp": err(401, "totp_invalid"),
      });
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill(STRONG_PASSWORD);
      await submit(page).click();
      await expect(field(page, "totp_code")).toBeFocused();
      await page.keyboard.type("۱۲۳۴۵۶");
      await expect.poll(() => callsTo(mock, "POST", "/auth/login/totp").length).toBe(1);
      expect(lastBody(mock, "POST", "/auth/login/totp")).toEqual({ticket: "mfa-ticket-17", totp_code: "123456"});
    });

    test("wp8-r17-1: a Persian-digit authenticator code is sent as ASCII in Forgot Password step 3", async ({page, context}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": {body: {ticket: "reset-ticket-17", second_factor: "totp"}},
        "POST /auth/password/reset/complete": err(401, "totp_invalid"),
      });
      await gotoForm(page, `/${lang}/forgot-password`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("۱۲۳۴۵۶");
      await field(page, "new_password").fill(STRONG_PASSWORD);
      await field(page, "totp_code").focus();
      await page.keyboard.type("۶۵۴۳۲۱");
      await expect.poll(() => callsTo(mock, "POST", "/auth/password/reset/complete").length).toBe(1);
      expect(lastBody(mock, "POST", "/auth/password/reset/complete")).toEqual({
        ticket: "reset-ticket-17",
        new_password: STRONG_PASSWORD,
        totp_code: "654321",
      });
    });

    // wp8-r17-2: a runtime `sms_unavailable` is worded by the flow. The generic line says to sign in with a password,
    // which a visitor who forgot it, has no account or has no password yet cannot do.
    test("wp8-r17-2: Forgot Password says to contact the administrator", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/otp/request": err(503, "sms_unavailable")});
      await gotoForm(page, `/${lang}/forgot-password`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(formAlert(page)).toHaveText(T("forgot.unavailableText"));
      expect(errorText(lang, "sms_unavailable")).not.toBe(T("forgot.unavailableText"));
    });

    test("wp8-r17-2: Register says to try again later", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/otp/request": err(503, "sms_unavailable")}, {registration_mode: "open"});
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(formAlert(page)).toHaveText(T("register.smsDown"));
    });

    test("wp8-r17-2: the invite says to ask the administrator", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/invites/lookup": {body: inviteInfoFixture()}, "POST /auth/otp/request": err(503, "sms_unavailable")});
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(submit(page)).toBeEnabled();
      await submit(page).click();
      await expect(formAlert(page)).toHaveText(T("invite.smsDown"));
    });

    // A failed Resend of a code step is the other place the API can find out first. The visitor holds a valid code there, so
    // the line is resend.smsDown (the code you have still works), not the flow's advice for a first send (wp8-r18-2).
    test("wp8-r18-2: a failed Resend on Forgot Password, Register and the Login SMS code says the code still works", async ({
      page,
      context,
    }) => {
      let calls = 0;
      const resendFails = () => (++calls === 1 ? issued : err(503, "sms_unavailable"));
      await openAnonymous(context, {"POST /auth/otp/request": resendFails}, {registration_mode: "open"});
      await gotoForm(page, `/${lang}/forgot-password`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.getByRole("button", {name: T("resend.action")}).click();
      await expect(formAlert(page)).toHaveText(T("resend.smsDown"));

      calls = 0;
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.getByRole("button", {name: T("resend.action")}).click();
      await expect(page.locator(".alert--danger")).toHaveText(T("resend.smsDown"));

      calls = 0;
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.getByRole("button", {name: T("resend.action")}).click();
      // The Login SMS code step is a code step too: the code held still works and an OTP-only account has no password (wp8-r19-1).
      await expect(formAlert(page)).toHaveText(T("resend.smsDown"));
      expect(T("resend.smsDown")).not.toBe(errorText(lang, "sms_unavailable"));
    });

    test("wp8-r18-2: a failed Resend on the invite confirm step does not tell the visitor to give up the invite", async ({page, context}) => {
      let calls = 0;
      await openAnonymous(context, {
        "POST /auth/invites/lookup": {body: inviteInfoFixture()},
        "POST /auth/otp/request": () => (++calls === 1 ? issued : err(503, "sms_unavailable")),
      });
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(submit(page)).toBeEnabled();
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.getByRole("button", {name: T("resend.action")}).click();
      await expect(page.locator(".alert--danger")).toHaveText(T("resend.smsDown"));
      expect(T("resend.smsDown")).not.toBe(T("invite.smsDown"));
    });

    // wp8-r17-3, r17-4: the screens that wait for an answer say so to a screen reader, and offline they say that too
    // (the paused request never fails) and give a way back to sign in.
    for (const path of ["register", "forgot-password"] as const) {
      test(`wp8-r17-3/4: /${path} while /auth/config is awaited has a busy status, a sign-in link, and says when offline`, async ({page, context}) => {
        const held = gate();
        let asked = 0;
        await openAnonymous(context, {
          "GET /auth/config": async () => {
            asked += 1;
            await held.opened;
            return {body: publicConfigFixture({registration_mode: "open"})};
          },
        });
        await page.goto(`/${lang}/${path}`);
        await expect.poll(() => asked).toBeGreaterThan(0);
        const status = page.getByRole("status").filter({hasText: T("form.waiting")});
        await expect(status).toHaveAttribute("aria-busy", "true");
        await expect(page.getByRole("link", {name: T(path === "register" ? "register.signIn" : "forgot.back")})).toBeVisible();
        await expect(page.getByText(T("form.offline"))).toHaveCount(0);
        await context.setOffline(true);
        await expect(page.getByText(T("form.offline"))).toBeVisible();
        await context.setOffline(false);
        held.release();
        await expect(field(page, "phone")).toBeVisible();
      });
    }

    test("wp8-r17-3/4: the login page at ?step=otp-phone falls back to the password form when offline, and keeps what was typed when the answer comes", async ({
      page,
      context,
    }) => {
      const held = gate();
      let asked = 0;
      await openAnonymous(context, {
        "GET /auth/config": async () => {
          asked += 1;
          await held.opened;
          return {body: publicConfigFixture({sms_available: true})};
        },
      });
      await page.goto(`/${lang}/login?step=otp-phone`);
      await expect.poll(() => asked).toBeGreaterThan(0);
      // Online: the skeleton, busy, with no form.
      await expect(page.getByRole("status").filter({hasText: T("form.waiting")})).toHaveAttribute("aria-busy", "true");
      await expect(page.locator("form")).toHaveCount(0);
      await context.setOffline(true);
      await expect(field(page, "password")).toBeVisible();
      await expect(page.getByText(T("form.offline"))).toBeVisible();
      await field(page, "password").fill("typed while offline");
      await context.setOffline(false);
      held.release();
      // The SMS tab arrives next to the password form, which keeps its place and what was typed.
      await expect(page.getByRole("tab", {name: T("login.tabOtp")})).toBeVisible();
      await expect(field(page, "password")).toHaveValue("typed while offline");
    });

    test("wp8-r17-4: the forced change page has a busy status while /me is awaited", async ({page, context, baseURL}) => {
      const held = gate();
      await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
      await installApiMock(context, {
        me: meFixture({user: {must_reset: true}}),
        handlers: {
          "GET /me": async (_c, s) => {
            await held.opened;
            return {body: s.me};
          },
        },
      });
      await page.goto(`/${lang}/change-password`);
      await expect(page.getByRole("status").filter({hasText: T("form.waiting")})).toHaveAttribute("aria-busy", "true");
      held.release();
      await expect(field(page, "new_password")).toBeVisible();
    });

    // wp8-r17-5: the forms that set a new password for a number the visitor typed earlier carry that number as the
    // account name, so the password manager saves the entry under it and not under the code.
    test("wp8-r17-5: Register's confirm step and Forgot Password step 3 carry the phone as a hidden account name", async ({page, context}) => {
      await openAnonymous(
        context,
        {
          "POST /auth/otp/request": issued,
          "POST /auth/password/reset/verify": {body: {ticket: "reset-ticket-17", second_factor: "none"}},
        },
        {registration_mode: "open"},
      );
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "password")).toBeVisible();
      const registerName = page.locator('input[autocomplete="username"]');
      await expect(registerName).toHaveCount(1);
      await expect(registerName).toHaveValue(PHONE);
      await expect(registerName).toHaveAttribute("readonly", "");
      await expect(registerName).toHaveAttribute("tabindex", "-1");
      // It comes before the code and the password in the form.
      const order = await page.locator("form input").evaluateAll((inputs) => inputs.map((input) => input.getAttribute("name")));
      expect(order.indexOf("username")).toBe(0);

      await gotoForm(page, `/${lang}/forgot-password`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("123456");
      await expect(field(page, "new_password")).toBeVisible();
      const forgotName = page.locator('input[autocomplete="username"]');
      await expect(forgotName).toHaveCount(1);
      await expect(forgotName).toHaveValue(PHONE);
    });

    test("wp8-r17-5: the password sign-in names its number as the account, the invite confirm step has no account-name field", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/invites/lookup": {body: inviteInfoFixture()}, "POST /auth/otp/request": issued});
      await gotoForm(page, `/${lang}/login`);
      await expect(field(page, "phone")).toHaveAttribute("autocomplete", "username");
      // The invite gives only a masked number: no account-name field on its confirm step.
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(submit(page)).toBeEnabled();
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await expect(page.locator('input[name="username"]')).toHaveCount(0);
    });
  });
}
