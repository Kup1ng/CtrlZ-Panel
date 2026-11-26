import {errorBody, otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
import type {Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectNoSecretResidue} from "@ctrlz/ui/testing/secretResidue.ts";

import {
  allowAuthErrors,
  callsTo,
  err,
  field,
  formAlert,
  gotoForm,
  lastBody,
  LANGS,
  meReady,
  openAnonymous,
  signedIn,
  submit,
  errorText,
  text,
  type Lang, typeWhenFocused} from "./auth-support.ts";

// Spec 17.3 `login.spec.ts` (T-092, T-093, T-097, T-099, T-102, T-104, T-112), in mock mode: every row of the
// outcome tables of 10.2. The passkey rows run on Chrome's virtual authenticator (CDP), which makes the real
// assertion; only the answer of the server is mocked.

test.beforeEach(({guard}) => allowAuthErrors(guard));

const PHONE = "09123456789";
const PASSWORD = "correct horse battery";
const OTP_ID = otpChallengeId(18);

async function fillPassword(page: Page, phone = PHONE, password = PASSWORD) {
  await field(page, "phone").fill(phone);
  await field(page, "password").fill(password);
}

for (const {lang, dir} of LANGS) {
  test.describe(`login, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    test("password: signs in and goes to /profiles, with what was typed and Remember me off", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": signedIn(context, baseURL),
        "GET /me": meReady(),
      });
      await gotoForm(page, `/${lang}/login`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.title"));
      await fillPassword(page);
      await submit(page).click();
      await page.waitForURL(`**/${lang}/profiles`);
      expect(lastBody(mock, "POST", "/auth/login/password")).toEqual({phone: PHONE, password: PASSWORD, remember_me: false});
      expect(mock.unhandled).toEqual([]);
      await expectNoSecretResidue(page, [PASSWORD], "the password sign-in");
    });

    test("password: Remember me sends remember_me, and the label says 30 days", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(context, {"POST /auth/login/password": signedIn(context, baseURL), "GET /me": meReady()});
      await gotoForm(page, `/${lang}/login`);
      await expect(page.getByRole("checkbox", {name: T("fields.remember")})).not.toBeChecked();
      expect(T("fields.remember")).toMatch(lang === "fa" ? /۳۰/ : /30/);
      await fillPassword(page);
      await page.getByText(T("fields.remember")).click();
      await submit(page).click();
      await page.waitForURL(`**/${lang}/profiles`);
      expect(lastBody(mock, "POST", "/auth/login/password")).toMatchObject({remember_me: true});
    });

    test("password: next goes back to the page the visitor came for, and a foreign next is dropped", async ({page, context, baseURL}) => {
      await openAnonymous(context, {"POST /auth/login/password": signedIn(context, baseURL), "GET /me": meReady()});
      await gotoForm(page, `/${lang}/login?next=%2Fendpoints`);
      await fillPassword(page);
      await submit(page).click();
      await page.waitForURL(`**/${lang}/endpoints`);

      await context.clearCookies();
      await gotoForm(page, `/${lang}/login?next=https%3A%2F%2Fevil.example%2F`);
      await fillPassword(page);
      await submit(page).click();
      await page.waitForURL(`**/${lang}/profiles`);
    });

    // wp8-r2-7: a known prefix followed by dot segments is a prefix check passed and a path the allowlist refuses.
    for (const [name, next] of [
      ["dot-dot", "/profiles/../en/register"],
      ["encoded dot-dot", "/profiles/%2e%2e/%2e%2e/en/register"],
      ["encoded slash between dots", "/profiles/..%2f..%2fx"],
    ] as const) {
      test(`password: a next with dot segments (${name}) falls back to /profiles`, async ({page, context, baseURL}) => {
        await openAnonymous(context, {"POST /auth/login/password": signedIn(context, baseURL), "GET /me": meReady()});
        await gotoForm(page, `/${lang}/login?next=${encodeURIComponent(next)}`);
        await fillPassword(page);
        await submit(page).click();
        await page.waitForURL(`**/${lang}/profiles`);
      });
    }

    test("password: invalid_credentials is one neutral line, the password is cleared and has the focus", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/login/password": err(401, "invalid_credentials")});
      await gotoForm(page, `/${lang}/login`);
      await fillPassword(page);
      await submit(page).click();
      await expect(formAlert(page)).toContainText(lang === "fa" ? "درست نیست" : "not correct");
      await expect(field(page, "password")).toHaveValue("");
      await expect(field(page, "password")).toBeFocused();
      await expect(field(page, "phone")).toHaveValue(PHONE);
      // It does not say which of the two was wrong.
      await expect(formAlert(page)).not.toContainText(/phone|password|شماره|گذرواژه/i);
      expect(callsTo(mock, "POST", "/auth/login/password")).toHaveLength(1);
    });

    test("password: an empty field is a field error before any request, and the focus goes to it", async ({page, context}) => {
      const mock = await openAnonymous(context);
      await gotoForm(page, `/${lang}/login`);
      await submit(page).click();
      await expect(page.getByText(T("fields.phone.required"))).toBeVisible();
      await expect(field(page, "phone")).toBeFocused();
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(page.getByText(T("fields.password.required"))).toBeVisible();
      await expect(field(page, "password")).toBeFocused();
      expect(callsTo(mock, "POST", "/auth/login/password")).toHaveLength(0);
    });

    test("password: the show toggle switches the type and keeps the value", async ({page, context}) => {
      await openAnonymous(context);
      await gotoForm(page, `/${lang}/login`);
      await field(page, "password").fill("abc");
      await expect(field(page, "password")).toHaveAttribute("type", "password");
      await page.getByRole("button", {name: T("fields.password.showLabel")}).click();
      await expect(field(page, "password")).toHaveAttribute("type", "text");
      await expect(field(page, "password")).toHaveValue("abc");
      // wp8-r3-4: the name follows the state and there is no aria-pressed, since both together read "Hide, pressed".
      const hide = page.getByRole("button", {name: T("fields.password.hideLabel")});
      await expect(hide).toBeVisible();
      await expect(hide).not.toHaveAttribute("aria-pressed");
      await expect(page.getByRole("button", {name: T("fields.password.showLabel")})).toHaveCount(0);
      await hide.click();
      await expect(field(page, "password")).toHaveAttribute("type", "password");
      await expect(page.getByRole("button", {name: T("fields.password.showLabel")})).not.toHaveAttribute("aria-pressed");
    });

    for (const [mode, register, invite] of [
      ["open", true, false],
      ["invite", false, true],
      ["closed", false, false],
    ] as const) {
      test(`mode links: ${mode} shows ${register ? "Register" : invite ? "the invite link" : "neither"}`, async ({page, context}) => {
        await openAnonymous(context, {}, {registration_mode: mode});
        await gotoForm(page, `/${lang}/login`);
        await expect(page.getByRole("button", {name: T("login.submit")})).toBeVisible();
        await expect(page.getByRole("link", {name: T("login.register")})).toHaveCount(register ? 1 : 0);
        await expect(page.getByRole("link", {name: T("login.invite")})).toHaveCount(invite ? 1 : 0);
      });
    }

    test("sms_available = false hides the SMS tab and the forgot link, and says so (T-099)", async ({page, context}) => {
      await openAnonymous(context, {}, {sms_available: false});
      await gotoForm(page, `/${lang}/login`);
      await expect(page.getByText(T("login.smsDown"))).toBeVisible();
      await expect(page.getByRole("tab")).toHaveCount(0);
      await expect(page.getByRole("link", {name: T("login.forgot")})).toHaveCount(0);
      await expect(field(page, "password")).toBeVisible();
    });

    test("/auth/config fails: the password form only, and no error shown for it", async ({page, context, guard}) => {
      guard.allowConsole(/status of 5\d\d/);
      await openAnonymous(context, {"GET /auth/config": err(500, "internal")});
      await gotoForm(page, `/${lang}/login`);
      await expect(field(page, "password")).toBeVisible();
      // The client retries a 503 only; a 500 is final.
      await expect(page.getByRole("tab")).toHaveCount(0);
      await expect(page.getByRole("link", {name: T("login.register")})).toHaveCount(0);
      await expect(page.getByRole("link", {name: T("login.invite")})).toHaveCount(0);
      await expect(page.getByRole("button", {name: T("login.passkey")})).toHaveCount(0);
      await expect(formAlert(page)).toHaveCount(0);
    });

    test("SMS code: request, Persian digits submit as ASCII, then /profiles", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 60}},
        "POST /auth/login/otp": signedIn(context, baseURL),
        "GET /me": meReady(),
      });
      await gotoForm(page, `/${lang}/login`);
      await page.getByRole("tab", {name: T("login.tabOtp")}).click();
      await expect(page).toHaveURL(/step=otp-phone/);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      expect(lastBody(mock, "POST", "/auth/otp/request")).toEqual({purpose: "login", phone: PHONE, locale: lang});

      // 10.3: the input, its direction and its autocomplete.
      const code = field(page, "code");
      await expect(code).toBeFocused();
      await expect(code).toHaveAttribute("autocomplete", "one-time-code");
      await expect(code).toHaveAttribute("inputmode", "numeric");
      expect(await code.evaluate((el) => el.closest("[dir]")?.getAttribute("dir"))).toBe("ltr");

      await page.keyboard.type("۱۲۳۴۵۶");
      await page.waitForURL(`**/${lang}/profiles`);
      expect(lastBody(mock, "POST", "/auth/login/otp")).toEqual({phone: PHONE, challenge_id: OTP_ID, code: "123456", remember_me: false});
      // One submit, however it was completed.
      expect(callsTo(mock, "POST", "/auth/login/otp")).toHaveLength(1);
      await expectNoSecretResidue(page, ["123456", "۱۲۳۴۵۶", OTP_ID], "the SMS code sign-in");
    });

    test("SMS code: a code that is not digits is not accepted by the slots", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/otp/request": {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 60}}});
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeWhenFocused(page, "12ab34");
      await expect(field(page, "code")).toHaveValue("1234");
    });

    test("SMS code: otp_invalid is under the code, the slots clear and the first has the focus", async ({page, context}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 60}},
        "POST /auth/login/otp": err(401, "otp_invalid"),
      });
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeWhenFocused(page, "111111");
      await expect(page.getByRole("alert").filter({hasText: lang === "fa" ? "درست نیست" : "not correct"})).toBeVisible();
      await expect(field(page, "code")).toHaveValue("");
      await expect(field(page, "code")).toBeFocused();
      // Typing again clears the message and submits again.
      await page.keyboard.type("222222");
      await expect.poll(() => callsTo(mock, "POST", "/auth/login/otp").length).toBe(2);
    });

    test("SMS code: otp_expired goes back to the number, which is kept, with the message", async ({page, context}) => {
      await openAnonymous(context, {
        "POST /auth/otp/request": {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 60}},
        "POST /auth/login/otp": err(401, "otp_expired"),
      });
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeWhenFocused(page, "123456");
      await expect(page.getByRole("tab", {name: T("login.tabOtp")})).toHaveAttribute("aria-selected", "true");
      await expect(field(page, "phone")).toHaveValue(PHONE);
      await expect(formAlert(page)).toContainText(lang === "fa" ? "منقضی" : "expired");
    });

    test("SMS code: otp_locked goes back to the number with the wait in the message", async ({page, context}) => {
      await openAnonymous(context, {
        "POST /auth/otp/request": {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 60}},
        "POST /auth/login/otp": err(429, "otp_locked", {retry_after_s: 300}),
      });
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeWhenFocused(page, "123456");
      await expect(field(page, "phone")).toHaveValue(PHONE);
      await expect(formAlert(page)).toContainText(/300|۳۰۰/);
    });

    test("SMS code: Resend waits resend_after_s, then asks for a new challenge", async ({page, context}) => {
      await page.clock.install();
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 30}},
      });
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      const resend = page.getByRole("button", {name: new RegExp(`${T("resend.action")}|${lang === "fa" ? "ارسال دوباره تا" : "Resend in"}`)});
      await expect(resend).toBeDisabled();
      await page.clock.fastForward(31_000);
      await expect(resend).toBeEnabled();
      await resend.click();
      await expect.poll(() => callsTo(mock, "POST", "/auth/otp/request").length).toBe(2);
      await expect(resend).toBeDisabled();
    });

    test("SMS code: otp_limited and sms_unavailable stay on the number step", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/otp/request": err(429, "otp_limited", {retry_after_s: 60})});
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(formAlert(page)).toBeVisible();
      // The button waits out the Retry-After, with the seconds on it.
      await expect(submit(page)).toBeDisabled();
      await expect(submit(page)).toContainText(/60|59|۶۰|۵۹/);
    });

    test("SMS code: invalid_phone is under the number field", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/otp/request": err(422, "invalid_phone")});
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill("12");
      await submit(page).click();
      await expect(field(page, "phone")).toHaveAttribute("aria-invalid", "true");
      await expect(field(page, "phone")).toBeFocused();
    });

    test("TOTP: mfa_required keeps the ticket, a wrong code keeps it and clears the slots, then success", async ({page, context, baseURL}) => {
      let attempts = 0;
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": {body: {status: "mfa_required", ticket: "mfa-ticket-1", ticket_expires_in_s: 300, methods: ["totp", "recovery_code"]}},
        "POST /auth/login/totp": async (call) => {
          attempts++;
          if (attempts === 1) return err(401, "totp_invalid");
          return signedIn(context, baseURL)(call, undefined as never);
        },
        "GET /me": meReady(),
      });
      await gotoForm(page, `/${lang}/login`);
      await fillPassword(page);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.twoFactor.title"));
      await expect(page).toHaveURL(/step=2fa/);
      // The ticket is in memory: never in the URL.
      expect(page.url()).not.toContain("mfa-ticket-1");
      await expect(field(page, "totp_code")).toBeFocused();
      await page.keyboard.type("654321");
      await expect(page.getByRole("alert").filter({hasText: lang === "fa" ? "درست نیست" : "not correct"})).toBeVisible();
      await expect(field(page, "totp_code")).toHaveValue("");
      await page.keyboard.type("123456");
      await page.waitForURL(`**/${lang}/profiles`);
      expect(callsTo(mock, "POST", "/auth/login/totp").map((c) => c.body)).toEqual([
        {ticket: "mfa-ticket-1", totp_code: "654321"},
        {ticket: "mfa-ticket-1", totp_code: "123456"},
      ]);
      await expectNoSecretResidue(page, ["mfa-ticket-1", "123456", "654321", PASSWORD], "the password and authenticator code sign-in");
    });

    test("TOTP: totp_step_reused says to wait for the next code, the ticket stays", async ({page, context}) => {
      await openAnonymous(context, {
        "POST /auth/login/password": {body: {status: "mfa_required", ticket: "t", methods: ["totp"]}},
        "POST /auth/login/totp": err(401, "totp_step_reused"),
      });
      await gotoForm(page, `/${lang}/login`);
      await fillPassword(page);
      await submit(page).click();
      await typeWhenFocused(page, "123456");
      await expect(page.getByText(lang === "fa" ? "کد بعدی" : "next code")).toBeVisible();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.twoFactor.title"));
      // Authenticator only: no recovery link was offered.
      await expect(page.getByRole("button", {name: T("login.twoFactor.useRecovery")})).toHaveCount(0);
    });

    test("TOTP: a recovery code is sent as recovery_code, canonical", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": {body: {status: "mfa_required", ticket: "t", methods: ["totp", "recovery_code"]}},
        "POST /auth/login/totp": signedIn(context, baseURL),
        "GET /me": meReady(),
      });
      await gotoForm(page, `/${lang}/login`);
      await fillPassword(page);
      await submit(page).click();
      await page.getByRole("button", {name: T("login.twoFactor.useRecovery")}).click();
      const recovery = field(page, "recovery_code");
      await expect(recovery).toBeFocused();
      await recovery.pressSequentially("abcd efgh-ijkl 1234");
      await expect(recovery).toHaveValue("ABCD-EFGH-IJKL-1234");
      await submit(page).click();
      await page.waitForURL(`**/${lang}/profiles`);
      expect(lastBody(mock, "POST", "/auth/login/totp")).toEqual({ticket: "t", recovery_code: "ABCDEFGHIJKL1234"});
      await expectNoSecretResidue(page, ["ABCDEFGHIJKL1234", "ABCD-EFGH-IJKL-1234", PASSWORD], "the recovery code sign-in");
    });

    test("TOTP: ticket_invalid goes back to the password step with the message", async ({page, context}) => {
      await openAnonymous(context, {
        "POST /auth/login/password": {body: {status: "mfa_required", ticket: "t", methods: ["totp"]}},
        "POST /auth/login/totp": err(401, "ticket_invalid"),
      });
      await gotoForm(page, `/${lang}/login`);
      await fillPassword(page);
      await submit(page).click();
      await typeWhenFocused(page, "123456");
      await expect(field(page, "password")).toBeVisible();
      await expect(formAlert(page)).toContainText(lang === "fa" ? "منقضی" : "expired");
      await expect(page).not.toHaveURL(/step=/);
    });

    test("TOTP: the page counts the ticket down and starts over when it ends", async ({page, context}) => {
      await page.clock.install();
      await openAnonymous(context, {"POST /auth/login/password": {body: {status: "mfa_required", ticket: "t", ticket_expires_in_s: 20, methods: ["totp"]}}});
      await gotoForm(page, `/${lang}/login`);
      await fillPassword(page);
      await submit(page).click();
      // The page clock keeps running, so the figure is not asserted, only that the ticket is being counted down.
      await expect(page.getByText(lang === "fa" ? /ثانیه دیگر پایان/ : /ends in [0-9]+ s/)).toBeVisible();
      await page.clock.fastForward(21_000);
      await expect(field(page, "password")).toBeVisible();
      await expect(formAlert(page)).toBeVisible();
    });

    // wp8-r2-1: AUTH 5.7 answers 403 account_suspended on the password path and creates no session. /suspended
    // would ask /me, get 401, fail to refresh and fall back to this page with no word of the suspension, so the
    // page explains it where it is. The mock answers like the API: /me and /auth/refresh are 401 for lack of a cookie.
    test("account_suspended is explained on the login page itself, since no session exists", async ({page, context}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": err(403, "account_suspended"),
        "POST /auth/refresh": err(401, "session_expired"),
      });
      await gotoForm(page, `/${lang}/login`);
      await fillPassword(page);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("suspended.title"));
      await expect(page.getByText(T("suspended.text"))).toBeVisible();
      await expect(page.getByRole("heading", {level: 1})).toBeFocused();
      expect(new URL(page.url()).pathname).toBe(`/${lang}/login`);
      // No session, so nothing to sign out of, and no call that would only fail.
      await expect(page.getByRole("button", {name: T("logout")})).toHaveCount(0);
      expect(callsTo(mock, "GET", "/me")).toHaveLength(0);
      expect(callsTo(mock, "POST", "/auth/refresh")).toHaveLength(0);
      // The way on is back to the form, with the password to retype.
      await page.getByRole("button", {name: T("suspended.back")}).click();
      await expect(field(page, "password")).toBeVisible();
      await expect(field(page, "password")).toHaveValue("");
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.title"));
    });

    test("a wait: 429 disables the button for retry_after_s, with the seconds on it", async ({page, context}) => {
      await page.clock.install();
      await openAnonymous(context, {"POST /auth/login/password": err(429, "too_many_attempts", {retry_after_s: 30})});
      await gotoForm(page, `/${lang}/login`);
      await fillPassword(page);
      await submit(page).click();
      await expect(formAlert(page)).toBeVisible();
      await expect(submit(page)).toBeDisabled();
      await expect(submit(page)).toContainText(/30|29|۳۰|۲۹/);
      await page.clock.fastForward(31_000);
      await expect(submit(page)).toBeEnabled();
      await expect(submit(page)).toContainText(T("login.submit"));
    });

    test("a busy server: 503 shows the text and a Retry that asks again", async ({page, context}) => {
      let first = true;
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": () => {
          if (first) {
            first = false;
            return err(503, "service_unavailable");
          }
          return {body: {status: "mfa_required", ticket: "t", methods: ["totp"]}};
        },
      });
      await gotoForm(page, `/${lang}/login`);
      await fillPassword(page);
      await submit(page).click();
      await expect(formAlert(page)).toContainText(lang === "fa" ? "در دسترس نیست" : "not available");
      await formAlert(page).getByRole("button", {name: lang === "fa" ? "تلاش دوباره" : "Try again"}).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.twoFactor.title"));
      expect(callsTo(mock, "POST", "/auth/login/password")).toHaveLength(2);
    });

    test("500 shows the request id, isolated left to right", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/login/password": {status: 500, body: errorBody("internal", {request_id: "req-abc123"})}});
      await gotoForm(page, `/${lang}/login`);
      await fillPassword(page);
      await submit(page).click();
      const id = formAlert(page).locator("bdi");
      await expect(id).toHaveText("req-abc123");
      await expect(id).toHaveAttribute("dir", "ltr");
    });

    test("csrf_rejected asks to reload the page", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/login/password": err(403, "csrf_rejected")});
      await gotoForm(page, `/${lang}/login`);
      await fillPassword(page);
      await submit(page).click();
      await expect(formAlert(page).getByRole("button", {name: T("form.reload")})).toBeVisible();
    });

    test("offline: the button is disabled and the form says so", async ({page, context}) => {
      await openAnonymous(context);
      await gotoForm(page, `/${lang}/login`);
      await expect(submit(page)).toBeEnabled();
      await context.setOffline(true);
      await expect(page.getByText(T("form.offline"))).toBeVisible();
      await expect(submit(page)).toBeDisabled();
      await context.setOffline(false);
      await expect(submit(page)).toBeEnabled();
    });
  });
}

// The passkey rows (10.2), with Chrome's virtual authenticator making the real assertion.
async function virtualPasskey(page: Page) {
  const cdp = await page.context().newCDPSession(page);
  // Chrome holds a WebAuthn call until its tab has the focus, and two workers each have a window of their own:
  // a window behind the other made one run wait out its 60 seconds. Focus emulation makes every page focused.
  await cdp.send("Emulation.setFocusEmulationEnabled", {enabled: true});
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  // A resident credential for this origin, so the login ceremony finds one with no allow list.
  await page.evaluate(async () => {
    const bytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
    await navigator.credentials.create({
      publicKey: {
        challenge: bytes(32),
        rp: {id: location.hostname, name: "Ctrl Z test"},
        user: {id: bytes(16), name: "e2e", displayName: "e2e"},
        pubKeyCredParams: [{type: "public-key", alg: -7}],
        authenticatorSelection: {residentKey: "required", userVerification: "required"},
      },
    });
  });
  return cdp;
}

const options = (rpId: string) => ({
  publicKey: {challenge: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", rpId, timeout: 60000, userVerification: "preferred"},
});

for (const {lang} of LANGS) {
  test.describe(`login passkey, ${lang}`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang as Lang, path);

    test("the passkey button is hidden when the server does not enable passkeys", async ({page, context}) => {
      await openAnonymous(context, {}, {passkey_enabled: false});
      await gotoForm(page, `/${lang}/login`);
      await expect(field(page, "password")).toBeVisible();
      await expect(page.getByRole("button", {name: T("login.passkey")})).toHaveCount(0);
    });

    test("the passkey button is shown when the server enables passkeys and the browser has WebAuthn", async ({page, context}) => {
      await openAnonymous(context, {}, {passkey_enabled: true});
      await gotoForm(page, `/${lang}/login`);
      await expect(page.getByRole("button", {name: T("login.passkey")})).toBeVisible();
    });

    test("passkey: begin, the browser's assertion, finish with the ticket in the header, then /profiles", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(
        context,
        {
          "POST /auth/passkey/login/begin": () => ({body: {ticket: "pk-ticket", options: options(new URL(baseURL!).hostname)}}),
          "POST /auth/passkey/login/finish": signedIn(context, baseURL),
          "GET /me": meReady(),
        },
        {passkey_enabled: true},
      );
      await gotoForm(page, `/${lang}/login`);
      await virtualPasskey(page);
      await page.getByRole("button", {name: T("login.passkey")}).click();
      await page.waitForURL(`**/${lang}/profiles`);
      const finish = callsTo(mock, "POST", "/auth/passkey/login/finish")[0]!;
      expect(finish.headers["x-ctrlz-ticket"]).toBe("pk-ticket");
      expect(finish.body).toMatchObject({type: "public-key", response: {clientDataJSON: expect.any(String), authenticatorData: expect.any(String), signature: expect.any(String)}});
      expect(lastBody(mock, "POST", "/auth/passkey/login/begin")).toEqual({remember_me: false});
      // gate-r27-5: the ticket of begin is a one-time value that LoginSteps holds in state; the flow has left /login, so the record of
      // the whole test is what is read, not only the page it ended on.
      await expectNoSecretResidue(page, ["pk-ticket"], "the passkey sign-in");
    });

    test("passkey: passkey_invalid shows a neutral message and Try again runs the ceremony again", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(
        context,
        {
          "POST /auth/passkey/login/begin": {body: {ticket: "pk-ticket", options: options(new URL(baseURL!).hostname)}},
          "POST /auth/passkey/login/finish": err(401, "passkey_invalid"),
        },
        {passkey_enabled: true},
      );
      await gotoForm(page, `/${lang}/login`);
      await virtualPasskey(page);
      await page.getByRole("button", {name: T("login.passkey")}).click();
      // The exact neutral line of errors.json, and nothing of the server's code in it.
      await expect(formAlert(page).locator(".alert__description")).toHaveText(errorText(lang, "passkey_invalid"));
      await expect(formAlert(page)).not.toContainText("passkey_invalid");
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.passkeyStep.title"));
      await page.getByRole("button", {name: T("login.passkeyStep.retry")}).click();
      await expect.poll(() => callsTo(mock, "POST", "/auth/passkey/login/finish").length).toBe(2);
      // The fallback is the way out: Forgot Password, and back to the password.
      await expect(page.getByRole("link", {name: T("login.forgot")})).toBeVisible();
      await page.getByRole("button", {name: T("login.passkeyStep.back")}).click();
      await expect(field(page, "password")).toBeVisible();
    });

    test("passkey: ticket_invalid from finish goes back to the password step with the message (wp8-r16-2)", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(
        context,
        {
          "POST /auth/passkey/login/begin": {body: {ticket: "pk-ticket", options: options(new URL(baseURL!).hostname)}},
          "POST /auth/passkey/login/finish": err(401, "ticket_invalid"),
        },
        {passkey_enabled: true},
      );
      await gotoForm(page, `/${lang}/login`);
      await virtualPasskey(page);
      await page.getByRole("button", {name: T("login.passkey")}).click();
      await expect(field(page, "password")).toBeVisible();
      await expect(formAlert(page)).toContainText(lang === "fa" ? "منقضی" : "expired");
      await expect(page.getByRole("heading", {level: 1})).not.toHaveText(T("login.passkeyStep.title"));
      await expect(page).not.toHaveURL(/step=/);
      expect(callsTo(mock, "POST", "/auth/passkey/login/finish")).toHaveLength(1);
    });

    test("passkey: account_suspended from finish is explained on the page, with no session behind it (wp8-r2-1)", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(
        context,
        {
          "POST /auth/passkey/login/begin": {body: {ticket: "pk-ticket", options: options(new URL(baseURL!).hostname)}},
          "POST /auth/passkey/login/finish": err(403, "account_suspended"),
          "POST /auth/refresh": err(401, "session_expired"),
        },
        {passkey_enabled: true},
      );
      await gotoForm(page, `/${lang}/login`);
      await virtualPasskey(page);
      await page.getByRole("button", {name: T("login.passkey")}).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("suspended.title"));
      expect(new URL(page.url()).pathname).toBe(`/${lang}/login`);
      expect(callsTo(mock, "GET", "/me")).toHaveLength(0);
    });

    test("passkey: closing the browser's prompt is silent", async ({page, context, baseURL}) => {
      // No virtual authenticator: Chrome answers NotAllowedError when there is no credential to use.
      await openAnonymous(
        context,
        {"POST /auth/passkey/login/begin": {body: {ticket: "pk-ticket", options: options(new URL(baseURL!).hostname)}}},
        {passkey_enabled: true},
      );
      await page.addInitScript(() => {
        navigator.credentials.get = () => Promise.reject(new DOMException("closed", "NotAllowedError"));
      });
      await gotoForm(page, `/${lang}/login`);
      await page.getByRole("button", {name: T("login.passkey")}).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.passkeyStep.title"));
      await expect(page.getByRole("button", {name: T("login.passkeyStep.retry")})).toBeEnabled();
      await expect(formAlert(page)).toHaveCount(0);
    });

    test("passkey: passkey_unavailable removes the passkey button", async ({page, context, guard}) => {
      guard.allowConsole(/status of 404/);
      await openAnonymous(context, {"POST /auth/passkey/login/begin": err(404, "passkey_unavailable")}, {passkey_enabled: true});
      await gotoForm(page, `/${lang}/login`);
      await page.getByRole("button", {name: T("login.passkey")}).click();
      await expect(field(page, "password")).toBeVisible();
      await expect(page.getByRole("button", {name: T("login.passkey")})).toHaveCount(0);
    });

    test("passkey_required after the password goes to the passkey step", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(
        context,
        {
          "POST /auth/login/password": {body: {status: "passkey_required"}},
          "POST /auth/passkey/login/begin": {body: {ticket: "pk-ticket", options: options(new URL(baseURL!).hostname)}},
          "POST /auth/passkey/login/finish": signedIn(context, baseURL),
          "GET /me": meReady(),
        },
        {passkey_enabled: true},
      );
      await gotoForm(page, `/${lang}/login`);
      await virtualPasskey(page);
      await fillPassword(page);
      await submit(page).click();
      // The prompt starts on its own: the step is the answer to a password that needs a passkey.
      await page.waitForURL(`**/${lang}/profiles`);
      expect(callsTo(mock, "POST", "/auth/passkey/login/begin")).toHaveLength(1);
    });
  });
}
