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
  openAnonymous,
  STRONG_PASSWORD,
  submit,
  text,
} from "./auth-support.ts";

// Round 3 of the review of WP8: where the first key of a number goes after a return (wp8-r3-1), the notice
// that a failed retry must not show beside its own error (r3-2), what Resend and the switch to a recovery code
// do to a wait (r3-3, r3-6), and the Forgot Password passkey proof during a wait (r3-6). The toast of r3-5 is in
// forgot.spec.ts and the toggle's name (r3-4) in login.spec.ts and forms.test.tsx.

test.beforeEach(({guard}) => allowAuthErrors(guard));

const PHONE = "09123456789";
const OTP_ID = otpChallengeId(8);
// One second, so the real clock is enough to wake the Resend button.
const issued = {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 1}};
const mfa = (methods: string[] = ["totp"]) => ({body: {status: "mfa_required", ticket: "t", ticket_expires_in_s: 300, methods}});
const CODE = "ABCDEFGHJKMNPQRSTVWX";

const options = (rpId: string) => ({
  publicKey: {challenge: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", rpId, timeout: 60000, userVerification: "preferred"},
});

/** The prompt of the browser is closed, which is what a cancelled passkey does. */
async function cancelPasskeyPrompt(page: Page) {
  await page.addInitScript(() => {
    navigator.credentials.get = () => Promise.reject(new DOMException("closed", "NotAllowedError"));
  });
}

async function virtualAuthenticator(page: Page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("Emulation.setFocusEmulationEnabled", {enabled: true});
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true},
  });
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
}

for (const {lang, dir} of LANGS) {
  test.describe(`round 3, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);
    const EXPIRED = lang === "fa" ? "منقضی" : "expired";

    // wp8-r3-1: a passkey sign-in needs no number, so the number is usually empty when the visitor comes back.
    // The focus target was computed from the number, so the first key moved it, and the rest of the number went
    // into the password field. Each return must keep the focus in the number while it is typed.
    async function expectNumberTypedIntoPhone(page: Page) {
      await expect(field(page, "phone")).toBeFocused();
      await page.keyboard.type("0912");
      await expect(field(page, "phone")).toHaveValue("0912");
      await expect(field(page, "password")).toHaveValue("");
      await expect(field(page, "phone")).toBeFocused();
    }

    test("wp8-r3-1: Back from the passkey prompt with no number keeps the focus in the number while it is typed", async ({page, context, baseURL}) => {
      await openAnonymous(
        context,
        {"POST /auth/passkey/login/begin": {body: {ticket: "pk", options: options(new URL(baseURL!).hostname)}}},
        {passkey_enabled: true},
      );
      await cancelPasskeyPrompt(page);
      await gotoForm(page, `/${lang}/login`);
      await page.getByRole("button", {name: T("login.passkey")}).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.passkeyStep.title"));
      await page.getByRole("button", {name: T("login.passkeyStep.back")}).click();
      await expectNumberTypedIntoPhone(page);
    });

    test("wp8-r3-1: passkey_unavailable with no number returns to the number, and it stays there while typed", async ({page, context, guard}) => {
      guard.allowConsole(/status of 404/);
      await openAnonymous(context, {"POST /auth/passkey/login/begin": err(404, "passkey_unavailable")}, {passkey_enabled: true});
      await gotoForm(page, `/${lang}/login`);
      await page.getByRole("button", {name: T("login.passkey")}).click();
      await expect(page.getByRole("button", {name: T("login.passkey")})).toHaveCount(0);
      await expectNumberTypedIntoPhone(page);
    });

    test("wp8-r3-1: Back to sign in from the suspended notice with no number does the same", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/passkey/login/begin": err(403, "account_suspended")}, {passkey_enabled: true});
      await gotoForm(page, `/${lang}/login`);
      await page.getByRole("button", {name: T("login.passkey")}).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("suspended.title"));
      await page.getByRole("button", {name: T("suspended.back")}).click();
      await expectNumberTypedIntoPhone(page);
    });

    // wp8-r3-2: the notice of a step we came back to goes with the next thing the visitor does.
    test("wp8-r3-2: Login, an expired ticket: editing the password drops the notice, and a failed retry shows one alert", async ({page, context}) => {
      await openAnonymous(context, {
        "POST /auth/login/password": (call) => ((call.body as {password: string}).password === "x" ? mfa() : err(401, "invalid_credentials")),
        "POST /auth/login/totp": err(401, "ticket_invalid"),
      });
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill("x");
      await submit(page).click();
      await expect(field(page, "totp_code")).toBeFocused();
      await page.keyboard.type("123456");
      await expect(formAlert(page)).toContainText(EXPIRED);
      await expect(formAlert(page)).toHaveCount(1);
      // A wrong password: the answer's own line, and no second alert for the old step.
      await field(page, "password").fill("wrong");
      await expect(formAlert(page)).toHaveCount(0);
      await submit(page).click();
      await expect(formAlert(page)).toHaveCount(1);
      await expect(formAlert(page)).not.toContainText(EXPIRED);
    });

    test("wp8-r3-2: Login, an expired SMS code: sending the number again shows one alert, not two", async ({page, context}) => {
      let sends = 0;
      await openAnonymous(context, {
        "POST /auth/otp/request": () => {
          sends += 1;
          return sends === 1 ? issued : err(422, "invalid_phone");
        },
        "POST /auth/login/otp": err(401, "otp_expired"),
      });
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("123456");
      await expect(formAlert(page)).toContainText(EXPIRED);
      await expect(field(page, "phone")).toBeFocused();
      // No edit: the request itself ends the notice.
      await submit(page).click();
      await expect.poll(() => sends).toBe(2);
      await expect(formAlert(page)).toHaveCount(0);
      await expect(page.locator('[data-invalid="true"]').first()).toBeVisible();
    });

    test("wp8-r3-2: Forgot Password, an expired code: a failed retry shows no notice beside its own error", async ({page, context}) => {
      let sends = 0;
      await openAnonymous(context, {
        "POST /auth/otp/request": () => {
          sends += 1;
          return sends === 1 ? issued : err(503, "server_busy", {retry_after_s: 30});
        },
        "POST /auth/password/reset/verify": err(401, "otp_expired"),
      });
      await gotoForm(page, `/${lang}/forgot-password`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("123456");
      await expect(formAlert(page)).toContainText(EXPIRED);
      await submit(page).click();
      await expect.poll(() => sends).toBe(2);
      await expect(formAlert(page)).toHaveCount(1);
      await expect(formAlert(page)).not.toContainText(EXPIRED);
    });

    test("wp8-r3-2: Forgot Password, editing the number drops the notice", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/otp/request": issued, "POST /auth/password/reset/verify": err(401, "otp_expired")});
      await gotoForm(page, `/${lang}/forgot-password`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("123456");
      await expect(formAlert(page)).toContainText(EXPIRED);
      await field(page, "phone").press("Backspace");
      await expect(formAlert(page)).toHaveCount(0);
    });

    test("wp8-r3-2: Invite, an expired code: a failed send shows one alert, and a retry that works leaves none", async ({page, context}) => {
      let sends = 0;
      await openAnonymous(context, {
        "POST /auth/invites/lookup": {body: inviteInfoFixture()},
        "POST /auth/otp/request": () => {
          sends += 1;
          if (sends === 2) return err(503, "server_busy", {retry_after_s: 30});
          return issued;
        },
        "POST /auth/register": err(401, "otp_expired"),
      });
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(submit(page)).toBeEnabled();
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("123456");
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.lookupTitle"));
      await expect(formAlert(page)).toContainText(EXPIRED);
      await submit(page).click();
      await expect.poll(() => sends).toBe(2);
      await expect(formAlert(page)).toHaveCount(1);
      await expect(formAlert(page)).not.toContainText(EXPIRED);
    });

    test("wp8-r3-2: Invite, a lookup that failed once does not come back on the info step", async ({page, context}) => {
      let lookups = 0;
      await openAnonymous(context, {
        "POST /auth/invites/lookup": () => {
          lookups += 1;
          return lookups === 1 ? err(503, "server_busy", {retry_after_s: 1}) : {body: inviteInfoFixture()};
        },
      });
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(formAlert(page)).toHaveCount(1);
      // The wait is one second; the code is still in the page, so the visitor sends it again.
      await expect(submit(page)).toBeEnabled();
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.lookupTitle"));
      await expect(formAlert(page)).toHaveCount(0);
    });

    // wp8-r3-3: Resend and the switch to a recovery code clear the messages and not a wait, and Resend does not
    // go out during one or offline.
    async function toLoginCode(page: Page, context: Parameters<typeof openAnonymous>[0], handlers = {}) {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/login/otp": err(429, "too_many_attempts", {retry_after_s: 60}),
        ...handlers,
      });
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      return mock;
    }

    test("wp8-r3-3: during a 429 wait on the code, Resend is disabled even when its own timer has ended, and the sixth digit sends nothing", async ({page, context}) => {
      const mock = await toLoginCode(page, context);
      await page.keyboard.type("123456");
      await expect(submit(page)).toBeDisabled();
      expect(callsTo(mock, "POST", "/auth/login/otp")).toHaveLength(1);
      // The Resend timer is one second, so it has ended by now: only the wait holds the button.
      await page.waitForTimeout(1300);
      const resend = page.getByRole("button", {name: T("resend.action")});
      await expect(resend).toBeDisabled();
      await resend.click({force: true});
      await page.waitForTimeout(300);
      expect(callsTo(mock, "POST", "/auth/otp/request")).toHaveLength(1);
      await expect(submit(page)).toBeDisabled();
      await field(page, "code").focus();
      await page.keyboard.press("End");
      await page.keyboard.press("Backspace");
      await page.keyboard.type("6");
      await page.waitForTimeout(300);
      expect(callsTo(mock, "POST", "/auth/login/otp")).toHaveLength(1);
    });

    test("wp8-r3-3: offline, Resend is disabled and sends nothing", async ({page, context, guard}) => {
      guard.allowConsole(/ERR_INTERNET_DISCONNECTED/);
      const mock = await toLoginCode(page, context, {"POST /auth/login/otp": err(401, "otp_invalid")});
      const resend = page.getByRole("button", {name: T("resend.action")});
      await expect(resend).toBeEnabled();
      await context.setOffline(true);
      await expect(resend).toBeDisabled();
      await resend.click({force: true});
      await page.waitForTimeout(300);
      await context.setOffline(false);
      expect(callsTo(mock, "POST", "/auth/otp/request")).toHaveLength(1);
    });

    test("wp8-r3-3: switching to a recovery code during a TOTP lockout does not end the wait", async ({page, context}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": mfa(["totp", "recovery_code"]),
        "POST /auth/login/totp": err(429, "too_many_attempts", {retry_after_s: 60}),
      });
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill("x");
      await submit(page).click();
      await expect(field(page, "totp_code")).toBeFocused();
      await page.keyboard.type("123456");
      await expect(submit(page)).toBeDisabled();
      await page.getByRole("button", {name: T("login.twoFactor.useRecovery")}).click();
      await expect(field(page, "recovery_code")).toBeVisible();
      await expect(submit(page)).toBeDisabled();
      await field(page, "recovery_code").fill("ABCD-EFGH-JKMN-PQRS");
      await field(page, "recovery_code").press("Enter");
      await page.waitForTimeout(300);
      expect(callsTo(mock, "POST", "/auth/login/totp")).toHaveLength(1);
    });

    test("wp8-r3-3: Forgot Password, switching to a recovery code during a lockout does not end the wait", async ({page, context}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": {body: {ticket: "reset-ticket-1", second_factor: "totp"}},
        "POST /auth/password/reset/complete": err(429, "too_many_attempts", {retry_after_s: 60}),
      });
      await gotoForm(page, `/${lang}/forgot-password`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("123456");
      await field(page, "new_password").fill(STRONG_PASSWORD);
      await field(page, "totp_code").focus();
      await page.keyboard.type("654321");
      await expect(submit(page)).toBeDisabled();
      await page.getByRole("button", {name: T("login.twoFactor.useRecovery")}).click();
      await expect(submit(page)).toBeDisabled();
      expect(callsTo(mock, "POST", "/auth/password/reset/complete")).toHaveLength(1);
    });

    // wp8-r3-6: a Resend that is refused holds the Resend button and nothing else.
    const refused = err(429, "otp_limited", {retry_after_s: 60});
    function twoStepOtp() {
      let sends = 0;
      return () => {
        sends += 1;
        return sends === 1 ? issued : refused;
      };
    }

    async function pressResendRefused(page: Page, mock: Awaited<ReturnType<typeof openAnonymous>>) {
      const resend = page.getByRole("button", {name: T("resend.action")});
      await expect(resend).toBeEnabled();
      await resend.click();
      await expect.poll(() => callsTo(mock, "POST", "/auth/otp/request").length).toBe(2);
      // Held for the 429's own wait: the label counts down, and pressing it again sends nothing.
      const waiting = page.getByRole("button", {name: T("resend.wait").split("{")[0]!.trim()});
      await expect(waiting).toBeDisabled();
      // The focus is back on the code (the button that had it is gone). Checked before the clicks below, which
      // land on a disabled button and take the focus to the page.
      await expect(field(page, "code")).toBeFocused();
      await expect(submit(page)).toBeEnabled();
      for (let i = 0; i < 3; i++) await waiting.click({force: true});
      await page.waitForTimeout(300);
      expect(callsTo(mock, "POST", "/auth/otp/request")).toHaveLength(2);
      // The code that was sent first is still good: Verify is not under a wait.
      await expect(submit(page)).toBeEnabled();
      await field(page, "code").focus();
    }

    test("wp8-r3-6: Login, a refused Resend holds Resend, and the sixth digit still sends", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/otp/request": twoStepOtp(), "POST /auth/login/otp": err(401, "otp_invalid")});
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await pressResendRefused(page, mock);
      await page.keyboard.type("123456");
      await expect.poll(() => callsTo(mock, "POST", "/auth/login/otp").length).toBe(1);
    });

    test("wp8-r3-6: Register, a refused Resend holds Resend and leaves Create account usable", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/otp/request": twoStepOtp()}, {registration_mode: "open"});
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await pressResendRefused(page, mock);
    });

    test("wp8-r3-6: Invite, a refused Resend holds Resend and leaves Create account usable", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": {body: inviteInfoFixture()}, "POST /auth/otp/request": twoStepOtp()});
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(submit(page)).toBeEnabled();
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await pressResendRefused(page, mock);
    });

    test("wp8-r3-6: Forgot Password, a refused Resend holds Resend and the sixth digit still verifies", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/otp/request": twoStepOtp(), "POST /auth/password/reset/verify": err(401, "otp_invalid")});
      await gotoForm(page, `/${lang}/forgot-password`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await pressResendRefused(page, mock);
      await page.keyboard.type("123456");
      await expect.poll(() => callsTo(mock, "POST", "/auth/password/reset/verify").length).toBe(1);
    });

    test("wp8-r3-6: Forgot Password, a 429 on the passkey proof disables Use my passkey", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": {body: {ticket: "reset-ticket-1", second_factor: "passkey"}},
        "POST /auth/password/reset/passkey/begin": {body: {ticket: "assertion-ticket", options: options(new URL(baseURL!).hostname)}},
        "POST /auth/password/reset/passkey/finish": err(429, "too_many_attempts", {retry_after_s: 60}),
      });
      await gotoForm(page, `/${lang}/forgot-password`);
      await virtualAuthenticator(page);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("123456");
      const use = page.getByRole("button", {name: T("forgot.passkeyUse")});
      await use.click();
      await expect.poll(() => callsTo(mock, "POST", "/auth/password/reset/passkey/finish").length).toBe(1);
      await expect(use).toBeDisabled();
      await use.click({force: true});
      await page.waitForTimeout(500);
      expect(callsTo(mock, "POST", "/auth/password/reset/passkey/begin")).toHaveLength(1);
      expect(callsTo(mock, "POST", "/auth/password/reset/passkey/finish")).toHaveLength(1);
    });
  });
}
