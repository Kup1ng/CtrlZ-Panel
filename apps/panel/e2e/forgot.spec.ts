import {errorBody, otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
import type {BrowserContext, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectNoSecretResidue} from "@ctrlz/ui/testing/secretResidue.ts";

import {
  allowAuthErrors,
  callsTo,
  err,
  errorText,
  field,
  formAlert,
  gotoForm,
  lastBody,
  LANGS,
  openAnonymous,
  submit,
  text, STRONG_PASSWORD, type Lang} from "./auth-support.ts";

// Spec 17.3 `forgot.spec.ts` (T-098), in mock mode: the table of 10.6 and AUTH 4.4. The passkey rows use
// Chrome's virtual authenticator for the real assertion; the server's answers are mocked.

test.beforeEach(({guard}) => allowAuthErrors(guard));

const STRONG = STRONG_PASSWORD;
const PHONE = "09123456789";
const OTP_ID = otpChallengeId(16);
const issued = {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 60}};
const verified = (second_factor: "none" | "totp" | "passkey") => ({body: {ticket: "reset-ticket-1", second_factor}});

// Spec 10.6 step 4: "success, link to login, toast". The toast is in the page's toast region, apart from the
// result card, and says the same thing in both languages whichever way the reset completed (wp8-r3-5).
async function expectDoneToast(page: Page, lang: Lang) {
  await expect(page.getByText(text(lang, "forgot.doneToast"), {exact: true})).toBeVisible();
}

async function toNewPassword(page: Page, lang: string) {
  await gotoForm(page, `/${lang}/forgot-password`);
  await field(page, "phone").fill(PHONE);
  await submit(page).click();
  // Keys typed before the code step has its focus go nowhere.
  await expect(field(page, "code")).toBeFocused();
  await page.keyboard.type("۱۲۳۴۵۶");
}

// A resident credential for this origin on a virtual authenticator, so the browser's own ceremony answers.
async function virtualPasskey(page: Page, context: BrowserContext) {
  const cdp = await context.newCDPSession(page);
  // Chrome holds a WebAuthn call until its tab has the focus (see login.spec.ts).
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

const proofBegin = (rpId: string) => ({
  body: {
    ticket: "assertion-ticket",
    options: {publicKey: {challenge: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", rpId, timeout: 60000, userVerification: "preferred"}},
  },
});

for (const {lang, dir} of LANGS) {
  test.describe(`forgot password, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    test("sms_available = false: the page is blocked with a notice to contact the admin", async ({page, context}) => {
      await openAnonymous(context, {}, {sms_available: false});
      await page.goto(`/${lang}/forgot-password`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("forgot.unavailableTitle"));
      await expect(page.getByText(T("forgot.unavailableText"))).toBeVisible();
      await expect(page.locator("form")).toHaveCount(0);
    });

    test("no second factor: number, code (Persian digits as ASCII), new password, done", async ({page, context}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": verified("none"),
        "POST /auth/password/reset/complete": {status: 204},
      });
      await gotoForm(page, `/${lang}/forgot-password`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      expect(lastBody(mock, "POST", "/auth/otp/request")).toEqual({purpose: "reset", phone: PHONE, locale: lang});

      // Step 2 always appears for a well-formed number, and never says the number has an account.
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("forgot.codeTitle"));
      await expect(page.getByText(T("forgot.codeDescription"))).toBeVisible();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("۱۲۳۴۵۶");
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("forgot.newTitle"));
      expect(lastBody(mock, "POST", "/auth/password/reset/verify")).toEqual({phone: PHONE, challenge_id: OTP_ID, code: "123456"});

      await expect(field(page, "new_password")).toBeFocused();
      await field(page, "new_password").fill(STRONG);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("forgot.doneTitle"));
      expect(lastBody(mock, "POST", "/auth/password/reset/complete")).toEqual({ticket: "reset-ticket-1", new_password: STRONG});
      await expect(page.getByText(T("forgot.doneText"))).toBeVisible();
      await expectDoneToast(page, lang);
      await expect(page.getByRole("link", {name: T("forgot.signIn")})).toHaveAttribute("href", `/${lang}/login`);
      // The ticket was never in a URL.
      expect(page.url()).not.toContain("reset-ticket");
      await expectNoSecretResidue(page, ["reset-ticket-1", STRONG, "123456", "۱۲۳۴۵۶", OTP_ID], "the reset by SMS code");
    });

    test("otp_invalid stays under the code; otp_expired and ticket_invalid start again with the message", async ({page, context}) => {
      let verifyAnswer: ReturnType<typeof err> | ReturnType<typeof verified> = err(401, "otp_invalid");
      const completeAnswer = err(401, "ticket_invalid");
      await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": () => verifyAnswer,
        "POST /auth/password/reset/complete": () => completeAnswer,
      });
      await toNewPassword(page, lang);
      await expect(field(page, "code")).toHaveValue("");
      await expect(page.getByRole("alert").filter({hasText: lang === "fa" ? "درست نیست" : "not correct"})).toBeVisible();

      verifyAnswer = err(401, "otp_expired");
      await page.keyboard.type("111111");
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("forgot.title"));
      await expect(field(page, "phone")).toHaveValue(PHONE);
      await expect(formAlert(page)).toContainText(lang === "fa" ? "منقضی" : "expired");

      // ticket_invalid at the last step (five minutes passed) goes back to step 1 as well.
      verifyAnswer = verified("none");
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("222222");
      await field(page, "new_password").fill(STRONG);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("forgot.title"));
      await expect(formAlert(page)).toBeVisible();
    });

    test("password_weak shows the server's reason under the new password", async ({page, context}) => {
      await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": verified("none"),
        "POST /auth/password/reset/complete": {status: 422, body: errorBody("password_weak", {fields: [{name: "new_password", code: "contains_phone"}]})},
      });
      await toNewPassword(page, lang);
      await field(page, "new_password").fill("09123456789xyz");
      await submit(page).click();
      // The reason is the field error; the page also has the "use a different number" button (wp8-r11-3), whose text has the same word.
      await expect(page.locator(".field-error").filter({hasText: lang === "fa" ? "شماره" : "phone number"})).toBeVisible();
      await expect(field(page, "new_password")).toHaveAttribute("aria-invalid", "true");
    });

    test("TOTP: the code goes with the new password, a wrong one is inline, a recovery code works", async ({page, context}) => {
      let answer: ReturnType<typeof err> | {status: number} = err(401, "totp_invalid");
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": verified("totp"),
        "POST /auth/password/reset/complete": () => answer,
      });
      await toNewPassword(page, lang);
      await field(page, "new_password").fill(STRONG);
      await expect(page.getByText(T("forgot.totpDescription"))).toBeVisible();
      await field(page, "totp_code").focus();
      await page.keyboard.type("123456");
      // The password was already there, so the finished code submits.
      await expect(field(page, "totp_code")).toHaveValue("");
      await expect(page.getByRole("alert").filter({hasText: lang === "fa" ? "درست نیست" : "not correct"})).toBeVisible();
      expect(lastBody(mock, "POST", "/auth/password/reset/complete")).toEqual({ticket: "reset-ticket-1", new_password: STRONG, totp_code: "123456"});

      answer = {status: 204};
      await page.getByRole("button", {name: T("login.twoFactor.useRecovery")}).click();
      await field(page, "recovery_code").pressSequentially("abcd-efgh-ijkl-1234");
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("forgot.doneTitle"));
      expect(lastBody(mock, "POST", "/auth/password/reset/complete")).toEqual({ticket: "reset-ticket-1", new_password: STRONG, recovery_code: "ABCDEFGHIJKL1234"});
      await expectNoSecretResidue(page, ["reset-ticket-1", STRONG, "123456", "ABCDEFGHIJKL1234", "abcd-efgh-ijkl-1234"], "the reset with a recovery code");
    });

    test("TOTP: no code is a field error before any request", async ({page, context}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": verified("totp"),
      });
      await toNewPassword(page, lang);
      await field(page, "new_password").fill(STRONG);
      await submit(page).click();
      await expect(page.getByText(T("fields.totp.required"))).toBeVisible();
      expect(callsTo(mock, "POST", "/auth/password/reset/complete")).toHaveLength(0);
    });

    test("passkey: the choice comes first, 'I lost my passkey' warns about 72 hours and completes with defer_enforce", async ({page, context}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": verified("passkey"),
        "POST /auth/password/reset/complete": {status: 204},
      });
      await toNewPassword(page, lang);
      await expect(page.getByText(T("forgot.passkeyText"))).toBeVisible();
      await expect(field(page, "new_password")).toHaveCount(0);
      await page.getByRole("button", {name: T("forgot.passkeyLost")}).click();
      await expect(page.getByText(T("forgot.passkeyLostWarning"))).toBeVisible();
      await field(page, "new_password").fill(STRONG);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("forgot.doneTitle"));
      await expect(page.getByText(T("forgot.doneDeferred"))).toBeVisible();
      await expectDoneToast(page, lang);
      expect(lastBody(mock, "POST", "/auth/password/reset/complete")).toEqual({ticket: "reset-ticket-1", new_password: STRONG, defer_enforce: true});
    });

    test("passkey: the proof gives a new ticket, which completes the reset without defer_enforce", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": verified("passkey"),
        "POST /auth/password/reset/passkey/begin": proofBegin(new URL(baseURL!).hostname),
        "POST /auth/password/reset/passkey/finish": {body: {ticket: "proven-ticket"}},
        "POST /auth/password/reset/complete": {status: 204},
      });
      await gotoForm(page, `/${lang}/forgot-password`);
      await virtualPasskey(page, context);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("123456");
      await page.getByRole("button", {name: T("forgot.passkeyUse")}).click();
      await expect(page.getByText(T("forgot.passkeyProven"))).toBeVisible();
      expect(lastBody(mock, "POST", "/auth/password/reset/passkey/begin")).toEqual({ticket: "reset-ticket-1"});
      const finish = callsTo(mock, "POST", "/auth/password/reset/passkey/finish")[0]!;
      expect(finish.headers["x-ctrlz-ticket"]).toBe("assertion-ticket");
      await field(page, "new_password").fill(STRONG);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("forgot.doneTitle"));
      expect(lastBody(mock, "POST", "/auth/password/reset/complete")).toEqual({ticket: "proven-ticket", new_password: STRONG});
      await expectDoneToast(page, lang);
      await expectNoSecretResidue(page, ["reset-ticket-1", "proven-ticket", "assertion-ticket", STRONG], "the reset with a passkey proof");
    });

    // wp8-r22-1: "I lost my passkey" costs 72 hours of password sign-in, so it can be taken back from the form.
    test("passkey: Back from 'I lost my passkey' returns to the choice, drops what was typed and completes with the proof, no defer_enforce", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": verified("passkey"),
        "POST /auth/password/reset/passkey/begin": proofBegin(new URL(baseURL!).hostname),
        "POST /auth/password/reset/passkey/finish": {body: {ticket: "proven-ticket"}},
        "POST /auth/password/reset/complete": {status: 204},
      });
      await gotoForm(page, `/${lang}/forgot-password`);
      await virtualPasskey(page, context);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("123456");
      await page.getByRole("button", {name: T("forgot.passkeyLost")}).click();
      await expect(page.getByText(T("forgot.passkeyLostWarning"))).toBeVisible();
      await expect(field(page, "new_password")).toBeFocused();
      await field(page, "new_password").fill(STRONG);
      await page.getByRole("button", {name: T("forgot.passkeyBack"), exact: true}).click();
      await expect(page.getByText(T("forgot.passkeyText"))).toBeVisible();
      await expect(page.getByText(T("forgot.passkeyLostWarning"))).toHaveCount(0);
      await expect(field(page, "new_password")).toHaveCount(0);
      // A second visit to the form starts empty and takes the focus again; the Back button exists only there.
      await page.getByRole("button", {name: T("forgot.passkeyLost")}).click();
      await expect(field(page, "new_password")).toHaveValue("");
      await expect(field(page, "new_password")).toBeFocused();
      await page.getByRole("button", {name: T("forgot.passkeyBack"), exact: true}).click();
      await page.getByRole("button", {name: T("forgot.passkeyUse")}).click();
      await expect(page.getByText(T("forgot.passkeyProven"))).toBeVisible();
      // wp8-r23-1: the first visit to the lost view used up the hook's one-time focus, so the proof must refocus.
      await expect(field(page, "new_password")).toBeFocused();
      await expect(page.getByRole("button", {name: T("forgot.passkeyBack"), exact: true})).toHaveCount(0);
      await field(page, "new_password").fill(STRONG);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("forgot.doneTitle"));
      expect(lastBody(mock, "POST", "/auth/password/reset/complete")).toEqual({ticket: "proven-ticket", new_password: STRONG});
      expect(callsTo(mock, "POST", "/auth/otp/request")).toHaveLength(1);
    });

    // wp8-r7-1: the rows of 10.4 and 10.6 that had working code and no case.
    test("otp_locked on the code goes back to the number with the wait in the message", async ({page, context}) => {
      await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": err(429, "otp_locked", {retry_after_s: 300}),
      });
      await toNewPassword(page, lang);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("forgot.title"));
      await expect(field(page, "phone")).toHaveValue(PHONE);
      await expect(formAlert(page)).toContainText(/300|۳۰۰/);
      // Not inline under a code field that no longer exists.
      await expect(field(page, "code")).toHaveCount(0);
    });

    test("totp_step_reused is inline under the code, which is cleared, and the step stays", async ({page, context}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": verified("totp"),
        "POST /auth/password/reset/complete": err(401, "totp_step_reused"),
      });
      await toNewPassword(page, lang);
      await field(page, "new_password").fill(STRONG);
      await field(page, "totp_code").focus();
      await page.keyboard.type("123456");
      await expect.poll(() => callsTo(mock, "POST", "/auth/password/reset/complete").length).toBe(1);
      await expect(page.getByText(errorText(lang, "totp_step_reused"))).toBeVisible();
      await expect(field(page, "totp_code")).toHaveValue("");
      await expect(field(page, "totp_code")).toHaveAttribute("aria-invalid", "true");
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("forgot.newTitle"));
      // The generic error line is not added beside it.
      await expect(formAlert(page)).toHaveCount(0);
    });

    test("passkey_invalid shows the exact neutral line in the choice card and the passkey button stays usable", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": verified("passkey"),
        "POST /auth/password/reset/passkey/begin": proofBegin(new URL(baseURL!).hostname),
        "POST /auth/password/reset/passkey/finish": err(401, "passkey_invalid"),
      });
      await gotoForm(page, `/${lang}/forgot-password`);
      await virtualPasskey(page, context);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("123456");
      const use = page.getByRole("button", {name: T("forgot.passkeyUse")});
      await use.click();
      // A proof on this page is not a sign-in, so the line says nothing about signing in (wp8-r24-1).
      await expect(formAlert(page).locator(".alert__description")).toHaveText(T("forgot.passkeyInvalid"));
      await expect(formAlert(page)).not.toContainText("passkey_invalid");
      await expect(page.getByText(T("forgot.passkeyText"))).toBeVisible();
      await expect(field(page, "new_password")).toHaveCount(0);
      // Usable again, and it runs the ceremony again.
      await expect(use).toBeEnabled();
      await use.click();
      await expect.poll(() => callsTo(mock, "POST", "/auth/password/reset/passkey/finish").length).toBe(2);
      expect(callsTo(mock, "POST", "/auth/password/reset/complete")).toHaveLength(0);
    });

    test("a wait on the number step is shown on the button, with the number kept", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/otp/request": err(429, "otp_limited", {retry_after_s: 60})});
      await gotoForm(page, `/${lang}/forgot-password`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(submit(page)).toBeDisabled();
      await expect(field(page, "phone")).toHaveValue(PHONE);
    });
  });
}
