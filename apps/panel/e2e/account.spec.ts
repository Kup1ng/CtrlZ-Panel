import {passkeyRowFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import type {MockHandler} from "@ctrlz/api-client/testing/mock.ts";
import type {Page} from "@playwright/test";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import {LIVE_ANNOUNCER} from "@ctrlz/ui/testing/axeLogic.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectNoSecretResidue} from "@ctrlz/ui/testing/secretResidue.ts";

import {
  acc,
  allowAccountErrors,
  bodies,
  broadcastFromBareTab,
  closeBareTab,
  openBareTab,
  err,
  fieldText,
  gotoAccount,
  LANGS,
  NEW_PHONE,
  open,
  PK_A,
  PK_B,
  PK_NEW,
  PK_STALE,
  passkeysFixture,
  row,
  SESSION_NEWER,
  SESSION_OLDER,
  sessionsFixture,
  TOTP_URI,
  typeCode,
  type Handlers,
} from "./account-support.ts";
import type {ApiMock} from "@ctrlz/api-client/testing/mock.ts";
import {errorText, STRONG_PASSWORD, text} from "./auth-support.ts";

// Spec 17.3 `account.spec.ts` (T-101, T-103, T-106, T-108, T-109, T-110, T-307, T-311): inline edit, the
// reauth variants, the phone change and its retry, the password, the two-step wizard, sessions, Log out
// all, passkeys, and the options, in mock mode (spec 17.1). The flows that need the real API or a
// real authenticator are in account.stack.spec.ts and run after the merge.

test.beforeEach(({guard}) => allowAccountErrors(guard));

const OLD = "123456";
const NEW_CODE = "654321";
const REQUEST_ID = "30000000-0000-4000-8000-000000000001";
const issuedPhone = {
  status: 202,
  body: {request_id: REQUEST_ID, old_challenge_id: "30000000-0000-4000-8000-0000000000a1", new_challenge_id: "30000000-0000-4000-8000-0000000000a2", expires_in_s: 300, resend_after_s: 60},
};

for (const {lang, dir} of LANGS) {
  test.describe(`account, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const A = (path: string, values?: Record<string, string | number>) => acc(lang, path, values);
    const T = (path: string) => text(lang, path);

    test("three sections of rows, an Edit button on a row, and only one row open at a time", async ({page, context, baseURL}) => {
      await open(context, baseURL);
      await gotoAccount(page, lang);
      await expect(page.getByRole("heading", {level: 1, name: A("page.title")})).toBeVisible();
      for (const key of ["details", "passkeys", "options"]) {
        await expect(page.getByRole("heading", {level: 2, name: A(`sections.${key}`)})).toBeVisible();
      }
      // Section titles are sentence case, not all-caps (DESIGN.md).
      expect(await page.getByRole("heading", {level: 2}).first().evaluate((el) => getComputedStyle(el).textTransform)).toBe("none");

      await row(page, "phone").getByRole("button", {name: A("phone.editAria")}).click();
      await expect(row(page, "phone").locator('input[name="password"]')).toBeVisible();
      await row(page, "password").getByRole("button", {name: A("password.changeAria")}).click();
      await expect(row(page, "password").locator('input[name="password"]')).toBeVisible();
      // The first row closed, and its editor is gone with whatever it held.
      await expect(row(page, "phone").locator('input[name="password"]')).toHaveCount(0);
      await expect(row(page, "phone").getByRole("button", {name: A("phone.editAria")})).toBeVisible();
    });

    // wp9-r1-1: a row that closes because another one opened must not pull the focus from the editor that just
    // appeared. The one order that used to fail is a lower row open first and an upper row opened after it.
    test("opening an upper row while a lower one is open leaves the focus in the new editor", async ({page, context, baseURL}) => {
      await open(context, baseURL, {handlers: {"GET /account/passkeys": {body: {passkeys: passkeysFixture()}}}});
      await gotoAccount(page, lang);
      await row(page, "sessions").getByRole("button", {name: A("sessions.manageAria")}).click();
      await expect(row(page, "sessions").getByRole("listitem").first()).toBeVisible();
      await row(page, "phone").getByRole("button", {name: A("phone.editAria")}).click();
      await expect(row(page, "phone").locator('input[name="password"]')).toBeFocused();
      await expect(row(page, "sessions").getByRole("listitem")).toHaveCount(0);

      // The same in the passkeys section: the rename of a passkey opens above the add row.
      await row(page, "passkey-add").getByRole("button", {name: A("passkeys.addAria")}).click();
      await expect(row(page, "passkey-add").locator('input[name="password"]')).toBeVisible();
      await row(page, `passkey-${PK_A}`).getByRole("button", {name: A("passkeys.renameAria", {name: "Work laptop"})}).click();
      await expect(row(page, `passkey-${PK_A}`).locator('input[name="passkey_name"]')).toBeFocused();
    });

    test("Cancel closes the editor and the focus goes back to Edit", async ({page, context, baseURL}) => {
      await open(context, baseURL);
      await gotoAccount(page, lang);
      const edit = row(page, "phone").getByRole("button", {name: A("phone.editAria")});
      await edit.click();
      await row(page, "phone").getByRole("button", {name: lang === "fa" ? "انصراف" : "Cancel"}).click();
      await expect(row(page, "phone").locator('input[name="password"]')).toHaveCount(0);
      await expect(edit).toBeFocused();
    });

    test.describe("reauth", () => {
      test("password only: the password goes to /auth/reauth and nothing else", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL);
        await gotoAccount(page, lang);
        await row(page, "phone").getByRole("button", {name: A("phone.editAria")}).click();
        await row(page, "phone").locator('input[name="password"]').fill("Correct-Horse-9");
        await row(page, "phone").getByRole("button", {name: A("reauth.submit")}).click();
        await expect(row(page, "phone").locator('input[name="new_phone"]')).toBeVisible();
        expect(bodies(mock, "POST", "/auth/reauth")).toEqual([{password: "Correct-Horse-9"}]);
      });

      test("a wrong password is said under the field and the row stays", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {handlers: {"POST /auth/reauth": err(401, "invalid_credentials")}});
        await gotoAccount(page, lang);
        await row(page, "phone").getByRole("button", {name: A("phone.editAria")}).click();
        await row(page, "phone").locator('input[name="password"]').fill("wrong");
        await row(page, "phone").getByRole("button", {name: A("reauth.submit")}).click();
        await expect(row(page, "phone").getByText(errorText(lang, "invalid_credentials"))).toBeVisible();
        await expect(row(page, "phone").locator('input[name="password"]')).toHaveValue("");
        expect(mock.count("POST /auth/reauth")).toBe(1);
      });

      test("password and authenticator: both are sent, a Persian-digit code goes out as ASCII, and a recovery code can stand in", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {me: {security: {totp_enabled: true, recovery_codes_left: 8}}});
        await gotoAccount(page, lang);
        await row(page, "phone").getByRole("button", {name: A("phone.editAria")}).click();
        await row(page, "phone").locator('input[name="password"]').fill("Correct-Horse-9");
        await typeCode(page, "totp_code", "۱۲۳۴۵۶");
        await expect(row(page, "phone").locator('input[name="new_phone"]')).toBeVisible();
        expect(bodies(mock, "POST", "/auth/reauth")).toEqual([{password: "Correct-Horse-9", totp_code: "123456"}]);

        await row(page, "password").getByRole("button", {name: A("password.changeAria")}).click();
        await row(page, "password").locator('input[name="password"]').fill("Correct-Horse-9");
        await row(page, "password").getByRole("button", {name: T("login.twoFactor.useRecovery")}).click();
        await row(page, "password").locator('input[name="recovery_code"]').fill("abcd-efgh-jkmn-pqrs");
        await row(page, "password").getByRole("button", {name: A("reauth.submit")}).click();
        await expect(row(page, "password").locator('input[name="new_password"]')).toBeVisible();
        expect(bodies(mock, "POST", "/auth/reauth").at(-1)).toEqual({password: "Correct-Horse-9", recovery_code: "ABCDEFGHJKMNPQRS"});
      });

      test("authenticator only: no password field, the code alone", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {me: {user: {has_password: false}, security: {totp_enabled: true, recovery_codes_left: 8}}});
        await gotoAccount(page, lang);
        await row(page, "phone").getByRole("button", {name: A("phone.editAria")}).click();
        await expect(row(page, "phone").locator('input[name="password"]')).toHaveCount(0);
        await typeCode(page, "totp_code", "123456");
        await expect(row(page, "phone").locator('input[name="new_phone"]')).toBeVisible();
        expect(bodies(mock, "POST", "/auth/reauth")).toEqual([{totp_code: "123456"}]);
      });

      test("neither: Send code, then the code of that request goes to /auth/reauth", async ({page, context, baseURL}) => {
        const challenge = "40000000-0000-4000-8000-000000000001";
        const mock = await open(context, baseURL, {
          me: {user: {has_password: false}},
          handlers: {"POST /auth/reauth/otp/request": {status: 202, body: {challenge_id: challenge, expires_in_s: 300, resend_after_s: 60}}},
        });
        await gotoAccount(page, lang);
        await row(page, "phone").getByRole("button", {name: A("phone.editAria")}).click();
        // No code field and no password field before a code was asked for.
        await expect(row(page, "phone").locator('input[name="otp_code"]')).toHaveCount(0);
        await row(page, "phone").getByRole("button", {name: A("reauth.send")}).click();
        await expect(row(page, "phone").locator('input[name="otp_code"]')).toBeFocused();
        expect(bodies(mock, "POST", "/auth/reauth/otp/request")).toEqual([undefined]);
        await page.keyboard.type("112233");
        await expect(row(page, "phone").locator('input[name="new_phone"]')).toBeVisible();
        expect(bodies(mock, "POST", "/auth/reauth")).toEqual([{otp_challenge_id: challenge, otp_code: "112233"}]);
        // gate-r27-5: ReauthPanel is shared by the phone, password, two-step and passkey rows; it keeps the challenge and the code in state only.
        await expectNoSecretResidue(page, [challenge, "112233"], "the reauthentication by SMS code");
      });

      test("Use a passkey is offered with a live passkey, and not while a review is pending or passkeys are off", async ({page, context, baseURL}) => {
        await open(context, baseURL, {me: {security: {passkeys: 1}}});
        await gotoAccount(page, lang);
        await row(page, "phone").getByRole("button", {name: A("phone.editAria")}).click();
        await expect(row(page, "phone").getByRole("button", {name: A("reauth.passkey")})).toBeVisible();

        const review = await context.newPage();
        await open(context, baseURL, {me: {security: {passkeys: 1, passkey_review_required: true}}});
        await gotoAccount(review, lang);
        await row(review, "phone").getByRole("button", {name: A("phone.editAria")}).click();
        await expect(row(review, "phone").locator('input[name="password"]')).toBeVisible();
        await expect(row(review, "phone").getByRole("button", {name: A("reauth.passkey")})).toHaveCount(0);

        const off = await context.newPage();
        await open(context, baseURL, {me: {security: {passkeys: 1}}, passkeyEnabled: false});
        await gotoAccount(off, lang);
        await row(off, "phone").getByRole("button", {name: A("phone.editAria")}).click();
        await expect(row(off, "phone").locator('input[name="password"]')).toBeVisible();
        await expect(row(off, "phone").getByRole("button", {name: A("reauth.passkey")})).toHaveCount(0);
      });
    });

    test.describe("phone change", () => {
      async function toCodes(page: Page) {
        await row(page, "phone").getByRole("button", {name: A("phone.editAria")}).click();
        await row(page, "phone").locator('input[name="password"]').fill("Correct-Horse-9");
        await row(page, "phone").getByRole("button", {name: A("reauth.submit")}).click();
        await row(page, "phone").locator('input[name="new_phone"]').fill(NEW_PHONE);
        await row(page, "phone").getByRole("button", {name: A("phone.sendCodes")}).click();
        await expect(row(page, "phone").locator('input[name="old_code"]')).toBeFocused();
      }

      test("both codes are asked for, a typo in one clears only that one, and the retry finishes the change", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {
          handlers: {
            "POST /account/phone/change": issuedPhone,
            "POST /account/phone/change/{id}/confirm": (call, state) => {
              const sent = call.body as {old_code: string; new_code: string};
              if (sent.new_code !== NEW_CODE) return err(401, "otp_invalid", {fields: [{name: "new_code", code: "invalid"}]});
              state.me = {...state.me, user: {...state.me.user, phone_masked: "0935***4567"}};
              return {status: 204};
            },
          },
        });
        await gotoAccount(page, lang);
        await toCodes(page);
        expect(bodies(mock, "POST", "/account/phone/change")).toEqual([{new_phone: NEW_PHONE, locale: lang}]);
        // The countdown starts from expires_in_s (5 minutes).
        await expect(row(page, "phone").getByText(/[45][:٫][0-5][0-9]|[۴۵][:٫][۰-۵][۰-۹]/)).toBeVisible();

        await typeCode(page, "old_code", OLD);
        await expect(row(page, "phone").locator('input[name="new_code"]')).toBeFocused();
        await page.keyboard.type("000000");
        await expect(row(page, "phone").getByText(errorText(lang, "otp_invalid"))).toBeVisible();
        // Only the code the server named is cleared; the other stays typed.
        await expect(row(page, "phone").locator('input[name="new_code"]')).toHaveValue("");
        await expect(row(page, "phone").locator('input[name="old_code"]')).toHaveValue(OLD);

        await page.keyboard.type(NEW_CODE);
        await expect(row(page, "phone").locator('input[name="old_code"]')).toHaveCount(0);
        expect(bodies(mock, "POST", `/account/phone/change/${REQUEST_ID}/confirm`)).toEqual([
          {old_code: OLD, new_code: "000000"},
          {old_code: OLD, new_code: NEW_CODE},
        ]);
        // The cache was refreshed: the row shows the new number, and the toast says what ended.
        await expect(row(page, "phone")).toContainText("0935");
        await expect(page.getByText(A("phone.done"))).toBeVisible();
        // gate-r27-5: both SMS codes, the one that failed, the change id and the password used to reauthenticate.
        await expectNoSecretResidue(page, [OLD, NEW_CODE, "000000", REQUEST_ID, "Correct-Horse-9"], "the phone change");
      });

      // T-307. The change ends the other sessions and the API tokens, and a thief who held one could have added a passkey: with a passkey on the
      // account the toast also sends the person to the Passkeys section. Without one it says only what ended (the case above, `phone.done`).
      test("with a passkey on the account the toast of a phone change says to check the passkeys (T-307)", async ({page, context, baseURL}) => {
        await open(context, baseURL, {
          me: {security: {passkeys: 1}},
          handlers: {
            "POST /account/phone/change": issuedPhone,
            "POST /account/phone/change/{id}/confirm": (_call, state) => {
              state.me = {...state.me, user: {...state.me.user, phone_masked: "0935***4567"}};
              return {status: 204};
            },
          },
        });
        await gotoAccount(page, lang);
        // Past the passkey reauth button, which the row offers first: the password field is the other way in.
        await row(page, "phone").getByRole("button", {name: A("phone.editAria")}).click();
        await row(page, "phone").locator('input[name="password"]').fill("Correct-Horse-9");
        await row(page, "phone").getByRole("button", {name: A("reauth.submit")}).click();
        await row(page, "phone").locator('input[name="new_phone"]').fill(NEW_PHONE);
        await row(page, "phone").getByRole("button", {name: A("phone.sendCodes")}).click();
        await typeCode(page, "old_code", OLD);
        await page.keyboard.type(NEW_CODE);
        await expect(row(page, "phone")).toContainText("0935");
        const toast = page.locator(".toast");
        await expect(toast).toContainText(A("phone.doneWithPasskeys"));
        // The whole sentence, and not the shorter one that an account with no passkey gets.
        await expect(toast.getByText(A("phone.done"), {exact: true})).toHaveCount(0);
      });

      // gate-r27-5: the check can fail on this flow. A debugging line that prints every request body (a console.info of the confirm body left in
      // by mistake) puts the two codes and the change id in the console, and the residue check must name the console and not the codes.
      test("a console line that prints the confirm body is found by the residue check of the phone change (gate-r27-5)", async ({page, context, baseURL}) => {
        await page.addInitScript(() => {
          const send = window.fetch.bind(window);
          // The API client calls fetch with a Request (openapi-fetch), so the body is read from a clone of it.
          window.fetch = async (input, init) => {
            const body = input instanceof Request ? await input.clone().text() : init?.body;
            if (typeof body === "string" && body) console.info("debug " + body);
            return send(input, init);
          };
        });
        await open(context, baseURL, {handlers: {"POST /account/phone/change": issuedPhone, "POST /account/phone/change/{id}/confirm": {status: 204}}});
        await gotoAccount(page, lang);
        await toCodes(page);
        await typeCode(page, "old_code", OLD);
        await page.keyboard.type(NEW_CODE);
        await expect(row(page, "phone").locator('input[name="old_code"]')).toHaveCount(0);
        const text = await expectNoSecretResidue(page, [OLD, NEW_CODE], "the phone change").then(
          () => "",
          (e: unknown) => String((e as Error).message),
        );
        expect(text).toContain("a console message");
        expect(text).not.toContain(NEW_CODE);
      });

      // wp9-r1-3 (AUTH 14.3): the field's own code decides. A wrong code is retried alone; an expired or locked one
      // cannot be, so both fields are cleared and the line points at "Send new codes".
      for (const code of ["locked", "expired"] as const) {
        test(`a ${code} code clears both fields and says to send new codes`, async ({page, context, baseURL}) => {
          await open(context, baseURL, {
            handlers: {
              "POST /account/phone/change": issuedPhone,
              "POST /account/phone/change/{id}/confirm": err(401, "otp_invalid", {fields: [{name: "new_code", code}]}),
            },
          });
          await gotoAccount(page, lang);
          await toCodes(page);
          await typeCode(page, "old_code", OLD);
          await page.keyboard.type(NEW_CODE);
          const phone = row(page, "phone");
          await expect(phone.getByText(A(code === "locked" ? "phone.codeLocked" : "phone.codeExpired"))).toBeVisible();
          await expect(phone.getByText(errorText(lang, "otp_invalid"))).toHaveCount(0);
          await expect(phone.locator('input[name="old_code"]')).toHaveValue("");
          await expect(phone.locator('input[name="new_code"]')).toHaveValue("");
        });
      }

      test("the same number is refused with its own line, and a taken number goes back to the number step", async ({page, context, baseURL}) => {
        let same = true;
        const mock = await open(context, baseURL, {
          handlers: {
            "POST /account/phone/change": () => (same ? err(422, "validation_failed", {fields: [{name: "new_phone", code: "same_phone"}]}) : issuedPhone),
            "POST /account/phone/change/{id}/confirm": err(409, "phone_unavailable"),
          },
        });
        await gotoAccount(page, lang);
        await row(page, "phone").getByRole("button", {name: A("phone.editAria")}).click();
        await row(page, "phone").locator('input[name="password"]').fill("Correct-Horse-9");
        await row(page, "phone").getByRole("button", {name: A("reauth.submit")}).click();
        await row(page, "phone").locator('input[name="new_phone"]').fill("09121234567");
        await row(page, "phone").getByRole("button", {name: A("phone.sendCodes")}).click();
        await expect(row(page, "phone").getByText(A("phone.same"))).toBeVisible();

        same = false;
        await row(page, "phone").locator('input[name="new_phone"]').fill(NEW_PHONE);
        await row(page, "phone").getByRole("button", {name: A("phone.sendCodes")}).click();
        await typeCode(page, "old_code", OLD);
        await page.keyboard.type(NEW_CODE);
        await expect(row(page, "phone").locator('input[name="new_phone"]')).toBeVisible();
        await expect(row(page, "phone").getByText(errorText(lang, "phone_unavailable"))).toBeVisible();
        expect(mock.count("POST /account/phone/change")).toBe(2);
      });

      test("Send new codes asks again, with the same number, and the fields start empty", async ({page, context, baseURL}) => {
        await page.clock.install();
        const mock = await open(context, baseURL, {handlers: {"POST /account/phone/change": issuedPhone}});
        await gotoAccount(page, lang);
        await toCodes(page);
        await typeCode(page, "old_code", OLD);
        // Resend is off until resend_after_s has passed.
        const resend = row(page, "phone").getByRole("button", {name: lang === "fa" ? /^ارسال دوباره/ : /^Resend/});
        await expect(resend).toBeDisabled();
        await page.clock.fastForward(61_000);
        await expect(resend).toBeEnabled();
        await resend.click();
        await expect(row(page, "phone").locator('input[name="old_code"]')).toHaveValue("");
        expect(bodies(mock, "POST", "/account/phone/change")).toEqual([
          {new_phone: NEW_PHONE, locale: lang},
          {new_phone: NEW_PHONE, locale: lang},
        ]);
      });

      test("when five minutes have passed the codes are refused on the page and Send new codes is the way on", async ({page, context, baseURL}) => {
        await page.clock.install();
        const mock = await open(context, baseURL, {handlers: {"POST /account/phone/change": issuedPhone}});
        await gotoAccount(page, lang);
        await toCodes(page);
        await page.clock.fastForward(301_000);
        await expect(row(page, "phone").getByText(A("phone.expired"))).toBeVisible();
        await expect(row(page, "phone").locator('input[name="old_code"]')).toBeDisabled();
        await row(page, "phone").getByRole("button", {name: T("resend.action")}).click();
        await expect(row(page, "phone").locator('input[name="old_code"]')).toBeEnabled();
        expect(mock.count("POST /account/phone/change")).toBe(2);
      });
    });

    test.describe("password", () => {
      const open_ = async (page: Page) => {
        await row(page, "password").getByRole("button", {name: A("password.changeAria")}).click();
        await row(page, "password").locator('input[name="password"]').fill("Correct-Horse-9");
        await row(page, "password").getByRole("button", {name: A("reauth.submit")}).click();
        await expect(row(page, "password").locator('input[name="new_password"]')).toBeFocused();
      };

      test("reauth, then the new password with its meter; only the password is sent, and the toast says what ended", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {handlers: {"POST /account/password": {status: 204}}});
        await gotoAccount(page, lang);
        await open_(page);
        await expect(page.getByRole("meter")).toHaveCount(0);
        await row(page, "password").locator('input[name="new_password"]').fill(STRONG_PASSWORD);
        await expect(page.getByRole("meter")).toBeVisible();
        await row(page, "password").getByRole("button", {name: A("password.save")}).click();
        await expect(page.getByText(A("password.done"))).toBeVisible();
        expect(bodies(mock, "POST", "/account/password")).toEqual([{new_password: STRONG_PASSWORD}]);
        // The row is closed again, and nothing of the password is in the page.
        await expect(row(page, "password").locator('input[name="new_password"]')).toHaveCount(0);
        expect(new URL(page.url()).search).toBe("");
        await expectNoSecretResidue(page, [STRONG_PASSWORD, "Correct-Horse-9"], "the password change");
      });

      test("a password the server calls weak is explained under the field", async ({page, context, baseURL}) => {
        await open(context, baseURL, {
          handlers: {"POST /account/password": err(422, "password_weak", {fields: [{name: "password", code: "too_short"}]})},
        });
        await gotoAccount(page, lang);
        await open_(page);
        await row(page, "password").locator('input[name="new_password"]').fill("short-one-1");
        await row(page, "password").getByRole("button", {name: A("password.save")}).click();
        await expect(row(page, "password").getByText(fieldText(lang, "too_short"))).toBeVisible();
      });

      test("an account with no password sets its first one in the same row", async ({page, context, baseURL}) => {
        const challenge = "40000000-0000-4000-8000-000000000002";
        const mock = await open(context, baseURL, {
          me: {user: {has_password: false}},
          handlers: {
            "POST /auth/reauth/otp/request": {status: 202, body: {challenge_id: challenge, expires_in_s: 300, resend_after_s: 60}},
            "POST /account/password": {status: 204},
          },
        });
        await gotoAccount(page, lang);
        await expect(row(page, "password")).toContainText(A("password.valueNone"));
        await row(page, "password").getByRole("button", {name: A("password.setAria")}).click();
        await row(page, "password").getByRole("button", {name: A("reauth.send")}).click();
        // The code field takes the focus when the answer to the request comes. Typing before that goes nowhere, the code is never complete and
        // the password field never appears (a failure of the full run under load, gate-r7), so the focus is waited for, as the phone row does.
        await expect(row(page, "password").locator('input[name="otp_code"]')).toBeFocused();
        await page.keyboard.type("445566");
        await row(page, "password").locator('input[name="new_password"]').fill(STRONG_PASSWORD);
        await row(page, "password").getByRole("button", {name: A("password.saveFirst")}).click();
        await expect(page.getByText(A("password.doneFirst"))).toBeVisible();
        expect(bodies(mock, "POST", "/account/password")).toEqual([{new_password: STRONG_PASSWORD}]);
      });

      test("a window that ended while the person typed opens the reauth dialog, and the save is repeated once", async ({page, context, baseURL}) => {
        let calls = 0;
        const mock = await open(context, baseURL, {
          handlers: {"POST /account/password": () => (++calls === 1 ? err(403, "reauth_required") : {status: 204})},
        });
        await gotoAccount(page, lang);
        await open_(page);
        await row(page, "password").locator('input[name="new_password"]').fill(STRONG_PASSWORD);
        await row(page, "password").getByRole("button", {name: A("password.save")}).click();
        const dialog = page.getByRole("dialog");
        await expect(dialog.getByRole("heading", {name: A("reauth.title")})).toBeVisible();
        await dialog.locator('input[name="password"]').fill("Correct-Horse-9");
        await dialog.getByRole("button", {name: A("reauth.confirm")}).click();
        await expect(page.getByText(A("password.done"))).toBeVisible();
        expect(mock.count("POST /account/password")).toBe(2);
        expect(mock.count("POST /auth/reauth")).toBe(2);
      });

      test("giving up on the reauth dialog leaves the row with the reason", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {handlers: {"POST /account/password": err(403, "reauth_required")}});
        await gotoAccount(page, lang);
        await open_(page);
        await row(page, "password").locator('input[name="new_password"]').fill(STRONG_PASSWORD);
        await row(page, "password").getByRole("button", {name: A("password.save")}).click();
        await page.getByRole("dialog").getByRole("button", {name: lang === "fa" ? "انصراف" : "Cancel"}).click();
        await expect(row(page, "password").getByText(errorText(lang, "reauth_required"))).toBeVisible();
        expect(mock.count("POST /account/password")).toBe(1);
      });
    });

    test.describe("two-step verification", () => {
      const CODES = Array.from({length: 10}, (_, i) => `ABCD-EFGH-JKMN-PQ${String(i).padStart(2, "0")}`);
      const SECRET = "JBSWY3DPEHPK3PXP";
      const dialog = (page: Page) => page.getByRole("dialog");

      const enableHandlers = (): Handlers => ({
        "POST /account/totp/setup": {body: {secret: SECRET, otpauth_uri: TOTP_URI}},
        "POST /account/totp/confirm": (call, mockState) => {
          const sent = call.body as {code: string; saved: boolean};
          if (sent.code !== "123456") return err(401, "totp_invalid");
          mockState.me = {...mockState.me, security: {...mockState.me.security, totp_enabled: true, recovery_codes_left: 10}};
          return {body: {recovery_codes: CODES, ended_sessions: 2}};
        },
      });

      async function toVerify(page: Page) {
        await row(page, "totp").getByRole("button", {name: A("totp.enable")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await dialog(page).getByRole("button", {name: A("reauth.submit")}).click();
        await expect(dialog(page).getByTestId("totp-qr")).toBeVisible();
        await dialog(page).getByRole("button", {name: lang === "fa" ? "ادامه" : "Continue"}).click();
        await expect(dialog(page).locator('input[name="totp_code"]')).toBeFocused();
      }

      test("enable: reauth, the QR and the key, the saved tick and the code, then the recovery codes once", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {handlers: enableHandlers()});
        await gotoAccount(page, lang);
        await expect(row(page, "totp")).toContainText(A("totp.off"));
        await row(page, "totp").getByRole("button", {name: A("totp.enable")}).click();
        // A stepper of four steps with the current one named.
        await expect(dialog(page).getByRole("heading", {name: A("totp.step0")})).toBeVisible();
        expect(mock.count("POST /account/totp/setup")).toBe(0);
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await dialog(page).getByRole("button", {name: A("reauth.submit")}).click();

        await expect(dialog(page).getByRole("heading", {name: A("totp.step1")})).toBeVisible();
        await expect(dialog(page).getByTestId("totp-qr").locator("svg")).toBeVisible();
        await expect(dialog(page).getByTestId("totp-secret")).toContainText("JBSW Y3DP EHPK 3PXP");
        // gate-r3-12: the browser's page translation sends text nodes to the vendor's server, so a one-time secret must be marked.
        await expect(dialog(page).getByTestId("totp-secret").locator("xpath=ancestor-or-self::*[@translate='no']")).not.toHaveCount(0);
        // The secret is made once, when the step is reached.
        expect(mock.count("POST /account/totp/setup")).toBe(1);
        await dialog(page).getByRole("button", {name: lang === "fa" ? "ادامه" : "Continue"}).click();

        // The tick comes first: a code without it is not sent.
        await expect(dialog(page).locator('input[name="totp_code"]')).toBeFocused();
        await page.keyboard.type("000000");
        await expect(dialog(page).getByText(A("totp.savedRequired"))).toBeVisible();
        expect(mock.count("POST /account/totp/confirm")).toBe(0);

        // Ticking the box sends the code that is already typed.
        await dialog(page).getByRole("checkbox", {name: A("totp.saved")}).check({force: true});
        await expect(dialog(page).getByText(errorText(lang, "totp_invalid"))).toBeVisible();
        await expect(dialog(page).locator('input[name="totp_code"]')).toHaveValue("");
        await page.keyboard.type("123456");

        await expect(dialog(page).getByRole("heading", {name: A("totp.step3")})).toBeVisible();
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
        await expect(dialog(page).getByTestId("recovery-codes").locator("xpath=ancestor-or-self::*[@translate='no']")).not.toHaveCount(0);
        expect(bodies(mock, "POST", "/account/totp/confirm")).toEqual([
          {code: "000000", saved: true},
          {code: "123456", saved: true},
        ]);
        // Secret and codes are in the dialog's state only: nothing in the address bar.
        expect(page.url()).not.toContain(SECRET);
        expect(new URL(page.url()).search).toBe("");
        // gate-r16-8: nowhere else either, while the secret and the codes are on screen: no storage, no history state, no cache.
        await expectNoSecretResidue(page, [SECRET, ...CODES, "Correct-Horse-9", "000000", "123456"], "enabling two-step verification");

        // Download goes through a Blob and an <a download>: no request.
        const before = mock.calls.length;
        const download = page.waitForEvent("download");
        await dialog(page).getByRole("button", {name: A("totp.download")}).click();
        const file = await download;
        expect(file.suggestedFilename()).toBe("ctrlz-recovery-codes.txt");
        const content = await (await import("node:fs/promises")).readFile((await file.path())!, "utf8");
        for (const code of CODES) expect(content).toContain(code);
        expect(mock.calls.length).toBe(before);

        // Closing asks first, and "keep them open" leaves everything as it was.
        await dialog(page).getByRole("button", {name: lang === "fa" ? "بستن" : "Close"}).first().click();
        await expect(dialog(page).getByText(A("totp.closeAsk"))).toBeVisible();
        await dialog(page).getByRole("button", {name: A("totp.closeKeep")}).click();
        await expect(dialog(page).getByTestId("recovery-codes")).toBeVisible();
        await dialog(page).getByRole("button", {name: A("totp.saveDone")}).click();
        await expect(dialog(page)).toHaveCount(0);

        // The row followed /me, and the sessions that ended were reported.
        await expect(row(page, "totp")).toContainText(A("totp.on"));
        await expect(row(page, "totp").getByRole("button", {name: A("totp.disable")})).toBeVisible();
        await expectNoSecretResidue(page, [SECRET, ...CODES, "Correct-Horse-9", "123456"], "enabling two-step verification, after the dialog closed");
      });

      // gate-r1-17: clipboard-write=(self) in the Permissions-Policy of 15.1 is for these two buttons. The header string is checked by
      // headersSpec, which is edited together with the header, so this is the case that fails when the feature is switched off for the
      // page: writeText then rejects and the button shows "could not copy" instead of "Copied".
      test("Copy on the secret and on the recovery codes reaches the clipboard under the page's Permissions-Policy", async ({page, context, baseURL}) => {
        await context.grantPermissions(["clipboard-read", "clipboard-write"], {origin: new URL(baseURL!).origin});
        await open(context, baseURL, {handlers: enableHandlers()});
        await gotoAccount(page, lang);
        const copied = lang === "fa" ? "کپی شد" : "Copied";
        const copy = dialog(page).getByRole("button", {name: lang === "fa" ? "کپی" : "Copy", exact: true});
        // Windows returns line breaks as CRLF from the system clipboard.
        const clipboard = () => page.evaluate(() => navigator.clipboard.readText()).then((t) => t.split(/\r?\n/).join("\n"));

        await row(page, "totp").getByRole("button", {name: A("totp.enable")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await dialog(page).getByRole("button", {name: A("reauth.submit")}).click();
        await expect(dialog(page).getByTestId("totp-qr")).toBeVisible();
        await copy.click();
        await expect(page.getByText(copied, {exact: true}).first()).toBeVisible();
        await expect(page.getByText(A("totp.copyFailed"))).toHaveCount(0);
        expect(await clipboard()).toBe(SECRET);

        await dialog(page).getByRole("button", {name: lang === "fa" ? "ادامه" : "Continue"}).click();
        await expect(dialog(page).locator('input[name="totp_code"]')).toBeFocused();
        await dialog(page).getByRole("checkbox", {name: A("totp.saved")}).check({force: true});
        await typeCode(page, "totp_code", "123456");
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
        await page.evaluate(() => navigator.clipboard.writeText("cleared"));
        await copy.click();
        await expect.poll(clipboard).toBe(CODES.join("\n"));
        await expect(page.getByText(A("totp.copyFailed"))).toHaveCount(0);
      });

      // gate-r5-8: Copy puts the secret and the codes in the system clipboard, a store that outlives the screen, the tab and the session.
      // Closing the wizard, whichever way and at whichever step, overwrites what it copied; the note beside Copy says what a page cannot reach.
      test("what Copy put in the clipboard is overwritten when the wizard closes, and the note says what is out of reach", async ({page, context, baseURL}) => {
        await context.grantPermissions(["clipboard-read", "clipboard-write"], {origin: new URL(baseURL!).origin});
        await open(context, baseURL, {handlers: enableHandlers()});
        await gotoAccount(page, lang);
        const copy = dialog(page).getByRole("button", {name: lang === "fa" ? "کپی" : "Copy", exact: true});
        const clipboard = () => page.evaluate(() => navigator.clipboard.readText()).then((t) => t.split(/\r?\n/).join("\n"));
        const startWizard = async () => {
          await row(page, "totp").getByRole("button", {name: A("totp.enable")}).click();
          await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
          await dialog(page).getByRole("button", {name: A("reauth.submit")}).click();
          await expect(dialog(page).getByTestId("totp-qr")).toBeVisible();
        };

        // The scan step, left with the Cancel button.
        await startWizard();
        await expect(dialog(page).getByTestId("copy-note")).toHaveText(A("totp.copyNote"));
        await copy.click();
        await expect.poll(clipboard).toBe(SECRET);
        await dialog(page).getByRole("button", {name: lang === "fa" ? "انصراف" : "Cancel"}).click();
        await expect(dialog(page)).toHaveCount(0);
        await expect.poll(clipboard).toBe("");

        // The scan step again, left with Escape, which is no user activation: the write still goes through where the permission is granted.
        await startWizard();
        await copy.click();
        await expect.poll(clipboard).toBe(SECRET);
        await page.keyboard.press("Escape");
        await expect(dialog(page)).toHaveCount(0);
        await expect.poll(clipboard).toBe("");

        // The codes, left with the last button. The confirmation of leaving is not asked on a normal finish, and the codes are gone from the clipboard.
        await startWizard();
        await dialog(page).getByRole("button", {name: lang === "fa" ? "ادامه" : "Continue"}).click();
        await dialog(page).getByRole("checkbox", {name: A("totp.saved")}).check({force: true});
        await typeCode(page, "totp_code", "123456");
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
        await expect(dialog(page).getByTestId("copy-note")).toHaveText(A("totp.copyNote"));
        await copy.click();
        await expect.poll(clipboard).toBe(CODES.join("\n"));
        await dialog(page).getByRole("button", {name: A("totp.saveDone")}).click();
        await expect(dialog(page)).toHaveCount(0);
        await expect.poll(clipboard).toBe("");
      });

      // gate-r8-8. The Regenerate dialog offers the same Copy on the codes through the same CodesView, and its wipe is a separate call, which no
      // test reached: deleting it left every case green. The codes are copied, and the dialog is left with the last button, and with Escape and the
      // confirmation; each time the clipboard must be empty.
      test("Regenerate: what Copy put in the clipboard is overwritten when the dialog closes, by the last button and by Escape with the confirmation", async ({page, context, baseURL}) => {
        await context.grantPermissions(["clipboard-read", "clipboard-write"], {origin: new URL(baseURL!).origin});
        await open(context, baseURL, {
          me: {security: {totp_enabled: true, recovery_codes_left: 2}},
          handlers: {"POST /account/totp/recovery-codes": {body: {recovery_codes: CODES}}},
        });
        await gotoAccount(page, lang);
        const clipboard = () => page.evaluate(() => navigator.clipboard.readText()).then((t) => t.split(/\r?\n/).join("\n"));
        const startRegenerate = async () => {
          await row(page, "totp").getByRole("button", {name: A("totp.regenerate")}).click();
          await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
          await typeCode(page, "totp_code", "123456");
          await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
          await expect(dialog(page).getByTestId("copy-note")).toHaveText(A("totp.copyNote"));
          await dialog(page).getByRole("button", {name: lang === "fa" ? "کپی" : "Copy", exact: true}).click();
          await expect.poll(clipboard).toBe(CODES.join("\n"));
        };

        await startRegenerate();
        await dialog(page).getByRole("button", {name: A("totp.saveDone")}).click();
        await expect(dialog(page)).toHaveCount(0);
        await expect.poll(clipboard).toBe("");

        await startRegenerate();
        await page.keyboard.press("Escape");
        await dialog(page).getByRole("button", {name: A("totp.closeAnyway")}).click();
        await expect(dialog(page)).toHaveCount(0);
        await expect.poll(clipboard).toBe("");
      });

      // gate-r33-7. The jump palette's pick is a router push that no leave guard stops, so over the dialog that holds the new recovery codes (the
      // old ones are already dead) Ctrl+K would drop them with no confirmation. The key opens nothing there, and the codes stay.
      test("Regenerate: Control+K does not open the jump palette over the recovery codes (gate-r33-7)", async ({page, context, baseURL}) => {
        await open(context, baseURL, {
          me: {security: {totp_enabled: true, recovery_codes_left: 2}},
          handlers: {"POST /account/totp/recovery-codes": {body: {recovery_codes: CODES}}},
        });
        await gotoAccount(page, lang);
        await row(page, "totp").getByRole("button", {name: A("totp.regenerate")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await typeCode(page, "totp_code", "123456");
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
        await page.keyboard.press("Control+k");
        await page.keyboard.press("Enter");
        await expect(page.getByRole("dialog", {name: lang === "fa" ? "پرش به صفحه" : "Jump to a page"})).toHaveCount(0);
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
        await expect(page).toHaveURL(new RegExp(`/${lang}/preferences/account`));
      });

      // gate-r34-5. Below 48rem Ctrl+B opens the mobile nav sheet, whose links are router pushes no leave guard stops: over the codes it would
      // let one click drop them. The key opens no sheet over a dialog, and the codes stay.
      test("Regenerate: Control+B does not open the mobile nav sheet over the recovery codes (gate-r34-5)", async ({page, context, baseURL}) => {
        await open(context, baseURL, {
          me: {security: {totp_enabled: true, recovery_codes_left: 2}},
          handlers: {"POST /account/totp/recovery-codes": {body: {recovery_codes: CODES}}},
        });
        await page.setViewportSize({width: 700, height: 800});
        await gotoAccount(page, lang);
        await row(page, "totp").getByRole("button", {name: A("totp.regenerate")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await typeCode(page, "totp_code", "123456");
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
        await page.keyboard.press("Control+b");
        await expect(page.locator(".sidebar__mobile-sheet")).toHaveCount(0);
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
      });

      // gate-r34-1. A toast is an alertdialog with aria-modal=false and the page behind it works: the shortcut must not count it as a modal.
      test("Control+K opens the jump palette while a toast is on screen (gate-r34-1)", async ({page, context, baseURL, guard}) => {
        guard.allowConsole(/status of 502/);
        await open(context, baseURL, {handlers: {"PATCH /account/preferences": {status: 502}}});
        await gotoAccount(page, lang);
        await page.getByText(A("options.hints"), {exact: true}).click();
        await expect(page.locator('[data-slot="toast"]')).toBeVisible();
        await page.keyboard.press("Control+k");
        await expect(page.getByRole("dialog", {name: lang === "fa" ? "پرش به صفحه" : "Jump to a page"})).toBeVisible();
      });

      // gate-r6-8 and gate-r6-6. The secret and every recovery code are `select-all`, so a person copies them with Ctrl+C and not with the button,
      // and a browser refuses the wipe when the document has no focus, which is the case for the idle cover and for a logout in another tab.
      // The first test copies by hand. The second makes the browser refuse the wipe (Playwright gives every page focus, so a refusal has to
      // be made): the copy must stay remembered, be wiped at the next press in the page, and, across a full load, at once on the new page.
      test("a copy made by hand with Ctrl+C is wiped when the wizard closes, and a copy of something else from the page is left alone", async ({page, context, baseURL}) => {
        await context.grantPermissions(["clipboard-read", "clipboard-write"], {origin: new URL(baseURL!).origin});
        await open(context, baseURL, {handlers: enableHandlers()});
        await gotoAccount(page, lang);
        const clipboard = () => page.evaluate(() => navigator.clipboard.readText()).then((t) => t.split(/\r?\n/).join("\n"));
        const cancel = () => dialog(page).getByRole("button", {name: lang === "fa" ? "انصراف" : "Cancel"});
        const startWizard = async () => {
          await row(page, "totp").getByRole("button", {name: A("totp.enable")}).click();
          await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
          await dialog(page).getByRole("button", {name: A("reauth.submit")}).click();
          await expect(dialog(page).getByTestId("totp-qr")).toBeVisible();
        };

        // The secret is selected by one click (select-all) and copied with the key: no Copy button, no clipboard call of ours.
        await startWizard();
        await dialog(page).getByTestId("totp-secret").click();
        await page.keyboard.press("Control+c");
        await expect.poll(clipboard).toContain(SECRET.slice(0, 4));
        await cancel().click();
        await expect(dialog(page)).toHaveCount(0);
        await expect.poll(clipboard).toBe("");

        // Something else copied from the page after the secret is the person's own and is not wiped (gate-r6-7).
        await startWizard();
        await dialog(page).getByTestId("totp-secret").click();
        await page.keyboard.press("Control+c");
        await expect.poll(clipboard).toContain(SECRET.slice(0, 4));
        await dialog(page).getByTestId("copy-note").selectText();
        await page.keyboard.press("Control+c");
        await expect.poll(async () => (await clipboard()).includes(SECRET.slice(0, 4))).toBe(false);
        const own = await clipboard();
        expect(own.length).toBeGreaterThan(0);
        await cancel().click();
        await expect(dialog(page)).toHaveCount(0);
        expect(await clipboard(), "the person's own copy is still there").toBe(own);
      });

      // gate-r28-7. The browser's own "Copy link to highlight" writes <address>#:~:text=<the selection> into the clipboard from outside the page and
      // fires no copy event in it, so the page can only know that a context menu was opened on the selected secret. The write is made here from the
      // test, with no copy event, which is what the browser does; closing the wizard must still empty the clipboard.
      test("a context menu opened on the selected secret is taken as a copy, so closing wipes the link the browser wrote (gate-r28-7)", async ({page, context, baseURL}) => {
        await context.grantPermissions(["clipboard-read", "clipboard-write"], {origin: new URL(baseURL!).origin});
        await open(context, baseURL, {handlers: enableHandlers()});
        await gotoAccount(page, lang);
        const clipboard = () => page.evaluate(() => navigator.clipboard.readText()).then((t) => t.split(/\r?\n/).join("\n"));
        await row(page, "totp").getByRole("button", {name: A("totp.enable")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await dialog(page).getByRole("button", {name: A("reauth.submit")}).click();
        await expect(dialog(page).getByTestId("totp-qr")).toBeVisible();
        await dialog(page).getByTestId("totp-secret").click();
        await dialog(page).getByTestId("totp-secret").click({button: "right"});
        let copyEvents = 0;
        await page.exposeFunction("__countCopy", () => void (copyEvents += 1));
        await page.evaluate(() => document.addEventListener("copy", () => void (window as unknown as {__countCopy: () => void}).__countCopy(), true));
        await page.evaluate((link) => navigator.clipboard.writeText(link), `https://panel.example/${lang}/preferences/account#:~:text=${SECRET.slice(0, 4)}`);
        await expect.poll(clipboard).toContain(SECRET.slice(0, 4));
        expect(copyEvents, "the browser's write is no copy event in the page").toBe(0);
        await dialog(page).getByRole("button", {name: lang === "fa" ? "انصراف" : "Cancel"}).click();
        await expect(dialog(page)).toHaveCount(0);
        await expect.poll(clipboard).toBe("");
      });

      // gate-r7-9. Ctrl+C with nothing selected fires `copy` and writes nothing, so the secret that the Copy button put there is still in the
      // clipboard. The module used to take that event for "the person copied something else" and forget the secret, so closing wiped nothing.
      test("Ctrl+C with nothing selected does not make the page forget a secret that Copy put in the clipboard", async ({page, context, baseURL}) => {
        await context.grantPermissions(["clipboard-read", "clipboard-write"], {origin: new URL(baseURL!).origin});
        await open(context, baseURL, {handlers: enableHandlers()});
        await gotoAccount(page, lang);
        const clipboard = () => page.evaluate(() => navigator.clipboard.readText()).then((t) => t.split(/\r?\n/).join("\n"));
        await row(page, "totp").getByRole("button", {name: A("totp.enable")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await dialog(page).getByRole("button", {name: A("reauth.submit")}).click();
        await expect(dialog(page).getByTestId("totp-qr")).toBeVisible();
        const copy = dialog(page).getByRole("button", {name: lang === "fa" ? "کپی" : "Copy", exact: true});
        await copy.click();
        await expect.poll(clipboard).toBe(SECRET);
        // The focus is on the button and nothing is selected: the person presses the key out of habit.
        await expect(copy).toBeFocused();
        expect(await page.evaluate(() => (document.getSelection()?.toString() ?? "") === "")).toBe(true);
        await page.keyboard.press("Control+c");
        expect(await clipboard(), "an empty copy writes nothing").toBe(SECRET);
        await dialog(page).getByRole("button", {name: lang === "fa" ? "انصراف" : "Cancel"}).click();
        await expect(dialog(page)).toHaveCount(0);
        await expect.poll(clipboard, "closing still wipes the secret").toBe("");
      });

      // gate-r7-8. A tertiary Button takes its text colour from the body of the dialog unless the theme names one, and under the pointer its
      // fill darkens: 4.22:1 in the light theme. The matrix parks the pointer now, so this is the case that holds the hover state, in both themes.
      for (const theme of ["light", "dark"] as const) {
        test(`a tertiary button in the dialog is readable under the pointer, ${theme} theme (gate-r7-8)`, async ({page, context, baseURL}) => {
          // The session gate adopts the account's theme once /me answers, so the account holds it (as in account.matrix.spec.ts).
          await open(context, baseURL, {me: {user: {theme}}, handlers: enableHandlers()});
          await gotoAccount(page, lang);
          await expect(page.locator("html")).toHaveClass(new RegExp(`flat-${theme}`));
          await row(page, "totp").getByRole("button", {name: A("totp.enable")}).click();
          await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
          await dialog(page).getByRole("button", {name: A("reauth.submit")}).click();
          await expect(dialog(page).getByTestId("totp-qr")).toBeVisible();
          const copy = dialog(page).getByRole("button", {name: lang === "fa" ? "کپی" : "Copy", exact: true});
          await expect(copy).toHaveClass(/button--tertiary/);
          await copy.hover();
          await expectAccessible(page, {
            screen: `totp-copy-hover-${theme}`,
            keepPointer: true,
            // The shared entry, which also covers the announcer's undecided aria-valid-attr-value node: a copy of it here had drifted without that rule.
            libraryDefects: [LIVE_ANNOUNCER],
          });
        });
      }

      // gate-r7-10. The clipboard is shared by every tab and the memory of a copy is per tab. Tab 1 copies and goes to the background; tab 2 has the
      // focus and logs out. Chrome refuses the wipe of the tab without the focus (made here, since Playwright gives every page focus), and tab 2
      // held nothing, so nothing wrote and the next person at the PC could paste the recovery codes. The tabs now tell each other that a copy exists.
      test("a logout in another tab overwrites a secret that this tab copied and cannot wipe from the background", async ({page, context, baseURL, guard}) => {
        await context.grantPermissions(["clipboard-read", "clipboard-write"], {origin: new URL(baseURL!).origin});
        await context.addInitScript(() => {
          // A new tab starts on about:blank, which has no clipboard.
          if (!navigator.clipboard) return;
          const real = navigator.clipboard.writeText.bind(navigator.clipboard);
          // window.name survives the page changes of one tab, which a variable does not: tab 1 stays "in the background" when the logout
          // message sends it to the login page, as a real background tab would, where Chrome refuses the write of a document without focus.
          navigator.clipboard.writeText = (text: string) =>
            text === "" && window.name === "background-tab"
              ? Promise.reject(new DOMException("Document is not focused.", "NotAllowedError"))
              : real(text);
        });
        const mock = await open(context, baseURL, {handlers: enableHandlers()});
        await gotoAccount(page, lang);
        const readClipboard = async () => {
          const bare = await openBareTab(context, guard);
          try {
            return await bare.evaluate(() => navigator.clipboard.readText());
          } finally {
            await closeBareTab(bare, guard);
          }
        };
        await row(page, "totp").getByRole("button", {name: A("totp.enable")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await dialog(page).getByRole("button", {name: A("reauth.submit")}).click();
        await expect(dialog(page).getByTestId("totp-qr")).toBeVisible();
        await dialog(page).getByRole("button", {name: lang === "fa" ? "کپی" : "Copy", exact: true}).click();
        await expect.poll(readClipboard).toBe(SECRET);
        // Tab 1 is now "in the background": its own wipe is refused, on this page and on the next.
        await page.evaluate(() => (window.name = "background-tab"));

        // Tab 2 never copied anything. It logs out through the shell.
        const second = await context.newPage();
        await second.goto(`/${lang}/profiles`);
        await expect(second.locator(".shell-page")).toBeVisible();
        await second.getByRole("row", {name: lang === "fa" ? /تنظیمات/ : /Preferences/}).first().click();
        await second.getByRole("row", {name: lang === "fa" ? /خروج/ : /Log out/}).first().click();
        await second.getByRole("button", {name: lang === "fa" ? "خروج" : "Log out", exact: true}).click();
        await second.waitForURL(`**/${lang}/login`);
        expect(mock.count("POST /auth/logout")).toBe(1);
        await expect.poll(readClipboard, "the tab with the focus overwrote the other tab's copy").toBe("");
      });

      // gate-r9-7. The case above, with one more refusal: the write of tab 2 is refused too (Safari wants a gesture, and the logout writes after an
      // await). logoutLocal starts a full load right after the wipe, which ends the listeners that the refusal armed, so the refusal has to be in the
      // flag that the next page reads. Before the fix the login page of tab 2 found no flag, nothing retried, and the copy stayed in the clipboard
      // for as long as tab 1, which cannot write from the background, was never looked at again.
      test("a logout whose own wipe is refused as well is retried by the login page, on its first press (gate-r9-7)", async ({page, context, baseURL, guard}) => {
        await context.grantPermissions(["clipboard-read", "clipboard-write"], {origin: new URL(baseURL!).origin});
        await context.addInitScript(() => {
          if (!navigator.clipboard) return;
          const real = navigator.clipboard.writeText.bind(navigator.clipboard);
          // Only a press in the LOGIN page counts as the gesture that Safari asks for, so the press that confirmed the logout does not; window.name and
          // sessionStorage survive the page changes of one tab.
          window.addEventListener("pointerdown", () => {
            try {
              if (location.pathname.endsWith("/login")) sessionStorage.setItem("gesture", "1");
            } catch {
              // Not the case under test.
            }
          }, {capture: true});
          navigator.clipboard.writeText = (text: string) => {
            const refused =
              text === "" && (window.name === "background-tab" || (window.name === "no-gesture-tab" && sessionStorage.getItem("gesture") !== "1"));
            return refused ? Promise.reject(new DOMException("Not allowed without a user gesture.", "NotAllowedError")) : real(text);
          };
        });
        await open(context, baseURL, {handlers: enableHandlers()});
        await gotoAccount(page, lang);
        const readClipboard = async () => {
          const bare = await openBareTab(context, guard);
          try {
            return await bare.evaluate(() => navigator.clipboard.readText());
          } finally {
            await closeBareTab(bare, guard);
          }
        };
        await row(page, "totp").getByRole("button", {name: A("totp.enable")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await dialog(page).getByRole("button", {name: A("reauth.submit")}).click();
        await expect(dialog(page).getByTestId("totp-qr")).toBeVisible();
        await dialog(page).getByRole("button", {name: lang === "fa" ? "کپی" : "Copy", exact: true}).click();
        await expect.poll(readClipboard).toBe(SECRET);
        await page.evaluate(() => (window.name = "background-tab"));

        const second = await context.newPage();
        await second.goto(`/${lang}/profiles`);
        await expect(second.locator(".shell-page")).toBeVisible();
        await second.evaluate(() => (window.name = "no-gesture-tab"));
        await second.getByRole("row", {name: lang === "fa" ? /تنظیمات/ : /Preferences/}).first().click();
        await second.getByRole("row", {name: lang === "fa" ? /خروج/ : /Log out/}).first().click();
        await second.getByRole("button", {name: lang === "fa" ? "خروج" : "Log out", exact: true}).click();
        await second.waitForURL(`**/${lang}/login`);
        expect(await second.evaluate(() => sessionStorage.getItem("ctrlz_clip_pending")), "the refused wipe is remembered by the next page").toBe("1");
        expect(await readClipboard(), "no gesture yet in the login page: the copy is still there").toBe(SECRET);
        // The first press in the login page is the gesture, and the page writes on it.
        await second.mouse.click(4, 4);
        await expect.poll(readClipboard, "the login page of the focused tab retried the wipe").toBe("");
        expect(await second.evaluate(() => sessionStorage.getItem("ctrlz_clip_pending"))).toBeNull();
      });

      test("a wipe that the browser refuses is not given up: the next press in the page, or the page that a full load opens, does it", async ({page, context, baseURL}) => {
        await context.grantPermissions(["clipboard-read", "clipboard-write"], {origin: new URL(baseURL!).origin});
        await context.addInitScript(() => {
          const real = navigator.clipboard.writeText.bind(navigator.clipboard);
          (window as unknown as {__refuse: boolean}).__refuse = false;
          navigator.clipboard.writeText = (text: string) =>
            text === "" && (window as unknown as {__refuse: boolean}).__refuse
              ? Promise.reject(new DOMException("Document is not focused.", "NotAllowedError"))
              : real(text);
        });
        await open(context, baseURL, {handlers: enableHandlers()});
        await gotoAccount(page, lang);
        const clipboard = () => page.evaluate(() => navigator.clipboard.readText()).then((t) => t.split(/\r?\n/).join("\n"));
        const refuse = (on: boolean) => page.evaluate((v) => ((window as unknown as {__refuse: boolean}).__refuse = v), on);
        const copyAndCancel = async () => {
          await row(page, "totp").getByRole("button", {name: A("totp.enable")}).click();
          await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
          await dialog(page).getByRole("button", {name: A("reauth.submit")}).click();
          await expect(dialog(page).getByTestId("totp-qr")).toBeVisible();
          await dialog(page).getByRole("button", {name: lang === "fa" ? "کپی" : "Copy", exact: true}).click();
          await expect.poll(clipboard).toBe(SECRET);
          await refuse(true);
          await dialog(page).getByRole("button", {name: lang === "fa" ? "انصراف" : "Cancel"}).click();
          await expect(dialog(page)).toHaveCount(0);
        };

        // The wipe is refused: the secret is still in the clipboard, and it is not forgotten. The next press in the page writes again.
        await copyAndCancel();
        await expect.poll(() => page.evaluate(() => sessionStorage.getItem("ctrlz_clip_pending"))).toBe("1");
        expect(await clipboard(), "the refused wipe left the secret").toBe(SECRET);
        await refuse(false);
        await page.mouse.click(4, 4);
        await expect.poll(clipboard).toBe("");
        expect(await page.evaluate(() => sessionStorage.getItem("ctrlz_clip_pending"))).toBeNull();

        // The same across a full load (the login page after a logout, a reload): the flag in this tab's sessionStorage is picked up by the
        // module on the new page, which writes at once, with no press.
        await copyAndCancel();
        expect(await clipboard()).toBe(SECRET);
        await page.reload();
        await expect.poll(clipboard).toBe("");
        expect(await page.evaluate(() => sessionStorage.getItem("ctrlz_clip_pending"))).toBeNull();
      });

      // wp9-r1-2 and wp9-r1-6: the answer of the confirm carries the recovery codes, shown once. Escape, a click
      // outside and the close button are all off while the call runs, so the dialog is there when the answer comes.
      test("Escape or a click outside while the confirm runs leaves the dialog, and the codes appear", async ({page, context, baseURL}) => {
        let release!: () => void;
        const gate = new Promise<void>((resolve) => (release = resolve));
        const base = enableHandlers();
        const mock = await open(context, baseURL, {
          handlers: {
            ...base,
            "POST /account/totp/confirm": async (call, state) => {
              await gate;
              return (base["POST /account/totp/confirm"] as MockHandler)(call, state);
            },
          },
        });
        await gotoAccount(page, lang);
        await toVerify(page);
        await dialog(page).getByRole("checkbox", {name: A("totp.saved")}).check({force: true});
        await typeCode(page, "totp_code", "123456");
        await expect.poll(() => mock.count("POST /account/totp/confirm")).toBe(1);
        await expect(dialog(page).getByRole("button", {name: lang === "fa" ? "بستن" : "Close", exact: true})).toHaveCount(0);
        await page.keyboard.press("Escape");
        await page.mouse.click(4, 4);
        await expect(dialog(page)).toBeVisible();
        release();
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
      });

      test("a code with the step already used asks for the next one", async ({page, context, baseURL}) => {
        await open(context, baseURL, {
          handlers: {...enableHandlers(), "POST /account/totp/confirm": err(401, "totp_step_reused")},
        });
        await gotoAccount(page, lang);
        await toVerify(page);
        await dialog(page).getByRole("checkbox", {name: A("totp.saved")}).check({force: true});
        await typeCode(page, "totp_code", "123456");
        await expect(dialog(page).getByText(errorText(lang, "totp_step_reused"))).toBeVisible();
      });

      test("a pending secret that ran out sends the person back to scan a new code", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {
          handlers: {...enableHandlers(), "POST /account/totp/confirm": err(409, "totp_not_pending")},
        });
        await gotoAccount(page, lang);
        await toVerify(page);
        await dialog(page).getByRole("checkbox", {name: A("totp.saved")}).check({force: true});
        await typeCode(page, "totp_code", "123456");
        await expect(dialog(page).getByTestId("totp-restarted")).toBeVisible();
        await expect(dialog(page).getByTestId("totp-qr")).toBeVisible();
        expect(mock.count("POST /account/totp/setup")).toBe(2);
      });

      test("the window ended before the confirm: the reauth dialog opens over the wizard and the confirm is repeated once", async ({page, context, baseURL}) => {
        let confirms = 0;
        const base = enableHandlers();
        const mock = await open(context, baseURL, {
          handlers: {
            ...base,
            "POST /account/totp/confirm": (call, state) => (++confirms === 1 ? err(403, "reauth_required") : (base["POST /account/totp/confirm"] as MockHandler)(call, state)),
          },
        });
        await gotoAccount(page, lang);
        await toVerify(page);
        await dialog(page).getByRole("checkbox", {name: A("totp.saved")}).check({force: true});
        await typeCode(page, "totp_code", "123456");
        const reauth = page.getByRole("dialog", {name: A("reauth.title")});
        await expect(reauth).toBeVisible();
        await reauth.locator('input[name="password"]').fill("Correct-Horse-9");
        await reauth.getByRole("button", {name: A("reauth.confirm")}).click();
        await expect(page.getByRole("heading", {name: A("totp.step3")})).toBeVisible();
        expect(mock.count("POST /account/totp/confirm")).toBe(2);
      });

      test("new recovery codes: reauth with password and a code, then the codes once, and the row counts them", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {
          me: {security: {totp_enabled: true, recovery_codes_left: 2}},
          handlers: {"POST /account/totp/recovery-codes": {body: {recovery_codes: CODES}}},
        });
        await gotoAccount(page, lang);
        // Fewer than three left: the row warns.
        await expect(row(page, "totp").getByText(lang === "fa" ? /فقط ۲ کد بازیابی باقی مانده. کدهای تازه/ : /Only 2 recovery codes left. Make new/)).toBeVisible();
        await row(page, "totp").getByRole("button", {name: A("totp.regenerate")}).click();
        expect(mock.count("POST /account/totp/recovery-codes")).toBe(0);
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await typeCode(page, "totp_code", "123456");
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
        expect(bodies(mock, "POST", "/auth/reauth")).toEqual([{password: "Correct-Horse-9", totp_code: "123456"}]);
        expect(mock.count("POST /account/totp/recovery-codes")).toBe(1);
        await expectNoSecretResidue(page, [...CODES, "Correct-Horse-9", "123456"], "making new recovery codes");
      });

      test("Escape or a click outside while the new codes are being made leaves the dialog, and the codes appear", async ({page, context, baseURL}) => {
        let release!: () => void;
        const gate = new Promise<void>((resolve) => (release = resolve));
        const mock = await open(context, baseURL, {
          me: {security: {totp_enabled: true, recovery_codes_left: 2}},
          handlers: {
            "POST /account/totp/recovery-codes": async () => {
              await gate;
              return {body: {recovery_codes: CODES}};
            },
          },
        });
        await gotoAccount(page, lang);
        await row(page, "totp").getByRole("button", {name: A("totp.regenerate")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await typeCode(page, "totp_code", "123456");
        await expect.poll(() => mock.count("POST /account/totp/recovery-codes")).toBe(1);
        await page.keyboard.press("Escape");
        await page.mouse.click(4, 4);
        await expect(dialog(page)).toBeVisible();
        release();
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
      });

      test("turn off: password and a code first, then a confirmation, then the call", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {
          me: {security: {totp_enabled: true, recovery_codes_left: 9}},
          handlers: {
            "POST /account/totp/disable": (_call, state) => {
              state.me = {...state.me, security: {...state.me.security, totp_enabled: false, recovery_codes_left: 0}};
              return {body: {ended_sessions: 0}};
            },
          },
        });
        await gotoAccount(page, lang);
        await row(page, "totp").getByRole("button", {name: A("totp.disable")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await typeCode(page, "totp_code", "123456");
        const confirm = page.getByRole("alertdialog");
        await expect(confirm.getByRole("heading", {name: A("totp.disableTitle")})).toBeVisible();
        expect(mock.count("POST /account/totp/disable")).toBe(0);
        await confirm.getByRole("button", {name: A("totp.disableConfirm")}).click();
        await expect(page.getByText(A("totp.disabled"))).toBeVisible();
        await expect(row(page, "totp")).toContainText(A("totp.off"));
        expect(bodies(mock, "POST", "/account/totp/disable")).toEqual([{}]);
        // wp9-r4-1: Regenerate and Turn off leave with the flow, so the focus goes to Turn on and not to the page.
        await expect(page.getByRole("alertdialog")).toHaveCount(0);
        await expect(row(page, "totp").getByRole("button", {name: A("totp.enable")})).toBeFocused();
        // gate-r27-5: the password and the code were typed into this flow; neither may be in the address, history, storage or the console.
        await expectNoSecretResidue(page, ["Correct-Horse-9", "123456"], "turning two-step verification off");
      });

      // wp9-r2-3: spec 12.3 names totp_not_enabled and totp_already_enabled as "refetch /me", on every path that can get them.
      test("two-step turned off in another tab: new recovery codes answers totp_not_enabled and the row follows /me", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {
          me: {security: {totp_enabled: true, recovery_codes_left: 9}},
          handlers: {
            "POST /account/totp/recovery-codes": (_call, state) => {
              state.me = {...state.me, security: {...state.me.security, totp_enabled: false, recovery_codes_left: 0}};
              return err(409, "totp_not_enabled");
            },
          },
        });
        await gotoAccount(page, lang);
        const meBefore = mock.count("GET /me");
        await row(page, "totp").getByRole("button", {name: A("totp.regenerate")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await typeCode(page, "totp_code", "123456");
        await expect(dialog(page).getByText(errorText(lang, "totp_not_enabled"))).toBeVisible();
        await expect.poll(() => mock.count("GET /me")).toBeGreaterThan(meBefore);
        await expect(row(page, "totp")).toContainText(A("totp.off"));
        await expect(row(page, "totp").getByRole("button", {name: A("totp.regenerate")})).toHaveCount(0);
        // A refused answer is a clear one: nothing says that codes may exist.
        await expect(dialog(page).getByTestId("totp-lost")).toHaveCount(0);
      });

      test("two-step turned off in another tab: Turn off answers totp_not_enabled and the row follows /me", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {
          me: {security: {totp_enabled: true, recovery_codes_left: 9}},
          handlers: {
            "POST /account/totp/disable": (_call, state) => {
              state.me = {...state.me, security: {...state.me.security, totp_enabled: false, recovery_codes_left: 0}};
              return err(409, "totp_not_enabled");
            },
          },
        });
        await gotoAccount(page, lang);
        const meBefore = mock.count("GET /me");
        await row(page, "totp").getByRole("button", {name: A("totp.disable")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await typeCode(page, "totp_code", "123456");
        await page.getByRole("alertdialog").getByRole("button", {name: A("totp.disableConfirm")}).click();
        await expect(page.getByRole("alertdialog").getByText(errorText(lang, "totp_not_enabled"))).toBeVisible();
        await expect.poll(() => mock.count("GET /me")).toBeGreaterThan(meBefore);
        await expect(row(page, "totp")).toContainText(A("totp.off"));
      });

      test("two-step turned on in another tab: the setup answers totp_already_enabled, the row follows /me and the way to new codes is named", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {
          handlers: {
            "POST /account/totp/setup": (_call, state) => {
              state.me = {...state.me, security: {...state.me.security, totp_enabled: true, recovery_codes_left: 10}};
              return err(409, "totp_already_enabled");
            },
          },
        });
        await gotoAccount(page, lang);
        const meBefore = mock.count("GET /me");
        await row(page, "totp").getByRole("button", {name: A("totp.enable")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await dialog(page).getByRole("button", {name: A("reauth.submit")}).click();
        await expect(dialog(page).getByText(errorText(lang, "totp_already_enabled"))).toBeVisible();
        await expect(dialog(page).getByText(A("totp.alreadyOnHint"))).toBeVisible();
        await expect.poll(() => mock.count("GET /me")).toBeGreaterThan(meBefore);
        await expect(row(page, "totp")).toContainText(A("totp.on"));
      });

      // wp9-r2-7: a call that makes one-time codes and gets no answer may have made them.
      test("new recovery codes: an answer that never comes (a 502) refetches /me and says the old codes may be dead", async ({page, context, baseURL, guard}) => {
        guard.allowConsole(/status of 502/);
        const mock = await open(context, baseURL, {
          me: {security: {totp_enabled: true, recovery_codes_left: 2}},
          handlers: {"POST /account/totp/recovery-codes": {status: 502}},
        });
        await gotoAccount(page, lang);
        const meBefore = mock.count("GET /me");
        await row(page, "totp").getByRole("button", {name: A("totp.regenerate")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await typeCode(page, "totp_code", "123456");
        await expect(dialog(page).getByTestId("totp-lost")).toContainText(A("totp.regenerateLost"));
        await expect.poll(() => mock.count("GET /me")).toBeGreaterThan(meBefore);
      });

      test("new recovery codes: a dropped connection says the same, and Retry makes the codes", async ({page, context, baseURL, guard}) => {
        guard.allowConsole(/ERR_FAILED|Failed to load resource/);
        const mock = await open(context, baseURL, {
          me: {security: {totp_enabled: true, recovery_codes_left: 2}},
          handlers: {"POST /account/totp/recovery-codes": {body: {recovery_codes: CODES}}},
        });
        // Registered after the mock's own route, so it is asked first.
        let drop = true;
        await context.route("**/api/v1/account/totp/recovery-codes", (route) => (drop ? route.abort() : route.fallback()));
        await gotoAccount(page, lang);
        const meBefore = mock.count("GET /me");
        await row(page, "totp").getByRole("button", {name: A("totp.regenerate")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await typeCode(page, "totp_code", "123456");
        await expect(dialog(page).getByTestId("totp-lost")).toContainText(A("totp.regenerateLost"));
        await expect.poll(() => mock.count("GET /me")).toBeGreaterThan(meBefore);
        drop = false;
        await dialog(page).getByRole("button", {name: lang === "fa" ? "تلاش دوباره" : "Try again"}).click();
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
        await expect(dialog(page).getByTestId("totp-lost")).toHaveCount(0);
      });

      test("enable: an answer that never comes (a 502) at the confirm refetches /me and says the codes may exist", async ({page, context, baseURL, guard}) => {
        guard.allowConsole(/status of 502/);
        const mock = await open(context, baseURL, {handlers: {...enableHandlers(), "POST /account/totp/confirm": {status: 502}}});
        await gotoAccount(page, lang);
        await toVerify(page);
        const meBefore = mock.count("GET /me");
        await dialog(page).getByRole("checkbox", {name: A("totp.saved")}).check({force: true});
        await typeCode(page, "totp_code", "123456");
        await expect(dialog(page).getByTestId("totp-lost")).toContainText(A("totp.enableLost"));
        await expect.poll(() => mock.count("GET /me")).toBeGreaterThan(meBefore);
        // The dialog can be closed again: the call is over. The code field was disabled while the call ran, so the browser dropped the focus to
        // the body, and useApiForm gives it back in an effect after the failure is drawn (wp8-r4-2). An Escape sent in that gap has the body as its
        // target and never reaches the dialog: the lost-answer text is on the page a few milliseconds before the focus is, so the test waits for
        // the focus, as a person's Escape always does (gate-r5-9: 3 of 60 runs under two workers failed here).
        await expect(dialog(page).locator('input[name="totp_code"]')).toBeFocused();
        await page.keyboard.press("Escape");
        await expect(dialog(page)).toHaveCount(0);
      });

      // wp9-r2-4: spec 4.4, no Latin digit in the Persian page.
      test("the wizard's steps are numbered in the digits of the page, and a finished step shows the check mark", async ({page, context, baseURL}) => {
        await open(context, baseURL, {handlers: enableHandlers()});
        await gotoAccount(page, lang);
        await row(page, "totp").getByRole("button", {name: A("totp.enable")}).click();
        const steps = dialog(page).locator("ol.stepper");
        const digits = lang === "fa" ? ["۱", "۲", "۳", "۴"] : ["1", "2", "3", "4"];
        await expect(steps.locator(".stepper__indicator")).toHaveText(digits);
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await dialog(page).getByRole("button", {name: A("reauth.submit")}).click();
        await expect(dialog(page).getByTestId("totp-qr")).toBeVisible();
        await expect(steps.locator(".stepper__indicator").first().locator("svg")).toHaveCount(1);
        await expect(steps.locator(".stepper__indicator")).toHaveText(["", ...digits.slice(1)]);
        if (lang === "fa") expect(await steps.innerText()).not.toMatch(/[0-9]/);
      });

      // wp9-r2-6: the codes exist on the server once the call is answered, and nothing can show them again. Back, a
      // reload and a closed tab leave the page without going through the dialog's own close paths.
      const beforeUnloadAsks = (page: Page) =>
        page.evaluate(() => {
          const event = new Event("beforeunload", {cancelable: true});
          window.dispatchEvent(event);
          return event.defaultPrevented;
        });
      // history.back() from the page, not page.goBack(): the guard cancels the step (Navigation API) or answers it with
      // a popstate, and either way no navigation commits, which goBack would wait for until its timeout.
      const goBack = (page: Page) => page.evaluate(() => history.back());
      const guardEntry = (page: Page) => page.evaluate(() => (history.state as Record<string, unknown> | null)?.ctrlzLeaveGuard ?? null);

      test("enable: Back while the confirm runs keeps the dialog, Back with the codes shown asks first, and the guard ends with the dialog", async ({page, context, baseURL}) => {
        // merge-r2-8, the one failure of this case in a 192-test run, not seen again in three reruns, and its error text was lost. What the code shows
        // is a read of page.url() right after history.back(): the traversal is cancelled or answered with a popstate and the guard pushes its entry
        // again, both asynchronous, and Playwright's own copy of the address follows by an event. A read that does not retry can meet the gap under
        // load, so the address is polled, and the case gets the framework's tripled budget like the two cases below that use three pages.
        test.slow();
        let release!: () => void;
        const gate = new Promise<void>((resolve) => (release = resolve));
        const base = enableHandlers();
        const mock = await open(context, baseURL, {
          handlers: {
            ...base,
            "POST /account/totp/confirm": async (call, state) => {
              await gate;
              return (base["POST /account/totp/confirm"] as MockHandler)(call, state);
            },
          },
        });
        await gotoAccount(page, lang);
        await toVerify(page);
        const url = page.url();
        expect(await beforeUnloadAsks(page)).toBe(false);
        await dialog(page).getByRole("checkbox", {name: A("totp.saved")}).check({force: true});
        await typeCode(page, "totp_code", "123456");
        await expect.poll(() => mock.count("POST /account/totp/confirm")).toBe(1);
        expect(await beforeUnloadAsks(page)).toBe(true);
        await goBack(page);
        await expect(dialog(page)).toBeVisible();
        await expect.poll(() => page.url()).toBe(url);
        release();
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);

        // The codes are on screen: Back asks, and the answer "keep them open" leaves everything as it was.
        expect(await beforeUnloadAsks(page)).toBe(true);
        await goBack(page);
        await expect(dialog(page).getByText(A("totp.closeAsk"))).toBeVisible();
        await expect.poll(() => page.url()).toBe(url);
        await dialog(page).getByRole("button", {name: A("totp.closeKeep")}).click();
        await goBack(page);
        await expect(dialog(page).getByText(A("totp.closeAsk"))).toBeVisible();
        await dialog(page).getByRole("button", {name: A("totp.closeAnyway")}).click();
        await expect(dialog(page)).toHaveCount(0);
        // The guard is off and takes its history entry back.
        expect(await beforeUnloadAsks(page)).toBe(false);
        await expect.poll(() => guardEntry(page)).toBeNull();
        await expect.poll(() => page.url()).toBe(url);
      });

      test("new recovery codes: Back while the codes are being made keeps the dialog, Back with them shown asks first", async ({page, context, baseURL}) => {
        let release!: () => void;
        const gate = new Promise<void>((resolve) => (release = resolve));
        const mock = await open(context, baseURL, {
          me: {security: {totp_enabled: true, recovery_codes_left: 2}},
          handlers: {
            "POST /account/totp/recovery-codes": async () => {
              await gate;
              return {body: {recovery_codes: CODES}};
            },
          },
        });
        await gotoAccount(page, lang);
        await row(page, "totp").getByRole("button", {name: A("totp.regenerate")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await typeCode(page, "totp_code", "123456");
        await expect.poll(() => mock.count("POST /account/totp/recovery-codes")).toBe(1);
        expect(await beforeUnloadAsks(page)).toBe(true);
        await goBack(page);
        await expect(dialog(page)).toBeVisible();
        release();
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
        expect(await beforeUnloadAsks(page)).toBe(true);
        await goBack(page);
        await expect(dialog(page).getByText(A("totp.closeAsk"))).toBeVisible();
        await dialog(page).getByRole("button", {name: A("totp.saveDone")}).click();
        await expect(dialog(page)).toHaveCount(0);
        expect(await beforeUnloadAsks(page)).toBe(false);
      });

      // wp9-r3-1: a step that replaces the one with the focus must hand the focus on, or Escape reaches nothing (the
      // handler is on the dialog) and the "close anyway?" question of 12.3 step 4 is never asked.
      const insideDialog = (page: Page) => page.evaluate(() => document.activeElement?.closest('[role="dialog"]') != null);
      async function toCodes(page: Page) {
        await toVerify(page);
        await dialog(page).getByRole("checkbox", {name: A("totp.saved")}).check({force: true});
        await typeCode(page, "totp_code", "123456");
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
      }

      test("enable: the focus stays in the dialog after the reauth step and when the codes appear, and Escape at the codes asks", async ({page, context, baseURL}) => {
        await open(context, baseURL, {handlers: enableHandlers()});
        await gotoAccount(page, lang);
        await row(page, "totp").getByRole("button", {name: A("totp.enable")}).click();
        const password = dialog(page).locator('input[name="password"]');
        await password.fill("Correct-Horse-9");
        await password.press("Enter");
        await expect(dialog(page).getByRole("heading", {name: A("totp.step1")})).toBeFocused();
        expect(await insideDialog(page)).toBe(true);
        await dialog(page).getByRole("button", {name: lang === "fa" ? "ادامه" : "Continue"}).click();
        await expect(dialog(page).locator('input[name="totp_code"]')).toBeFocused();
        await dialog(page).getByRole("checkbox", {name: A("totp.saved")}).check({force: true});
        await typeCode(page, "totp_code", "123456");
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
        await expect(dialog(page).getByRole("heading", {name: A("totp.step3")})).toBeFocused();
        expect(await insideDialog(page)).toBe(true);
        await page.keyboard.press("Escape");
        await expect(dialog(page).getByText(A("totp.closeAsk"))).toBeVisible();
      });

      test("new recovery codes: the focus stays in the dialog after the proof and when the codes appear, and Escape at the codes asks", async ({page, context, baseURL}) => {
        await open(context, baseURL, {
          me: {security: {totp_enabled: true, recovery_codes_left: 2}},
          handlers: {"POST /account/totp/recovery-codes": {body: {recovery_codes: CODES}}},
        });
        await gotoAccount(page, lang);
        await row(page, "totp").getByRole("button", {name: A("totp.regenerate")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await typeCode(page, "totp_code", "123456");
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
        await expect.poll(() => insideDialog(page)).toBe(true);
        await page.keyboard.press("Escape");
        await expect(dialog(page).getByText(A("totp.closeAsk"))).toBeVisible();
      });

      // wp9-r3-3 and wp9-r3-5: the guard is for the person's own leaving. The end of the session is a full load that
      // wipes the tab (spec 14.4), and a "Leave site?" question that anyone can cancel would leave the codes on screen
      // under a session that is gone.
      // The mock keeps /me alive, so the login page may send the tab back at once: the request for it is the proof.
      const loginRequest = (page: Page) => page.waitForRequest((request) => request.isNavigationRequest() && new RegExp(`/${lang}/login`).test(request.url()));
      const trackDialogs = (page: Page) => {
        const seen: string[] = [];
        page.on("dialog", (event) => {
          seen.push(event.type());
          void event.dismiss();
        });
        return seen;
      };

      // wp9-r4-2: asking for the login page is not enough (the round 3 case only waited for the request, and a mock whose
      // /me stays alive sends the committed login page straight back, which hung the context teardown). The guard's own history.back(), queued when the guarded call
      // ends, aborts that load in Chrome and the old document lives on with the session marked as ending. The proof is a
      // new document: a marker set on the old one is gone, and the address is the login page. /me keeps answering 401, so
      // the login page has no reason to send the tab back.
      const sessionGone = (mock: ApiMock) => {
        mock.on("GET /me", err(401, "session_expired"));
        mock.on("POST /auth/refresh", err(401, "session_expired"));
      };
      const mark = (page: Page) => page.evaluate(() => ((window as unknown as {__ctrlzOld?: boolean}).__ctrlzOld = true));
      // Polled and not waitForURL: that one is bound to the first navigation it sees and throws ERR_ABORTED when a second load
      // of the same page (two calls that both end the session) replaces it, which is not a failure of the page.
      async function expectNewLoginDocument(page: Page) {
        await expect
          .poll(
            () =>
              page
                .evaluate(() => ({path: location.pathname, old: Boolean((window as unknown as {__ctrlzOld?: boolean}).__ctrlzOld)}))
                .catch(() => null),
            {timeout: 20_000},
          )
          .toMatchObject({path: expect.stringMatching(new RegExp(`/${lang}/login`)), old: false});
        await expect(page.getByTestId("recovery-codes")).toHaveCount(0);
      }

      test("enable: a confirm that answers session_expired commits the login page and wipes the old document", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {handlers: {...enableHandlers(), "POST /account/totp/confirm": err(401, "session_expired")}});
        const dialogs = trackDialogs(page);
        await gotoAccount(page, lang);
        await toVerify(page);
        await dialog(page).getByRole("checkbox", {name: A("totp.saved")}).check({force: true});
        sessionGone(mock);
        await mark(page);
        await typeCode(page, "totp_code", "123456");
        await expectNewLoginDocument(page);
        expect(dialogs).toEqual([]);
      });

      test("new recovery codes: a regenerate that answers session_expired commits the login page and wipes the old document", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {
          me: {security: {totp_enabled: true, recovery_codes_left: 2}},
          handlers: {"POST /account/totp/recovery-codes": err(401, "session_expired")},
        });
        const dialogs = trackDialogs(page);
        await gotoAccount(page, lang);
        await row(page, "totp").getByRole("button", {name: A("totp.regenerate")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        sessionGone(mock);
        await mark(page);
        await typeCode(page, "totp_code", "123456");
        await expectNewLoginDocument(page);
        expect(dialogs).toEqual([]);
      });

      // gate-r11-4. A page that shows recovery codes has the leave guard armed. When it is restored from the back/forward cache, the restore
      // handler reloads it; the guard's beforeunload must not answer that reload with a prompt, because a person who presses Stay keeps a
      // live document with the codes in it (a PC that someone else sits down at). The reload is the page's own, like a logout's. A synthetic
      // pageshow is how a restore is reached in Chrome, which evicts real pages by itself (session.spec.ts says the same).
      for (const flow of ["enable", "regenerate"] as const) {
        test(`${flow}: a page restored from the back/forward cache with the codes on screen is loaded again, and the leave guard asks nothing`, async ({page, context, baseURL}) => {
          await open(context, baseURL, {
            ...(flow === "enable" ? {handlers: enableHandlers()} : {}),
            ...(flow === "regenerate"
              ? {me: {security: {totp_enabled: true, recovery_codes_left: 2}}, handlers: {"POST /account/totp/recovery-codes": {body: {recovery_codes: CODES}}}}
              : {}),
          });
          const dialogs = trackDialogs(page);
          await gotoAccount(page, lang);
          if (flow === "enable") {
            await toCodes(page);
          } else {
            await row(page, "totp").getByRole("button", {name: A("totp.regenerate")}).click();
            await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
            await typeCode(page, "totp_code", "123456");
            await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
          }
          expect(await beforeUnloadAsks(page), "the guard is armed while the codes are shown").toBe(true);
          await mark(page);
          // A persisted:false pageshow is an ordinary load: nothing happens.
          await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pageshow", {persisted: false})));
          await page.waitForTimeout(300);
          await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
          const reloaded = page.waitForEvent("load", {timeout: 15_000});
          await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pageshow", {persisted: true})));
          await reloaded;
          expect(await page.evaluate(() => (window as unknown as {__ctrlzOld?: boolean}).__ctrlzOld), "a new document, not the restored one").toBeUndefined();
          await expect(page.getByTestId("recovery-codes")).toHaveCount(0);
          expect(dialogs, "no Leave site? prompt for the reload of a restored page").toEqual([]);
        });
      }

      // gate-r11-4, second half. While the reload is on its way the restored page is still in the window, and html `visibility: hidden` is
      // undone by any descendant that sets `visibility: visible`: the sidebar's labels and chips do. The page is taken out of the rendering
      // instead, with a rule that no stylesheet can win. Looked at in the same task as the event, before the reload can replace the document
      // (a held document request does not help: Playwright's evaluate hangs while it is held).
      test("a restored page is not rendered at all while its reload is pending: no element of it can show through", async ({page, context, baseURL}) => {
        await open(context, baseURL);
        await gotoAccount(page, lang);
        await expect(page.locator(".shell-page")).toBeVisible();
        const before = await page.evaluate(() => document.querySelectorAll('[data-sidebar="label"], [data-slot="chip"]').length);
        expect(before, "the shell has sidebar labels or chips for the check to look at").toBeGreaterThan(0);
        // The reload is waited for, so the context is not torn down in the middle of it (wp9-r4-2: that hangs the teardown).
        const reloaded = page.waitForEvent("load", {timeout: 20_000});
        const seen = await page.evaluate(() => {
          window.dispatchEvent(new PageTransitionEvent("pageshow", {persisted: true}));
          const shown = Array.from(document.querySelectorAll('[data-sidebar="label"], [data-slot="chip"], .shell-page, body')).filter(
            (el) => el.getClientRects().length > 0,
          ).length;
          return {display: getComputedStyle(document.documentElement).display, shown, style: document.documentElement.getAttribute("style")};
        });
        expect(seen.display).toBe("none");
        expect(seen.shown, "no element of the page has a box").toBe(0);
        expect(seen.style).toContain("!important");
        await reloaded;
        await expect(page.locator(".shell-page")).toBeVisible();
      });

      // gate-r13-10. A session that ends elsewhere while recovery codes are on screen: the codes were painted, selectable and (on a phone)
      // captured for the swipe-back preview until the login document commits, and for good if that load never commits. The page is taken out of
      // the rendering before the navigation starts. `beforeunload` is the last moment of the old document before the load begins, and a held
      // document request would hang Playwright's evaluate (wp9-r4-2), so the page writes down what it looked like then, in window.name, which
      // the next document of the tab can read.
      test("recovery codes on screen: a logout in another tab takes the page out of the rendering before the login page is asked for (gate-r13-10)", async ({page, context, baseURL, guard}) => {
        const mock = await open(context, baseURL, {
          me: {security: {totp_enabled: true, recovery_codes_left: 2}},
          handlers: {"POST /account/totp/recovery-codes": {body: {recovery_codes: CODES}}},
        });
        await gotoAccount(page, lang);
        await row(page, "totp").getByRole("button", {name: A("totp.regenerate")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await typeCode(page, "totp_code", "123456");
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
        await expect(dialog(page).getByTestId("recovery-codes")).toBeVisible();
        await page.evaluate(() => {
          window.addEventListener(
            "beforeunload",
            () => {
              window.name = JSON.stringify({
                display: getComputedStyle(document.documentElement).display,
                style: document.documentElement.getAttribute("style") ?? "",
                codeBoxes: document.querySelector('[data-testid="recovery-codes"]')?.getClientRects().length ?? -1,
              });
            },
            {capture: true},
          );
        });
        sessionGone(mock);
        await mark(page);
        const second = await openBareTab(context, guard);
        await second.evaluate(() => {
          const channel = new BroadcastChannel("ctrlz-session");
          channel.postMessage("logout");
          channel.close();
        });
        await expectNewLoginDocument(page);
        const seen = JSON.parse(await page.evaluate(() => window.name || "{}")) as {display?: string; style?: string; codeBoxes?: number};
        expect(seen.display, "the page was out of the rendering when the navigation began").toBe("none");
        expect(seen.style).toContain("!important");
        expect(seen.codeBoxes, "the recovery codes had no box").toBe(0);
        await closeBareTab(second, guard);
      });

      test("enable: another tab logs out during the held confirm, the confirm then answers 401, and the login page still commits", async ({page, context, baseURL, guard}) => {
        let release!: () => void;
        const gate = new Promise<void>((resolve) => (release = resolve));
        const mock = await open(context, baseURL, {
          handlers: {
            ...enableHandlers(),
            "POST /account/totp/confirm": async () => {
              await gate;
              return err(401, "session_expired");
            },
          },
        });
        const dialogs = trackDialogs(page);
        const second = await context.newPage();
        await second.goto(`/${lang}/profiles`);
        await expect(second.locator(".shell-page")).toBeVisible();
        await gotoAccount(page, lang);
        await toVerify(page);
        await dialog(page).getByRole("checkbox", {name: A("totp.saved")}).check({force: true});
        sessionGone(mock);
        await mark(page);
        await typeCode(page, "totp_code", "123456");
        await expect.poll(() => mock.count("POST /account/totp/confirm")).toBe(1);
        const left = loginRequest(page);
        await broadcastFromBareTab(context, guard, "logout");
        await left;
        // The call fails while the load is on its way: the guard ends, and its cleanup must leave the load alone.
        release();
        await expectNewLoginDocument(page);
        expect(dialogs).toEqual([]);
      });

      test("another tab logs out while the codes are on screen: this tab leaves for the login page, with no question, and the codes are gone", async ({page, context, baseURL, guard}) => {
        // Three pages and a bare tab through Caddy: 30 to 45 s on this shared host with nothing else wrong (measured in the first stack run of
        // the web merge, where the en variant timed out at 60 s under load), so the budget is the framework's tripled one (merge-r1 flake).
        test.slow();
        const mock = await open(context, baseURL, {handlers: enableHandlers()});
        const dialogs = trackDialogs(page);
        const second = await context.newPage();
        await second.goto(`/${lang}/profiles`);
        await expect(second.locator(".shell-page")).toBeVisible();
        await gotoAccount(page, lang);
        await toCodes(page);
        expect(await beforeUnloadAsks(page)).toBe(true);
        sessionGone(mock);
        await mark(page);
        await broadcastFromBareTab(context, guard, "logout");
        await expectNewLoginDocument(page);
        expect(dialogs).toEqual([]);
      });

      test("a /me that answers session_expired while the codes are on screen leaves for the login page, with no question", async ({page, context, baseURL, guard}) => {
        // Three pages and a bare tab through Caddy: 30 to 45 s on this shared host with nothing else wrong (measured in the first stack run of
        // the web merge, where the en variant timed out at 60 s under load), so the budget is the framework's tripled one (merge-r1 flake).
        test.slow();
        const mock = await open(context, baseURL, {handlers: enableHandlers()});
        const dialogs = trackDialogs(page);
        const other = await context.newPage();
        await other.goto(`/${lang}/profiles`);
        await expect(other.locator(".shell-page")).toBeVisible();
        await gotoAccount(page, lang);
        await toCodes(page);
        sessionGone(mock);
        await mark(page);
        // Another tab signed in: this one asks /me again, and the answer is that the session is gone.
        await broadcastFromBareTab(context, guard, "login");
        await expectNewLoginDocument(page);
        expect(dialogs).toEqual([]);
      });

      // wp9-r3-6: a step back of more than one entry lands on an older route, and the framework renders it before a
      // popstate listener of ours can run. The Navigation API's navigate event comes first and can be cancelled.
      async function twoEntriesBack(page: Page) {
        await page.goto(`/${lang}/profiles`);
        await page.getByRole("row", {name: lang === "fa" ? /اندپوینت/ : /Endpoints/}).first().click();
        await page.waitForURL(`**/${lang}/endpoints`);
        await page.getByRole("row", {name: lang === "fa" ? /تنظیمات/ : /Preferences/}).first().click();
        await page.getByRole("row", {name: lang === "fa" ? /حساب کاربری/ : /Account/}).first().click();
        await page.waitForURL(`**/${lang}/preferences/account`);
        await expect(page.locator('[data-row-id="phone"]')).toBeVisible();
      }

      test("enable: a jump two entries back (history.go(-2)) while the confirm runs or the codes are shown keeps the dialog", async ({page, context, baseURL}) => {
        let release!: () => void;
        const gate = new Promise<void>((resolve) => (release = resolve));
        const base = enableHandlers();
        const mock = await open(context, baseURL, {
          handlers: {
            ...base,
            "POST /account/totp/confirm": async (call, state) => {
              await gate;
              return (base["POST /account/totp/confirm"] as MockHandler)(call, state);
            },
          },
        });
        await twoEntriesBack(page);
        await toVerify(page);
        await dialog(page).getByRole("checkbox", {name: A("totp.saved")}).check({force: true});
        await typeCode(page, "totp_code", "123456");
        await expect.poll(() => mock.count("POST /account/totp/confirm")).toBe(1);
        await page.evaluate(() => history.go(-2));
        await page.waitForTimeout(400);
        await expect(dialog(page)).toBeVisible();
        expect(page.url()).toMatch(new RegExp(`/${lang}/preferences/account$`));
        release();
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
        await page.evaluate(() => history.go(-2));
        await expect(dialog(page).getByText(A("totp.closeAsk"))).toBeVisible();
        expect(page.url()).toMatch(new RegExp(`/${lang}/preferences/account$`));
      });

      test("new recovery codes: a jump two entries back while the codes are being made keeps the dialog", async ({page, context, baseURL}) => {
        let release!: () => void;
        const gate = new Promise<void>((resolve) => (release = resolve));
        const mock = await open(context, baseURL, {
          me: {security: {totp_enabled: true, recovery_codes_left: 2}},
          handlers: {
            "POST /account/totp/recovery-codes": async () => {
              await gate;
              return {body: {recovery_codes: CODES}};
            },
          },
        });
        await twoEntriesBack(page);
        await row(page, "totp").getByRole("button", {name: A("totp.regenerate")}).click();
        await dialog(page).locator('input[name="password"]').fill("Correct-Horse-9");
        await typeCode(page, "totp_code", "123456");
        await expect.poll(() => mock.count("POST /account/totp/recovery-codes")).toBe(1);
        await page.evaluate(() => history.go(-2));
        await page.waitForTimeout(400);
        await expect(dialog(page)).toBeVisible();
        expect(page.url()).toMatch(new RegExp(`/${lang}/preferences/account$`));
        release();
        await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
      });
    });

    test.describe("sessions", () => {
      test("the list names the method, the address and the agent, marks this session, and ends another with no more proof when it is older", async ({page, context, baseURL}) => {
        let list = sessionsFixture();
        const mock = await open(context, baseURL, {
          handlers: {
            "GET /account/sessions": () => ({body: {sessions: list}}),
            "DELETE /account/sessions/{id}": (call) => {
              const id = call.path.split("/")[3];
              list = list.filter((s) => s.id !== id);
              return {status: 204};
            },
          },
        });
        await gotoAccount(page, lang);
        await row(page, "sessions").getByRole("button", {name: A("sessions.manageAria")}).click();
        const items = row(page, "sessions").getByRole("listitem");
        await expect(items).toHaveCount(3);
        await expect(items.filter({hasText: A("sessions.current")})).toHaveCount(1);
        await expect(items.first()).toContainText("203.0.113.9");
        await expect(items.nth(1)).toContainText(A("sessions.method.otp"));
        // The current one has no End button.
        await expect(row(page, "sessions").getByRole("button", {name: lang === "fa" ? /^پایان نشستی/ : /^End the session/})).toHaveCount(2);

        await items.nth(1).getByRole("button").click();
        await expect(row(page, "sessions").getByRole("listitem")).toHaveCount(2);
        expect(mock.count(`DELETE /account/sessions/${SESSION_OLDER}`)).toBe(1);
        expect(mock.count("POST /auth/reauth")).toBe(0);
      });

      // wp9-r1-5: the row that had the focus leaves the page; the keyboard path goes on at the End button that took its place.
      test("after End the focus moves to the next End button, and to the list when none is left", async ({page, context, baseURL}) => {
        let list = sessionsFixture();
        await open(context, baseURL, {
          handlers: {
            "GET /account/sessions": () => ({body: {sessions: list}}),
            "DELETE /account/sessions/{id}": (call) => {
              list = list.filter((s) => s.id !== call.path.split("/")[3]);
              return {status: 204};
            },
          },
        });
        await gotoAccount(page, lang);
        await row(page, "sessions").getByRole("button", {name: A("sessions.manageAria")}).click();
        const ends = row(page, "sessions").getByRole("button", {name: lang === "fa" ? /^پایان نشستی/ : /^End the session/});
        await expect(ends).toHaveCount(2);
        await ends.first().click();
        await expect(ends).toHaveCount(1);
        await expect(ends.first()).toBeFocused();
        await ends.first().click();
        await expect(ends).toHaveCount(0);
        await expect(row(page, "sessions").getByRole("list", {name: A("sessions.listLabel")})).toBeFocused();
      });

      test("a failed End keeps the focus on the button that was pressed", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {handlers: {"DELETE /account/sessions/{id}": err(503, "service_unavailable")}});
        await gotoAccount(page, lang);
        await row(page, "sessions").getByRole("button", {name: A("sessions.manageAria")}).click();
        const ends = row(page, "sessions").getByRole("button", {name: lang === "fa" ? /^پایان نشستی/ : /^End the session/});
        await ends.first().focus();
        await page.keyboard.press("Enter");
        await expect.poll(() => mock.count("DELETE /account/sessions/{id}")).toBe(1);
        await expect(row(page, "sessions").getByText(errorText(lang, "service_unavailable"))).toBeVisible();
        await expect(ends.first()).toBeFocused();
      });

      test("a session newer than this one needs a reauth: the dialog opens and the delete is repeated once", async ({page, context, baseURL}) => {
        let list = sessionsFixture();
        let tries = 0;
        const mock = await open(context, baseURL, {
          handlers: {
            "GET /account/sessions": () => ({body: {sessions: list}}),
            "DELETE /account/sessions/{id}": (call) => {
              if (++tries === 1) return err(403, "reauth_required");
              list = list.filter((s) => s.id !== call.path.split("/")[3]);
              return {status: 204};
            },
          },
        });
        await gotoAccount(page, lang);
        await row(page, "sessions").getByRole("button", {name: A("sessions.manageAria")}).click();
        await row(page, "sessions").getByRole("listitem").nth(2).getByRole("button").click();
        const reauth = page.getByRole("dialog", {name: A("reauth.title")});
        await reauth.locator('input[name="password"]').fill("Correct-Horse-9");
        await reauth.getByRole("button", {name: A("reauth.confirm")}).click();
        await expect(row(page, "sessions").getByRole("listitem")).toHaveCount(2);
        expect(mock.count(`DELETE /account/sessions/${SESSION_NEWER}`)).toBe(2);
      });

      test("Log out all asks first, calls /auth/logout-all once, leaves for the login page and never calls /auth/logout", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL);
        await gotoAccount(page, lang);
        await row(page, "sessions").getByRole("button", {name: A("sessions.manageAria")}).click();
        await row(page, "sessions").getByRole("button", {name: A("sessions.logoutAll")}).click();
        const confirm = page.getByRole("alertdialog");
        await expect(confirm.getByText(A("sessions.logoutAllText"))).toBeVisible();
        expect(mock.count("POST /auth/logout-all")).toBe(0);
        // Cancel leaves everything as it was.
        await confirm.getByRole("button", {name: lang === "fa" ? "انصراف" : "Cancel"}).click();
        await expect(confirm).toHaveCount(0);
        expect(mock.count("POST /auth/logout-all")).toBe(0);

        await row(page, "sessions").getByRole("button", {name: A("sessions.logoutAll")}).click();
        await page.getByRole("alertdialog").getByRole("button", {name: A("sessions.logoutAllConfirm")}).click();
        await page.waitForURL(`**/${lang}/login`);
        expect(mock.count("POST /auth/logout-all")).toBe(1);
        expect(mock.count("POST /auth/logout")).toBe(0);
      });

      test("a failed Log out all says so in the dialog and the page stays", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {handlers: {"POST /auth/logout-all": err(503, "service_unavailable")}});
        await gotoAccount(page, lang);
        await row(page, "sessions").getByRole("button", {name: A("sessions.manageAria")}).click();
        await row(page, "sessions").getByRole("button", {name: A("sessions.logoutAll")}).click();
        await page.getByRole("alertdialog").getByRole("button", {name: A("sessions.logoutAllConfirm")}).click();
        await expect(page.getByRole("alertdialog").getByText(errorText(lang, "service_unavailable"))).toBeVisible();
        expect(page.url()).toContain("/preferences/account");
        expect(mock.count("POST /auth/logout")).toBe(0);
      });
    });

    test("Log out from the shell asks first (T-109) and ends the session with one call", async ({page, context, baseURL}) => {
      const mock = await open(context, baseURL);
      await gotoAccount(page, lang);
      await page.getByRole("row", {name: lang === "fa" ? /خروج/ : /Log out/}).first().click();
      const confirm = page.getByRole("alertdialog");
      await expect(confirm).toBeVisible();
      expect(mock.count("POST /auth/logout")).toBe(0);
      await confirm.getByRole("button", {name: lang === "fa" ? "خروج" : "Log out", exact: true}).click();
      await page.waitForURL(`**/${lang}/login`);
      expect(mock.count("POST /auth/logout")).toBe(1);
    });

    test.describe("passkeys", () => {
      const stale = () => passkeyRowFixture({id: PK_STALE, name: "Old phone", stale: true, backup_eligible: false});

      test("the section is not there when passkeys are off", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {passkeyEnabled: false});
        await gotoAccount(page, lang);
        await expect(page.getByRole("heading", {level: 2, name: A("sections.options")})).toBeVisible();
        await expect(page.getByRole("heading", {level: 2, name: A("sections.passkeys")})).toHaveCount(0);
        expect(mock.count("GET /account/passkeys")).toBe(0);
      });

      test("the list shows the name, when it was made and last used, Synced and Stale", async ({page, context, baseURL}) => {
        await open(context, baseURL, {handlers: {"GET /account/passkeys": {body: {passkeys: [...passkeysFixture(), stale()]}}}});
        await gotoAccount(page, lang);
        const work = row(page, `passkey-${PK_A}`);
        await expect(work).toContainText("Work laptop");
        await expect(work.getByText(A("passkeys.synced"))).toBeVisible();
        const key = row(page, `passkey-${PK_B}`);
        await expect(key.getByText(A("passkeys.synced"))).toHaveCount(0);
        await expect(key).toContainText(A("passkeys.neverUsed"));
        const old = row(page, `passkey-${PK_STALE}`);
        await expect(old.getByText(A("passkeys.stale"), {exact: true})).toBeVisible();
        await expect(old.getByText(A("passkeys.staleText"))).toBeVisible();
      });

      test("rename is inline, 1 to 64 characters, and sends the trimmed name", async ({page, context, baseURL}) => {
        let list = passkeysFixture();
        const mock = await open(context, baseURL, {
          handlers: {
            "GET /account/passkeys": () => ({body: {passkeys: list}}),
            "PATCH /account/passkeys/{id}": (call) => {
              const id = call.path.split("/")[3];
              const name = (call.body as {name: string}).name;
              list = list.map((p) => (p.id === id ? {...p, name} : p));
              return {body: list.find((p) => p.id === id)};
            },
          },
        });
        await gotoAccount(page, lang);
        const work = row(page, `passkey-${PK_A}`);
        await work.getByRole("button", {name: A("passkeys.renameAria", {name: "Work laptop"})}).click();
        const input = work.locator('input[name="passkey_name"]');
        await expect(input).toBeFocused();
        await expect(input).toHaveValue("Work laptop");
        await input.fill("");
        await work.getByRole("button", {name: A("passkeys.saveName")}).click();
        await expect(work.getByText(A("passkeys.nameRequired"))).toBeVisible();
        await input.fill("x".repeat(65));
        await work.getByRole("button", {name: A("passkeys.saveName")}).click();
        await expect(work.getByText(lang === "fa" ? /حداکثر ۶۴ نویسه/ : /at most 64 characters/)).toBeVisible();
        expect(mock.count(`PATCH /account/passkeys/${PK_A}`)).toBe(0);
        await input.fill("  Office laptop  ");
        await work.getByRole("button", {name: A("passkeys.saveName")}).click();
        await expect(work).toContainText("Office laptop");
        expect(bodies(mock, "PATCH", `/account/passkeys/${PK_A}`)).toEqual([{name: "Office laptop"}]);
      });

      test("rename sends a Persian name without its half-space, as the server stores it, drops the other invisible characters, and counts the limit in characters, not UTF-16 units", async ({page, context, baseURL}) => {
        let list = passkeysFixture();
        const mock = await open(context, baseURL, {
          handlers: {
            "GET /account/passkeys": () => ({body: {passkeys: list}}),
            "PATCH /account/passkeys/{id}": (call) => {
              const id = call.path.split("/")[3];
              const name = (call.body as {name: string}).name;
              // The API's pattern for a name (prosecontent in api/openapi.yaml; Go's \p{C} is Cc, Cf, Co and Cs): no control, format or
              // private-use character except U+200C, and the first character is neither one of those nor a separator, unless it is U+200C itself.
              if (!/^(?:[^\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Z}]|\u200c)(?:[^\p{Cc}\p{Cf}\p{Co}\p{Cs}]|\u200c)*$/u.test(name)) return err(400, "bad_request");
              // RenamePasskey drops the half-space and trims before it stores the name (routes_passkey.go, D64 zwnj-fields).
              const stored = name.replaceAll("\u200c", "").trim();
              list = list.map((p) => (p.id === id ? {...p, name: stored} : p));
              return {body: list.find((p) => p.id === id)};
            },
          },
        });
        await gotoAccount(page, lang);
        const work = row(page, `passkey-${PK_A}`);
        await work.getByRole("button", {name: A("passkeys.renameAria", {name: "Work laptop"})}).click();
        const input = work.locator('input[name="passkey_name"]');
        await input.fill("\u200eلپ\u200cتاپ\u200f");
        await work.getByRole("button", {name: A("passkeys.saveName")}).click();
        // B5, review round 1: the LRM, the RLM and the half-space are all dropped before the request, because the server stores the name without the half-space.
        await expect(work).toContainText("لپتاپ");
        expect(bodies(mock, "PATCH", `/account/passkeys/${PK_A}`)).toEqual([{name: "لپتاپ"}]);
        // 40 emoji are 80 UTF-16 units and 40 characters: the server takes them.
        await work.getByRole("button", {name: A("passkeys.renameAria", {name: "لپتاپ"})}).click();
        await input.fill("😀".repeat(40));
        await work.getByRole("button", {name: A("passkeys.saveName")}).click();
        await expect(work).toContainText("😀".repeat(40));
        // 65 characters are still too many, and a name of nothing but invisible characters is empty.
        await work.getByRole("button", {name: A("passkeys.renameAria", {name: "😀".repeat(40)})}).click();
        await input.fill("😀".repeat(65));
        await work.getByRole("button", {name: A("passkeys.saveName")}).click();
        await expect(work.getByText(lang === "fa" ? /حداکثر ۶۴ نویسه/ : /at most 64 characters/)).toBeVisible();
        await input.fill("‌‏");
        await work.getByRole("button", {name: A("passkeys.saveName")}).click();
        await expect(work.getByText(A("passkeys.nameRequired"))).toBeVisible();
        expect(bodies(mock, "PATCH", `/account/passkeys/${PK_A}`)).toHaveLength(2);
      });

      test("delete asks first, warns when the last live passkey takes Enforce with it, and repeats after a reauth", async ({page, context, baseURL}) => {
        let list = [passkeysFixture()[0]!];
        let tries = 0;
        const mock = await open(context, baseURL, {
          me: {security: {passkeys: 1, enforce_passkey: true}},
          handlers: {
            "GET /account/passkeys": () => ({body: {passkeys: list}}),
            "DELETE /account/passkeys/{id}": () => {
              if (++tries === 1) return err(403, "reauth_required");
              list = [];
              return {status: 204};
            },
          },
        });
        await gotoAccount(page, lang);
        await row(page, `passkey-${PK_A}`).getByRole("button", {name: A("passkeys.deleteAria", {name: "Work laptop"})}).click();
        const confirm = page.getByRole("alertdialog");
        await expect(confirm.getByText(A("passkeys.deleteEnforce"))).toBeVisible();
        expect(mock.count(`DELETE /account/passkeys/${PK_A}`)).toBe(0);
        await confirm.getByRole("button", {name: A("passkeys.deleteConfirm")}).click();
        const reauth = page.getByRole("dialog", {name: A("reauth.title")});
        await reauth.locator('input[name="password"]').fill("Correct-Horse-9");
        await reauth.getByRole("button", {name: A("reauth.confirm")}).click();
        await expect(row(page, `passkey-${PK_A}`)).toHaveCount(0);
        expect(mock.count(`DELETE /account/passkeys/${PK_A}`)).toBe(2);
      });

      test("after a delete the focus goes to the section title, not to the top of the page", async ({page, context, baseURL}) => {
        let list = passkeysFixture();
        await open(context, baseURL, {
          handlers: {
            "GET /account/passkeys": () => ({body: {passkeys: list}}),
            "DELETE /account/passkeys/{id}": (call) => {
              list = list.filter((p) => p.id !== call.path.split("/")[3]);
              return {status: 204};
            },
          },
        });
        await gotoAccount(page, lang);
        await row(page, `passkey-${PK_A}`).getByRole("button", {name: A("passkeys.deleteAria", {name: "Work laptop"})}).click();
        await page.getByRole("alertdialog").getByRole("button", {name: A("passkeys.deleteConfirm")}).click();
        await expect(row(page, `passkey-${PK_A}`)).toHaveCount(0);
        await expect(page.getByRole("heading", {level: 2, name: A("sections.passkeys")})).toBeFocused();
      });

      test("add: reauth, the browser's prompt (a virtual authenticator), then a name", async ({page, context, baseURL}) => {
        const cdp = await context.newCDPSession(page);
        await cdp.send("WebAuthn.enable");
        await cdp.send("WebAuthn.addVirtualAuthenticator", {
          options: {protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true},
        });
        let list = passkeysFixture();
        const added = passkeyRowFixture({id: PK_NEW, name: "Passkey 3"});
        const mock = await open(context, baseURL, {
          handlers: {
            "GET /account/passkeys": () => ({body: {passkeys: list}}),
            "POST /account/passkeys/begin": {
              body: {
                ticket: "reg-ticket-1",
                options: {
                  publicKey: {
                    challenge: "AAECAwQFBgcICQoLDA0ODw",
                    rp: {name: "Ctrl Z", id: new URL(baseURL!).hostname},
                    user: {id: "dXNlci0x", name: "0912***4567", displayName: "0912***4567"},
                    pubKeyCredParams: [{type: "public-key", alg: -7}],
                    timeout: 60000,
                    attestation: "none",
                    authenticatorSelection: {residentKey: "preferred", userVerification: "preferred"},
                  },
                },
              },
            },
            "POST /account/passkeys/finish": (_call, state) => {
              list = [...list, added];
              state.me = {...state.me, security: {...state.me.security, passkeys: list.length}};
              return {status: 201, body: {passkey: added, ended_sessions: 1}};
            },
            "PATCH /account/passkeys/{id}": (call) => {
              const name = (call.body as {name: string}).name;
              list = list.map((p) => (p.id === PK_NEW ? {...p, name} : p));
              return {body: list.find((p) => p.id === PK_NEW)};
            },
          },
        });
        await gotoAccount(page, lang);
        const add = row(page, "passkey-add");
        await add.getByRole("button", {name: A("passkeys.addAria")}).click();
        // The reauth comes first; the browser is not asked before it.
        expect(mock.count("POST /account/passkeys/begin")).toBe(0);
        await add.locator('input[name="password"]').fill("Correct-Horse-9");
        await add.getByRole("button", {name: A("reauth.submit")}).click();
        await add.getByRole("button", {name: A("passkeys.create")}).click();
        await expect(add.locator('input[name="passkey_name"]')).toBeFocused();
        expect(mock.calls.find((c) => c.path === "/account/passkeys/finish")?.headers["x-ctrlz-ticket"]).toBe("reg-ticket-1");
        await expect(page.getByText(lang === "fa" ? /۱ نشست دیگر/ : /1 other session/)).toBeVisible();
        // wp9-r6-1, B5: an RLM in the name (a paste from Telegram) would get a bare 400 from the API, so the name goes out without it, and
        // without the ZWNJ, which the server would remove.
        await add.locator('input[name="passkey_name"]').fill("Ph\u200cone\u200f");
        await add.getByRole("button", {name: A("passkeys.saveName")}).click();
        await expect(row(page, `passkey-${PK_NEW}`)).toContainText("Phone");
        expect(bodies(mock, "PATCH", `/account/passkeys/${PK_NEW}`)).toEqual([{name: "Phone"}]);
        // gate-r27-5: the ticket of begin and the challenge in its options are one-time values that live only in the component's state.
        await expectNoSecretResidue(page, ["reg-ticket-1", "AAECAwQFBgcICQoLDA0ODw", "Correct-Horse-9"], "adding a passkey");
      });

      // gate-r16-9: finish registers the passkey and ends the other sessions, so a row that closes while it is on the wire must not cancel it.
      // The page then drops the passkey list, /me and the session list, and says what ended, with nobody looking at the row.
      test("add: a row that closes while finish is on the wire does not cancel it, and the lists are asked again (gate-r16-9)", async ({page, context, baseURL}) => {
        const cdp = await context.newCDPSession(page);
        await cdp.send("WebAuthn.enable");
        await cdp.send("WebAuthn.addVirtualAuthenticator", {
          options: {protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true},
        });
        let list = passkeysFixture();
        const added = passkeyRowFixture({id: PK_NEW, name: "Passkey 3"});
        let release!: () => void;
        const gate = new Promise<void>((resolve) => (release = resolve));
        const mock = await open(context, baseURL, {
          handlers: {
            "GET /account/passkeys": () => ({body: {passkeys: list}}),
            "POST /account/passkeys/begin": {
              body: {
                ticket: "reg-ticket-1",
                options: {
                  publicKey: {
                    challenge: "AAECAwQFBgcICQoLDA0ODw",
                    rp: {name: "Ctrl Z", id: new URL(baseURL!).hostname},
                    user: {id: "dXNlci0x", name: "0912***4567", displayName: "0912***4567"},
                    pubKeyCredParams: [{type: "public-key", alg: -7}],
                    timeout: 60000,
                    attestation: "none",
                    authenticatorSelection: {residentKey: "preferred", userVerification: "preferred"},
                  },
                },
              },
            },
            "POST /account/passkeys/finish": async (_call, state) => {
              await gate;
              list = [...list, added];
              state.me = {...state.me, security: {...state.me.security, passkeys: list.length}};
              return {status: 201, body: {passkey: added, ended_sessions: 1}};
            },
          },
        });
        await gotoAccount(page, lang);
        const add = row(page, "passkey-add");
        await add.getByRole("button", {name: A("passkeys.addAria")}).click();
        await add.locator('input[name="password"]').fill("Correct-Horse-9");
        await add.getByRole("button", {name: A("reauth.submit")}).click();
        await add.getByRole("button", {name: A("passkeys.create")}).click();
        await expect.poll(() => mock.count("POST /account/passkeys/finish")).toBe(1);
        const listed = mock.count("GET /account/passkeys");
        // Another row opens, and the add row goes away with its prompt state.
        await row(page, "phone").getByRole("button", {name: A("phone.editAria")}).click();
        await expect(add.getByRole("button", {name: A("passkeys.create")})).toHaveCount(0);
        release();
        await expect.poll(() => mock.count("GET /account/passkeys")).toBeGreaterThan(listed);
        await expect(row(page, `passkey-${PK_NEW}`)).toBeVisible();
        await expect(page.getByText(lang === "fa" ? /۱ نشست دیگر/ : /1 other session/)).toBeVisible();
      });

      test("Enforce: reauth is the server's, the answer says what ended, and a refusal says what is missing", async ({page, context, baseURL}) => {
        let refuse = true;
        const mock = await open(context, baseURL, {
          me: {security: {passkeys: 2}},
          handlers: {
            "GET /account/passkeys": {body: {passkeys: passkeysFixture()}},
            "PUT /account/passkey-enforcement": (call, state) => {
              const {enabled} = call.body as {enabled: boolean};
              if (enabled && refuse) return err(409, "enforce_precondition_failed");
              state.me = {...state.me, security: {...state.me.security, enforce_passkey: enabled}};
              return {body: {ended_sessions: 3}};
            },
          },
        });
        await gotoAccount(page, lang);
        const toggle = row(page, "enforce").getByRole("switch", {name: A("passkeys.enforce.label")});
        const control = row(page, "enforce").locator(".switch__control");
        await control.click();
        await expect(row(page, "enforce").getByText(A("passkeys.enforce.needs"))).toBeVisible();
        await expect(toggle).not.toBeChecked();

        refuse = false;
        await control.click();
        await expect(toggle).toBeChecked();
        await expect(page.getByText(lang === "fa" ? /۳ نشست دیگر/ : /3 other sessions/)).toBeVisible();
        expect(bodies(mock, "PUT", "/account/passkey-enforcement")).toEqual([{enabled: true}, {enabled: true}]);
      });

      // wp9-r3-2: the switch has the focus when it is pressed. A disabled control gives it up for good, so the next Tab
      // started at the top of the document.
      test("Enforce: the focus stays on the switch while the call runs and after it, on success and on a refusal", async ({page, context, baseURL}) => {
        let release!: () => void;
        let gate = new Promise<void>((resolve) => (release = resolve));
        let refuse = true;
        const mock = await open(context, baseURL, {
          me: {security: {passkeys: 2}},
          handlers: {
            "GET /account/passkeys": {body: {passkeys: passkeysFixture()}},
            "PUT /account/passkey-enforcement": async (call, state) => {
              await gate;
              const {enabled} = call.body as {enabled: boolean};
              if (refuse) return err(409, "enforce_precondition_failed");
              state.me = {...state.me, security: {...state.me.security, enforce_passkey: enabled}};
              return {body: {ended_sessions: 0}};
            },
          },
        });
        await gotoAccount(page, lang);
        const toggle = row(page, "enforce").getByRole("switch", {name: A("passkeys.enforce.label")});
        for (const ok of [false, true]) {
          refuse = !ok;
          const before = mock.count("PUT /account/passkey-enforcement");
          await toggle.focus();
          await page.keyboard.press("Space");
          await expect.poll(() => mock.count("PUT /account/passkey-enforcement")).toBe(before + 1);
          await expect(toggle).toBeFocused();
          release();
          await expect(row(page, "enforce")).toBeVisible();
          if (ok) await expect(toggle).toBeChecked();
          else await expect(row(page, "enforce").getByText(A("passkeys.enforce.needs"))).toBeVisible();
          await expect(toggle).toBeFocused();
          gate = new Promise<void>((resolve) => (release = resolve));
        }
      });

      test("add: after the password the focus is on Create passkey, not on the page", async ({page, context, baseURL}) => {
        await open(context, baseURL);
        await gotoAccount(page, lang);
        await row(page, "passkey-add").getByRole("button", {name: A("passkeys.addAria")}).click();
        const password = row(page, "passkey-add").locator('input[name="password"]');
        await password.fill("Correct-Horse-9");
        await password.press("Enter");
        await expect(row(page, "passkey-add").getByRole("button", {name: A("passkeys.create")})).toBeFocused();
      });

      test("Enforce while a review is pending says to confirm the list first", async ({page, context, baseURL}) => {
        await open(context, baseURL, {
          me: {security: {passkeys: 2, passkey_review_required: true}},
          handlers: {
            "GET /account/passkeys": {body: {passkeys: passkeysFixture()}},
            "PUT /account/passkey-enforcement": err(409, "enforce_precondition_failed"),
          },
        });
        await gotoAccount(page, lang);
        await row(page, "enforce").locator(".switch__control").click();
        await expect(row(page, "enforce").getByText(A("passkeys.enforce.needsReview"))).toBeVisible();
      });

      test("while Enforce is lifting, an alert says when it ends", async ({page, context, baseURL}) => {
        await open(context, baseURL, {
          me: {security: {passkeys: 2, enforce_passkey: true, enforce_lift_at: "2026-11-25T08:00:00Z"}},
          handlers: {"GET /account/passkeys": {body: {passkeys: passkeysFixture()}}},
        });
        await gotoAccount(page, lang);
        await expect(page.getByTestId("enforce-lift")).toBeVisible();
        await expect(page.getByTestId("enforce-lift")).toContainText(lang === "fa" ? /۱۴۰۵|۱۴۰۴/ : /2026/);
      });

      test("a pending review is an alert above the list, Reviewed asks for a reauth that cannot be a passkey", async ({page, context, baseURL}) => {
        let tries = 0;
        const mock = await open(context, baseURL, {
          me: {security: {passkeys: 2, passkey_review_required: true}},
          handlers: {
            "GET /account/passkeys": {body: {passkeys: passkeysFixture()}},
            "POST /account/passkeys/review": (_call, state) => {
              if (++tries === 1) return err(403, "reauth_required");
              state.me = {...state.me, security: {...state.me.security, passkey_review_required: false}};
              return {status: 204};
            },
          },
        });
        await gotoAccount(page, lang);
        const alert = page.getByTestId("passkey-review");
        await expect(alert).toBeVisible();
        // Every row keeps its Delete while the review is pending.
        await expect(row(page, `passkey-${PK_A}`).getByRole("button", {name: A("passkeys.deleteAria", {name: "Work laptop"})})).toBeVisible();
        await alert.getByRole("button", {name: A("passkeys.reviewed")}).click();
        const reauth = page.getByRole("dialog", {name: A("reauth.title")});
        await expect(reauth.getByRole("button", {name: A("reauth.passkey")})).toHaveCount(0);
        await reauth.locator('input[name="password"]').fill("Correct-Horse-9");
        await reauth.getByRole("button", {name: A("reauth.confirm")}).click();
        await expect(alert).toHaveCount(0);
        expect(mock.count("POST /account/passkeys/review")).toBe(2);
      });

      // wp9-r2-2: the alert and its button leave the page when the review is done, so the focus goes to the section title.
      test("after I checked the list the focus goes to the section title, not to the top of the page", async ({page, context, baseURL}) => {
        await open(context, baseURL, {
          me: {security: {passkeys: 2, passkey_review_required: true}},
          handlers: {
            "GET /account/passkeys": {body: {passkeys: passkeysFixture()}},
            "POST /account/passkeys/review": (_call, state) => {
              state.me = {...state.me, security: {...state.me.security, passkey_review_required: false}};
              return {status: 204};
            },
          },
        });
        await gotoAccount(page, lang);
        const alert = page.getByTestId("passkey-review");
        await alert.getByRole("button", {name: A("passkeys.reviewed")}).click();
        await expect(alert).toHaveCount(0);
        await expect(page.getByRole("heading", {level: 2, name: A("sections.passkeys")})).toBeFocused();
      });
    });

    test.describe("options", () => {
      test("Theme sets the page at once and the choice is saved to the account", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL);
        await gotoAccount(page, lang);
        const theme = row(page, "theme");
        await theme.getByRole("radio", {name: lang === "fa" ? "تیره" : "Dark"}).click();
        await expect(page.locator("html")).toHaveClass(/dark/);
        await expect.poll(() => bodies(mock, "PATCH", "/account/preferences").at(-1)).toEqual({theme: "dark"});
        await theme.getByRole("radio", {name: lang === "fa" ? "روشن" : "Light"}).click();
        await expect(page.locator("html")).not.toHaveClass(/dark/);
        await expect.poll(() => bodies(mock, "PATCH", "/account/preferences").at(-1)).toEqual({theme: "light"});
      });

      test("Show onboarding hints is a switch that saves {onboarding_hints: {enabled}}", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL);
        await gotoAccount(page, lang);
        const hints = page.getByRole("switch", {name: A("options.hints")});
        await expect(hints).toBeChecked();
        // The whole cell is the target: the input behind it is not clickable.
        await page.getByText(A("options.hints"), {exact: true}).click();
        await expect(hints).not.toBeChecked();
        expect(bodies(mock, "PATCH", "/account/preferences")).toEqual([{onboarding_hints: {enabled: false}}]);
      });

      test("Haptic feedback is not offered on a pointer that is not touch", async ({page, context, baseURL}) => {
        await open(context, baseURL);
        await gotoAccount(page, lang);
        await expect(page.getByRole("switch", {name: A("options.hints")})).toBeVisible();
        await expect(page.getByRole("switch", {name: A("options.haptic")})).toHaveCount(0);
      });

      test("Language switches the page to the other language and saves it", async ({page, context, baseURL}) => {
        const other = lang === "fa" ? "en" : "fa";
        const mock = await open(context, baseURL);
        await gotoAccount(page, lang);
        await row(page, "language").getByRole("radio", {name: other === "fa" ? "فارسی" : "English"}).click();
        await page.waitForURL(`**/${other}/preferences/account`);
        expect(bodies(mock, "PATCH", "/account/preferences")).toContainEqual({locale: other});
      });
    });

    test.describe("options on a touch screen", () => {
      test.use({hasTouch: true, isMobile: true, viewport: {width: 375, height: 812}});

      test("Haptic feedback is offered, device-local, and writes the key the shell reads", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL);
        await gotoAccount(page, lang);
        const haptic = page.getByRole("switch", {name: A("options.haptic")});
        await expect(haptic).not.toBeChecked();
        await page.getByText(A("options.haptic"), {exact: true}).tap();
        await expect(haptic).toBeChecked();
        expect(await page.evaluate(() => localStorage.getItem("ctrlz.haptics"))).toBe("1");
        // Nothing about it goes to the account.
        expect(mock.count("PATCH /account/preferences")).toBe(0);
        await page.getByText(A("options.haptic"), {exact: true}).tap();
        expect(await page.evaluate(() => localStorage.getItem("ctrlz.haptics"))).toBe("0");
      });
    });

    test.describe("home countries", () => {
      const combo = (page: Page) => page.getByRole("combobox", {name: A("home.search")});
      // A click and keys, as a person does it: `fill` scrolls after the list has opened, and the library closes a list on scroll.
      const search = async (page: Page, query: string) => {
        await combo(page).click();
        await page.keyboard.press("Control+A");
        await page.keyboard.type(query);
      };
      const handlers = (): Handlers => ({
        "PUT /account/home-countries": (call, state) => {
          const {countries} = call.body as {countries: string[]};
          state.me = {...state.me, tenant: {...state.me.tenant, home_countries: countries}};
          return {body: {countries}};
        },
      });

      test("choose by name, up to three; the fourth is not offered and the line says why; remove frees a place", async ({page, context, baseURL}) => {
        const mock = await open(context, baseURL, {handlers: handlers()});
        await gotoAccount(page, lang);
        const name = (en: string, fa: string) => (lang === "fa" ? fa : en);
        const home = row(page, "home-countries");
        // The passkeys above have loaded: a list that is open while the page above it moves is closed by the library.
        await expect(row(page, "enforce")).toBeVisible();
        await expect(home.getByRole("row", {name: name("Iran", "ایران")})).toBeVisible();

        await search(page, name("Germany", "آلمان"));
        await page.getByRole("option", {name: name("Germany", "آلمان"), exact: true}).click();
        await expect(home.getByRole("row", {name: name("Germany", "آلمان")})).toBeVisible();
        await search(page, name("France", "فرانسه"));
        await page.getByRole("option", {name: name("France", "فرانسه"), exact: true}).click();
        await expect(home.getByRole("row", {name: name("France", "فرانسه")})).toBeVisible();

        expect(bodies(mock, "PUT", "/account/home-countries")).toEqual([{countries: ["IR", "DE"]}, {countries: ["IR", "DE", "FR"]}]);
        await expect(combo(page)).toBeDisabled();
        await expect(home.getByText(lang === "fa" ? /حداکثر ۳ کشور/ : /up to 3 countries/)).toBeVisible();

        await home.getByRole("row", {name: name("France", "فرانسه")}).getByRole("button").click();
        await expect(combo(page)).toBeEnabled();
        expect(bodies(mock, "PUT", "/account/home-countries").at(-1)).toEqual({countries: ["IR", "DE"]});
      });

      // wp9-r2-1: the field is off while the PUT runs, and a disabled input takes no focus, so it is refocused when it is back.
      test("after a pick the focus is in the search field again, for the next country", async ({page, context, baseURL}) => {
        await open(context, baseURL, {handlers: handlers()});
        await gotoAccount(page, lang);
        const name = (en: string, fa: string) => (lang === "fa" ? fa : en);
        await expect(row(page, "enforce")).toBeVisible();
        await search(page, name("Germany", "آلمان"));
        await page.keyboard.press("ArrowDown");
        await page.keyboard.press("Enter");
        await expect(row(page, "home-countries").getByRole("row", {name: name("Germany", "آلمان")})).toBeVisible();
        await expect(combo(page)).toBeEnabled();
        await expect(combo(page)).toBeFocused();
        // The next country is typed with no Tab or click in between.
        await page.keyboard.type(name("France", "فرانسه"));
        await expect(page.getByRole("option", {name: name("France", "فرانسه"), exact: true})).toBeVisible();
      });

      // wp9-r1-4: the PUT replaces the whole list, so a second removal made before the first answer must wait.
      test("while a save runs the other tags cannot be removed, and the list that was saved is the one asked for", async ({page, context, baseURL}) => {
        let release!: () => void;
        const gate = new Promise<void>((resolve) => (release = resolve));
        const base = handlers();
        const mock = await open(context, baseURL, {
          me: {tenant: {home_countries: ["IR", "DE", "FR"]}},
          handlers: {
            "PUT /account/home-countries": async (call, state) => {
              await gate;
              return (base["PUT /account/home-countries"] as MockHandler)(call, state);
            },
          },
        });
        await gotoAccount(page, lang);
        const name = (en: string, fa: string) => (lang === "fa" ? fa : en);
        const home = row(page, "home-countries");
        await expect(row(page, "enforce")).toBeVisible();
        await home.getByRole("row", {name: name("France", "فرانسه")}).getByRole("button").click();
        await expect.poll(() => mock.count("PUT /account/home-countries")).toBe(1);
        await expect(home.getByRole("row", {name: name("Germany", "آلمان")}).getByRole("button")).toBeDisabled();
        release();
        await expect(home.getByRole("row", {name: name("Germany", "آلمان")}).getByRole("button")).toBeEnabled();
        await home.getByRole("row", {name: name("Germany", "آلمان")}).getByRole("button").click();
        await expect.poll(() => mock.count("PUT /account/home-countries")).toBe(2);
        expect(bodies(mock, "PUT", "/account/home-countries")).toEqual([{countries: ["IR", "DE"]}, {countries: ["IR"]}]);
      });

      test("the search finds a Persian name typed with Arabic letters, and says when nothing matches", async ({page, context, baseURL}) => {
        test.skip(lang !== "fa", "the folding of yeh and kaf is for Persian");
        await open(context, baseURL, {handlers: handlers()});
        await gotoAccount(page, lang);
        await expect(row(page, "enforce")).toBeVisible();
        // U+064A, the Arabic yeh, in place of the Persian one.
        await search(page, "ترك");
        await expect(page.getByRole("option", {name: "ترکیه"})).toBeVisible();
        await search(page, "zzzz");
        await expect(page.getByText(A("home.noMatch"))).toBeVisible();
      });
    });
  });
}
