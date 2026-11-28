import type {BrowserContext, Page} from "@playwright/test";
import {otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
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
  liveConfig,
  lastBody,
  LANGS,
  meReady,
  openAnonymous,
  refetchConfig,
  signedIn,
  STRONG_PASSWORD,
  submit,
  text,
  type Handlers,
} from "./auth-support.ts";

// Round 14 of the review of WP8: a later answer of /auth/config must not take a flow away once its SMS step is
// behind it (wp8-r14-1). The answer is flipped while the visitor is on a later step, the way a browser that comes
// back online does it: the 30 s stale time passes and the `online` event refetches. The gates guard the first
// step, the one that sends a text, and the Resend button; the step the visitor is on, its ticket or challenge and
// what was typed stay.

test.beforeEach(({guard}) => allowAuthErrors(guard));

const PHONE = "09123456789";
const OTP_ID = otpChallengeId(4);
const issued = {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 1}};

/** The first call to the route is answered with the first reply, every later one with the second. */
function firstThen<A, B>(first: A, then: B) {
  let n = 0;
  return () => (n++ === 0 ? first : then);
}

const DOWN = {sms_available: false, registration_mode: "closed"} as const;

for (const {lang, dir} of LANGS) {
  test.describe(`round 14, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    test("wp8-r14-1: Forgot Password step 3 keeps its ticket and what was typed when SMS goes down", async ({page, context}) => {
      await page.clock.install();
      const {answer, handlers} = liveConfig({});
      const mock = await openAnonymous(context, {
        ...handlers,
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": {body: {ticket: "reset-ticket-1", second_factor: "totp"}},
        "POST /auth/password/reset/complete": {status: 204},
      });
      await gotoForm(page, `/${lang}/forgot-password`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("123456");
      await expect(field(page, "new_password")).toBeFocused();
      await field(page, "new_password").fill(STRONG_PASSWORD);
      await field(page, "totp_code").focus();
      await page.keyboard.type("123");

      answer.value = {sms_available: false};
      await refetchConfig(page, () => callsTo(mock, "GET", "/auth/config").length);

      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("forgot.newTitle"));
      await expect(page.getByText(T("forgot.unavailableText"))).toHaveCount(0);
      await expect(field(page, "new_password")).toHaveValue(STRONG_PASSWORD);
      await expect(field(page, "totp_code")).toHaveValue("123");
      await field(page, "totp_code").focus();
      await page.keyboard.type("456");
      await expect.poll(() => lastBody(mock, "POST", "/auth/password/reset/complete")).toEqual({
        ticket: "reset-ticket-1",
        new_password: STRONG_PASSWORD,
        totp_code: "123456",
      });
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("forgot.doneTitle"));
    });

    test("wp8-r14-1: Forgot Password code step stays, Resend goes off with the reason, the code still verifies", async ({page, context}) => {
      await page.clock.install();
      const {answer, handlers} = liveConfig({});
      const mock = await openAnonymous(context, {
        ...handlers,
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": {body: {ticket: "reset-ticket-1", second_factor: "none"}},
      });
      await gotoForm(page, `/${lang}/forgot-password`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      const resend = page.getByRole("button", {name: T("resend.action")});

      answer.value = {sms_available: false};
      await refetchConfig(page, () => callsTo(mock, "GET", "/auth/config").length);

      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("forgot.codeTitle"));
      await expect(page.getByText(T("resend.smsDown"))).toBeVisible();
      await expect(resend).toBeDisabled();
      await field(page, "code").focus();
      await page.keyboard.type("123456");
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("forgot.newTitle"));
      expect(callsTo(mock, "POST", "/auth/otp/request")).toHaveLength(1);
    });

    test("wp8-r14-1: Register keeps its code step when SMS goes down and registration closes", async ({page, context, baseURL}) => {
      await page.clock.install();
      const {answer, handlers} = liveConfig({registration_mode: "open"});
      const mock = await openAnonymous(context, {
        ...handlers,
        "POST /auth/otp/request": issued,
        "POST /auth/register": signedIn(context, baseURL),
        "GET /me": meReady(),
      });
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("123456");
      await field(page, "password").fill(STRONG_PASSWORD);

      answer.value = DOWN;
      await refetchConfig(page, () => callsTo(mock, "GET", "/auth/config").length);

      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("register.confirmTitle"));
      await expect(page.getByText(T("register.closedTitle"))).toHaveCount(0);
      await expect(field(page, "password")).toHaveValue(STRONG_PASSWORD);
      await expect(page.getByText(T("resend.smsDown"))).toBeVisible();
      await expect(page.getByRole("button", {name: T("resend.action")})).toBeDisabled();
      await submit(page).click();
      await page.waitForURL(`**/${lang}/profiles`);
      expect(lastBody(mock, "POST", "/auth/register")).toMatchObject({phone: PHONE, challenge_id: OTP_ID, code: "123456"});
      expect(callsTo(mock, "POST", "/auth/otp/request")).toHaveLength(1);
    });

    test("wp8-r14-1: Login SMS code step stays and Resend goes off when SMS goes down", async ({page, context, baseURL}) => {
      await page.clock.install();
      const {answer, handlers} = liveConfig({});
      const mock = await openAnonymous(context, {
        ...handlers,
        "POST /auth/otp/request": issued,
        "POST /auth/login/otp": signedIn(context, baseURL),
        "GET /me": meReady(),
      });
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();

      answer.value = {sms_available: false};
      await refetchConfig(page, () => callsTo(mock, "GET", "/auth/config").length);

      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.otpCode.title"));
      await expect(field(page, "password")).toHaveCount(0);
      await expect(page.getByText(T("resend.smsDown"))).toBeVisible();
      await expect(page.getByRole("button", {name: T("resend.action")})).toBeDisabled();
      await field(page, "code").focus();
      await page.keyboard.type("123456");
      await page.waitForURL(`**/${lang}/profiles`);
      expect(lastBody(mock, "POST", "/auth/login/otp")).toMatchObject({phone: PHONE, challenge_id: OTP_ID, code: "123456"});
    });

    test("wp8-r14-1: Invite confirm step keeps Resend off when SMS goes down", async ({page, context}) => {
      await page.clock.install();
      const {answer, handlers} = liveConfig({registration_mode: "invite"});
      const mock = await openAnonymous(context, {
        ...handlers,
        "POST /auth/invites/lookup": {body: {phone_masked: "+98912***4567", expires_at: "2026-11-20T10:00:00Z"}},
        "POST /auth/otp/request": issued,
      });
      await page.goto(`/${lang}/invite#${INVITE_TOKEN}`);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();

      answer.value = {sms_available: false, registration_mode: "invite"};
      await refetchConfig(page, () => callsTo(mock, "GET", "/auth/config").length);

      await expect(field(page, "code")).toBeVisible();
      await expect(page.getByText(T("resend.smsDown"))).toBeVisible();
      await expect(page.getByRole("button", {name: T("resend.action")})).toBeDisabled();
    });

    // wp8-r15-1: a failed Resend leaves a Retry button; once SMS is down Resend refuses, so that Retry would
    // do nothing. The failure is taken back and the reason line stays. wp8-r15-2: the line is announced, so its
    // region is already in the page, empty, when the answer arrives.
    const FLOWS = [
      {
        name: "Login SMS code",
        open: async (page: Page, context: BrowserContext, handlers: Handlers) => {
          const mock = await openAnonymous(context, handlers);
          await gotoForm(page, `/${lang}/login?step=otp-phone`);
          return mock;
        },
      },
      {
        name: "Forgot Password code",
        open: async (page: Page, context: BrowserContext, handlers: Handlers) => {
          const mock = await openAnonymous(context, handlers);
          await gotoForm(page, `/${lang}/forgot-password`);
          return mock;
        },
      },
    ];
    for (const flow of FLOWS) {
      test(`wp8-r15-1, r15-2: ${flow.name}, a failed Resend loses its Retry when SMS goes down and the reason is announced`, async ({page, context}) => {
        await page.clock.install();
        const {answer, handlers} = liveConfig({});
        const mock = await flow.open(page, context, {
          ...handlers,
          "POST /auth/otp/request": firstThen(issued, err(503, "service_unavailable")),
        });
        await field(page, "phone").fill(PHONE);
        await submit(page).click();
        await expect(field(page, "code")).toBeFocused();
        await page.clock.fastForward(2_000);
        const resend = page.getByRole("button", {name: T("resend.action")});
        await expect(resend).toBeEnabled();
        await resend.click();
        const failure = formAlert(page).filter({hasText: errorText(lang, "service_unavailable")});
        await expect(failure.getByRole("button")).toBeVisible();

        // Both status lines of the step are in the page before the answer, empty; the reason is the last one.
        const region = page.locator('p[role="status"][aria-live="polite"]').last();
        await expect(region).toBeEmpty();
        const before = await region.elementHandle();

        answer.value = {sms_available: false};
        await refetchConfig(page, () => callsTo(mock, "GET", "/auth/config").length);

        await expect(page.getByText(T("resend.smsDown"))).toBeVisible();
        await expect(failure).toHaveCount(0);
        expect(await before!.evaluate((el) => el.isConnected && el.textContent)).toBe(T("resend.smsDown"));
        expect(callsTo(mock, "POST", "/auth/otp/request")).toHaveLength(2);
      });
    }
  });
}
