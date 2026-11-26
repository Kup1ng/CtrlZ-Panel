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
  inviteInfoFixture,
  LANGS,
  openAnonymous,
  submit,
  text,
  type Handlers,
} from "./auth-support.ts";

// Round 4 of the review of WP8: the Retry button under a failed Resend resends (wp8-r4-1), a failure that no
// field owns leaves the focus in the form (r4-2), and "Use a different number" is off while a Resend runs, so
// a late answer cannot take the visitor back to the code step (r4-3). The stack-mode half of r4-4 is in
// auth.stack.spec.ts, and a static check of it in packages/ui/src/testing/stackSpec.test.ts.

test.beforeEach(({guard}) => allowAuthErrors(guard));

const PHONE = "09123456789";
const OTP_ID = otpChallengeId(9);
// One second, so the real clock is enough to wake the Resend button.
const issued = {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 1}};
const CODE = INVITE_TOKEN;

type Lang = "fa" | "en";

type Flow = {
  name: string;
  /** Opens the page and goes to the code step, with the focus in the code field. */
  open: (page: Page, context: BrowserContext, lang: Lang, handlers: Handlers) => Promise<Awaited<ReturnType<typeof openAnonymous>>>;
  /** The route that checks the code. */
  verify: string;
  /** The button that goes back to the number. */
  change: (lang: Lang) => string;
};

const FLOWS: Flow[] = [
  {
    name: "Login",
    verify: "/auth/login/otp",
    change: (lang) => text(lang, "login.otpCode.change"),
    open: async (page, context, lang, handlers) => {
      const mock = await openAnonymous(context, handlers);
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      return mock;
    },
  },
  {
    name: "Register",
    verify: "/auth/register",
    change: (lang) => text(lang, "register.change"),
    open: async (page, context, lang, handlers) => {
      const mock = await openAnonymous(context, handlers, {registration_mode: "open"});
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      return mock;
    },
  },
  {
    name: "Invite",
    verify: "/auth/register",
    change: (lang) => text(lang, "invite.another"),
    open: async (page, context, lang, handlers) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": {body: inviteInfoFixture()}, ...handlers});
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(submit(page)).toBeEnabled();
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      return mock;
    },
  },
  {
    name: "Forgot Password",
    verify: "/auth/password/reset/verify",
    change: (lang) => text(lang, "forgot.change"),
    open: async (page, context, lang, handlers) => {
      const mock = await openAnonymous(context, handlers);
      await gotoForm(page, `/${lang}/forgot-password`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      return mock;
    },
  },
];

type Reply = typeof issued | ReturnType<typeof err>;

/** Answers the n-th call to a route with the n-th reply of the list, and the last one for every call after. */
function inOrder(...replies: Array<Reply | (() => Promise<Reply>)>) {
  let n = 0;
  return async () => {
    const reply = replies[Math.min(n++, replies.length - 1)]!;
    return typeof reply === "function" ? reply() : reply;
  };
}

for (const {lang, dir} of LANGS) {
  test.describe(`round 4, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    for (const flow of FLOWS) {
      // wp8-r4-1: the Retry under a failed Resend ran the verify path of the code step, so no new code was asked
      // for and the alert went away as if it had worked.
      test(`wp8-r4-1: ${flow.name}, Retry under a failed Resend asks for the code again and verifies nothing`, async ({page, context}) => {
        const mock = await flow.open(page, context, lang, {
          "POST /auth/otp/request": inOrder(issued, err(503, "service_unavailable"), issued),
          [`POST ${flow.verify}`]: err(401, "otp_invalid"),
        });
        // Register and Invite also show a warning alert of their own, so the failure is found by its text.
        const failure = formAlert(page).filter({hasText: errorText(lang, "service_unavailable")});
        const resend = page.getByRole("button", {name: T("resend.action")});
        await expect(resend).toBeEnabled();
        await resend.click();
        await expect(failure).toHaveCount(1);
        await expect.poll(() => callsTo(mock, "POST", "/auth/otp/request").length).toBe(2);
        // Digits typed while the alert is up must not be what Retry sends.
        await field(page, "code").focus();
        await page.keyboard.type("123");
        await failure.getByRole("button").click();
        await expect.poll(() => callsTo(mock, "POST", "/auth/otp/request").length).toBe(3);
        expect(callsTo(mock, "POST", flow.verify)).toHaveLength(0);
        await expect(failure).toHaveCount(0);
        await expect(field(page, "code")).toBeFocused();
        await expect(page.getByRole("status").filter({hasText: T("resend.sent")})).toBeVisible();
        // The field has no validation message from a code check that never ran.
        await expect(field(page, "code")).not.toHaveAttribute("aria-invalid", "true");
      });

      // wp8-r4-3: the change button was off only while the submit ran.
      test(`wp8-r4-3: ${flow.name}, the change button is off while Resend runs, and a late answer stays on the code step`, async ({page, context}) => {
        const mock = await flow.open(page, context, lang, {
          "POST /auth/otp/request": inOrder(issued, async () => {
            await new Promise((r) => setTimeout(r, 1500));
            return issued;
          }),
        });
        const resend = page.getByRole("button", {name: T("resend.action")});
        await expect(resend).toBeEnabled();
        await resend.click();
        const change = page.getByRole("button", {name: flow.change(lang)});
        await expect(change).toBeDisabled();
        await change.click({force: true});
        await expect.poll(() => callsTo(mock, "POST", "/auth/otp/request").length).toBe(2);
        await expect(page.getByRole("status").filter({hasText: T("resend.sent")})).toBeVisible();
        await expect(field(page, "code")).toBeVisible();
        await expect(change).toBeEnabled();
      });
    }

    // wp8-r4-2: the fields are disabled while the call runs, which drops the focus to BODY; a failure with no
    // field of its own had nothing to give it back to.
    test("wp8-r4-2: a 500 on the password form leaves the focus in the form", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/login/password": err(500, "internal", {request_id: "req-r4-2"})});
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill("x");
      // Enter in the field, as a keyboard user does: the field is disabled while the call runs, and a click on the
      // submit button would leave the focus on that button and hide the defect.
      await field(page, "password").press("Enter");
      await expect(formAlert(page)).toHaveCount(1);
      // The field it was in, not any field (wp8-r5-2 tightened this from a count of one).
      await expect(field(page, "password")).toBeFocused();
    });

    test("wp8-r4-2: a 503 on the SMS code leaves the focus in the code field", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/otp/request": issued, "POST /auth/login/otp": err(503, "service_unavailable")});
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("123456");
      await expect(formAlert(page)).toHaveCount(1);
      await expect(field(page, "code")).toBeFocused();
    });

    test("wp8-r4-2: the Retry button keeps the focus it was pressed with", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/login/password": err(503, "service_unavailable")});
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill("x");
      await submit(page).click();
      await expect(formAlert(page)).toHaveCount(1);
      const retry = formAlert(page).getByRole("button");
      await retry.focus();
      await retry.press("Enter");
      await expect.poll(() => callsTo(mock, "POST", "/auth/login/password").length).toBe(2);
      await expect(formAlert(page)).toHaveCount(1);
      await expect(page.locator("form :focus")).toHaveCount(1);
    });
  });
}
