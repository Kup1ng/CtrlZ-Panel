import {errorBody, meFixture, otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
import {installApiMock} from "@ctrlz/api-client/testing/mock.ts";
import type {BrowserContext, Page} from "@playwright/test";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import type {LibraryDefect} from "@ctrlz/ui/testing/axeLogic.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectMatrixPage} from "@ctrlz/ui/testing/matrixAssert.ts";

import {
  INVITE_TOKEN,
  allowAuthErrors,
  callsTo,
  err,
  field,
  inviteInfoFixture,
  liveConfig,
  openAnonymous,
  refetchConfig,
  STRONG_PASSWORD,
  submit,
  text,
  type Lang,
  typeWhenFocused,
} from "./auth-support.ts";

// The smoke case of every user auth screen (spec 17.1, 19.1) on all 12 projects (three widths, two
// languages, two themes): the page renders in the project's language, direction and theme, has no
// sideways scroll, carries dark text on the accent, and has no serious or critical axe violation (17.5).

test.beforeEach(({guard}) => allowAuthErrors(guard));

// React Aria's live announcer, which a Button with `isPending` creates (spec 10.1 asks for that button) the first
// time a form is submitted: a `role="log"` holding an empty `role="img"` with an `aria-labelledby` that points
// at nothing. axe fails it as `role-img-alt` (serious). It is the library's element and not ours, it is inert
// (a screen reader reads the announcement from the log, not from the image), and the owner cannot fix it here.
// Its selector holds a random id, so `axe-known.json` (rule plus selector, 17.5) cannot list it. It is listed
// here by the region it sits in: the run summary reports it, nothing else inside the log is excused, and the
// entry fails as stale on the login-code screen when axe stops failing it (wp8-r5-5).
const LIVE_ANNOUNCER: LibraryDefect = {
  rule: "role-img-alt",
  within: '[role="log"]',
  element: '[role="img"]',
  note: "React Aria live announcer: an empty role=img with a dangling aria-labelledby",
};

const PHONE = "09123456789";
const issued = {status: 202, body: {challenge_id: otpChallengeId(1), expires_in_s: 300, resend_after_s: 60}};

type Screen = {
  name: string;
  path: (lang: string) => string;
  setup: (context: BrowserContext, baseURL: string | undefined) => Promise<void>;
  after?: (page: Page, lang: Lang, context: BrowserContext) => Promise<void>;
  /** The screen shows an answer of 404 on purpose (the browser logs it as a console error). */
  expects404?: boolean;
  /**
   * The submit button is disabled on purpose once the screen has settled (the invite's Send while SMS is down), so
   * "enabled" cannot be the sign that React owns the page: it is enabled only until `/auth/config` answers, and a
   * fast answer made the wait fail. `after` waits for a client-rendered line instead.
   */
  submitStaysDisabled?: boolean;
  /** The screen changes with time (a refetch of /auth/config), so the page runs on a fake clock. */
  clock?: boolean;
};

// The mock of the screen that flips /auth/config while it is open. Matrix tests of one worker run one after
// the other, so one slot is enough.
let flipping: {flip: () => Promise<void>} | null = null;
let flippingMock: Awaited<ReturnType<typeof openAnonymous>> | null = null;

const cookie = (context: BrowserContext, baseURL: string | undefined) =>
  context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);

const SCREENS: Screen[] = [
  {
    name: "login",
    path: (l) => `/${l}/login`,
    setup: async (context) => void (await openAnonymous(context, {}, {registration_mode: "open", passkey_enabled: true})),
    after: async (page) => {
      await expect(page.getByRole("tab")).toHaveCount(2);
    },
  },
  {
    name: "login-sms",
    path: (l) => `/${l}/login?step=otp-phone`,
    setup: async (context) => void (await openAnonymous(context, {"POST /auth/otp/request": issued})),
    after: async (page) => {
      await expect(page.getByRole("tab").nth(1)).toHaveAttribute("aria-selected", "true");
    },
  },
  {
    name: "login-code",
    path: (l) => `/${l}/login?step=otp-phone`,
    setup: async (context) => void (await openAnonymous(context, {"POST /auth/otp/request": issued})),
    after: async (page) => {
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeVisible();
    },
  },
  {
    name: "login-2fa",
    path: (l) => `/${l}/login`,
    setup: async (context) =>
      void (await openAnonymous(context, {"POST /auth/login/password": {body: {status: "mfa_required", ticket: "t", ticket_expires_in_s: 300, methods: ["totp", "recovery_code"]}}})),
    after: async (page) => {
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill("x");
      await submit(page).click();
      await expect(field(page, "totp_code")).toBeVisible();
    },
  },
  {
    name: "register",
    path: (l) => `/${l}/register`,
    setup: async (context) => void (await openAnonymous(context, {}, {registration_mode: "open"})),
  },
  {
    name: "register-confirm",
    path: (l) => `/${l}/register`,
    setup: async (context) => void (await openAnonymous(context, {"POST /auth/otp/request": issued}, {registration_mode: "open"})),
    after: async (page) => {
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await field(page, "password").fill(STRONG_PASSWORD);
      await expect(page.getByRole("meter")).toBeVisible();
    },
  },
  {
    name: "register-closed",
    path: (l) => `/${l}/register`,
    setup: async (context) => void (await openAnonymous(context, {}, {registration_mode: "closed"})),
  },
  {
    name: "invite",
    path: (l) => `/${l}/invite`,
    setup: async (context) => void (await openAnonymous(context)),
  },
  {
    name: "invite-lookup",
    path: (l) => `/${l}/invite#${INVITE_TOKEN}`,
    setup: async (context) => void (await openAnonymous(context, {"POST /auth/invites/lookup": {body: {phone_masked: "+98912***4567", expires_at: "2026-11-20T10:00:00Z"}}})),
    after: async (page) => {
      await expect(page.locator("bdi", {hasText: "+98912***4567"})).toBeVisible();
    },
  },
  {
    name: "forgot-password",
    path: (l) => `/${l}/forgot-password`,
    setup: async (context) => void (await openAnonymous(context)),
  },
  {
    name: "change-password",
    path: (l) => `/${l}/change-password`,
    setup: async (context, baseURL) => {
      await cookie(context, baseURL);
      await installApiMock(context, {me: meFixture({user: {must_reset: true}, security: {totp_enabled: true}})});
    },
  },
  // Every step and every state of 10.9 that the first-render screens above do not reach (wp8-r1-9): a field
  // error, an error line, a wait, offline, a warning, the meter, the passkey and recovery modes, the later
  // steps of Forgot Password and of the invite. The two contrast findings of round 1 (an error in the dark
  // theme, the offline line in the light one) sat in exactly these gaps.
  {
    name: "login-field-error",
    path: (l) => `/${l}/login`,
    setup: async (context) => void (await openAnonymous(context)),
    after: async (page, lang) => {
      await submit(page).click();
      await expect(page.getByText(text(lang, "fields.phone.required"))).toBeVisible();
      await expect(field(page, "phone")).toHaveAttribute("aria-invalid", "true");
    },
  },
  {
    name: "login-error-line",
    path: (l) => `/${l}/login`,
    setup: async (context) => void (await openAnonymous(context, {"POST /auth/login/password": err(401, "invalid_credentials")})),
    after: async (page) => {
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill("x");
      await submit(page).click();
      await expect(page.locator(".alert")).toBeVisible();
    },
  },
  {
    name: "login-wait",
    path: (l) => `/${l}/login`,
    setup: async (context) => void (await openAnonymous(context, {"POST /auth/login/password": err(429, "too_many_attempts", {retry_after_s: 60})})),
    after: async (page) => {
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill("x");
      await submit(page).click();
      await expect(page.locator(".alert")).toBeVisible();
      await expect(submit(page)).toBeDisabled();
    },
  },
  {
    name: "login-suspended",
    path: (l) => `/${l}/login`,
    setup: async (context) => void (await openAnonymous(context, {"POST /auth/login/password": err(403, "account_suspended")})),
    after: async (page, lang) => {
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill("x");
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(text(lang, "suspended.title"));
    },
  },
  {
    name: "login-offline",
    path: (l) => `/${l}/login`,
    setup: async (context) => void (await openAnonymous(context)),
    after: async (page, lang, context) => {
      await context.setOffline(true);
      await expect(page.getByText(text(lang, "form.offline"))).toBeVisible();
    },
  },
  {
    name: "login-sms-down",
    path: (l) => `/${l}/login`,
    setup: async (context) => void (await openAnonymous(context, {}, {sms_available: false})),
    after: async (page, lang) => {
      await expect(page.getByText(text(lang, "login.smsDown"))).toBeVisible();
    },
  },
  {
    // wp8-r15-2: the line that says why Resend is off, with its contrast on the card surface, in the 12 projects.
    name: "login-code-sms-down",
    path: (l) => `/${l}/login?step=otp-phone`,
    clock: true,
    setup: async (context) => {
      const {answer, handlers} = liveConfig({});
      const mock = await openAnonymous(context, {...handlers, "POST /auth/otp/request": issued});
      flipping = {
        flip: async () => {
          answer.value = {sms_available: false};
        },
      };
      flippingMock = mock;
    },
    after: async (page, lang) => {
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeVisible();
      await flipping!.flip();
      await refetchConfig(page, () => callsTo(flippingMock!, "GET", "/auth/config").length);
      await expect(page.getByText(text(lang, "resend.smsDown"))).toBeVisible();
    },
  },
  {
    name: "login-code-error",
    path: (l) => `/${l}/login?step=otp-phone`,
    setup: async (context) => void (await openAnonymous(context, {"POST /auth/otp/request": issued, "POST /auth/login/otp": err(401, "otp_invalid")})),
    after: async (page) => {
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("111111");
      await expect(page.getByRole("alert").filter({hasText: /./})).toBeVisible();
    },
  },
  {
    name: "login-2fa-recovery",
    path: (l) => `/${l}/login`,
    setup: async (context) =>
      void (await openAnonymous(context, {"POST /auth/login/password": {body: {status: "mfa_required", ticket: "t", ticket_expires_in_s: 300, methods: ["totp", "recovery_code"]}}})),
    after: async (page, lang) => {
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill("x");
      await submit(page).click();
      await page.getByRole("button", {name: text(lang, "login.twoFactor.useRecovery")}).click();
      await expect(field(page, "recovery_code")).toBeVisible();
    },
  },
  {
    name: "login-2fa-error",
    path: (l) => `/${l}/login`,
    setup: async (context) =>
      void (await openAnonymous(context, {
        "POST /auth/login/password": {body: {status: "mfa_required", ticket: "t", ticket_expires_in_s: 300, methods: ["totp", "recovery_code"]}},
        "POST /auth/login/totp": err(401, "totp_invalid"),
      })),
    after: async (page) => {
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill("x");
      await submit(page).click();
      await expect(field(page, "totp_code")).toBeFocused();
      await page.keyboard.type("654321");
      await expect(page.getByRole("alert").filter({hasText: /./})).toBeVisible();
    },
  },
  {
    name: "login-passkey",
    path: (l) => `/${l}/login`,
    setup: async (context, baseURL) => {
      await openAnonymous(
        context,
        {
          "POST /auth/passkey/login/begin": {body: {ticket: "pk", options: {publicKey: {challenge: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", rpId: new URL(baseURL!).hostname, timeout: 60000}}}},
        },
        {passkey_enabled: true},
      );
      // The prompt is closed at once, so the step settles with its two buttons and no spinner.
      await context.addInitScript(() => {
        // The script also runs in frames that are not a secure context, where there is no credentials object.
        if (navigator.credentials) navigator.credentials.get = () => Promise.reject(new DOMException("closed", "NotAllowedError"));
      });
    },
    after: async (page, lang) => {
      await page.getByRole("button", {name: text(lang, "login.passkey")}).click();
      await expect(page.getByRole("button", {name: text(lang, "login.passkeyStep.retry")})).toBeEnabled();
    },
  },
  {
    name: "register-no-password",
    path: (l) => `/${l}/register`,
    setup: async (context) => void (await openAnonymous(context, {"POST /auth/otp/request": issued}, {registration_mode: "open"})),
    after: async (page, lang) => {
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(page.getByText(text(lang, "register.noPassword"))).toBeVisible();
    },
  },
  {
    name: "register-weak",
    path: (l) => `/${l}/register`,
    setup: async (context) =>
      void (await openAnonymous(
        context,
        {"POST /auth/otp/request": issued, "POST /auth/register": {status: 422, body: errorBody("password_weak", {fields: [{name: "password", code: "repeated"}]})}},
        {registration_mode: "open"},
      )),
    after: async (page) => {
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await field(page, "password").fill("aaaaaaaaaaaaaaa");
      await field(page, "code").focus();
      await page.keyboard.type("123456");
      await submit(page).click();
      await expect(field(page, "password")).toHaveAttribute("aria-invalid", "true");
    },
  },
  {
    name: "invite-confirm",
    path: (l) => `/${l}/invite#${INVITE_TOKEN}`,
    setup: async (context) => void (await openAnonymous(context, {"POST /auth/invites/lookup": {body: inviteInfoFixture()}, "POST /auth/otp/request": issued})),
    after: async (page) => {
      await expect(page.locator("bdi", {hasText: "+98912***4567"})).toBeVisible();
      await submit(page).click();
      await expect(field(page, "code")).toBeVisible();
    },
  },
  {
    name: "invite-sms-down",
    submitStaysDisabled: true,
    path: (l) => `/${l}/invite#${INVITE_TOKEN}`,
    setup: async (context) => void (await openAnonymous(context, {"POST /auth/invites/lookup": {body: inviteInfoFixture()}}, {sms_available: false})),
    after: async (page, lang) => {
      await expect(page.getByText(text(lang, "invite.smsDown"))).toBeVisible();
      await expect(submit(page)).toBeDisabled();
    },
  },
  {
    name: "invite-invalid",
    expects404: true,
    path: (l) => `/${l}/invite#${INVITE_TOKEN}`,
    setup: async (context) => void (await openAnonymous(context, {"POST /auth/invites/lookup": err(404, "invite_invalid")})),
    after: async (page, lang) => {
      await expect(page.getByRole("heading", {level: 1})).toHaveText(text(lang, "invite.invalidTitle"));
    },
  },
  {
    name: "forgot-unavailable",
    path: (l) => `/${l}/forgot-password`,
    setup: async (context) => void (await openAnonymous(context, {}, {sms_available: false})),
  },
  {
    name: "forgot-code",
    path: (l) => `/${l}/forgot-password`,
    setup: async (context) => void (await openAnonymous(context, {"POST /auth/otp/request": issued})),
    after: async (page) => {
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeVisible();
    },
  },
  {
    name: "forgot-new-totp",
    path: (l) => `/${l}/forgot-password`,
    setup: async (context) =>
      void (await openAnonymous(context, {"POST /auth/otp/request": issued, "POST /auth/password/reset/verify": {body: {ticket: "r", second_factor: "totp"}}})),
    after: async (page) => {
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeWhenFocused(page, "123456");
      await field(page, "new_password").fill(STRONG_PASSWORD);
      await expect(page.getByRole("meter")).toBeVisible();
      await expect(field(page, "totp_code")).toBeVisible();
    },
  },
  {
    name: "forgot-new-error",
    path: (l) => `/${l}/forgot-password`,
    setup: async (context) =>
      void (await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": {body: {ticket: "r", second_factor: "none"}},
        "POST /auth/password/reset/complete": {status: 422, body: errorBody("password_weak", {fields: [{name: "new_password", code: "repeated"}]})},
      })),
    after: async (page) => {
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeWhenFocused(page, "123456");
      await field(page, "new_password").fill("aaaaaaaaaaaaaaa");
      await submit(page).click();
      await expect(field(page, "new_password")).toHaveAttribute("aria-invalid", "true");
    },
  },
  {
    name: "forgot-passkey-choice",
    path: (l) => `/${l}/forgot-password`,
    setup: async (context) =>
      void (await openAnonymous(context, {"POST /auth/otp/request": issued, "POST /auth/password/reset/verify": {body: {ticket: "r", second_factor: "passkey"}}})),
    after: async (page, lang) => {
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeWhenFocused(page, "123456");
      await expect(page.getByRole("button", {name: text(lang, "forgot.passkeyLost")})).toBeVisible();
    },
  },
  {
    name: "forgot-passkey-lost",
    path: (l) => `/${l}/forgot-password`,
    setup: async (context) =>
      void (await openAnonymous(context, {"POST /auth/otp/request": issued, "POST /auth/password/reset/verify": {body: {ticket: "r", second_factor: "passkey"}}})),
    after: async (page, lang) => {
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeWhenFocused(page, "123456");
      await page.getByRole("button", {name: text(lang, "forgot.passkeyLost")}).click();
      await expect(page.getByText(text(lang, "forgot.passkeyLostWarning"))).toBeVisible();
    },
  },
  {
    name: "forgot-done",
    path: (l) => `/${l}/forgot-password`,
    setup: async (context) =>
      void (await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": {body: {ticket: "r", second_factor: "none"}},
        "POST /auth/password/reset/complete": {status: 204},
      })),
    after: async (page, lang) => {
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeWhenFocused(page, "123456");
      await field(page, "new_password").fill(STRONG_PASSWORD);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(text(lang, "forgot.doneTitle"));
    },
  },
  {
    name: "change-password-error",
    path: (l) => `/${l}/change-password`,
    setup: async (context, baseURL) => {
      await cookie(context, baseURL);
      await installApiMock(context, {
        me: meFixture({user: {must_reset: true}}),
        handlers: {"POST /account/password": {status: 422, body: errorBody("password_weak", {fields: [{name: "new_password", code: "repeated"}]})}},
      });
    },
    after: async (page) => {
      await field(page, "new_password").fill("aaaaaaaaaaaaaaa");
      await submit(page).click();
      await expect(field(page, "new_password")).toHaveAttribute("aria-invalid", "true");
    },
  },
  {
    name: "change-password-reauth",
    path: (l) => `/${l}/change-password`,
    setup: async (context, baseURL) => {
      await cookie(context, baseURL);
      await installApiMock(context, {
        me: meFixture({user: {must_reset: true}}),
        handlers: {"POST /account/password": err(403, "reauth_required")},
      });
    },
    after: async (page) => {
      await field(page, "new_password").fill(STRONG_PASSWORD);
      await submit(page).click();
      await expect(field(page, "reauth_password")).toBeFocused();
    },
  },
  {
    name: "suspended",
    path: (l) => `/${l}/suspended`,
    setup: async (context, baseURL) => {
      await cookie(context, baseURL);
      await installApiMock(context, {me: meFixture({tenant: {status: "suspended"}})});
    },
  },
];

for (const screen of SCREENS) {
  test(`${screen.name}: language, direction, theme, no overflow, accessible`, async ({page, context, baseURL, matrix, guard}) => {
    expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
    if (screen.expects404) guard.allowConsole(/status of 404/);
    await screen.setup(context, baseURL);
    if (screen.clock) await page.clock.install();
    const response = await page.goto(screen.path(matrix!.lang));
    await expect(page.getByRole("heading", {level: 1})).toBeVisible();
    // Past hydration where there is a form to hydrate.
    if (!screen.submitStaysDisabled && (await submit(page).count())) await expect(submit(page).first()).toBeEnabled();
    await screen.after?.(page, matrix!.lang, context);
    await expectMatrixPage({page, context, response, baseURL, matrix: matrix!});
    await expectAccessible(page, {
      screen: `auth-${screen.name}`,
      libraryDefects: [LIVE_ANNOUNCER],
      // One screen that always has the defect keeps the entry honest; on the others the image is sometimes labelled.
      libraryDefectsMustOccur: screen.name === "login-code",
    });
  });
}

test("the language and theme menu opens, is accessible, and the language switch keeps the page", async ({page, context, baseURL, matrix}) => {
  await openAnonymous(context);
  const response = await page.goto(`/${matrix!.lang}/login`);
  await expect(submit(page).first()).toBeEnabled();
  await expectMatrixPage({page, context, response, baseURL, matrix: matrix!});
  await page.getByRole("button", {name: matrix!.lang === "fa" ? "زبان و پوسته" : "Language and theme"}).click();
  await expect(page.getByRole("menu")).toBeVisible();
  await expectAccessible(page, {screen: "auth-corner-menu"});
});
