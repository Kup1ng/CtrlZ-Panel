import {
  adminUserFixture,
  alertFixture,
  auditFixture,
  gatewayFixture,
  inviteFixture,
  limitsFixture,
  statsFixture,
  templateFixture,
} from "@ctrlz/api-client/testing/adminFixtures.ts";
import type {adminMeFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import type {Page} from "@playwright/test";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import type {LibraryDefect} from "@ctrlz/ui/testing/axeLogic.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectMatrixPage} from "@ctrlz/ui/testing/matrixAssert.ts";

import {adm, allowAdminErrors, err, type Handlers, type Lang, openAdmin, shellText, TOTP_URI} from "./admin-support.ts";

// The smoke case of every admin screen (spec 17.1, 19.2) on all 12 projects (three widths, two languages, two themes): the
// page renders in the project's language, direction and theme, has no sideways scroll, carries dark text on the accent, and
// has no serious or critical axe violation (17.5). Each state that draws something else is its own screen: the dialogs, the
// one-time result, the setup steps, the SMS tabs, the impact before a confirm and the banner stack.

test.beforeEach(({guard}) => allowAdminErrors(guard));

// React Aria's live announcer, which a Button with `isPending` creates the first time a form is submitted
// (see account.matrix.spec.ts): the library's own element, inert, and listed by the region it sits in.
const LIVE_ANNOUNCER: LibraryDefect = {
  rule: "role-img-alt",
  within: '[role="log"]',
  element: '[role="img"]',
  note: "React Aria live announcer: an empty role=img with a dangling aria-labelledby",
};

const users = Array.from({length: 6}, (_, i) => adminUserFixture({phone_e164: `+98912000${1001 + i}`, tenant_status: i === 3 ? "suspended" : "active", one_time_password_expires_at: i === 1 ? "2026-11-20T00:00:00Z" : undefined}));
const gateways = [
  gatewayFixture(),
  gatewayFixture({provider: "melipayamak", role: "fallback", hint: "…77c1", last_error_at: "2026-11-16T05:00:00Z", last_error_code: "timeout", breaker_open_until: "2099-01-01T00:00:00Z"}),
  gatewayFixture({provider: "noop", role: "disabled", configured: false, hint: undefined, cost_per_message: undefined, last_ok_at: undefined}),
];

const handlers: Handlers = {
  "GET /users": {body: {items: users}},
  "GET /invites": {body: {items: [inviteFixture(), inviteFixture({state: "used"}), inviteFixture({state: "expired"}), inviteFixture({state: "revoked"})]}},
  "GET /audit": {body: {items: [auditFixture({action: "sms.gateway_put", target: "sms_ir", params: {fields: ["credentials"]}}), auditFixture()]}},
  "GET /sms/gateways": {body: {items: gateways}},
  "GET /sms/templates": {body: {items: [templateFixture({mappings: [{provider: "sms_ir", provider_template_id: "123456", param_names: ["code"]}]}), templateFixture({key: "invite", locale: "en", body: "Join Ctrl Z: {code}"})]}},
  "GET /sms/limits": {body: limitsFixture()},
  "GET /sms/stats": {body: statsFixture()},
  "GET /settings/registration": {body: {mode: "invite", open_grace_days: 0, takeover_idle_days: 30}},
  "GET /settings/webauthn": {body: {rp_id: "panel.example.ir", allowed_origins: ["https://panel.example.ir"], enabled: false}},
  "GET /settings/registration/impact": {body: {graced: 12, suspended_at_once: 3}},
  "GET /settings/webauthn/impact": {body: {credentials: 4, users: 3, enforced_users: 1}},
  "POST /users": {status: 201, body: {tenant_id: "00000000-0000-4000-8000-0000000000aa", user_id: "00000000-0000-4000-8000-0000000000bb", one_time_password: "fixture-otp-value"}},
  "POST /me/totp/setup": {body: {secret: "JBSWY3DPEHPK3PXP", otpauth_uri: TOTP_URI}},
};

type Screen = {
  name: string;
  /** The path after the language. */
  path: string;
  /** Something to wait for, so the page does not move under the checks. */
  ready: (page: Page, lang: Lang) => Promise<void>;
  me?: Partial<ReturnType<typeof adminMeFixture>>;
  signedIn?: boolean;
  alerts?: boolean;
  handlers?: Handlers;
  after?: (page: Page, lang: Lang) => Promise<void>;
};

const heading = (key: string) => async (page: Page, lang: Lang) => {
  await expect(page.getByRole("heading", {level: 1, name: adm(lang, key)})).toBeVisible();
};

const SCREENS: Screen[] = [
  {name: "login", path: "/login", signedIn: false, ready: heading("login.title")},
  {name: "login-ended", path: "/login?ended=1", signedIn: false, ready: heading("login.title"), after: async (page) => expect(page.getByTestId("session-ended")).toBeVisible()},
  {
    name: "setup-password",
    path: "/setup",
    me: {must_change_password: true, totp_enrolled: false},
    ready: heading("setup.password.title"),
  },
  {
    name: "setup-totp",
    path: "/setup",
    me: {must_change_password: false, totp_enrolled: false},
    ready: heading("setup.totp.title"),
    // A page opened straight on this step makes no secret until it is asked for (gate-r33-2).
    after: async (page) => {
      await page.getByTestId("totp-show").click();
      await expect(page.getByTestId("totp-qr")).toBeVisible();
    },
  },
  {name: "users", path: "/users", ready: heading("pages.users.title"), after: async (page, lang) => expect(page.getByRole("grid", {name: adm(lang, "users.gridLabel")}).getByRole("row")).toHaveCount(users.length + 1)},
  {
    name: "users-banners",
    path: "/users",
    me: {fresh_until: new Date(Date.now() + 4 * 60_000).toISOString(), notices: [{kind: "password_reset", at: "2026-11-16T08:00:00Z"}]},
    alerts: true,
    ready: heading("pages.users.title"),
    after: async (page, lang) => expect(page.getByText(adm(lang, "notices.password_reset.title"))).toBeVisible(),
  },
  {name: "users-empty", path: "/users", handlers: {"GET /users": {body: {items: []}}}, ready: heading("pages.users.title"), after: async (page) => expect(page.getByTestId("grid-empty")).toBeVisible()},
  {name: "users-failed", path: "/users", handlers: {"GET /users": err(503, "service_unavailable")}, ready: heading("pages.users.title"), after: async (page) => expect(page.getByRole("alert")).toBeVisible()},
  {name: "users-create", path: "/users?dialog=createUser", ready: heading("pages.users.title"), after: async (page, lang) => expect(page.getByRole("dialog", {name: adm(lang, "users.create.title")})).toBeVisible()},
  {
    name: "users-result",
    path: "/users",
    ready: heading("pages.users.title"),
    after: async (page, lang) => {
      await page.getByRole("button", {name: adm(lang, "users.create.open")}).click();
      await page.locator('input[name="phone"]').fill("09121234567");
      await page.getByRole("button", {name: adm(lang, "users.create.submit"), exact: true}).click();
      await expect(page.getByTestId("one-time-result")).toBeVisible();
    },
  },
  {name: "invites", path: "/invites", ready: heading("pages.invites.title"), after: async (page, lang) => expect(page.getByRole("grid", {name: adm(lang, "invites.gridLabel")}).getByRole("row")).toHaveCount(5)},
  {name: "invites-create", path: "/invites?dialog=createInvite", ready: heading("pages.invites.title"), after: async (page, lang) => expect(page.getByRole("dialog", {name: adm(lang, "invites.create.title")})).toBeVisible()},
  {name: "sms-gateways", path: "/sms", alerts: true, ready: heading("pages.sms.title"), after: async (page) => expect(page.getByTestId("gateway-sms_ir")).toBeVisible()},
  {
    name: "sms-edit",
    path: "/sms",
    ready: heading("pages.sms.title"),
    after: async (page, lang) => {
      await page.getByTestId("gateway-melipayamak").getByRole("button", {name: adm(lang, "sms.gateways.edit")}).click();
      await expect(page.getByRole("dialog").locator('input[name="gw_melipayamak_password"]')).toBeVisible();
    },
  },
  {
    name: "sms-test",
    path: "/sms",
    ready: heading("pages.sms.title"),
    after: async (page, lang) => {
      await page.getByTestId("gateway-sms_ir").getByRole("button", {name: adm(lang, "sms.gateways.test")}).click();
      await expect(page.getByRole("dialog").locator('input[name="phone"]')).toBeVisible();
    },
  },
  {
    name: "sms-routing",
    path: "/sms",
    ready: heading("pages.sms.title"),
    after: async (page, lang) => {
      await page.getByRole("tab", {name: adm(lang, "sms.tabs.routing")}).click();
      await expect(page.getByTestId("sms-routing")).toBeVisible();
    },
  },
  {
    name: "sms-templates",
    path: "/sms",
    ready: heading("pages.sms.title"),
    after: async (page, lang) => {
      await page.getByRole("tab", {name: adm(lang, "sms.tabs.templates")}).click();
      await expect(page.getByTestId("template-otp-fa")).toBeVisible();
      await page.getByTestId("template-otp-fa").locator("textarea").fill("ک".repeat(70));
      await expect(page.getByTestId("otp-refused")).toBeVisible();
    },
  },
  {
    name: "sms-limits",
    path: "/sms",
    ready: heading("pages.sms.title"),
    after: async (page, lang) => {
      await page.getByRole("tab", {name: adm(lang, "sms.tabs.limits")}).click();
      await expect(page.getByTestId("sms-limits")).toBeVisible();
    },
  },
  {
    name: "sms-stats",
    path: "/sms",
    ready: heading("pages.sms.title"),
    after: async (page, lang) => {
      await page.getByRole("tab", {name: adm(lang, "sms.tabs.stats")}).click();
      await expect(page.getByTestId("sms-stats")).toBeVisible();
    },
  },
  {name: "settings", path: "/settings", ready: heading("pages.settings.title"), after: async (page) => expect(page.getByTestId("webauthn-origins")).toBeVisible()},
  {
    name: "settings-impact",
    path: "/settings",
    ready: heading("pages.settings.title"),
    after: async (page, lang) => {
      await page.getByRole("radio", {name: adm(lang, "settings.registration.mode.open")}).click();
      await expect(page.getByTestId("impact-graced")).toBeVisible();
      await page.getByTestId("settings-webauthn").locator('input[name="rp_id"]').fill("example.ir");
      await expect(page.getByTestId("impact-credentials")).toBeVisible();
    },
  },
  {name: "audit", path: "/audit", ready: heading("pages.audit.title"), after: async (page, lang) => expect(page.getByRole("grid", {name: adm(lang, "audit.gridLabel")}).getByRole("row")).toHaveCount(3)},
  {
    name: "account-dialog",
    path: "/users",
    ready: heading("pages.users.title"),
    after: async (page, lang) => {
      // Below md the sidebar is a panel behind the hamburger, and the user menu is at its foot.
      const hamburger = page.getByRole("button", {name: shellText(lang, "sidebar.openMenu")});
      if (await hamburger.isVisible()) await hamburger.click();
      await page.getByRole("button", {name: adm(lang, "userMenu.label", {name: "admin"})}).first().click();
      await page.getByRole("menuitem", {name: adm(lang, "userMenu.account")}).click();
      await expect(page.getByRole("dialog", {name: adm(lang, "account.title")})).toBeVisible();
      // The panel that held the menu has finished closing: it is a dialog too, and a half-faded one makes the contrast undecidable.
      await expect(page.getByRole("dialog")).toHaveCount(1);
      // At 375 the Account item sat where the dialog's Cancel button appears, and a hovered tertiary button is 4.22:1 (#66696c on
      // #e1e1e2). That is the theme's hover state, not this screen's, so the pointer leaves before the check (reported in the WP10 notes).
      await page.mouse.move(0, 0);
    },
  },
  {
    name: "fresh-dialog",
    path: "/settings",
    handlers: {"PUT /settings/webauthn": err(403, "totp_fresh_required")},
    ready: heading("pages.settings.title"),
    after: async (page, lang) => {
      const card = page.getByTestId("settings-webauthn");
      await card.getByRole("switch", {name: adm(lang, "settings.webauthn.enabled")}).locator("xpath=ancestor::label").click();
      await card.getByRole("button", {name: adm(lang, "settings.webauthn.submit")}).click();
      await expect(page.getByRole("dialog", {name: adm(lang, "fresh.title")})).toBeVisible();
    },
  },
];

for (const screen of SCREENS) {
  test(`${screen.name}: language, direction, theme, no overflow, accessible`, async ({page, context, baseURL, matrix}) => {
    expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
    const lang = matrix!.lang;
    await openAdmin(context, baseURL, {
      cookie: screen.signedIn !== false,
      me: screen.me,
      alerts: screen.alerts ? [alertFixture({severity: "critical", params: {provider: "sms_ir", class: "credit", code: "no_credit"}})] : [],
      handlers: {...handlers, ...screen.handlers},
    });
    const response = await page.goto(`/${lang}${screen.path}`);
    await screen.ready(page, lang);
    await screen.after?.(page, lang);
    await expectMatrixPage({page, context, response, baseURL, matrix: matrix!});
    await expectAccessible(page, {screen: `admin-${screen.name}`, libraryDefects: [LIVE_ANNOUNCER]});
  });
}
