import type {Page} from "@playwright/test";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import {LIVE_ANNOUNCER} from "@ctrlz/ui/testing/axeLogic.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectMatrixPage} from "@ctrlz/ui/testing/matrixAssert.ts";

import {acc, allowAccountErrors, type Handlers, type Lang, open, passkeysFixture, PK_STALE, row, TOTP_URI} from "./account-support.ts";
import {passkeyRowFixture, type meFixture} from "@ctrlz/api-client/testing/fixtures.ts";

// The smoke case of the Account page (spec 17.1, 19.1) on all 12 projects (three widths, two languages,
// two themes): the page renders in the project's language, direction and theme, has no sideways scroll,
// carries dark text on the accent, and has no serious or critical axe violation (17.5). Each state that
// draws something else is its own screen: the rows, an open editor, the wizard's modal, the session list,
// the passkey section with every alert, and the Home Countries limit.

test.beforeEach(({guard}) => allowAccountErrors(guard));


type Screen = {
  name: string;
  me?: Parameters<typeof meFixture>[0];
  handlers?: Handlers;
  after?: (page: Page, lang: Lang) => Promise<void>;
};

const passkeyHandlers: Handlers = {
  "GET /account/passkeys": {body: {passkeys: [...passkeysFixture(), passkeyRowFixture({id: PK_STALE, name: "Old phone", stale: true})]}},
};

const SCREENS: Screen[] = [
  {name: "rows"},
  {
    name: "phone-editor",
    after: async (page, lang) => {
      await row(page, "phone").getByRole("button", {name: acc(lang, "phone.editAria")}).click();
      await expect(row(page, "phone").locator('input[name="password"]')).toBeVisible();
    },
  },
  {
    name: "totp-wizard",
    handlers: {"POST /account/totp/setup": {body: {secret: "JBSWY3DPEHPK3PXP", otpauth_uri: TOTP_URI}}},
    after: async (page, lang) => {
      await row(page, "totp").getByRole("button", {name: acc(lang, "totp.enable")}).click();
      const dialog = page.getByRole("dialog");
      await dialog.locator('input[name="password"]').fill("Correct-Horse-9");
      await dialog.getByRole("button", {name: acc(lang, "reauth.submit")}).click();
      await expect(dialog.getByTestId("totp-qr")).toBeVisible();
    },
  },
  {
    name: "sessions",
    after: async (page, lang) => {
      await row(page, "sessions").getByRole("button", {name: acc(lang, "sessions.manageAria")}).click();
      await expect(row(page, "sessions").getByRole("listitem")).toHaveCount(3);
    },
  },
  {
    name: "passkeys",
    me: {security: {passkeys: 3, passkey_review_required: true, enforce_passkey: true, enforce_lift_at: "2026-11-25T08:00:00Z"}},
    handlers: passkeyHandlers,
    after: async (page) => {
      await expect(page.getByTestId("passkey-review")).toBeVisible();
      await expect(page.getByTestId("enforce-lift")).toBeVisible();
      await expect(row(page, "enforce")).toBeVisible();
    },
  },
  {
    name: "home-countries-full",
    me: {tenant: {home_countries: ["IR", "DE", "FR"]}},
    after: async (page) => {
      await expect(page.getByRole("combobox")).toBeDisabled();
    },
  },
  {
    name: "two-step-on",
    me: {security: {totp_enabled: true, recovery_codes_left: 2}},
  },
];

for (const screen of SCREENS) {
  test(`${screen.name}: language, direction, theme, no overflow, accessible`, async ({page, context, baseURL, matrix}) => {
    expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
    // The session gate adopts the account's theme once `/me` answers (spec 5.1), so the account holds the project's.
    await open(context, baseURL, {me: {...screen.me, user: {...screen.me?.user, theme: matrix!.theme}}, handlers: screen.handlers});
    const lang = matrix!.lang;
    const response = await page.goto(`/${lang}/preferences/account`);
    await expect(row(page, "phone")).toBeVisible();
    // The passkey section has loaded: the page does not move under the checks below.
    await expect(row(page, "enforce")).toBeVisible();
    await screen.after?.(page, lang);
    await expectMatrixPage({page, context, response, baseURL, matrix: matrix!});
    await expectAccessible(page, {screen: `account-${screen.name}`, libraryDefects: [LIVE_ANNOUNCER]});
  });
}
