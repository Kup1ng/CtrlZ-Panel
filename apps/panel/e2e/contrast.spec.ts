import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {measureContrast, type Measured} from "@ctrlz/ui/testing/measureContrast.ts";

import {acc, allowAccountErrors, gotoAccount, open, row, TOTP_URI} from "./account-support.ts";
import {allowAuthErrors, field, openAnonymous, submit, typeWhenFocused} from "./auth-support.ts";

// P1 gate. The contrast of states that axe cannot judge in a matrix run, measured on what the page paints (measureContrast.ts):
//   - a tertiary button (Cancel and Copy of every dialog) at rest, under the pointer and while pressed. Its text took the muted
//     colour of the dialog body, which on the hover fill of the light theme (#e1e1e2) was 4.22:1; tokens.css now names a foreground for it;
//   - the number in the active step of a stepper, 10px text in the accent colour: 2.33:1 on white in the light theme (axe: "incomplete",
//     the text is too short for it to decide), so the number is drawn in the foreground colour, and so is the ring, which must reach 3:1 (WCAG 1.4.11).
//   - on the sign-in page, the selected tab over its own indicator (axe: "overlapped by another element") and the digits in the slots of the
//     one-time code (axe: "too short", and the real input over them is transparent, so it has "no value").
//   - the selected item of the Theme segment on the Account page, over its own indicator (axe: "overlapped by another element").
// Each is held to 4.5:1 (WCAG 1.4.3, normal text) in both themes and both languages. The figures are logged so that a run shows them.

test.beforeEach(({guard}) => {
  allowAccountErrors(guard);
  allowAuthErrors(guard);
});

const LANGS = ["fa", "en"] as const;
const SCHEMES = ["light", "dark"] as const;

const log = (what: string, m: Measured) => {
  const line = `${what}: rgb(${m.fg}) on rgb(${m.bg}) = ${m.ratio.toFixed(2)}`;
  test.info().annotations.push({type: "contrast", description: line});
  console.log(line);
};

for (const lang of LANGS) {
  for (const theme of SCHEMES) {
    test.describe(`${lang} ${theme}`, () => {
      test.use({viewport: {width: 1280, height: 800}, colorScheme: theme});

      test("a tertiary button and the active step of the wizard reach 4.5:1", async ({page, context, baseURL}) => {
        await open(context, baseURL, {me: {user: {theme}}, handlers: {"POST /account/totp/setup": {body: {secret: "JBSWY3DPEHPK3PXP", otpauth_uri: TOTP_URI}}}});
        await gotoAccount(page, lang);
        await expect(page.locator("html")).toHaveClass(new RegExp(`flat-${theme}`));
        await row(page, "totp").getByRole("button", {name: acc(lang, "totp.enable")}).click();
        const dialog = page.getByRole("dialog");
        await dialog.locator('input[name="password"]').fill("Correct-Horse-9");
        await dialog.getByRole("button", {name: acc(lang, "reauth.submit")}).click();
        await expect(dialog.getByTestId("totp-qr")).toBeVisible();

        // The pointer is off the dialog, and the step is not mid-animation.
        await page.mouse.move(0, 0);
        await page.waitForTimeout(600);
        const active = dialog.locator('.stepper__indicator[data-status="active"]');
        const step = await measureContrast(active);
        log(`${lang} ${theme} active step`, step);
        expect(step.ratio, "the number in the active step").toBeGreaterThanOrEqual(4.5);
        const ring = await measureContrast(active, {part: "border"});
        log(`${lang} ${theme} active step ring`, ring);
        expect(ring.ratio, "the ring of the active step").toBeGreaterThanOrEqual(3);

        for (const [name, button] of [
          ["Copy", dialog.getByRole("button", {name: lang === "fa" ? "کپی" : "Copy", exact: true})],
          ["Cancel", dialog.getByRole("button", {name: lang === "fa" ? "انصراف" : "Cancel", exact: true})],
        ] as const) {
          await expect(button).toHaveClass(/button--tertiary/);
          await page.mouse.move(0, 0);
          await page.waitForTimeout(400);
          const rest = await measureContrast(button);
          log(`${lang} ${theme} ${name} at rest`, rest);
          expect(rest.ratio, `${name} at rest`).toBeGreaterThanOrEqual(4.5);

          await button.hover();
          // The fill is a transition: read it after it stopped, and prove that this is the state under the pointer and not the one at rest.
          await page.waitForTimeout(600);
          const hover = await measureContrast(button);
          log(`${lang} ${theme} ${name} under the pointer`, hover);
          expect(hover.bg, `${name}: the fill changes under the pointer`).not.toEqual(rest.bg);
          expect(hover.ratio, `${name} under the pointer`).toBeGreaterThanOrEqual(4.5);

          // Pressed: the mouse is down on the button and released away from it, so nothing is activated.
          await page.mouse.down();
          await page.waitForTimeout(400);
          const pressed = await measureContrast(button);
          log(`${lang} ${theme} ${name} pressed`, pressed);
          expect(pressed.ratio, `${name} pressed`).toBeGreaterThanOrEqual(4.5);
          await page.mouse.move(0, 0);
          await page.mouse.up();
        }
        await expect(dialog).toBeVisible();
      });
    });
  }
}

for (const lang of LANGS) {
  for (const theme of SCHEMES) {
    test.describe(`${lang} ${theme} sign-in`, () => {
      test.use({viewport: {width: 1280, height: 800}, colorScheme: theme});

      test("the selected tab and the digits of the code reach 4.5:1", async ({page, context}) => {
        await openAnonymous(context, {"POST /auth/otp/request": {status: 202, body: {challenge_id: "c1", expires_in_s: 300, resend_after_s: 60}}}, {registration_mode: "open", passkey_enabled: true});
        await page.goto(`/${lang}/login`);
        await expect(page.getByRole("tab")).toHaveCount(2);
        await page.mouse.move(0, 0);
        await page.waitForTimeout(700);
        const indicator = page.locator('[data-slot="tabs-indicator"]').first();
        const password = await measureContrast(page.getByRole("tab", {selected: true}), {bg: indicator});
        log(`${lang} ${theme} selected tab (password)`, password);
        expect(password.ratio, "the selected tab on its indicator").toBeGreaterThanOrEqual(4.5);

        await page.goto(`/${lang}/login?step=otp-phone`);
        await expect(page.getByRole("tab", {selected: true})).toHaveCount(1);
        await page.mouse.move(0, 0);
        await page.waitForTimeout(700);
        const sms = await measureContrast(page.getByRole("tab", {selected: true}), {bg: page.locator('[data-slot="tabs-indicator"]').first()});
        log(`${lang} ${theme} selected tab (SMS)`, sms);
        expect(sms.ratio, "the selected tab on its indicator").toBeGreaterThanOrEqual(4.5);

        await field(page, "phone").fill("09123456789");
        await submit(page).click();
        await expect(field(page, "code")).toBeVisible();
        await field(page, "code").focus();
        await typeWhenFocused(page, "123");
        const slots = page.locator('.input-otp__slot[data-filled="true"]');
        await expect(slots).toHaveCount(3);
        for (let i = 0; i < 3; i++) {
          const slot = slots.nth(i);
          const digit = await measureContrast(slot.locator(".input-otp__slot-value"), {bg: slot});
          log(`${lang} ${theme} code digit ${i + 1}`, digit);
          expect(digit.ratio, "a digit of the code on its slot").toBeGreaterThanOrEqual(4.5);
        }
      });
    });
  }
}

for (const lang of LANGS) {
  for (const theme of SCHEMES) {
    test.describe(`${lang} ${theme} account`, () => {
      test.use({viewport: {width: 1280, height: 800}, colorScheme: theme});

      test("the selected item of the Theme segment reaches 4.5:1", async ({page, context, baseURL}) => {
        await open(context, baseURL, {me: {user: {theme}}});
        await gotoAccount(page, lang);
        await expect(page.locator("html")).toHaveClass(new RegExp(`flat-${theme}`));
        await page.mouse.move(0, 0);
        await page.waitForTimeout(700);
        const item = page.locator('[aria-label] .segment__item[data-selected="true"]').first();
        await expect(item).toBeVisible();
        const m = await measureContrast(item, {bg: page.locator(".segment__indicator").first()});
        log(`${lang} ${theme} selected segment item`, m);
        expect(m.ratio, "the selected segment item on its indicator").toBeGreaterThanOrEqual(4.5);
      });
    });
  }
}
