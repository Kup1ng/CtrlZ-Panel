import {gatewayFixture, limitsFixture, templateFixture} from "@ctrlz/api-client/testing/adminFixtures.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {measureContrast} from "@ctrlz/ui/testing/measureContrast.ts";

import {adm, allowAdminErrors, type Handlers, LANGS, openAdmin, TOTP_URI} from "./admin-support.ts";

// P1 gate. Two nodes of the SMS templates screen that axe leaves "incomplete" in the matrix, measured here on what the page paints:
//   - the selected tab, which sits over the tab's own indicator (axe: "overlapped by another element");
//   - the conflict note under a field (a tab, and a dialog), whose text, value and two buttons axe leaves "partially obscured";
//   - the refusal of an OTP template, a danger Alert on a coloured surface (the plan's first guess for the same node).
// Each must reach 4.5:1, in both themes and both languages, at the narrowest and the widest width. The setup stepper at the end is held to 4.5:1 (number) and 3:1 (ring).

test.beforeEach(({guard}) => allowAdminErrors(guard));

const handlers: Handlers = {
  "GET /sms/gateways": {body: {items: [gatewayFixture()]}},
  "GET /sms/templates": {body: {items: [templateFixture()]}},
};

for (const {lang} of LANGS) {
  for (const scheme of ["light", "dark"] as const) {
    for (const width of [375, 1280]) {
      test.describe(`${lang} ${scheme} ${width}`, () => {
        test.use({colorScheme: scheme});
        test(`${lang} ${scheme} ${width}: the selected tab and the OTP refusal reach 4.5:1`, async ({page, context, baseURL}) => {
          await page.setViewportSize({width, height: 900});
          await openAdmin(context, baseURL, {handlers});
          await page.goto(`/${lang}/sms`);
          const tab = page.getByRole("tab", {name: adm(lang, "sms.tabs.templates")});
          await tab.click();
          await expect(page.getByTestId("template-otp-fa")).toBeVisible();
          await page.getByTestId("template-otp-fa").locator("textarea").fill("ک".repeat(70));
          const refused = page.getByTestId("otp-refused");
          await expect(refused).toBeVisible();
          await page.mouse.move(0, 0);
          // The indicator slides under the tab and the alert fades in: wait until both stopped.
          await page.waitForTimeout(700);

          const indicator = page.locator('[data-slot="tabs-indicator"]').first();
          const onIndicator = await measureContrast(tab, {bg: indicator});
          console.log(`${lang} ${scheme} ${width} tab: fg ${onIndicator.fg} on ${onIndicator.bg} = ${onIndicator.ratio.toFixed(2)}`);
          expect(onIndicator.ratio, "the selected tab on its indicator").toBeGreaterThanOrEqual(4.5);

          const text = refused.locator('[data-slot="alert-description"]');
          const alert = await measureContrast(text, {bg: refused});
          console.log(`${lang} ${scheme} ${width} refusal: fg ${alert.fg} on ${alert.bg} = ${alert.ratio.toFixed(2)}`);
          expect(alert.ratio, "the OTP refusal text on its alert").toBeGreaterThanOrEqual(4.5);
        });
      });
    }
  }
}

for (const {lang} of LANGS) {
  for (const scheme of ["light", "dark"] as const) {
    for (const width of [375, 1280]) {
      test.describe(`${lang} ${scheme} ${width} conflict`, () => {
        test.use({colorScheme: scheme});

        test("the conflict note under a field of a tab and of a dialog reaches 4.5:1", async ({page, context, baseURL}) => {
          await page.setViewportSize({width, height: 900});
          await page.clock.install();
          let limits = limitsFixture();
          let gateways = [gatewayFixture()];
          await openAdmin(context, baseURL, {
            handlers: {
              ...handlers,
              "GET /sms/limits": () => ({body: limits}),
              "GET /sms/gateways": () => ({body: {items: gateways}}),
              "PUT /sms/gateways/{provider}": {body: gateways[0]},
            },
          });
          await page.goto(`/${lang}/sms`);
          await page.getByRole("tab", {name: adm(lang, "sms.tabs.limits")}).click();
          const form = page.getByTestId("sms-limits");
          const ip = form.locator('input[name="otp_cap_ip"]');
          await ip.fill("60");
          await ip.blur();
          limits = limitsFixture({otp_cap_ip: 10});
          await page.clock.fastForward(31_000);
          await page.evaluate(() => {
            window.dispatchEvent(new Event("offline"));
            window.dispatchEvent(new Event("online"));
          });
          const tabNote = form.getByTestId("conflict-otp_cap_ip");
          await expect(tabNote).toBeVisible();

          const dialogNote = async () => {
            await page.getByRole("tab", {name: adm(lang, "sms.tabs.gateways")}).click();
            await page.getByTestId("gateway-sms_ir").getByRole("button", {name: adm(lang, "sms.gateways.edit")}).click();
            const dialog = page.getByRole("dialog");
            const price = dialog.locator('input[name="cost_per_message"]');
            await price.fill("600");
            await price.focus();
            gateways = [{...gateways[0]!, cost_per_message: "1500.0000"}];
            await page.keyboard.press("Enter");
            const note = dialog.getByTestId("conflict-cost_per_message");
            await expect(note).toBeVisible();
            return note;
          };

          const check = async (name: string, note: ReturnType<typeof page.getByTestId>) => {
            await page.mouse.move(0, 0);
            await page.waitForTimeout(600);
            const parts: [string, ReturnType<typeof page.getByTestId>][] = [
              ["text", note.locator("span").nth(0)],
              ["value", note.locator("span").nth(1)],
              ["keep", note.getByRole("button").nth(0)],
              ["use the server's", note.getByRole("button").nth(1)],
            ];
            for (const [part, el] of parts) {
              const m = await measureContrast(el);
              console.log(`${lang} ${scheme} ${width} ${name} ${part}: fg ${m.fg} on ${m.bg} = ${m.ratio.toFixed(2)}`);
              expect(m.ratio, `the ${part} of the conflict note (${name})`).toBeGreaterThanOrEqual(4.5);
            }
          };
          await check("tab", tabNote);
          await check("dialog", await dialogNote());
        });
      });
    }
  }
}

// The stepper of the first-admin setup (SetupFlow), which tokens.css fixes with the Account wizard of the panel: the number of the active step
// (4.5:1) and its ring (3:1, WCAG 1.4.11), on the surface of the setup card and not on a dialog. The matrix leaves this node "incomplete", so
// nothing else would notice a later change of a token or a surface.
for (const {lang} of LANGS) {
  for (const scheme of ["light", "dark"] as const) {
    for (const width of [375, 1280]) {
      test.describe(`${lang} ${scheme} ${width} setup`, () => {
        test.use({colorScheme: scheme});

        test("the active step of the setup stepper reaches 4.5:1 for its number and 3:1 for its ring", async ({page, context, baseURL}) => {
          await page.setViewportSize({width, height: 900});
          await openAdmin(context, baseURL, {
            me: {must_change_password: false, totp_enrolled: false},
            handlers: {"POST /me/totp/setup": {body: {secret: "JBSWY3DPEHPK3PXP", otpauth_uri: TOTP_URI}}},
          });
          await page.goto(`/${lang}/setup`);
          await expect(page.getByRole("heading", {level: 1, name: adm(lang, "setup.totp.title")})).toBeVisible();
          const active = page.locator('.stepper__indicator[data-status="active"]');
          await expect(active).toHaveCount(1);
          await page.mouse.move(0, 0);
          await page.waitForTimeout(600);

          const number = await measureContrast(active);
          console.log(`${lang} ${scheme} ${width} setup number: fg ${number.fg} on ${number.bg} = ${number.ratio.toFixed(2)}`);
          expect(number.ratio, "the number in the active step of the setup").toBeGreaterThanOrEqual(4.5);
          const ring = await measureContrast(active, {part: "border"});
          console.log(`${lang} ${scheme} ${width} setup ring: fg ${ring.fg} on ${ring.bg} = ${ring.ratio.toFixed(2)}`);
          expect(ring.ratio, "the ring of the active step of the setup").toBeGreaterThanOrEqual(3);
        });
      });
    }
  }
}
