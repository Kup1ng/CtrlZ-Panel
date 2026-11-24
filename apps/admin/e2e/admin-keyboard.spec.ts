import {adminUserFixture, alertFixture, gatewayFixture, inviteFixture, templateFixture, limitsFixture, statsFixture} from "@ctrlz/api-client/testing/adminFixtures.ts";
import type {Locator, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {adm, allowAdminErrors, err, errText, commonText, gotoShell, LANGS, openAdmin, shellText, typeCode, type Lang} from "./admin-support.ts";

// Spec 17.5 for the admin app (wp10-r1-4): where the focus goes when a dialog opens, that Tab cannot leave it, where the
// focus returns when it closes, that the arrow keys of a Tabs and of a Segment follow the reading direction, and that Back
// asks before a one-time value is lost. axe scans static states and sees none of this. Mock mode (spec 17.1).

test.beforeEach(({guard}) => allowAdminErrors(guard));

const FRESH = {body: {fresh_until: "2099-01-01T00:00:00Z"}};
const inside = (box: Locator) => box.evaluate((el) => el.contains(document.activeElement));

/** Tab and Shift+Tab around the whole dialog: the focus is in it after every press. */
async function trapped(page: Page, dialog: Locator) {
  await expect.poll(() => inside(dialog)).toBe(true);
  for (let i = 0; i < 14; i++) {
    await page.keyboard.press("Tab");
    expect(await inside(dialog), `Tab ${i + 1}`).toBe(true);
  }
  for (let i = 0; i < 14; i++) {
    await page.keyboard.press("Shift+Tab");
    expect(await inside(dialog), `Shift+Tab ${i + 1}`).toBe(true);
  }
}

for (const {lang, dir} of LANGS) {
  test.describe(`admin keyboard, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 900}});
    const A = (path: string, values?: Record<string, string | number>) => adm(lang, path, values);
        const goto = (page: Page, path: string, title: string) => gotoShell(page, lang as Lang, path, title);
    // In a right-to-left page the arrow that points at the next item is the left one.
    const forward = lang === "fa" ? "ArrowLeft" : "ArrowRight";
    const backward = lang === "fa" ? "ArrowRight" : "ArrowLeft";

    const sms = gatewayFixture({provider: "sms_ir", role: "primary"});
    const smsHandlers = {
      "GET /sms/gateways": {body: {items: [sms]}},
      "GET /sms/templates": {body: {items: [templateFixture()]}},
      "GET /sms/limits": {body: limitsFixture()},
      "GET /sms/stats": {body: statsFixture()},
    } as const;

    test("Create user: the focus goes in, Tab stays in, Escape returns it to the button", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL);
      await goto(page, "/users", A("pages.users.title"));
      const trigger = page.getByRole("button", {name: A("users.create.open")});
      await trigger.focus();
      await page.keyboard.press("Enter");
      const dialog = page.getByRole("dialog", {name: A("users.create.title")});
      await expect(dialog).toBeVisible();
      await trapped(page, dialog);
      await page.keyboard.press("Escape");
      await expect(dialog).toHaveCount(0);
      await expect(trigger).toBeFocused();
    });

    test("Create invite: the focus goes in, Tab stays in, Escape returns it to the button", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL);
      await goto(page, "/invites", A("pages.invites.title"));
      const trigger = page.getByRole("button", {name: A("invites.create.open")});
      await trigger.focus();
      await page.keyboard.press("Enter");
      const dialog = page.getByRole("dialog", {name: A("invites.create.title")});
      await expect(dialog).toBeVisible();
      await trapped(page, dialog);
      await page.keyboard.press("Escape");
      await expect(dialog).toHaveCount(0);
      await expect(trigger).toBeFocused();
    });

    test("Edit credentials: the focus goes in, Tab stays in, Escape returns it to Edit", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: smsHandlers});
      await goto(page, "/sms", A("pages.sms.title"));
      const trigger = page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")});
      await trigger.focus();
      await page.keyboard.press("Enter");
      const dialog = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
      await expect(dialog).toBeVisible();
      await trapped(page, dialog);
      await page.keyboard.press("Escape");
      await expect(dialog).toHaveCount(0);
      await expect(trigger).toBeFocused();
    });

    test("Account: the focus goes in and stays in, and closing returns it to the user menu button", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL);
      await goto(page, "/users", A("pages.users.title"));
      const trigger = page.getByRole("button", {name: A("userMenu.label", {name: "admin"})}).first();
      await trigger.focus();
      await page.keyboard.press("Enter");
      await page.getByRole("menuitem", {name: A("userMenu.account")}).press("Enter");
      const dialog = page.getByRole("dialog", {name: A("account.title")});
      await expect(dialog).toBeVisible();
      await trapped(page, dialog);
      await page.keyboard.press("Escape");
      await expect(dialog).toHaveCount(0);
      // The menu item that opened it is gone, so the button of the menu is where the focus has to come back to.
      await expect(trigger).toBeFocused();
    });

    test.describe("at 375", () => {
      test.use({viewport: {width: 375, height: 812}});

      test("Account from the mobile panel: the focus goes in, and closing does not drop it on the page body", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL);
        await goto(page, "/users", A("pages.users.title"));
        await page.getByRole("button", {name: shellText(lang, "sidebar.openMenu")}).click();
        await page.getByRole("button", {name: A("userMenu.label", {name: "admin"})}).first().click();
        await page.getByRole("menuitem", {name: A("userMenu.account")}).press("Enter");
        const dialog = page.getByRole("dialog", {name: A("account.title")});
        await expect(dialog).toBeVisible();
        await expect(page.getByRole("dialog")).toHaveCount(1);
        await trapped(page, dialog);
        await page.keyboard.press("Escape");
        await expect(dialog).toHaveCount(0);
        // The panel and the menu item are both gone: the hamburger that opened the panel is where a keyboard user is put back.
        await expect(page.getByRole("button", {name: shellText(lang, "sidebar.openMenu")})).toBeFocused();
      });
    });

    test("Fresh TOTP: the code field has the focus, Tab stays in, and Escape returns the focus to the button that asked", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: {...smsHandlers, "PUT /sms/gateways/{provider}": err(403, "totp_fresh_required"), "POST /auth/totp/fresh": FRESH}});
      await goto(page, "/sms", A("pages.sms.title"));
      await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
      const edit = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
      await edit.locator('input[name="gw_sms_ir_api_key"]').fill("fixture-key-value");
      await edit.getByRole("button", {name: A("sms.edit.submit")}).click();
      const fresh = page.getByRole("dialog").filter({has: page.locator('input[name="totp_code"]')});
      await expect(fresh).toBeVisible();
      await expect(fresh.locator('input[name="totp_code"]')).toBeFocused();
      await trapped(page, fresh);
      await page.keyboard.press("Escape");
      await expect(fresh).toHaveCount(0);
      // The edit dialog it was opened over is still there and has the focus again.
      await expect(edit).toBeVisible();
      expect(await inside(edit)).toBe(true);
    });

    test("the SMS tabs move with the arrow that points at the next tab, in both directions", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: smsHandlers});
      await goto(page, "/sms", A("pages.sms.title"));
      const tab = (id: string) => page.getByRole("tab", {name: A(`sms.tabs.${id}`)});
      await tab("gateways").focus();
      await page.keyboard.press(forward);
      await expect(tab("routing")).toBeFocused();
      await page.keyboard.press(forward);
      await expect(tab("templates")).toBeFocused();
      await page.keyboard.press(backward);
      await expect(tab("routing")).toBeFocused();
      await page.keyboard.press("Enter");
      await expect(tab("routing")).toHaveAttribute("aria-selected", "true");
    });

    test("the language choice of Create user follows the arrows of the reading direction", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL);
      await goto(page, "/users", A("pages.users.title"));
      await page.getByRole("button", {name: A("users.create.open")}).click();
      const dialog = page.getByRole("dialog", {name: A("users.create.title")});
      const radios = dialog.getByRole("radio");
      await expect(radios).toHaveCount(2);
      // The first item in the document is the first in reading order, whatever the page language.
      await radios.first().focus();
      await page.keyboard.press("Space");
      await expect(radios.first()).toBeChecked();
      // The arrows move the focus along the reading direction; Space chooses.
      await page.keyboard.press(forward);
      await expect(radios.nth(1)).toBeFocused();
      await page.keyboard.press("Space");
      await expect(radios.nth(1)).toBeChecked();
      await page.keyboard.press(backward);
      await expect(radios.first()).toBeFocused();
      await page.keyboard.press("Space");
      await expect(radios.first()).toBeChecked();
    });

    // wp10-r7-1: the result panel is mounted only while it has a value, and its primary button closed it by unmounting
    // the whole modal, so React Aria had nothing to hand the focus back to and it fell to <body>. Escape was fine, so
    // these cases use the keys that were not covered: Done by Enter, Done by Space, and the confirm of a revoke.
    for (const key of ["Enter", "Space"] as const) {
      test(`Create user: Done by ${key} returns the focus to the Create button, not to the page body`, async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {
          handlers: {"POST /users": {status: 201, body: {tenant_id: "00000000-0000-4000-8000-0000000000aa", user_id: "00000000-0000-4000-8000-0000000000bb", one_time_password: "fixture-otp-value"}}},
        });
        await goto(page, "/users", A("pages.users.title"));
        const trigger = page.getByRole("button", {name: A("users.create.open")});
        await trigger.focus();
        await page.keyboard.press("Enter");
        await page.locator('input[name="phone"]').fill("09121234567");
        await page.keyboard.press("Enter");
        const result = page.getByRole("dialog", {name: A("users.result.title")});
        await expect(result).toBeVisible();
        await result.getByRole("checkbox").focus();
        await page.keyboard.press("Space");
        await result.getByRole("button", {name: commonText(lang as Lang, "done"), exact: true}).focus();
        await page.keyboard.press(key);
        await expect(result).toHaveCount(0);
        await expect(trigger).toBeFocused();
      });

      test(`Create invite: Done by ${key} returns the focus to the Create button, not to the page body`, async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {
          handlers: {"POST /invites": {status: 201, body: {id: "10000000-0000-4000-8000-0000000000a9", code: "INV-CODE-4821", link: "https://panel.example.ir/invite#INV-CODE-4821"}}},
        });
        await goto(page, "/invites", A("pages.invites.title"));
        const trigger = page.getByRole("button", {name: A("invites.create.open")});
        await trigger.focus();
        await page.keyboard.press("Enter");
        await page.locator('input[name="phone"]').fill("09351234567");
        await page.keyboard.press("Enter");
        const result = page.getByRole("dialog", {name: A("invites.result.title")});
        await expect(result).toBeVisible();
        await result.getByRole("checkbox").focus();
        await page.keyboard.press("Space");
        await result.getByRole("button", {name: commonText(lang as Lang, "done"), exact: true}).focus();
        await page.keyboard.press(key);
        await expect(result).toHaveCount(0);
        await expect(trigger).toBeFocused();
      });
    }

    test("Revoke: confirming by keyboard leaves the focus on the list, not on the page body", async ({page, context, baseURL}) => {
      const pending = inviteFixture({id: "10000000-0000-4000-8000-0000000000a1", phone_e164: "+989350001001"});
      let revoked = false;
      await openAdmin(context, baseURL, {
        handlers: {
          "GET /invites": () => ({body: {items: [revoked ? {...pending, state: "revoked" as const} : pending]}}),
          "DELETE /invites/{id}": () => {
            revoked = true;
            return {status: 204};
          },
        },
      });
      await goto(page, "/invites", A("pages.invites.title"));
      const row = page.getByRole("button", {name: A("invites.revoke.row", {phone: "+989350001001"})});
      // The grid is one tab stop: when something inside it takes the focus and the grid holds none yet, React Aria moves the focus on to the first
      // row, a frame later. A keyboard user arrives by Tab, row first, then the arrow into the cell, so the focus is already settled. A bare focus()
      // followed at once by Enter raced that move: Enter reached the button when it came first and the row, which does nothing with it, when it
      // came after. It was won on a quiet machine and lost on a loaded one (merge of the gate into WP10: 4 of 4 here). Wait for the row to hold
      // the focus, then step into the button.
      await row.focus();
      await expect(page.getByRole("row").filter({has: row})).toBeFocused();
      await row.focus();
      await page.keyboard.press("Enter");
      const dialog = page.getByRole("alertdialog");
      await expect(dialog).toBeVisible();
      await dialog.getByRole("button", {name: A("invites.revoke.confirm")}).focus();
      await page.keyboard.press("Enter");
      await expect(dialog).toHaveCount(0);
      // The row's own button went with the pending state, so the focus has to be somewhere the next Tab continues from.
      await expect(row).toHaveCount(0);
      const grid = page.getByRole("grid", {name: A("invites.gridLabel")});
      await expect.poll(() => inside(grid)).toBe(true);
    });

    // wp10-r8-1: the fields of a guarded write are disabled while it runs (the read, the fresh-code dialog and the PUT), and an admin who
    // submits with Enter holds the focus in one of them. The browser drops the focus of a disabled field to <body>, and React Aria cannot
    // hand it back to a disabled field when the dialog closes, so nothing gave it back and the next Tab started at the skip link.
    test.describe("a guarded write gives the focus back to the field that had it (wp10-r8-1)", () => {
      const openLimits = async (page: Page, context: Parameters<typeof openAdmin>[0], baseURL: string | undefined, handlers: Record<string, unknown> = {}) => {
        const mock = await openAdmin(context, baseURL, {
          handlers: {...smsHandlers, "PUT /sms/limits": (c: {body: unknown}) => ({body: c.body}), "POST /auth/totp/fresh": FRESH, ...handlers} as never,
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByRole("tab", {name: A("sms.tabs.limits")}).click();
        const form = page.getByTestId("sms-limits");
        const cooldown = form.locator('input[name="otp_cooldown_s"]');
        await cooldown.fill("90");
        await cooldown.focus();
        return {mock, form, cooldown};
      };

      test("Enter in a field, the fresh code asked and answered: the focus is in that field", async ({page, context, baseURL}) => {
        let puts = 0;
        const {mock, cooldown} = await openLimits(page, context, baseURL, {"PUT /sms/limits": (c: {body: unknown}) => (++puts === 1 ? err(403, "totp_fresh_required") : {body: c.body})});
        await page.keyboard.press("Enter");
        const fresh = page.getByRole("dialog", {name: A("fresh.title")});
        await expect(fresh).toBeVisible();
        await typeCode(page, "totp_code", "123456");
        await expect.poll(() => mock.count("PUT /sms/limits")).toBe(2);
        await expect(fresh).toHaveCount(0);
        await expect(cooldown).toBeEnabled();
        await expect(cooldown).toBeFocused();
      });

      test("Enter in a field with a code still fresh: the focus is in that field", async ({page, context, baseURL}) => {
        const {mock, cooldown} = await openLimits(page, context, baseURL);
        await page.keyboard.press("Enter");
        await expect.poll(() => mock.count("PUT /sms/limits")).toBe(1);
        await expect(cooldown).toBeEnabled();
        await expect(cooldown).toBeFocused();
      });

      test("a write refused because the server value moved: the focus is back in the field, with the conflict shown", async ({page, context, baseURL}) => {
        let server = limitsFixture();
        let puts = 0;
        const {mock, cooldown, form} = await openLimits(page, context, baseURL, {
          "GET /sms/limits": () => ({body: server}),
          "PUT /sms/limits": (c: {body: unknown}) => (++puts === 1 ? err(403, "totp_fresh_required") : {body: c.body}),
        });
        await page.keyboard.press("Enter");
        await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
        server = limitsFixture({otp_cap_ip: 7, otp_cooldown_s: 30});
        await typeCode(page, "totp_code", "123456");
        await expect(page.getByText(A("conflict.refreshed"))).toBeVisible();
        expect(mock.count("PUT /sms/limits")).toBe(1);
        await expect(form.getByTestId("conflict-otp_cooldown_s")).toBeVisible();
        await expect(cooldown).toBeEnabled();
        await expect(cooldown).toBeFocused();
      });

      test("a fresh-code dialog that is cancelled: the focus is back in the field", async ({page, context, baseURL}) => {
        const {cooldown} = await openLimits(page, context, baseURL, {"PUT /sms/limits": () => err(403, "totp_fresh_required")});
        await page.keyboard.press("Enter");
        const fresh = page.getByRole("dialog", {name: A("fresh.title")});
        await expect(fresh).toBeVisible();
        await page.keyboard.press("Escape");
        await expect(fresh).toHaveCount(0);
        await expect(cooldown).toBeEnabled();
        await expect(cooldown).toBeFocused();
      });

      // wp10-r20-1. The focus is given back for the keyboard only. A press on Save leaves Save focused, Save is off once the write
      // succeeds, and the fallback was the first field of the form: the page scrolled up to it, and on a phone its soft keyboard opened.
      test("a pointer click on Save leaves the focus alone: it is not sent to the first field, and Save stays in view", async ({page, context, baseURL}) => {
        await page.setViewportSize({width: 375, height: 667});
        const {mock, form} = await openLimits(page, context, baseURL);
        const last = form.locator('input[name="sms_outbox_cap_daily"]');
        await last.fill("123");
        const save = form.getByRole("button", {name: A("sms.limits.submit")});
        await save.scrollIntoViewIfNeeded();
        await save.click();
        await expect.poll(() => mock.count("PUT /sms/limits")).toBe(1);
        await expect(page.getByText(A("sms.limits.saved"))).toBeVisible();
        await expect(save).toBeDisabled();
        // Give a wrong restore (it waits two frames after the write) time to show itself.
        await page.waitForTimeout(400);
        const active = await page.evaluate(() => ({tag: document.activeElement?.tagName ?? "", name: document.activeElement?.getAttribute("name") ?? ""}));
        expect(active.tag, `focus is on ${active.name}`).not.toBe("INPUT");
        const box = await save.boundingBox();
        expect(box).not.toBeNull();
        expect(box!.y).toBeGreaterThanOrEqual(0);
        expect(box!.y + box!.height).toBeLessThanOrEqual(667);
      });

      // wp10-r9-1. A control that removes itself takes the focus with it, and Chrome drops it to <body>: the next Tab starts at the skip
      // link. Each case below ends with the focus on a control inside the form or card the admin was working in.
      const stillHere = (page: Page, scope: string) =>
        page.evaluate((selector) => {
          const active = document.activeElement;
          return !!active && active !== document.body && !!active.closest(selector);
        }, scope);

      test("Retry of a failed save by keyboard: the error clears, and the focus is in the form, not on the page body", async ({page, context, baseURL}) => {
        let puts = 0;
        const {mock, form} = await openLimits(page, context, baseURL, {"PUT /sms/limits": (c: {body: unknown}) => (++puts === 1 ? err(503, "service_unavailable") : {body: c.body})});
        await page.keyboard.press("Enter");
        const retry = form.getByRole("button", {name: commonText(lang, "retry")});
        await expect(retry).toBeVisible();
        await retry.focus();
        await page.keyboard.press("Enter");
        await expect.poll(() => mock.count("PUT /sms/limits")).toBe(2);
        await expect(retry).toHaveCount(0);
        await expect.poll(() => stillHere(page, '[data-testid="sms-limits"]')).toBe(true);
      });

      // wp10-r11-1. The Retry of the refresh-failed line leaves with the line when the refetch succeeds, so the focus it held has to be
      // given back, as for every other admin Retry. The line is an alert (wp10-r11-2) so a screen reader hears that the page is stale.
      test("Retry of the refresh-failed line by keyboard: the line goes, and the focus is on a control of the page, not on the body", async ({page, context, baseURL}) => {
        await page.clock.install();
        let up = true;
        await openAdmin(context, baseURL, {
          handlers: {...smsHandlers, "GET /sms/limits": () => (up ? {body: limitsFixture()} : err(503, "service_unavailable")), "POST /auth/totp/fresh": FRESH} as never,
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByRole("tab", {name: A("sms.tabs.limits")}).click();
        const form = page.getByTestId("sms-limits");
        await form.locator('input[name="otp_cooldown_s"]').fill("90");
        up = false;
        await page.clock.fastForward(31_000);
        await page.evaluate(() => {
          window.dispatchEvent(new Event("offline"));
          window.dispatchEvent(new Event("online"));
        });
        const line = page.getByTestId("refresh-failed");
        await expect(line).toBeVisible({timeout: 20_000});
        await expect(page.getByRole("alert").filter({hasText: A("refreshFailed")})).toBeVisible();
        const retry = line.getByRole("button", {name: commonText(lang, "retry")});
        await retry.focus();
        up = true;
        await page.keyboard.press("Enter");
        await expect(line).toHaveCount(0);
        await expect.poll(() => stillHere(page, "main")).toBe(true);
        await expect(form.locator('input[name="otp_cooldown_s"]')).toHaveValue(lang === "fa" ? "۹۰" : "90");
      });

      for (const answer of ["keep", "useServer"] as const) {
        test(`a conflict note answered by keyboard (${answer}): the focus returns to the field the note belongs to`, async ({page, context, baseURL}) => {
          let server = limitsFixture();
          const {form} = await openLimits(page, context, baseURL, {"GET /sms/limits": () => ({body: server})});
          const ip = form.locator('input[name="otp_cap_ip"]');
          await ip.fill("60");
          await ip.blur();
          server = limitsFixture({otp_cap_ip: 10});
          await form.getByRole("button", {name: A("sms.limits.submit")}).focus();
          await page.keyboard.press("Enter");
          const note = form.getByTestId("conflict-otp_cap_ip");
          await expect(note).toBeVisible();
          await note.getByRole("button", {name: A(`conflict.${answer}`)}).focus();
          await page.keyboard.press("Enter");
          await expect(note).toHaveCount(0);
          await expect(ip).toBeFocused();
        });
      }

      const registration = {
        "GET /settings/registration": {body: {mode: "invite", open_grace_days: 0, takeover_idle_days: 30}},
        "GET /settings/webauthn": {body: {rp_id: "panel.example.ir", allowed_origins: ["https://panel.example.ir"], enabled: false}},
        "GET /settings/registration/impact": {body: {graced: 3, suspended_at_once: 1}},
        "PUT /settings/registration": {body: {mode: "closed", open_grace_days: 0, takeover_idle_days: 30}},
        "POST /auth/totp/fresh": FRESH,
      } as const;
      const pickClosed = async (page: Page) => {
        await page.getByRole("radio", {name: A("settings.registration.mode.closed")}).click();
        await expect(page.getByTestId("registration-draft")).toBeVisible();
      };

      test("Registration Confirm by keyboard: the draft block closes with the button, and the focus is in the card", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: registration as never});
        await goto(page, "/settings", A("pages.settings.title"));
        await pickClosed(page);
        const confirm = page.getByRole("button", {name: A("settings.registration.confirm", {mode: A("settings.registration.mode.closed")})});
        await expect(confirm).toBeEnabled();
        await confirm.focus();
        await page.keyboard.press("Enter");
        await expect.poll(() => mock.count("PUT /settings/registration")).toBe(1);
        await expect(page.getByTestId("registration-draft")).toHaveCount(0);
        await expect.poll(() => stillHere(page, '[data-testid="settings-registration"]')).toBe(true);
      });

      test("Registration Cancel by keyboard: the draft block closes with the button, and the focus is in the card", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: registration as never});
        await goto(page, "/settings", A("pages.settings.title"));
        await pickClosed(page);
        await page.getByTestId("registration-draft").getByRole("button", {name: A("settings.cancel")}).focus();
        await page.keyboard.press("Enter");
        await expect(page.getByTestId("registration-draft")).toHaveCount(0);
        await expect.poll(() => stillHere(page, '[data-testid="settings-registration"]')).toBe(true);
      });

      test("Gateway price: Enter in the price field, a price another admin set is a conflict, and the focus stays in the field (wp10-r8-3)", async ({page, context, baseURL}) => {
        let server = [sms];
        const mock = await openAdmin(context, baseURL, {
          handlers: {...smsHandlers, "GET /sms/gateways": () => ({body: {items: server}}), "PUT /sms/gateways/{provider}": {body: sms}},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        const dialog = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
        const price = dialog.locator('input[name="cost_per_message"]');
        await price.fill("600");
        await price.focus();
        server = [{...sms, cost_per_message: "1500.0000"}];
        await page.keyboard.press("Enter");
        await expect(dialog.getByTestId("conflict-cost_per_message")).toBeVisible();
        expect(mock.count("PUT /sms/gateways/{provider}")).toBe(0);
        await expect(price).toBeEnabled();
        await expect(price).toBeFocused();
      });
    });

    // wp10-r8-2: the Done cases above pass on the old code most of the time, because React Aria's own restore usually wins. Here its
    // restore cannot succeed: a focus call on the page header's button that does not ask for `preventScroll: false` (React Aria asks for
    // `true`) is swallowed once the panel is open. Only restoreFocusLater, which asks for `false`, can put the focus on the button, and it
    // can do that only if createButton still finds the button by its accessible name in the page header.
    const swallowReactAriaFocus = (page: Page) =>
      page.addInitScript(() => {
        const original = HTMLElement.prototype.focus;
        HTMLElement.prototype.focus = function focus(this: HTMLElement, options?: FocusOptions) {
          const header = this.closest(".page-header") !== null && this.tagName === "BUTTON";
          if (header && (window as unknown as {__swallow?: boolean}).__swallow && options?.preventScroll !== false) return;
          return original.call(this, options);
        };
      });

    for (const spec of [
      {
        name: "Create user",
        path: "/users",
        title: "pages.users.title",
        open: "users.create.open",
        result: "users.result.title",
        post: "POST /users",
        reply: {status: 201, body: {tenant_id: "00000000-0000-4000-8000-0000000000aa", user_id: "00000000-0000-4000-8000-0000000000bb", one_time_password: "fixture-otp-value"}},
        phone: "09121234567",
      },
      {
        name: "Create invite",
        path: "/invites",
        title: "pages.invites.title",
        open: "invites.create.open",
        result: "invites.result.title",
        post: "POST /invites",
        reply: {status: 201, body: {id: "10000000-0000-4000-8000-0000000000a9", code: "INV-CODE-4821", link: "https://panel.example.ir/invite#INV-CODE-4821"}},
        phone: "09351234567",
      },
    ] as const) {
      test(`${spec.name}: when only restoreFocusLater can restore it, Done still returns the focus to the Create button (wp10-r8-2)`, async ({page, context, baseURL}) => {
        await swallowReactAriaFocus(page);
        await openAdmin(context, baseURL, {handlers: {[spec.post]: spec.reply}});
        await goto(page, spec.path, A(spec.title));
        const trigger = page.getByRole("button", {name: A(spec.open)});
        await trigger.focus();
        await page.keyboard.press("Enter");
        await page.locator('input[name="phone"]').fill(spec.phone);
        await page.keyboard.press("Enter");
        const result = page.getByRole("dialog", {name: A(spec.result)});
        await expect(result).toBeVisible();
        await result.getByRole("checkbox").focus();
        await page.keyboard.press("Space");
        await page.evaluate(() => ((window as unknown as {__swallow?: boolean}).__swallow = true));
        // The patch must really be in the way, or the case proves nothing: React Aria's kind of call does nothing now.
        await trigger.evaluate((el) => (el as HTMLElement).focus({preventScroll: true}));
        await expect(trigger).not.toBeFocused();
        await result.getByRole("button", {name: commonText(lang as Lang, "done"), exact: true}).focus();
        await page.keyboard.press("Enter");
        await expect(result).toHaveCount(0);
        await expect(trigger).toBeFocused();
      });
    }

    // wp10-r12-1. The Acknowledge button leaves with its alert when the call succeeds, and the whole section with the last alert. The
    // focus goes to the next alert's button, and after the last one to the selected tab, never to the page body.
    test("Acknowledge by keyboard: the focus goes to the next alert, then to the selected tab, never to the body", async ({page, context, baseURL}) => {
      const first = alertFixture({id: "30000000-0000-4000-8000-0000000000d1", severity: "critical", kind: "sms_down", params: {}});
      const second = alertFixture({id: "30000000-0000-4000-8000-0000000000d2", severity: "warning", params: {provider: "sms_ir", class: "credit", code: "no_credit"}});
      const mock = await openAdmin(context, baseURL, {handlers: {...smsHandlers, "POST /alerts/{id}/ack": {status: 204}}, alerts: [first, second]});
      await goto(page, "/sms", A("pages.sms.title"));
      const alerts = page.getByTestId("sms-alerts");
      const ack = alerts.getByRole("button", {name: A("sms.alerts.ack")});
      await expect(ack).toHaveCount(2);
      await ack.first().focus();
      mock.alerts.current = [second];
      await page.keyboard.press("Enter");
      await expect(ack).toHaveCount(1);
      await expect(ack).toBeFocused();
      mock.alerts.current = [];
      await page.keyboard.press("Enter");
      await expect(alerts).toHaveCount(0);
      await expect(page.getByRole("tab", {name: A("sms.tabs.gateways")})).toBeFocused();
    });

    // wp10-r15-1. The Retry of an error that the content replaces when the refetch succeeds leaves with the error: the failed outbox
    // lookup inside the test-send dialog, and the section error of a tab that failed to load. The focus goes to a control of the
    // dialog or the page, never to the body (the next Tab would start at the skip link).
    test("Retry of the failed test-send lookup by keyboard: the focus stays in the dialog, not on the body", async ({page, context, baseURL}) => {
      let up = false;
      await openAdmin(context, baseURL, {
        handlers: {
          ...smsHandlers,
          "POST /sms/gateways/{provider}/test": {status: 202, body: {outbox_id: "20000000-0000-4000-8000-0000000000f1"}},
          "GET /sms/outbox/{id}": () => (up ? {body: {state: "sent"}} : err(503, "service_unavailable")),
        } as never,
      });
      await goto(page, "/sms", A("pages.sms.title"));
      await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.test")}).click();
      const dialog = page.getByRole("dialog", {name: A("sms.test.title", {provider: "sms.ir"})});
      await dialog.locator('input[name="phone"]').fill("09121234567");
      await dialog.getByRole("button", {name: A("sms.test.submit")}).click();
      const retry = dialog.getByRole("button", {name: commonText(lang, "retry")});
      await expect(retry).toBeVisible({timeout: 20_000});
      await retry.focus();
      up = true;
      await page.keyboard.press("Enter");
      await expect(page.getByTestId("test-state")).toContainText(A("sms.test.sent", {provider: "sms.ir"}), {timeout: 15_000});
      await expect(retry).toHaveCount(0);
      await expect.poll(() => inside(dialog)).toBe(true);
      await expect(page.locator("body")).not.toBeFocused();
    });

    test("Retry of the section error of a tab by keyboard: the focus is on a control of the page, not on the body", async ({page, context, baseURL}) => {
      let up = false;
      await openAdmin(context, baseURL, {handlers: {...smsHandlers, "GET /sms/limits": () => (up ? {body: limitsFixture()} : err(503, "service_unavailable"))} as never});
      await goto(page, "/sms", A("pages.sms.title"));
      await page.getByRole("tab", {name: A("sms.tabs.limits")}).click();
      const retry = page.getByRole("alert").getByRole("button", {name: commonText(lang, "retry")});
      await expect(retry).toBeVisible({timeout: 20_000});
      await retry.focus();
      up = true;
      await page.keyboard.press("Enter");
      await expect(page.getByTestId("sms-limits")).toBeVisible();
      await expect(retry).toHaveCount(0);
      await expect
        .poll(() => page.evaluate(() => !!document.activeElement && document.activeElement !== document.body && !!document.activeElement.closest("main, #main-content")))
        .toBe(true);
    });

    // wp10-r13-1. The close button of a shell banner leaves with its banner. The focus goes to the next banner's close button, and
    // after the last banner (the stack renders nothing) to the page's main region, never to the body.
    test("Dismissing a shell banner by keyboard: the focus goes to the next banner, then to the main region, never to the body", async ({page, context, baseURL}) => {
      const critical = alertFixture({id: "30000000-0000-4000-8000-0000000000e1", severity: "critical", kind: "sms_down", params: {}});
      const mock = await openAdmin(context, baseURL, {
        handlers: {"POST /alerts/{id}/ack": {status: 204}},
        alerts: [critical],
        me: {notices: [{kind: "totp_reset", at: "2026-11-16T08:00:00Z"}]},
      });
      await goto(page, "/users", A("pages.users.title"));
      const stack = page.getByRole("region", {name: shellText(lang, "banners.region")});
      const dismiss = stack.getByRole("button", {name: shellText(lang, "banners.dismiss")});
      await expect(dismiss).toHaveCount(2);
      // The alert is first. Acknowledging it by Enter leaves the notice, and the focus is on the notice's button.
      await dismiss.first().focus();
      mock.alerts.current = [];
      await page.keyboard.press("Enter");
      await expect(dismiss).toHaveCount(1);
      await expect(dismiss).toBeFocused();
      // The last banner: the whole stack goes, and the focus is on a control of the page, not on the body.
      await page.keyboard.press("Enter");
      await expect(stack).toHaveCount(0);
      await expect(page.locator("#main-content")).toBeFocused();
      expect(await page.evaluate(() => document.activeElement === document.body)).toBe(false);
    });

    // wp10-r14-1. The "n more" button leaves with the press (nothing is hidden any more). The focus goes to the first banner that
    // was revealed, not to the body, so the admin lands on what they opened.
    test("The 'more' button by keyboard: the focus goes to the first banner it revealed, never to the body", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {
        alerts: [alertFixture({id: "30000000-0000-4000-8000-0000000000f1", severity: "critical", kind: "sms_down", params: {}})],
        me: {notices: [{kind: "totp_reset", at: "2026-11-16T08:00:00Z"}, {kind: "password_reset", at: "2026-11-16T07:00:00Z"}]},
      });
      await goto(page, "/users", A("pages.users.title"));
      const stack = page.getByRole("region", {name: shellText(lang, "banners.region")});
      const more = stack.getByRole("button", {name: lang === "fa" ? /اعلان دیگر/ : /more notice/});
      const items = stack.locator(".banner-stack__item");
      await expect(items).toHaveCount(2);
      await more.focus();
      await page.keyboard.press("Enter");
      await expect(items).toHaveCount(3);
      await expect(more).toHaveCount(0);
      await expect(items.nth(2).getByRole("button", {name: shellText(lang, "banners.dismiss")})).toBeFocused();
      expect(await page.evaluate(() => document.activeElement === document.body)).toBe(false);
    });

    // wp10-r16-1. The Load more of a failed later page leaves with its error block when the page loads, so the focus it held has to
    // be given back like the one of every Retry. The rows of the page are appended.
    test("Load more of a failed later page by keyboard: the rows are appended and the focus is on a control of the page, not on the body", async ({page, context, baseURL}) => {
      const first = Array.from({length: 50}, (_, i) => adminUserFixture({phone_e164: `+98912100${String(1000 + i)}`}));
      const second = [adminUserFixture({phone_e164: "+989122001000"}), adminUserFixture({phone_e164: "+989122001001"})];
      let fail = true;
      const mock = await openAdmin(context, baseURL, {
        handlers: {
          "GET /users": (call: {query: URLSearchParams}) =>
            call.query.get("cursor") === "next-page" ? (fail ? err(503, "service_unavailable") : {body: {items: second}}) : {body: {items: first, next_cursor: "next-page"}},
        } as never,
      });
      await goto(page, "/users", A("pages.users.title"));
      const grid = page.getByRole("grid", {name: A("users.gridLabel")});
      await expect(grid.getByRole("row").nth(1)).toBeVisible();
      await grid.hover();
      for (let i = 0; i < 40 && mock.calls.filter((c) => c.path === "/users" && c.query.get("cursor")).length < 1; i++) await page.mouse.wheel(0, 1500);
      const block = page.getByTestId("grid-more-error");
      await expect(block).toBeVisible({timeout: 30_000});
      await expect(block.getByRole("alert")).toContainText(errText(lang, "service_unavailable"));
      const more = block.getByRole("button", {name: A("grid.loadMore")});
      await more.focus();
      fail = false;
      await page.keyboard.press("Enter");
      await expect(block).toHaveCount(0);
      await expect
        .poll(() =>
          page.evaluate(() => {
            const active = document.activeElement;
            return !!active && active !== document.body && !!active.closest("main");
          }),
        )
        .toBe(true);
      await grid.hover();
      await expect
        .poll(async () => {
          await page.mouse.wheel(0, 1500);
          return grid.locator('bdi[dir="ltr"]', {hasText: "+989122001001"}).count();
        })
        .toBeGreaterThan(0);
    });

    // wp10-r16-2. A page that throws while rendering lands in the shell's error boundary, whose Retry is Next's `reset`. When the page
    // renders again the error and its focused Retry leave, and the focus must not fall to <body>. The throw is made in the browser
    // (the date formatter of the Users grid) and switched off before Retry, because the data of the page is already in the cache.
    test("the render-error boundary's Retry by keyboard: the page comes back and the focus is on a control of the page, not on the body", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/boom|Error/);
      await openAdmin(context, baseURL, {handlers: {"GET /users": {body: {items: [adminUserFixture({phone_e164: "+989120001001"})]}}}});
      await page.addInitScript(() => {
        const w = window as unknown as {__boom: boolean};
        w.__boom = true;
        const proto = Intl.DateTimeFormat.prototype;
        const descriptor = Object.getOwnPropertyDescriptor(proto, "format")!;
        Object.defineProperty(proto, "format", {
          configurable: true,
          get() {
            const format = descriptor.get!.call(this) as (date?: Date | number) => string;
            return (date?: Date | number) => {
              if (w.__boom) throw new Error("boom");
              return format(date);
            };
          },
        });
      });
      await page.goto(`/${lang}/users`);
      const retry = page.getByRole("button", {name: commonText(lang, "retry")});
      await expect(retry).toBeVisible();
      await page.evaluate(() => ((window as unknown as {__boom: boolean}).__boom = false));
      await retry.focus();
      await page.keyboard.press("Enter");
      await expect(page.getByRole("grid", {name: A("users.gridLabel")})).toBeVisible();
      await expect(retry).toHaveCount(0);
      await expect
        .poll(() =>
          page.evaluate(() => {
            const active = document.activeElement;
            return !!active && active !== document.body;
          }),
        )
        .toBe(true);
    });

    test("Back while a one-time value is open asks first, and keeping it leaves the value on the page", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {
        handlers: {"POST /users": {status: 201, body: {tenant_id: "00000000-0000-4000-8000-0000000000aa", user_id: "00000000-0000-4000-8000-0000000000bb", one_time_password: "fixture-otp-value"}}},
      });
      await goto(page, "/users", A("pages.users.title"));
      await page.getByRole("button", {name: A("users.create.open")}).click();
      await page.locator('input[name="phone"]').fill("09121234567");
      await page.getByRole("button", {name: A("users.create.submit"), exact: true}).click();
      await expect(page.getByTestId("one-time-result")).toBeVisible();
      // The guard cancels the traversal, so no navigation finishes and `page.goBack()` would wait for one.
      const back = () => page.evaluate(() => window.history.back());
      await back();
      const confirm = page.getByRole("alertdialog");
      await expect(confirm).toContainText(A("result.confirmTitle"));
      await confirm.getByRole("button", {name: A("result.keep")}).click();
      await expect(page.getByTestId("one-time-password")).toHaveText("fixture-otp-value");
      // Back again: still asked, so the guard was put back after the first answer.
      await back();
      await expect(page.getByRole("alertdialog")).toContainText(A("result.confirmTitle"));
    });
  });
}
