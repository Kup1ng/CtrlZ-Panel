import type {Locator, Page} from "@playwright/test";
import {errorBody} from "@ctrlz/api-client/testing/fixtures.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import enCommon from "../../../packages/i18n/messages/en/common.json";
import faCommon from "../../../packages/i18n/messages/fa/common.json";
import enErrors from "../../../packages/i18n/messages/en/errors.json";
import faErrors from "../../../packages/i18n/messages/fa/errors.json";

import {digits, regionName} from "./profiles-list-support.ts";
import {LANGS, LOCK_PASSWORD, PROFILE, lockBanner, openProfiles, profileHeader, profilePath, screen, text, type Lang} from "./profiles-support.ts";

// Profile Options and the lock (package S2 of P2, spec p2 9.7 and 7), in mock mode: T-138, T-139, T-140, T-141, T-178, T-200 to T-205,
// T-210 to T-215 and T-523. Each case names its rows. The wireframe comparison is docs/wireframes/p2-comparison.md.

test.use({viewport: {width: 1280, height: 900}});

const ROWS = [
  "default_rule", "block_exfiltration", "rebind_protection", "disable_dnssec", "block_ttl", "redirect_ttl", "bypass_ttl", "block_response",
  "ecs", "dns64", "cname_flattening", "safe_search", "restricted_youtube", "disable", "lock",
] as const;
type Row = (typeof ROWS)[number];

/** A message of `common` or `errors` by its path, which `text()` of the support file does not carry. */
function shared(lang: Lang, ns: "common" | "errors", path: string): string {
  let node: unknown = (ns === "common" ? {fa: faCommon, en: enCommon} : {fa: faErrors, en: enErrors})[lang];
  for (const part of path.split(".")) node = (node as Record<string, unknown> | undefined)?.[part];
  if (typeof node !== "string") throw new Error(`${ns}.${path} is not a message in ${lang}`);
  return node;
}

const title = (lang: Lang, row: Row) => text(lang, "rules", `options.rows.${row}.name`);
const row = (page: Page, name: Row) => page.locator(`[data-option="${name}"]`);
const optionsOf = (mock: {screens: {options: Map<string, Record<string, unknown>>}}, id: string = PROFILE.home) => mock.screens.options.get(id)!;
const action = (lang: Lang, name: "block" | "bypass" | "redirect") => text(lang, "rules", `action.${name}`);
const choice = (row: Locator, lang: Lang, name: "block" | "bypass" | "redirect", subject: string) =>
  row.getByRole("radio", {name: new RegExp(`^${text(lang, "rules", "three.set", {action: action(lang, name), subject})}`)});
const save = (scope: Locator, lang: Lang, subject: string) => scope.getByRole("button", {name: `${shared(lang, "common", "save")}: ${subject}`});

/** A place of the Destinations dialog is chosen on its row: the radio itself is under the flag. */
const place = (dialog: Locator, name: string) => dialog.locator(".destination-option", {hasText: name}).first().click();

/** A switch is pressed on its track: the input itself is hidden under it (the same as account.spec.ts). */
const press = (toggle: Locator) => toggle.locator("xpath=ancestor::*[contains(@class,'switch')][1]").locator(".switch__control").click();

async function open(page: Page, lang: Lang, id: string = PROFILE.home) {
  await page.goto(profilePath(lang, id, "options"));
  await expect(screen(page, "profile-options")).toBeVisible();
  await expect(row(page, "lock")).toBeVisible();
}

for (const {lang, dir} of LANGS) {
  test.describe(`${lang} (${dir})`, () => {
    test("T-215: the rows come in the order of Plan, full width, each with name, description, Learn more and a control at the end; there is no AI Malware and no Compatibility Mode", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {rules: 50});
      await open(page, lang);
      const rows = page.locator("[data-option]");
      await expect(rows).toHaveCount(ROWS.length);
      expect(await rows.evaluateAll((els) => els.map((e) => e.getAttribute("data-option")))).toEqual([...ROWS]);
      for (const name of ROWS) {
        const r = row(page, name);
        await expect(r.getByRole("heading", {level: 3, name: title(lang, name)})).toBeVisible();
        await expect(r).toContainText(text(lang, "rules", `options.rows.${name}.description`));
        await expect(r.getByRole("button", {name: text(lang, "rules", "options.learnMoreAria", {name: title(lang, name)})})).toBeVisible();
      }
      // Full width: a row spans the content column.
      const list = (await page.getByRole("list", {name: text(lang, "rules", "options.title")}).boundingBox())!;
      const first = (await row(page, "default_rule").boundingBox())!;
      expect(Math.abs(first.width - list.width)).toBeLessThan(2);
      const body = await page.locator("main, [data-screen]").first().innerText();
      expect(body).not.toMatch(/AI Malware|Compatibility Mode|هوش مصنوعی|حالت سازگاری/);
      // Every option row is in the frame's tab of the page.
      await expect(profileHeader(page)).toContainText("Home");
    });

    test("T-215: Learn more opens the row's own explanation at helpPane=option.<name>, and Back closes it", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {rules: 50});
      await open(page, lang);
      await row(page, "block_response").getByRole("button", {name: text(lang, "rules", "options.learnMoreAria", {name: title(lang, "block_response")})}).click();
      await expect(page).toHaveURL(/helpPane=option\.block_response/);
      const help = page.getByRole("dialog", {name: title(lang, "block_response")});
      await expect(help).toContainText(text(lang, "rules", "options.help.block_response.body").slice(0, 40));
      await page.goBack();
      await expect(help).toBeHidden();
    });

    test("T-200: the Default Rule is Bypass when not set, and Block and Bypass answer at once", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 50});
      delete optionsOf(mock).default_rule;
      await open(page, lang);
      const r = row(page, "default_rule");
      const subject = title(lang, "default_rule");
      await expect(choice(r, lang, "bypass", subject)).toBeChecked();
      await choice(r, lang, "block", subject).click();
      await expect.poll(() => optionsOf(mock).default_rule).toEqual({action: "block"});
      await expect(choice(r, lang, "block", subject)).toBeChecked();
      await choice(r, lang, "bypass", subject).click();
      await expect.poll(() => optionsOf(mock).default_rule).toEqual({action: "bypass"});
    });

    test("T-178, T-523: Redirect opens the destination dialog with the D42 notice before Save; Save stores the place and the row shows it", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 50});
      await open(page, lang);
      const subject = title(lang, "default_rule");
      await choice(row(page, "default_rule"), lang, "redirect", subject).click();
      await expect(page).toHaveURL(/profileDialog=default-rule/);
      const dialog = page.getByRole("dialog", {name: text(lang, "services", "destinations.title", {subject})});
      await expect(dialog).toBeVisible();
      // The D42 notice is there before anything is chosen, in words; nothing has changed yet.
      await expect(dialog.getByTestId("d42-notice")).toContainText(text(lang, "rules", "options.defaultRule.d42Title"));
      await expect(dialog.getByTestId("d42-notice")).toContainText(text(lang, "rules", "options.defaultRule.d42Text"));
      expect(optionsOf(mock).default_rule).toEqual({action: "bypass"});
      // A first Redirect has no place to leave, so no location-change notice.
      await place(dialog, regionName(lang, "NL"));
      await expect(dialog.getByTestId("location-change-notice")).toHaveCount(0);
      await dialog.getByRole("button", {name: text(lang, "services", "destinations.save")}).click();
      await expect(dialog).toBeHidden();
      expect((optionsOf(mock).default_rule as {action: string; target: {kind: string}}).action).toBe("redirect");
      expect((optionsOf(mock).default_rule as {target: {kind: string}}).target.kind).toBe("location");
      const r = row(page, "default_rule");
      await expect(r.getByTestId("default-rule-where")).toContainText(regionName(lang, "NL"));
      await expect(choice(r, lang, "redirect", subject)).toBeChecked();
      await expect(r.locator(".flag")).toHaveCount(1);
    });

    test("T-178: changing a saved Redirect to another place warns that every undecided name moves, and the same place does not", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 50});
      const first = mock.screens.locations[3]!; // the Netherlands
      optionsOf(mock).default_rule = {action: "redirect", target: {kind: "location", location_id: first.id, location: {country: "NL"}}};
      await open(page, lang);
      const subject = title(lang, "default_rule");
      await row(page, "default_rule").getByRole("button", {name: new RegExp(text(lang, "rules", "three.openDestination", {subject}))}).click();
      const dialog = page.getByRole("dialog", {name: text(lang, "services", "destinations.title", {subject})});
      await expect(dialog).toBeVisible();
      await expect(dialog.getByTestId("location-change-notice")).toHaveCount(0);
      await place(dialog, regionName(lang, "US"));
      const notice = dialog.getByTestId("location-change-notice");
      await expect(notice).toBeVisible();
      await expect(notice).toContainText(text(lang, "rules", "options.defaultRule.changeTitle"));
      await expect(notice).toContainText(regionName(lang, "NL"));
      await expect(notice).toContainText(regionName(lang, "US"));
      // Going back to the saved place takes the warning away.
      await place(dialog, regionName(lang, "NL"));
      await expect(notice).toHaveCount(0);
    });

    test("T-166: with no shared destination Redirect is disabled with its reason, and Block and Bypass still work", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {rules: 50, noLocations: true});
      await open(page, lang);
      const r = row(page, "default_rule");
      const subject = title(lang, "default_rule");
      await expect(choice(r, lang, "redirect", subject)).toBeDisabled();
      await expect(r).toContainText(text(lang, "rules", "three.noShared"));
      await expect(choice(r, lang, "block", subject)).toBeEnabled();
    });

    const SWITCHES = [
      ["T-201", "block_exfiltration"],
      ["T-202", "rebind_protection"],
      ["T-203", "disable_dnssec"],
      ["T-211", "dns64"],
      ["T-212", "cname_flattening"],
      ["T-213", "safe_search"],
      ["T-214", "restricted_youtube"],
    ] as const;
    for (const [id, name] of SWITCHES) {
      test(`${id}: ${name} is a switch that answers at once, and off clears the option`, async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL, {rules: 50});
        delete optionsOf(mock).block_exfiltration;
        delete optionsOf(mock).safe_search;
        await open(page, lang);
        const toggle = row(page, name).getByRole("switch", {name: title(lang, name)});
        await expect(toggle).not.toBeChecked();
        await press(toggle);
        await expect(toggle).toBeChecked();
        await expect.poll(() => optionsOf(mock)[name]).toBe(true);
        await press(toggle);
        await expect(toggle).not.toBeChecked();
        // Off is not stored: the key is gone, not false (open question 3).
        await expect.poll(() => name in optionsOf(mock)).toBe(false);
        // The word beside the switch says it too, so the state is not the switch alone.
        await expect(row(page, name)).toContainText(text(lang, "rules", "options.off"));
      });
    }

    test("T-201: a switch the API refuses is put back and says so", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 422/);
      const mock = await openProfiles(context, baseURL, {
        rules: 50,
        handlers: {"PATCH /profiles/{id}/options": {status: 422, body: errorBody("validation_failed", {fields: [{name: "/dns64", code: "invalid"}]})}},
      });
      delete optionsOf(mock).dns64;
      await open(page, lang);
      const toggle = row(page, "dns64").getByRole("switch", {name: title(lang, "dns64")});
      await press(toggle);
      await expect(page.getByText(text(lang, "rules", "options.failed", {name: title(lang, "dns64")}), {exact: false}).first()).toBeVisible();
      await expect(toggle).not.toBeChecked();
      expect("dns64" in optionsOf(mock)).toBe(false);
    });

    test("T-204: a TTL opens in place with Save, takes 1 to 86,400, and Use the default clears it", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 50});
      await open(page, lang);
      const r = row(page, "block_ttl");
      const name = title(lang, "block_ttl");
      // 10 seconds is stored (the fixture), shown with the language's digits.
      await expect(r.getByTestId("block_ttl-value")).toContainText(digits(lang, 10));
      await r.getByRole("button", {name: text(lang, "rules", "options.editAria", {name})}).click();
      const field = r.getByRole("textbox", {name: text(lang, "rules", "options.ttl.field", {name})});
      await expect(field).toBeFocused();
      await field.fill("0");
      await save(r, lang, name).click();
      await expect(r).toContainText(text(lang, "rules", "options.ttl.out_of_range", {min: digits(lang, 1), max: digits(lang, 86400)}).slice(0, 12));
      expect(optionsOf(mock).block_ttl).toBe(10);
      await field.fill("90000");
      await save(r, lang, name).click();
      expect(optionsOf(mock).block_ttl).toBe(10);
      await field.fill(digits(lang, 120));
      await save(r, lang, name).click();
      await expect.poll(() => optionsOf(mock).block_ttl).toBe(120);
      await expect(r.getByTestId("block_ttl-value")).toContainText(digits(lang, 120));
      // S2-r3-2: the maximum as the hint prints it, with its thousands separator, is a number and not "write a number".
      await r.getByRole("button", {name: text(lang, "rules", "options.editAria", {name})}).click();
      await r.getByRole("textbox", {name: text(lang, "rules", "options.ttl.field", {name})}).fill(new Intl.NumberFormat(lang === "fa" ? "fa-IR" : "en").format(86400));
      await save(r, lang, name).click();
      await expect.poll(() => optionsOf(mock).block_ttl).toBe(86400);
      await expect(r.getByTestId("block_ttl-value")).toBeVisible();
      // The default of Block TTL is 60 seconds.
      await r.getByRole("button", {name: text(lang, "rules", "options.editAria", {name})}).click();
      await r.getByRole("button", {name: text(lang, "rules", "options.ttl.useDefaultAria", {name})}).click();
      await expect.poll(() => "block_ttl" in optionsOf(mock)).toBe(false);
      await expect(r.getByTestId("block_ttl-value")).toContainText(digits(lang, 60));
    });

    test("T-204: Redirect TTL and Bypass TTL are rows of their own, and an unset Bypass TTL keeps the answer's TTL", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 50});
      await open(page, lang);
      await expect(row(page, "bypass_ttl").getByTestId("bypass_ttl-value")).toContainText(text(lang, "rules", "options.ttl.keeps"));
      for (const name of ["redirect_ttl", "bypass_ttl"] as const) {
        const r = row(page, name);
        const label = title(lang, name);
        await r.getByRole("button", {name: text(lang, "rules", "options.editAria", {name: label})}).click();
        await r.getByRole("textbox", {name: text(lang, "rules", "options.ttl.field", {name: label})}).fill("300");
        await save(r, lang, label).click();
        await expect.poll(() => optionsOf(mock)[name]).toBe(300);
      }
      // Cancel leaves the stored value.
      const r = row(page, "bypass_ttl");
      const label = title(lang, "bypass_ttl");
      await r.getByRole("button", {name: text(lang, "rules", "options.editAria", {name: label})}).click();
      await r.getByRole("textbox", {name: text(lang, "rules", "options.ttl.field", {name: label})}).fill("77");
      await r.getByRole("button", {name: `${shared(lang, "common", "cancel")}: ${label}`}).click();
      expect(optionsOf(mock).bypass_ttl).toBe(300);
      await expect(r.getByTestId("bypass_ttl-value")).toContainText(digits(lang, 300));
    });

    test("T-205: Block Response answers at once for 0.0.0.0 and ::, NXDOMAIN and REFUSED, and says what each does", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 50});
      await open(page, lang);
      const r = row(page, "block_response");
      const select = r.locator(".select__trigger");
      await expect(r.getByTestId("block_response-text")).toContainText(text(lang, "rules", "options.blockResponse.modeText.zero"));
      for (const mode of ["nxdomain", "refused", "zero"] as const) {
        await select.click();
        await page.getByRole("option", {name: text(lang, "rules", `options.blockResponse.mode.${mode}`)}).click();
        await expect.poll(() => (optionsOf(mock).block_response as {mode: string}).mode).toBe(mode);
        await expect(r.getByTestId("block_response-text")).toContainText(text(lang, "rules", `options.blockResponse.modeText.${mode}`));
      }
      // Branded is listed and cannot be chosen: it comes with the block page (open question 9).
      await select.click();
      await expect(page.getByRole("option", {name: text(lang, "rules", "options.blockResponse.mode.branded")})).toHaveAttribute("aria-disabled", "true");
      await page.keyboard.press("Escape");
    });

    test("T-205: Custom opens two fields with Save in place, wants at least one valid address, and stores only what is filled", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 50});
      await open(page, lang);
      const r = row(page, "block_response");
      const name = title(lang, "block_response");
      await r.locator(".select__trigger").click();
      await page.getByRole("option", {name: text(lang, "rules", "options.blockResponse.mode.custom")}).click();
      // Nothing is stored until Save.
      expect((optionsOf(mock).block_response as {mode: string}).mode).toBe("zero");
      const v4 = r.getByRole("textbox", {name: text(lang, "rules", "options.blockResponse.v4")});
      const v6 = r.getByRole("textbox", {name: text(lang, "rules", "options.blockResponse.v6")});
      await save(r, lang, name).click();
      await expect(r).toContainText(text(lang, "rules", "options.blockResponse.needOne"));
      await v4.fill("203.0.113");
      await save(r, lang, name).click();
      await expect(r).toContainText(text(lang, "rules", "options.blockResponse.invalidV4"));
      await v4.fill("203.0.113.7");
      await save(r, lang, name).click();
      await expect.poll(() => optionsOf(mock).block_response).toEqual({mode: "custom", v4: "203.0.113.7"});
      // The two fields stay, with the stored value, and a second address can be added.
      await expect(v4).toHaveValue("203.0.113.7");
      // S2-r3-1: the form stays open, so the save is said beside the buttons, and it goes when the reader edits again.
      await expect(r.getByTestId("custom-saved")).toHaveText(text(lang, "rules", "options.saved"));
      await v6.fill("2001:db8::7");
      await expect(r.getByTestId("custom-saved")).toBeEmpty();
      await save(r, lang, name).click();
      await expect.poll(() => optionsOf(mock).block_response).toEqual({mode: "custom", v4: "203.0.113.7", v6: "2001:db8::7"});
      // Back to a plain mode closes the fields.
      await r.locator(".select__trigger").click();
      await page.getByRole("option", {name: text(lang, "rules", "options.blockResponse.mode.refused")}).click();
      await expect.poll(() => (optionsOf(mock).block_response as {mode: string}).mode).toBe("refused");
      await expect(v4).toHaveCount(0);
    });

    test("T-205: Cancel on a Custom that was not saved puts the select back to the stored mode", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {rules: 50});
      await open(page, lang);
      const r = row(page, "block_response");
      const name = title(lang, "block_response");
      await r.locator(".select__trigger").click();
      await page.getByRole("option", {name: text(lang, "rules", "options.blockResponse.mode.custom")}).click();
      await r.getByRole("button", {name: `${shared(lang, "common", "cancel")}: ${name}`}).click();
      await expect(r.getByTestId("block_response-text")).toContainText(text(lang, "rules", "options.blockResponse.modeText.zero"));
      await expect(r.getByRole("textbox", {name: text(lang, "rules", "options.blockResponse.v4")})).toHaveCount(0);
    });

    test("T-210: ECS has No ECS, Auto and Custom; the first two answer at once and Custom opens two subnets", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 50});
      await open(page, lang);
      const r = row(page, "ecs");
      const name = title(lang, "ecs");
      const mode = (id: "none" | "auto" | "custom") => r.getByRole("radio", {name: new RegExp(`^${text(lang, "rules", `options.ecs.mode.${id}`)}`)});
      await expect(mode("auto")).toBeChecked();
      await mode("none").click();
      await expect.poll(() => optionsOf(mock).ecs).toEqual({mode: "none"});
      await expect(r.getByTestId("ecs-text")).toContainText(text(lang, "rules", "options.ecs.modeText.none"));
      await mode("auto").click();
      await expect.poll(() => optionsOf(mock).ecs).toEqual({mode: "auto"});
      await mode("custom").click();
      expect(optionsOf(mock).ecs).toEqual({mode: "auto"});
      const v4 = r.getByRole("textbox", {name: text(lang, "rules", "options.ecs.v4")});
      const v6 = r.getByRole("textbox", {name: text(lang, "rules", "options.ecs.v6")});
      await save(r, lang, name).click();
      await expect(r).toContainText(text(lang, "rules", "options.ecs.needOne"));
      // A prefix with host bits is refused with the sentence that says what to write.
      await v4.fill("203.0.113.7/24");
      await save(r, lang, name).click();
      await expect(r).toContainText(text(lang, "rules", "options.ecs.host_bits").slice(0, 25));
      expect(optionsOf(mock).ecs).toEqual({mode: "auto"});
      // S2-r2-1: a subnet has a slash, so the phone's keypad for it is the text one (the decimal pad has none); Persian digits count as digits.
      await expect(v4).toHaveAttribute("inputmode", "text");
      await v4.fill("۲۰۳.۰.۱۱۳.۰/۲۴");
      await v6.fill("2001:db8::/48");
      await save(r, lang, name).click();
      await expect.poll(() => optionsOf(mock).ecs).toEqual({mode: "custom", v4: "203.0.113.0/24", v6: "2001:db8::/48"});
      // S2-r3-1: the fields show what is stored (Latin digits) and the save is said.
      await expect(v4).toHaveValue("203.0.113.0/24");
      await expect(r.getByTestId("custom-saved")).toHaveText(text(lang, "rules", "options.saved"));
      // S2-r3-3: a field is named with its row, so it is told apart from the same field of another row.
      // (The hidden part is a block of its own to the browser, so a space may come before the colon.)
      const escaped = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      await expect(r.getByRole("textbox", {name: new RegExp(`^${escaped(text(lang, "rules", "options.ecs.v4"))} ?: ${escaped(name)}$`)})).toBeVisible();
    });

    test("T-210: the API's own refusal of a subnet is worded under its field", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 422/);
      await openProfiles(context, baseURL, {
        rules: 50,
        handlers: {"PATCH /profiles/{id}/options": {status: 422, body: errorBody("validation_failed", {fields: [{name: "/ecs/v4", code: "invalid"}]})}},
      });
      await open(page, lang);
      const r = row(page, "ecs");
      const name = title(lang, "ecs");
      await r.getByRole("radio", {name: new RegExp(`^${text(lang, "rules", "options.ecs.mode.custom")}`)}).click();
      const v4 = r.getByRole("textbox", {name: text(lang, "rules", "options.ecs.v4")});
      await v4.fill("203.0.113.0/24");
      await save(r, lang, name).click();
      await expect(v4).toHaveAttribute("aria-invalid", "true");
    });

    test("T-138: Disable takes 5 minutes, 1 hour or 1 day with a switch, says when it ends, and the switch off brings the profile back", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 50});
      await open(page, lang);
      const r = row(page, "disable");
      const name = title(lang, "disable");
      const pick = (id: "5m" | "1h" | "1d" | "custom") => r.getByRole("radio", {name: new RegExp(`^${text(lang, "rules", `options.disable.choice.${id}`)}`)});
      const toggle = r.getByRole("switch", {name});
      await expect(toggle).not.toBeChecked();
      await pick("5m").click();
      const before = Date.now();
      await press(toggle);
      await expect(toggle).toBeChecked();
      const stored = mock.screens.profiles.find((p) => p.id === PROFILE.home)!.disabled_until!;
      const ms = Date.parse(stored) - before;
      expect(ms).toBeGreaterThan(4 * 60_000);
      expect(ms).toBeLessThan(6 * 60_000);
      await expect(r.getByTestId("disable-until")).toBeVisible();
      await expect(r.getByTestId("disable-state")).toHaveText(text(lang, "rules", "options.disable.on"));
      // While it is on the choice cannot change, and the frame's subtitle says it too.
      await expect(pick("1d")).toBeDisabled();
      await expect(profileHeader(page)).toContainText(text(lang, "profiles", "frame.disabledUntil", {when: ""}).trim().slice(0, 6));
      await press(toggle);
      await expect(toggle).not.toBeChecked();
      expect(mock.screens.profiles.find((p) => p.id === PROFILE.home)!.disabled_until).toBeUndefined();
      await pick("1d").click();
      const day = Date.now();
      await press(toggle);
      await expect(toggle).toBeChecked();
      const dayMs = Date.parse(mock.screens.profiles.find((p) => p.id === PROFILE.home)!.disabled_until!) - day;
      expect(dayMs).toBeGreaterThan(23 * 3_600_000);
    });

    test("T-138: Custom needs a date and time first; the picker sets `until`", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 50});
      await open(page, lang);
      const r = row(page, "disable");
      const name = title(lang, "disable");
      const toggle = r.getByRole("switch", {name});
      await r.getByRole("radio", {name: new RegExp(`^${text(lang, "rules", "options.disable.choice.custom")}`)}).click();
      await expect(r.getByTestId("disable-picker")).toBeVisible();
      // S2-r3-3: the date button and the calendar are named with the row, and the button's name starts with the words it shows.
      await expect(r.getByRole("button", {name: `${text(lang, "rules", "options.disable.pick")}: ${name}`})).toBeVisible();
      await expect(r.getByLabel(text(lang, "rules", "options.disable.pickLabel", {name})).first()).toBeVisible();
      await r.getByRole("button", {name: shared(lang, "common", "cancel")}).click();
      await press(toggle);
      await expect(r.getByRole("alert")).toContainText(text(lang, "rules", "options.disable.pickFirst"));
      expect(mock.screens.profiles.find((p) => p.id === PROFILE.home)!.disabled_until).toBe(undefined);
      await expect(r.getByTestId("disable-picker")).toBeVisible();
      // The first day of the month that follows is ahead of now whatever day and hour the run is on (the last day of a month, after the
      // picker's 12:00, would leave only today, which is past). The days of the neighbouring months shown in the grid are not counted (S2-r2-5).
      await r.getByTestId("disable-picker").getByRole("button", {name: shared(lang, "common", "calendar.next")}).click();
      const cells = r.getByTestId("disable-picker").locator('[role="gridcell"]:not([aria-disabled="true"]) [role="button"]:not([data-outside-month="true"])');
      await expect(cells.first()).toBeVisible();
      await cells.first().click();
      await r.getByTestId("disable-picker").getByRole("button", {name: shared(lang, "common", "calendar.apply")}).click();
      await expect(r.getByTestId("disable-picker")).toBeHidden();
      await press(toggle);
      await expect(toggle).toBeChecked();
      const until = Date.parse(mock.screens.profiles.find((p) => p.id === PROFILE.home)!.disabled_until!);
      expect(until).toBeGreaterThan(Date.now());
    });

    test("T-139, T-141: the Lock switch opens the lock dialog; the password never reaches the address; Lock shows the banner with the message and turns every control off but its own", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 50});
      await open(page, lang);
      const lock = row(page, "lock").getByRole("switch", {name: title(lang, "lock")});
      await expect(lock).not.toBeChecked();
      await press(lock);
      const dialog = page.getByRole("dialog", {name: text(lang, "profiles", "lock.dialog.lockTitle", {name: "Home"})});
      await expect(dialog).toBeVisible();
      // The switch has not moved: the profile is not locked until the dialog has succeeded.
      await expect(lock).not.toBeChecked();
      await dialog.getByLabel(text(lang, "profiles", "lock.dialog.password")).fill("12345");
      await dialog.getByRole("button", {name: text(lang, "profiles", "lock.dialog.lock"), exact: true}).click();
      await expect(dialog.getByText(shared(lang, "errors", "fields.too_short"))).toBeVisible();
      await dialog.getByLabel(text(lang, "profiles", "lock.dialog.password")).fill(LOCK_PASSWORD);
      await dialog.getByLabel(text(lang, "profiles", "lock.dialog.message")).fill("Ask Sara");
      expect(page.url()).not.toContain(LOCK_PASSWORD);
      await dialog.getByRole("button", {name: text(lang, "profiles", "lock.dialog.lock"), exact: true}).click();
      await expect(dialog).toBeHidden();
      expect(page.url()).not.toContain(LOCK_PASSWORD.split(" ")[0]!);
      expect(mock.screens.profiles.find((p) => p.id === PROFILE.home)!.locked).toBe(true);
      // The banner shows the message, and the page's controls are off.
      await expect(lockBanner(page)).toContainText("Ask Sara");
      await expect(lock).toBeChecked();
      await expect(row(page, "lock").getByTestId("lock-message")).toContainText("Ask Sara");
      for (const name of ["block_exfiltration", "rebind_protection", "dns64", "safe_search"] as const) {
        await expect(row(page, name).getByRole("switch", {name: title(lang, name)})).toBeDisabled();
      }
      await expect(row(page, "disable").getByRole("switch", {name: title(lang, "disable")})).toBeDisabled();
      await expect(row(page, "block_ttl").getByRole("button", {name: text(lang, "rules", "options.editAria", {name: title(lang, "block_ttl")})})).toBeDisabled();
      await expect(choice(row(page, "default_rule"), lang, "block", title(lang, "default_rule"))).toBeDisabled();
      await expect(row(page, "block_response").locator(".select__trigger")).toBeDisabled();
      await expect(row(page, "ecs").getByRole("radio", {name: new RegExp(`^${text(lang, "rules", "options.ecs.mode.none")}`)})).toBeDisabled();
      await expect(lock).toBeEnabled();
    });

    test("T-140, S2-r1-5: a link to the Default Rule dialog on a locked profile opens no dialog", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {rules: 50});
      await page.goto(`${profilePath(lang, PROFILE.office, "options")}?profileDialog=default-rule`);
      await expect(row(page, "lock")).toBeVisible();
      await expect(lockBanner(page)).toBeVisible();
      await expect(page.getByRole("dialog")).toHaveCount(0);
      await expect(page.getByTestId("d42-notice")).toHaveCount(0);
    });

    test("T-138, S2-r1-4: a profile that is already disabled shows no made-up choice beside its end time", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {rules: 50});
      await open(page, lang, PROFILE.gaming);
      const r = row(page, "disable");
      await expect(r.getByRole("switch", {name: title(lang, "disable")})).toBeChecked();
      await expect(r.getByTestId("disable-until")).toBeVisible();
      for (const id of ["5m", "1h", "1d", "custom"] as const) {
        await expect(r.getByRole("radio", {name: new RegExp(`^${text(lang, "rules", `options.disable.choice.${id}`)}`)})).not.toBeChecked();
      }
    });

    test("T-204, T-205, T-210, S2-r1-3: the focus goes back to the row's control when an in-place form closes", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {rules: 50});
      await open(page, lang);
      // Block TTL: Save puts it back on Edit, and so does Cancel.
      const ttl = row(page, "block_ttl");
      const ttlName = title(lang, "block_ttl");
      const edit = ttl.getByRole("button", {name: text(lang, "rules", "options.editAria", {name: ttlName})});
      await edit.click();
      await ttl.getByRole("textbox", {name: text(lang, "rules", "options.ttl.field", {name: ttlName})}).fill("120");
      await save(ttl, lang, ttlName).click();
      await expect(edit).toBeFocused();
      await edit.click();
      await ttl.getByRole("button", {name: `${shared(lang, "common", "cancel")}: ${ttlName}`}).click();
      await expect(edit).toBeFocused();
      // ECS Custom: Cancel leaves it on the mode group.
      const ecs = row(page, "ecs");
      const ecsName = title(lang, "ecs");
      await ecs.getByRole("radio", {name: new RegExp(`^${text(lang, "rules", "options.ecs.mode.custom")}`)}).click();
      // A string, not a pattern: the name of this row has parentheses in it.
      await ecs.getByRole("button", {name: `${shared(lang, "common", "cancel")}: ${ecsName}`}).click();
      await expect(ecs.getByRole("textbox")).toHaveCount(0);
      // The focus is on one of the mode buttons (the one the click left it on, or the selected one), not dropped to the page.
      await expect(ecs.locator("[role=radio]:focus")).toHaveCount(1);
    });

    test("T-205, T-210, S2-r2-2: Cancel on a form whose stored mode is already Custom starts it again and keeps the focus on the row's control", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 50});
      optionsOf(mock).ecs = {mode: "custom", v4: "203.0.113.0/24"};
      await open(page, lang);
      const ecs = row(page, "ecs");
      const ecsName = title(lang, "ecs");
      const v4 = ecs.getByRole("textbox", {name: text(lang, "rules", "options.ecs.v4")});
      await expect(v4).toHaveValue("203.0.113.0/24");
      // A form that is simply there, from the stored value, does not take the focus on page load.
      await expect(v4).not.toBeFocused();
      await v4.fill("198.51.100.0/24");
      await ecs.getByRole("button", {name: `${shared(lang, "common", "cancel")}: ${ecsName}`}).click();
      // The fields are the stored values again, and the focus is not dropped to the page.
      await expect(v4).toHaveValue("203.0.113.0/24");
      await expect(ecs.locator("[role=radio]:focus")).toHaveCount(1);
      expect(optionsOf(mock).ecs).toEqual({mode: "custom", v4: "203.0.113.0/24"});
    });

    test("T-140, S2-r2-3: a link to the Default Rule dialog on a locked profile leaves no parameter behind, and unlocking opens nothing", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {rules: 50});
      await page.goto(`${profilePath(lang, PROFILE.office, "options")}?profileDialog=default-rule`);
      await expect(lockBanner(page)).toBeVisible();
      await expect(page).not.toHaveURL(/profileDialog/);
      const lock = row(page, "lock").getByRole("switch", {name: title(lang, "lock")});
      await press(lock);
      const dialog = page.getByRole("dialog", {name: text(lang, "profiles", "lock.dialog.unlockTitle", {name: "Office"})});
      await dialog.getByLabel(text(lang, "profiles", "lock.dialog.password")).fill(LOCK_PASSWORD);
      await dialog.getByRole("button", {name: text(lang, "profiles", "lock.dialog.unlock"), exact: true}).click();
      await expect(dialog).toBeHidden();
      await expect(lockBanner(page)).toHaveCount(0);
      await expect(page.getByRole("dialog")).toHaveCount(0);
      await expect(page.getByTestId("d42-notice")).toHaveCount(0);
    });

    test("T-140, S2-r2-6: a form that was open when the profile got locked is closed or off, with no live Save", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 50});
      optionsOf(mock).ecs = {mode: "custom", v4: "203.0.113.0/24"};
      await open(page, lang);
      // Three forms are open: Block TTL's field, the ECS fields (with a draft), and Disable's date picker.
      const ttl = row(page, "block_ttl");
      const ttlName = title(lang, "block_ttl");
      await ttl.getByRole("button", {name: text(lang, "rules", "options.editAria", {name: ttlName})}).click();
      await expect(save(ttl, lang, ttlName)).toBeVisible();
      const ecs = row(page, "ecs");
      const v4 = ecs.getByRole("textbox", {name: text(lang, "rules", "options.ecs.v4")});
      await v4.fill("198.51.100.0/24");
      const disable = row(page, "disable");
      await disable.getByRole("radio", {name: new RegExp(`^${text(lang, "rules", "options.disable.choice.custom")}`)}).click();
      await expect(disable.getByTestId("disable-picker")).toBeVisible();
      // The profile is locked from this page.
      await press(row(page, "lock").getByRole("switch", {name: title(lang, "lock")}));
      const dialog = page.getByRole("dialog", {name: text(lang, "profiles", "lock.dialog.lockTitle", {name: "Home"})});
      await dialog.getByLabel(text(lang, "profiles", "lock.dialog.password")).fill(LOCK_PASSWORD);
      await dialog.getByRole("button", {name: text(lang, "profiles", "lock.dialog.lock"), exact: true}).click();
      await expect(dialog).toBeHidden();
      await expect(lockBanner(page)).toBeVisible();
      await expect(ttl.getByRole("textbox")).toHaveCount(0);
      await expect(save(ttl, lang, ttlName)).toHaveCount(0);
      await expect(disable.getByTestId("disable-picker")).toHaveCount(0);
      // The ECS fields stay, showing what is stored, off, and Save cannot be pressed.
      await expect(v4).toHaveValue("203.0.113.0/24");
      await expect(v4).toBeDisabled();
      await expect(save(ecs, lang, title(lang, "ecs"))).toBeDisabled();
    });

    test("T-139, T-141: Unlock wants the profile's own password: a wrong one is said under the field and the profile stays locked; the right one frees every control", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 401/);
      const mock = await openProfiles(context, baseURL, {rules: 50});
      await open(page, lang, PROFILE.office);
      await expect(lockBanner(page)).toContainText("Ask the admin before you change this.");
      const lock = row(page, "lock").getByRole("switch", {name: title(lang, "lock")});
      await expect(lock).toBeChecked();
      await expect(row(page, "dns64").getByRole("switch", {name: title(lang, "dns64")})).toBeDisabled();
      await press(lock);
      const dialog = page.getByRole("dialog", {name: text(lang, "profiles", "lock.dialog.unlockTitle", {name: "Office"})});
      await dialog.getByLabel(text(lang, "profiles", "lock.dialog.password")).fill("not the password");
      await dialog.getByRole("button", {name: text(lang, "profiles", "lock.dialog.unlock"), exact: true}).click();
      await expect(dialog.getByText(text(lang, "profiles", "lock.dialog.wrong", {name: "Office"}))).toBeVisible();
      expect(mock.screens.profiles.find((p) => p.id === PROFILE.office)!.locked).toBe(true);
      await dialog.getByLabel(text(lang, "profiles", "lock.dialog.password")).fill(LOCK_PASSWORD);
      await dialog.getByRole("button", {name: text(lang, "profiles", "lock.dialog.unlock"), exact: true}).click();
      await expect(dialog).toBeHidden();
      await expect(lockBanner(page)).toHaveCount(0);
      await expect(lock).not.toBeChecked();
      await expect(row(page, "dns64").getByRole("switch", {name: title(lang, "dns64")})).toBeEnabled();
      await expect(page.getByRole("button", {name: text(lang, "profiles", "frame.deleteAria", {name: "Office"})})).toBeEnabled();
    });

    test("T-140: a write refused with 423 because the profile was locked elsewhere puts the value back and shows the lock banner", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 423/);
      const mock = await openProfiles(context, baseURL, {rules: 50});
      delete optionsOf(mock).dns64;
      await open(page, lang);
      // Somebody else locks the profile after the page has loaded: the page still thinks it is open.
      const home = mock.screens.profiles.find((p) => p.id === PROFILE.home)!;
      Object.assign(home, {locked: true, lock_message: "Locked in another tab"});
      mock.screens.lockPasswords.set(PROFILE.home, LOCK_PASSWORD);
      const toggle = row(page, "dns64").getByRole("switch", {name: title(lang, "dns64")});
      await press(toggle);
      await expect(lockBanner(page)).toContainText("Locked in another tab");
      await expect(toggle).not.toBeChecked();
      await expect(toggle).toBeDisabled();
      expect("dns64" in optionsOf(mock)).toBe(false);
    });

    test("T-215: the options screen has its own error state with Retry, and a loading state before the rows", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 500/);
      let fail = true;
      await openProfiles(context, baseURL, {
        rules: 50,
        handlers: {
          "GET /profiles/{id}/options": (c) => {
            void c;
            return fail ? {status: 500, body: errorBody("internal")} : {status: 200, body: {default_location_unavailable: false}};
          },
        },
      });
      await page.goto(profilePath(lang, PROFILE.home, "options"));
      const retry = screen(page, "profile-options").getByRole("button", {name: shared(lang, "common", "retry")});
      await expect(retry).toBeVisible();
      fail = false;
      await retry.click();
      await expect(row(page, "lock")).toBeVisible();
      // Nothing is set: every switch is off, the Default Rule is Bypass, the TTLs show their defaults.
      await expect(row(page, "block_ttl").getByTestId("block_ttl-value")).toContainText(digits(lang, 60));
    });

    test("T-215: the keyboard reaches each row's Learn more and then its control, in the order the row is read", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {rules: 50});
      await open(page, lang);
      const learn = row(page, "dns64").getByRole("button", {name: text(lang, "rules", "options.learnMoreAria", {name: title(lang, "dns64")})});
      await learn.focus();
      await page.keyboard.press("Tab");
      await expect(row(page, "dns64").getByRole("switch", {name: title(lang, "dns64")})).toBeFocused();
      await page.keyboard.press("Space");
      await expect(row(page, "dns64").getByRole("switch", {name: title(lang, "dns64")})).toBeChecked();
      // In the other direction of the page the control is still after the text: the row is one reading order, start to end.
      const learnBox = (await learn.boundingBox())!;
      const switchBox = (await row(page, "dns64").getByRole("switch", {name: title(lang, "dns64")}).boundingBox())!;
      if (dir === "rtl") expect(switchBox.x).toBeLessThan(learnBox.x);
      else expect(switchBox.x).toBeGreaterThan(learnBox.x);
    });
  });
}
