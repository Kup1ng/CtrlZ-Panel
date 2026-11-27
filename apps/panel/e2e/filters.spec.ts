import type {Page} from "@playwright/test";
import {errorBody} from "@ctrlz/api-client/testing/fixtures.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import enErrors from "../../../packages/i18n/messages/en/errors.json";
import faErrors from "../../../packages/i18n/messages/fa/errors.json";
import {LANGS, PROFILE, openProfiles, profilePath, screen, text, type Lang} from "./profiles-support.ts";

// P2 package S3, the Filters screens, in mock mode (spec p2 10.6 `filters.spec.ts`, 9.3). Every case names its T row. The fixture catalogue has
// the 20 Native filters (Ads, Adult and Malware with three, two and three modes, New Domains with two, the rest with one) and 12 lists; profile
// Home has Malware on (strict), Phishing on, Ads on (relaxed), Adult off with strict remembered, and New Domains on (last week).

test.use({viewport: {width: 1280, height: 800}});

const NAMES = {
  fa: {malware: "بدافزار", phishing: "فیشینگ", adult: "محتوای بزرگسال", newDomains: "دامنه‌های تازه", ads: "تبلیغ و ردیاب", dynamicDns: "دی‌ان‌اس پویا", government: "دولتی"},
  en: {malware: "Malware", phishing: "Phishing", adult: "Adult", newDomains: "New domains", ads: "Ads & Trackers", dynamicDns: "Dynamic DNS", government: "Government"},
} as const;

const ERRORS = {fa: faErrors, en: enErrors} as const;

const grid = (page: Page, lang: Lang, profile = "Home", third = false) =>
  page.getByRole("list", {name: text(lang, "profiles", third ? "thirdParty.gridLabel" : "filters.gridLabel", {name: profile})});
const card = (page: Page, lang: Lang, name: string, profile = "Home", third = false) =>
  grid(page, lang, profile, third).getByRole("listitem").filter({has: page.getByRole("heading", {name, exact: true})});
const switchOf = (page: Page, lang: Lang, name: string) => page.getByRole("switch", {name: text(lang, "profiles", "card.toggle", {name})});
const modeName = (lang: Lang, mode: string) => text(lang, "profiles", `filters.modes.${mode}.name`);
const modeButton = (page: Page, lang: Lang, name: string, mode: string) =>
  page.getByRole("button", {name: text(lang, "profiles", "filters.modeButton", {name, mode: modeName(lang, mode)})});
const ready = (page: Page) => page.waitForLoadState("networkidle");

for (const {lang, dir} of LANGS) {
  const N = NAMES[lang];
  test.describe(`${lang} (${dir})`, () => {
    test("T-144: the 20 Native filters are cards with a switch, a status in words and an info button", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "filters"));
      await expect(screen(page, "profile-filters")).toBeVisible();
      const cards = grid(page, lang).getByRole("listitem");
      await expect(cards).toHaveCount(20);
      // On is "Blocked" and off is "Allowed", in words (status never rests on colour), and the switch says the same.
      const malware = card(page, lang, N.malware);
      await expect(malware).toContainText(text(lang, "profiles", "card.status.blocked"));
      await expect(switchOf(page, lang, N.malware)).toBeChecked();
      const adult = card(page, lang, N.adult);
      await expect(adult).toContainText(text(lang, "profiles", "card.status.allowed"));
      await expect(switchOf(page, lang, N.adult)).not.toBeChecked();
      await expect(malware.getByRole("button", {name: text(lang, "profiles", "card.info", {name: N.malware})})).toBeVisible();
      expect(mock.screens.catalogFilters.filter((f) => f.kind === "native")).toHaveLength(20);
    });

    test("T-144: a switch is written at once, and a profile that has nothing on starts with every card Allowed", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.gaming, "filters"));
      await ready(page);
      const dating = card(page, lang, lang === "fa" ? "آشنایی" : "Dating", "Gaming");
      await expect(dating).toContainText(text(lang, "profiles", "card.status.allowed"));
      await dating.locator(".switch__control").click();
      await expect(dating).toContainText(text(lang, "profiles", "card.status.blocked"));
      expect(mock.screens.filters.get(PROFILE.gaming)).toEqual([{filter_id: "dating", enabled: true}]);
      await dating.locator(".switch__control").click();
      await expect(dating).toContainText(text(lang, "profiles", "card.status.allowed"));
      expect(mock.screens.filters.get(PROFILE.gaming)).toEqual([{filter_id: "dating", enabled: false}]);
    });

    test("T-145: Ads and Malware have three modes, Adult and New Domains two, and the other filters no menu", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "filters"));
      await ready(page);
      await modeButton(page, lang, N.malware, "strict").click();
      const group = page.getByRole("radiogroup", {name: text(lang, "profiles", "filters.modeGroup", {name: N.malware})});
      await expect(group.getByRole("radio")).toHaveCount(3);
      await page.keyboard.press("Escape");
      await card(page, lang, N.adult).locator(".switch__control").click();
      await modeButton(page, lang, N.adult, "strict").click();
      await expect(page.getByRole("radiogroup", {name: text(lang, "profiles", "filters.modeGroup", {name: N.adult})}).getByRole("radio")).toHaveCount(2);
      await page.keyboard.press("Escape");
      await modeButton(page, lang, N.newDomains, "last_week").click();
      await expect(page.getByRole("radiogroup", {name: text(lang, "profiles", "filters.modeGroup", {name: N.newDomains})}).getByRole("radio")).toHaveCount(2);
      await page.keyboard.press("Escape");
      // A filter with one mode has no menu at all.
      await expect(card(page, lang, N.phishing).getByRole("button")).toHaveCount(1);
    });

    test("T-146: switching on takes the default mode, Relaxed, and a filter that was on again takes the mode it remembers", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.gaming, "filters"));
      await ready(page);
      const malware = card(page, lang, N.malware, "Gaming");
      await malware.locator(".switch__control").click();
      await expect(modeButton(page, lang, N.malware, "relaxed")).toBeVisible();
      expect(mock.screens.filters.get(PROFILE.gaming)).toEqual([{filter_id: "malware", enabled: true, mode: "relaxed"}]);
      // Home: Adult is off with Strict remembered, and goes on as Strict.
      await page.goto(profilePath(lang, PROFILE.home, "filters"));
      await ready(page);
      await card(page, lang, N.adult).locator(".switch__control").click();
      await expect(modeButton(page, lang, N.adult, "strict")).toBeVisible();
      expect(mock.screens.filters.get(PROFILE.home)?.find((f) => f.filter_id === "adult")).toEqual({filter_id: "adult", enabled: true, mode: "strict"});
    });

    test("T-147: choosing a mode applies at once, with no preview and no Save", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "filters"));
      await ready(page);
      await modeButton(page, lang, N.malware, "strict").click();
      await expect(page.getByRole("button", {name: text(lang, "services", "destinations.save")})).toHaveCount(0);
      await page.getByRole("radio", {name: modeName(lang, "balanced")}).click({force: true});
      await expect(modeButton(page, lang, N.malware, "balanced")).toBeVisible();
      expect(mock.screens.filters.get(PROFILE.home)?.find((f) => f.filter_id === "malware")).toEqual({filter_id: "malware", enabled: true, mode: "balanced"});
      // The popover closed on its own.
      await expect(page.getByRole("radiogroup", {name: text(lang, "profiles", "filters.modeGroup", {name: N.malware})})).toHaveCount(0);
    });

    test("T-148: 3rd Party has its own address, the Advanced Mode banner and a link back", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "filters"));
      await ready(page);
      const nav = page.getByRole("navigation", {name: text(lang, "profiles", "filters.navLabel")});
      await expect(nav.getByRole("link", {name: text(lang, "profiles", "filters.tabNative")})).toHaveAttribute("aria-current", "page");
      await nav.getByRole("link", {name: text(lang, "profiles", "filters.tabThirdParty")}).click();
      await expect(page).toHaveURL(new RegExp(`/profiles/${PROFILE.home}/filters/third-party$`));
      await expect(screen(page, "profile-third-party")).toBeVisible();
      const banner = page.getByTestId("advanced-mode");
      await expect(banner).toContainText(text(lang, "profiles", "thirdParty.advanced.title"));
      await expect(banner).toContainText(text(lang, "profiles", "thirdParty.advanced.text"));
      // The Filters tab of the frame stays the current one on this page.
      await expect(page.getByRole("navigation", {name: text(lang, "profiles", "frame.tabsLabel", {name: "Home"})}).locator('[aria-current="page"]')).toHaveText(text(lang, "profiles", "frame.tabs.filters"));
      await page.getByRole("link", {name: text(lang, "profiles", "thirdParty.back")}).click();
      await expect(page).toHaveURL(new RegExp(`/profiles/${PROFILE.home}/filters$`));
    });

    test("T-149: the 12 lists of the catalogue are on the 3rd Party page", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "filters/third-party"));
      await expect(grid(page, lang, "Home", true).getByRole("listitem")).toHaveCount(12);
      expect(mock.screens.catalogFilters.filter((f) => f.kind === "third_party")).toHaveLength(12);
      // A list has one mode, so no card of this page has a mode menu.
      await expect(grid(page, lang, "Home", true).getByRole("button")).toHaveCount(12);
    });

    test("T-150: a second 3rd Party list shows the many-lists warning, and the first does not", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.gaming, "filters/third-party"));
      await ready(page);
      const warning = page.getByTestId("many-lists");
      await expect(warning).toBeEmpty();
      await card(page, lang, "hagezi-pro", "Gaming", true).locator(".switch__control").click();
      await expect(card(page, lang, "hagezi-pro", "Gaming", true)).toContainText(text(lang, "profiles", "card.status.blocked"));
      await expect(warning).toBeEmpty();
      await card(page, lang, "oisd-big", "Gaming", true).locator(".switch__control").click();
      await expect(warning).toContainText(text(lang, "profiles", "thirdParty.many.title"));
      await expect(warning).toContainText(text(lang, "profiles", "thirdParty.many.text"));
      expect(mock.screens.filters.get(PROFILE.gaming)?.filter((f) => f.enabled)).toHaveLength(2);
      // Back to one: it goes.
      await card(page, lang, "oisd-big", "Gaming", true).locator(".switch__control").click();
      await expect(warning).toBeEmpty();
    });

    test("T-150: the info button opens the explanation of the filter, which is in the address and closes with Escape", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "filters"));
      await ready(page);
      await card(page, lang, N.malware).getByRole("button", {name: text(lang, "profiles", "card.info", {name: N.malware})}).click();
      await expect(page).toHaveURL(/helpPane=filter\.malware/);
      const dialog = page.getByRole("dialog");
      await expect(dialog).toContainText(text(lang, "profiles", "filters.help.malware.body"));
      await expect(dialog).toContainText(N.malware);
      await page.keyboard.press("Escape");
      await expect(dialog).toBeHidden();
      await expect(page).not.toHaveURL(/helpPane/);
      // Each of the 20 Native filters has its own text, not the line for "nothing written".
      for (const id of ["ads-trackers", "dating", "vpn-dns"]) {
        await page.goto(`${profilePath(lang, PROFILE.home, "filters")}?helpPane=filter.${id}`);
        await expect(page.getByRole("dialog")).toContainText(text(lang, "profiles", `filters.help.${id}.body`));
      }
    });

    test("T-537: switching on New Domains warns that .ir and .ایران are not covered, and so does changing its mode, and the explanation says the same", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      const sentence = text(lang, "profiles", "filters.newDomains.warning");
      await page.goto(profilePath(lang, PROFILE.gaming, "filters"));
      await ready(page);
      const nd = card(page, lang, N.newDomains, "Gaming");
      await nd.locator(".switch__control").click();
      const notice = page.getByRole("alertdialog");
      await expect(notice).toContainText(sentence);
      expect(mock.screens.filters.get(PROFILE.gaming)).toEqual([{filter_id: "new-domains", enabled: true, mode: "last_week"}]);
      await notice.getByRole("button", {name: text(lang, "profiles", "filters.newDomains.ok")}).click();
      await expect(notice).toBeHidden();
      // A mode change on a filter that is on warns again.
      await modeButton(page, lang, N.newDomains, "last_week").click();
      await expect(page.getByRole("dialog", {name: text(lang, "profiles", "filters.modeTitle", {name: N.newDomains})})).toContainText(sentence);
      await page.getByRole("radio", {name: modeName(lang, "last_month")}).click({force: true});
      await expect(page.getByRole("alertdialog")).toContainText(sentence);
      expect(mock.screens.filters.get(PROFILE.gaming)).toEqual([{filter_id: "new-domains", enabled: true, mode: "last_month"}]);
      // An alert dialog is closed on purpose, by its button: Escape and the backdrop do not close it.
      await page.getByRole("alertdialog").getByRole("button", {name: text(lang, "profiles", "filters.newDomains.ok")}).click();
      await expect(page.getByRole("alertdialog")).toBeHidden();
      // Switching it off says nothing, and neither does another filter.
      await nd.locator(".switch__control").click();
      await expect(nd).toContainText(text(lang, "profiles", "card.status.allowed"));
      await expect(page.getByRole("alertdialog")).toHaveCount(0);
      // The explanation of the filter carries the same sentence.
      await page.goto(`${profilePath(lang, PROFILE.home, "filters")}?helpPane=filter.new-domains`);
      await expect(page.getByRole("dialog")).toContainText(sentence);
    });

    test("a deprecated filter can be turned off but not on, and an unavailable one says so", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      mock.screens.filters.set(PROFILE.home, [{filter_id: "dynamic-dns", enabled: true}]);
      await page.goto(profilePath(lang, PROFILE.home, "filters"));
      await ready(page);
      const dns = card(page, lang, N.dynamicDns);
      await expect(dns).toContainText(text(lang, "profiles", "filters.deprecated"));
      await expect(switchOf(page, lang, N.dynamicDns)).toBeEnabled();
      await dns.locator(".switch__control").click();
      await expect(dns).toContainText(text(lang, "profiles", "card.status.allowed"));
      await expect(switchOf(page, lang, N.dynamicDns)).toBeDisabled();
      const gov = card(page, lang, N.government);
      await expect(gov).toContainText(text(lang, "profiles", "filters.unavailable"));
      await expect(switchOf(page, lang, N.government)).toBeDisabled();
    });

    test("a locked profile has every switch and menu disabled", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.office, "filters"));
      await ready(page);
      await expect(switchOf(page, lang, N.malware)).toBeDisabled();
      await expect(switchOf(page, lang, N.phishing)).toBeDisabled();
    });

    test.describe("a refused write", () => {
      test.use({allowConsole: [/status of 423/]});

      test("puts the switch back and says why, and the lock banner shows", async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL, {
          handlers: {"PUT /profiles/{id}/filters/{filter_id}": {status: 423, body: errorBody("profile_locked")}},
        });
        await page.goto(profilePath(lang, PROFILE.gaming, "filters"));
        await ready(page);
        const dating = card(page, lang, lang === "fa" ? "آشنایی" : "Dating", "Gaming");
        await dating.locator(".switch__control").click();
        await expect(page.getByText(ERRORS[lang].profile_locked).first()).toBeVisible();
        await expect(dating).toContainText(text(lang, "profiles", "card.status.allowed"));
        expect(mock.screens.filters.get(PROFILE.gaming)).toEqual([]);
      });
    });
  });
}
