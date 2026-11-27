import type {Locator, Page} from "@playwright/test";
import {errorBody} from "@ctrlz/api-client/testing/fixtures.ts";
import {LOCATIONS, serviceFixture, uid} from "@ctrlz/api-client/testing/screenFixtures.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import enErrors from "../../../packages/i18n/messages/en/errors.json";
import faErrors from "../../../packages/i18n/messages/fa/errors.json";
import enCommon from "../../../packages/i18n/messages/en/common.json";
import faCommon from "../../../packages/i18n/messages/fa/common.json";
import {LANGS, PROFILE, openProfiles, profilePath, screen, text, type Lang} from "./profiles-support.ts";

// P2 package S3, the Services screen, Choose Service and the Destinations dialog of a service, in mock mode (spec p2 10.6 `services.spec.ts`,
// 9.4, 9.5). Every case names its T row. Profile Home has Telegram (block), Instagram (off, bypass), Spotify (redirect to Frankfurt), Aparat
// (a redirect that acts as Bypass, D42), Steam (a redirect whose location left the set) and Video 4 (deprecated, block). The catalogue holds
// 320 services in Video, one of them never proxied, one with the risk flag, one limited by region and one deprecated.

test.use({viewport: {width: 1280, height: 800}});

const ERRORS = {fa: faErrors, en: enErrors} as const;
const COMMON = {fa: faCommon, en: enCommon} as const;
const CATEGORY = {fa: {video: "ویدیو", social: "شبکه اجتماعی", news: "خبر", shop: "خرید"}, en: {video: "Video", social: "Social", news: "News", shop: "Shop"}} as const;
const APARAT = {fa: "آپارات", en: "Aparat"} as const;
const DIGIKALA = {fa: "دیجی‌کالا", en: "Digikala"} as const;

const S = (lang: Lang, path: string, values: Record<string, string | number> = {}) => text(lang, "services", path, values);
const DIGITS = "۰۱۲۳۴۵۶۷۸۹";
// The Add button of Choose Service names its count: "Add (2)", and in Persian with Persian digits.
const addName = (lang: Lang, n: number) => new RegExp(`^${lang === "fa" ? "افزودن" : "Add"} \\((?:${n}|${String(n).replace(/\d/g, (d) => DIGITS[Number(d)]!)})\\)`);
const action = (lang: Lang, a: string) => text(lang, "rules", `action.${a}`);
const three = (lang: Lang, a: string, subject: string) => text(lang, "rules", "three.set", {action: action(lang, a), subject});
const ready = (page: Page) => page.waitForLoadState("networkidle");

const grid = (page: Page, lang: Lang, category: string) => page.getByRole("list", {name: S(lang, "page.gridLabel", {category})});
const card = (page: Page, name: string): Locator =>
  screen(page, "profile-services").getByRole("listitem").filter({has: page.getByRole("heading", {name, exact: true})});
const press = (card: Locator, lang: Lang, a: string, name: string) => card.getByLabel(three(lang, a, name), {exact: false}).first();
// The name of a category button is its category and its count, in both states, so a test names it by its start.
const toggleName = (lang: Lang, category: string) => new RegExp(`^${category}${lang === "fa" ? "،" : ","} `);
const addButton = (page: Page, lang: Lang, profile = "Home") => page.getByRole("button", {name: S(lang, "page.addAria", {name: profile})});
const chooseDialog = (page: Page, lang: Lang) => page.getByRole("dialog", {name: S(lang, "choose.title")});
// The destination step is the same dialog under another title.
const stepDialog = (page: Page, lang: Lang) => page.getByRole("dialog", {name: S(lang, "choose.destinationTitle")});
// The option's name may carry its note ("only in some locations"), and "Video 160" is another service: the name starts with it and no digit follows.
const VIDEO_16 = new RegExp("^Video 16(?![0-9])");
// A number as the page writes it: Persian digits in fa.
const num = (lang: Lang, n: number) => (lang === "fa" ? String(n).replace(/[0-9]/g, (d) => DIGITS[Number(d)]!) : String(n));
const COUNT =(n: number) => new RegExp(`${n}|${String(n).replace(/\d/g, (d) => "۰۱۲۳۴۵۶۷۸۹"[Number(d)]!)}`);

for (const {lang, dir} of LANGS) {
  const C = CATEGORY[lang];
  test.describe(`${lang} (${dir})`, () => {
    test("T-162: a card has the logo, name, status in words, remove, the switch and the three-state control, and a press is written at once", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "services"));
      await expect(screen(page, "profile-services")).toBeVisible();
      const telegram = card(page, "Telegram");
      await expect(telegram).toContainText(action(lang, "block"));
      await expect(telegram.getByRole("switch", {name: S(lang, "card.switch", {name: "Telegram"})})).toBeChecked();
      await expect(telegram.getByRole("button", {name: S(lang, "card.remove", {name: "Telegram"})})).toBeVisible();
      await expect(telegram.getByRole("radiogroup", {name: text(lang, "rules", "three.group", {subject: "Telegram"})})).toBeVisible();
      await press(telegram, lang, "bypass", "Telegram").click();
      await expect(telegram).toContainText(action(lang, "bypass"));
      expect(mock.screens.services.get(PROFILE.home)?.find((s) => s.slug === "telegram")).toMatchObject({action: "bypass", enabled: true});
      // The switch turns it off and keeps what it was set to: off is not Bypass.
      await telegram.locator(".switch__control").click();
      await expect(telegram).toContainText(S(lang, "card.statusOff"));
      expect(mock.screens.services.get(PROFILE.home)?.find((s) => s.slug === "telegram")).toMatchObject({action: "bypass", enabled: false});
    });

    test("T-162: the switch of a Redirect card writes the Redirect with its destination, also for a row set before the rule", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "services"));
      await ready(page);
      const row = (slug: string) => mock.screens.services.get(PROFILE.home)?.find((s) => s.slug === slug);
      // Spotify goes off and keeps Redirect and Frankfurt. The API refuses a Redirect that names no target, and the mock does as well.
      const spotify = card(page, "Spotify");
      await spotify.locator(".switch__control").click();
      await expect(spotify).toContainText(S(lang, "card.statusOff"));
      await expect.poll(() => row("spotify")?.enabled).toBe(false);
      expect(row("spotify")).toMatchObject({action: "redirect", target: {kind: "location", location_id: LOCATIONS[1]!.id}});
      await spotify.locator(".switch__control").click();
      await expect.poll(() => row("spotify")?.enabled).toBe(true);
      await expect(spotify.locator("svg.flag")).toBeVisible();
      // Aparat (never proxied, set before the rule) and Steam (its location left the set) keep their state and their flags.
      for (const [slug, name] of [["aparat", APARAT[lang]], ["steam", "Steam"]] as const) {
        const one = card(page, name);
        await one.locator(".switch__control").click();
        await expect(one).toContainText(S(lang, "card.statusOff"));
        await expect.poll(() => row(slug)?.enabled).toBe(false);
        expect(row(slug)).toMatchObject({action: "redirect", iranian_bypass: slug === "aparat", location_unavailable: slug === "steam"});
        expect(row(slug)?.target).toBeDefined();
      }
      await expect(page.getByText(S(lang, "card.failed", {name: "Spotify"}), {exact: false})).toHaveCount(0);
    });

    test("T-175: the country that holds the chosen city can be closed and opened again", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=destination:spotify`);
      const dialog = page.getByRole("dialog", {name: S(lang, "destinations.title", {subject: "Spotify"})});
      const germany = lang === "fa" ? "آلمان" : "Germany";
      await expect(dialog.getByRole("radio", {name: "Frankfurt"})).toBeVisible();
      await dialog.getByRole("button", {name: S(lang, "destinations.hideCities", {country: germany})}).click();
      await expect(dialog.getByRole("radio", {name: "Frankfurt"})).toHaveCount(0);
      await dialog.getByRole("button", {name: S(lang, "destinations.showCities", {country: germany})}).click();
      await expect(dialog.getByRole("radio", {name: "Frankfurt"})).toBeVisible();
    });

    test("T-162: Remove takes the service out of the profile", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "services"));
      await ready(page);
      await card(page, "Steam").getByRole("button", {name: S(lang, "card.remove", {name: "Steam"})}).click();
      await expect(card(page, "Steam")).toHaveCount(0);
      expect(mock.screens.services.get(PROFILE.home)?.some((s) => s.slug === "steam")).toBe(false);
    });

    test("T-162: a Redirect shows the flag of its destination, and its button opens Destinations with the row's own choice", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "services"));
      await ready(page);
      const spotify = card(page, "Spotify");
      await expect(spotify.locator("svg.flag")).toBeVisible();
      await spotify.getByRole("button", {name: new RegExp(text(lang, "rules", "three.openDestination", {subject: "Spotify"}))}).click();
      await expect(page).toHaveURL(/serviceDialog=destination%3Aspotify|serviceDialog=destination:spotify/);
      const dialog = page.getByRole("dialog", {name: S(lang, "destinations.title", {subject: "Spotify"})});
      await expect(dialog).toBeVisible();
      // The row's own destination (Frankfurt) is the chosen one, and its country is open so that it is seen.
      await expect(dialog.getByRole("radio", {name: "Frankfurt"})).toBeChecked();
      await dialog.getByRole("radio", {name: lang === "fa" ? "هلند" : "Netherlands"}).click({force: true});
      await dialog.getByRole("button", {name: S(lang, "destinations.save")}).click();
      await expect(dialog).toBeHidden();
      await expect(page).not.toHaveURL(/serviceDialog/);
      expect(mock.screens.services.get(PROFILE.home)?.find((s) => s.slug === "spotify")).toMatchObject({action: "redirect", target: {kind: "location", location_id: uid("lo", 4)}});
    });

    test("T-162: choosing Redirect on a card asks for the destination first, and writes the Redirect only when it is saved", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "services"));
      await ready(page);
      await press(card(page, "Telegram"), lang, "redirect", "Telegram").click();
      const dialog = page.getByRole("dialog", {name: S(lang, "destinations.title", {subject: "Telegram"})});
      await expect(dialog).toBeVisible();
      expect(mock.screens.services.get(PROFILE.home)?.find((s) => s.slug === "telegram")?.action).toBe("block");
      await dialog.getByRole("radio", {name: S(lang, "destinations.auto")}).click({force: true});
      await dialog.getByRole("button", {name: S(lang, "destinations.save")}).click();
      await expect(dialog).toBeHidden();
      await expect(card(page, "Telegram")).toContainText(action(lang, "redirect"));
      expect(mock.screens.services.get(PROFILE.home)?.find((s) => s.slug === "telegram")).toMatchObject({action: "redirect", target: {kind: "auto"}});
    });

    test("T-162: Cancel in Destinations writes nothing, and a direct address of a service that is not in the profile opens nothing", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=destination:telegram`);
      const dialog = page.getByRole("dialog", {name: S(lang, "destinations.title", {subject: "Telegram"})});
      await expect(dialog).toBeVisible();
      await page.keyboard.press("Escape");
      await expect(dialog).toBeHidden();
      expect(mock.screens.services.get(PROFILE.home)?.find((s) => s.slug === "telegram")?.action).toBe("block");
      await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=destination:not-in-the-profile`);
      await ready(page);
      await expect(page.getByRole("dialog")).toHaveCount(0);
      await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=nonsense`);
      await ready(page);
      await expect(page.getByRole("dialog")).toHaveCount(0);
    });

    test("T-175: Proxies has a search, Auto and Random, the countries with a flag, and cities that open under their country", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=destination:telegram`);
      const dialog = page.getByRole("dialog", {name: S(lang, "destinations.title", {subject: "Telegram"})});
      // The two tabs are a segmented control, a group of two radio buttons.
      await expect(dialog.getByRole("radio", {name: S(lang, "destinations.proxies")})).toBeChecked();
      await expect(dialog.getByRole("radio", {name: S(lang, "destinations.auto")})).toBeVisible();
      await expect(dialog.getByRole("radio", {name: S(lang, "destinations.random")})).toBeVisible();
      const germany = lang === "fa" ? "آلمان" : "Germany";
      await expect(dialog.getByRole("radio", {name: germany})).toBeVisible();
      await expect(dialog.locator("svg.flag").first()).toBeVisible();
      // A location with only a label is listed by its label, and cities are hidden until their country opens.
      await expect(dialog.getByRole("radio", {name: "Home lab"})).toBeVisible();
      await expect(dialog.getByRole("radio", {name: "Frankfurt"})).toHaveCount(0);
      await dialog.getByRole("button", {name: S(lang, "destinations.showCities", {country: germany})}).click();
      await expect(dialog.getByRole("radio", {name: "Frankfurt"})).toBeVisible();
      await expect(dialog.getByRole("radio", {name: "Berlin"})).toBeVisible();
      // The search finds a city and opens its country; Auto and Random step aside while one is typed.
      await dialog.getByRole("searchbox", {name: S(lang, "destinations.searchLabel")}).fill("paris");
      await expect(dialog.getByRole("radio", {name: "Paris"})).toBeVisible();
      await expect(dialog.getByRole("radio", {name: S(lang, "destinations.auto")})).toHaveCount(0);
      await dialog.getByRole("searchbox", {name: S(lang, "destinations.searchLabel")}).fill("zzzz");
      await expect(dialog.getByText(S(lang, "destinations.noMatch"))).toBeVisible();
    });

    test("T-175: a deployment with no location says so in the dialog and offers no Save", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {noLocations: true});
      await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=destination:telegram`);
      const dialog = page.getByRole("dialog", {name: S(lang, "destinations.title", {subject: "Telegram"})});
      await expect(dialog.getByText(S(lang, "destinations.none"))).toBeVisible();
      await expect(dialog.getByRole("button", {name: S(lang, "destinations.save")})).toBeDisabled();
      // With no destination a card cannot choose Redirect either (T-166), and says why.
      await page.goto(profilePath(lang, PROFILE.home, "services"));
      await expect(card(page, "Telegram")).toContainText(text(lang, "rules", "three.noShared"));
      await expect(press(card(page, "Telegram"), lang, "redirect", "Telegram")).toBeDisabled();
    });

    test("T-177: IP or Hostname takes an A record (IPv4, IPv6) or a CNAME, checks each, and writes the target", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=destination:telegram`);
      const dialog = page.getByRole("dialog", {name: S(lang, "destinations.title", {subject: "Telegram"})});
      await dialog.getByRole("radio", {name: S(lang, "destinations.ip")}).click({force: true});
      const save = dialog.getByRole("button", {name: S(lang, "destinations.save")});
      await expect(save).toBeDisabled();
      const v4 = dialog.getByRole("textbox", {name: S(lang, "destinations.ipv4")});
      await v4.fill("999.1.1.1");
      await expect(dialog.getByText(S(lang, "destinations.invalidV4"))).toBeVisible();
      await expect(save).toBeDisabled();
      await v4.fill("203.0.113.7");
      await dialog.getByRole("textbox", {name: S(lang, "destinations.ipv6")}).fill("2001:db8::1");
      await expect(save).toBeEnabled();
      // CNAME is another record: a host name, checked as one.
      await dialog.getByRole("radio", {name: S(lang, "destinations.recordCname"), exact: true}).click({force: true});
      const host = dialog.getByRole("textbox", {name: S(lang, "destinations.host")});
      await host.fill("not a host");
      await expect(dialog.getByText(S(lang, "destinations.invalidHost"))).toBeVisible();
      await expect(save).toBeDisabled();
      await host.fill("relay.example.net");
      await save.click();
      await expect(dialog).toBeHidden();
      expect(mock.screens.services.get(PROFILE.home)?.find((s) => s.slug === "telegram")).toMatchObject({action: "redirect", target: {kind: "host", host: "relay.example.net"}});
      await expect(card(page, "Telegram")).toContainText(action(lang, "redirect"));
    });

    test("T-163: services are grouped under their category with a count, and Remove all asks first", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "services"));
      await ready(page);
      await expect(grid(page, lang, C.video).getByRole("listitem")).toHaveCount(2);
      await expect(grid(page, lang, C.social).getByRole("listitem")).toHaveCount(2);
      const removeAll = page.getByRole("button", {name: S(lang, "category.removeAllAria", {category: C.video})});
      await removeAll.click();
      const confirm = page.getByRole("alertdialog");
      await expect(confirm).toContainText(S(lang, "category.confirmTitle", {category: C.video}));
      await confirm.getByRole("button", {name: COMMON[lang].cancel}).click();
      await expect(confirm).toBeHidden();
      await expect(grid(page, lang, C.video).getByRole("listitem")).toHaveCount(2);
      await removeAll.click();
      await page.getByRole("alertdialog").getByRole("button", {name: S(lang, "category.confirm")}).click();
      await expect(grid(page, lang, C.video)).toHaveCount(0);
      expect(mock.screens.services.get(PROFILE.home)?.map((s) => s.slug).sort()).toEqual(["instagram", "spotify", "steam", "telegram"]);
      await expect(grid(page, lang, C.social).getByRole("listitem")).toHaveCount(2);
    });

    test("T-164: Choose Service lists the categories with counts, without the services the profile already has", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "services"));
      await ready(page);
      await addButton(page, lang).click();
      await expect(page).toHaveURL(/serviceDialog=choose/);
      const dialog = chooseDialog(page, lang);
      await expect(dialog).toBeVisible();
      // Social has only Telegram and Instagram, and the profile has both: the category is not offered. Video had 321 and the profile has two of them,
      // one of those deprecated: 319 are left.
      await expect(dialog.locator('[data-category="social"]')).toHaveCount(0);
      await expect(dialog.locator('[data-category="video"]')).toContainText(COUNT(319));
      await expect(dialog.locator('[data-category="news"]')).toContainText(COUNT(1));
      await dialog.getByRole("button", {name: toggleName(lang, C.video)}).click();
      await expect(dialog.getByRole("button", {name: toggleName(lang, C.video)})).toHaveAttribute("aria-expanded", "true");
      await expect(dialog.getByRole("option", {name: "Video 4", exact: true})).toHaveCount(0);
      await page.keyboard.press("Escape");
      await expect(dialog).toBeHidden();
      await expect(page).not.toHaveURL(/serviceDialog/);
    });

    test("T-164, FE 8.10: Video with 320 services keeps a few rows in the page and scrolls to the last one", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=choose`);
      const dialog = chooseDialog(page, lang);
      await dialog.getByRole("button", {name: toggleName(lang, C.video)}).click();
      const list = dialog.getByRole("listbox", {name: S(lang, "choose.list", {category: C.video})});
      await expect(list.getByRole("option").first()).toBeVisible();
      const inPage = await list.getByRole("option").count();
      expect(inPage, "options in the page").toBeLessThan(30);
      expect(inPage).toBeGreaterThan(0);
      await list.evaluate((el) => el.scrollTo(0, el.scrollHeight));
      await expect(list.getByRole("option", {name: "Video 99", exact: true})).toBeVisible();
      expect(await list.getByRole("option").count()).toBeLessThan(30);
    });

    test("T-164: selected services are added with the chosen action, and the dialog closes with them in the page", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=choose`);
      const dialog = chooseDialog(page, lang);
      await dialog.getByRole("button", {name: toggleName(lang, C.video)}).click();
      const list = dialog.getByRole("listbox", {name: S(lang, "choose.list", {category: C.video})});
      await list.getByRole("option", {name: "Video 1", exact: true}).click();
      await list.getByRole("option", {name: "Video 10", exact: true}).click();
      await expect(dialog.getByRole("status").filter({hasText: COUNT(2)})).toBeVisible();
      await press(dialog, lang, "bypass", S(lang, "choose.actionSubject")).click();
      await dialog.getByRole("button", {name: addName(lang, 2)}).click();
      await expect(dialog).toBeHidden();
      await expect(card(page, "Video 1")).toContainText(action(lang, "bypass"));
      expect(mock.screens.services.get(PROFILE.home)?.filter((s) => ["video-001", "video-010"].includes(s.slug)).map((s) => s.action)).toEqual(["bypass", "bypass"]);
    });

    test("T-164: a whole category is selected with its check box, and a search opens the category it matched", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=choose`);
      const dialog = chooseDialog(page, lang);
      await dialog.getByRole("searchbox", {name: S(lang, "choose.searchLabel")}).fill("tv");
      await expect(dialog.getByRole("button", {name: toggleName(lang, C.video)})).toHaveCount(0);
      await expect(dialog.getByText(S(lang, "choose.noMatch"))).toBeVisible();
      await dialog.getByRole("searchbox", {name: S(lang, "choose.searchLabel")}).fill("");
      await dialog.getByRole("checkbox", {name: S(lang, "choose.selectCategory", {category: C.shop})}).check({force: true});
      await expect(dialog.getByRole("status").filter({hasText: COUNT(1)})).toBeVisible();
      await dialog.getByRole("button", {name: addName(lang, 1)}).click();
      await expect(dialog).toBeHidden();
      expect(mock.screens.services.get(PROFILE.home)?.some((s) => s.slug === "digikala")).toBe(true);
    });

    test("T-164: while a search runs a category can be hidden, and its check box takes the services that were found, as its name says", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=choose`);
      const dialog = chooseDialog(page, lang);
      await dialog.getByRole("searchbox", {name: S(lang, "choose.searchLabel")}).fill("Video 16");
      const list = dialog.getByRole("listbox", {name: S(lang, "choose.list", {category: C.video})});
      await expect(list).toBeVisible();
      await dialog.getByRole("button", {name: toggleName(lang, C.video)}).click();
      await expect(list).toHaveCount(0);
      await dialog.getByRole("button", {name: toggleName(lang, C.video)}).click();
      await expect(list).toBeVisible();
      // Video 16 and Video 160 to 169 are what the search found; the name of the check box says so, and it takes just those.
      await expect(dialog.getByRole("checkbox", {name: S(lang, "choose.selectCategory", {category: C.video})})).toHaveCount(0);
      await dialog.getByRole("checkbox", {name: S(lang, "choose.selectMatching", {category: C.video})}).check({force: true});
      await expect(dialog.getByRole("status").filter({hasText: COUNT(11)})).toBeVisible();
      await dialog.getByRole("button", {name: addName(lang, 11)}).click();
      await expect(dialog).toBeHidden();
      const slugs = mock.screens.services.get(PROFILE.home)?.map((s) => s.slug) ?? [];
      expect(slugs).toContain("video-016");
      expect(slugs).toContain("video-169");
      expect(slugs).not.toContain("video-001");
    });

    test("T-165: a service with the risk flag asks Enable Anyway before it is added, and Back writes nothing", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=choose`);
      const dialog = chooseDialog(page, lang);
      await dialog.getByRole("checkbox", {name: S(lang, "choose.selectCategory", {category: C.news})}).check({force: true});
      await dialog.getByRole("button", {name: addName(lang, 1)}).click();
      const risk = page.getByRole("dialog", {name: S(lang, "risk.title")});
      await expect(risk).toBeVisible();
      await expect(risk).toContainText("BBC");
      await risk.getByRole("button", {name: S(lang, "risk.back")}).click();
      await expect(chooseDialog(page, lang)).toBeVisible();
      expect(mock.screens.services.get(PROFILE.home)?.some((s) => s.slug === "bbc")).toBe(false);
      await chooseDialog(page, lang).getByRole("button", {name: addName(lang, 1)}).click();
      await page.getByRole("dialog", {name: S(lang, "risk.title")}).getByRole("button", {name: S(lang, "risk.enableAnyway")}).click();
      await expect(page.getByRole("dialog")).toHaveCount(0);
      expect(mock.screens.services.get(PROFILE.home)?.find((s) => s.slug === "bbc")).toMatchObject({action: "block", enabled: true});
    });

    test("T-166: a selection with no shared destination disables Redirect and says why", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {
        handlers: {
          "GET /profiles/{id}/locations": (call) =>
            (call.query.get("services") ?? "").includes("video-016") ? {body: {locations: [], auto_random: false}} : {body: {locations: LOCATIONS, auto_random: true}},
        },
      });
      await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=choose`);
      const dialog = chooseDialog(page, lang);
      const redirect = press(dialog, lang, "redirect", S(lang, "choose.actionSubject"));
      await expect(redirect).toBeEnabled();
      await dialog.getByRole("searchbox", {name: S(lang, "choose.searchLabel")}).fill("Video 16");
      await dialog.getByRole("option", {name: VIDEO_16}).click();
      await expect(redirect).toBeDisabled();
      // The sentence is the one of the selection, not the generic one of a card (T-166).
      await expect(dialog).toContainText(S(lang, "choose.noShared"));
      // A selection of the same service with one that has a shared destination is still empty: the intersection is what counts.
      await dialog.getByRole("option", {name: VIDEO_16}).click();
      await expect(redirect).toBeEnabled();
    });

    test("T-166: a selection of more than 100 services is answered in several calls and offers what all of them share", async ({page, context, baseURL}) => {
      // Video has 319 services to add: four calls. The first two each say "Auto and Random" and hold two locations, but only one is the same.
      const mock = await openProfiles(context, baseURL, {
        handlers: {
          "GET /profiles/{id}/locations": (call) => {
            const services = call.query.get("services") ?? "";
            if (services.includes("video-016")) return {body: {locations: [LOCATIONS[0], LOCATIONS[3]], auto_random: true}};
            if (services.includes("video-150")) return {body: {locations: [LOCATIONS[0], LOCATIONS[5]], auto_random: true}};
            return {body: {locations: LOCATIONS, auto_random: true}};
          },
        },
      });
      // The one never-proxied service of Video would take Redirect away from the selection (T-521), and this case is about the sets.
      mock.screens.catalogServices.find((x) => x.slug === "video-008")!.redirect_allowed = true;
      await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=choose`);
      const dialog = chooseDialog(page, lang);
      await dialog.getByRole("checkbox", {name: S(lang, "choose.selectCategory", {category: C.video})}).check({force: true});
      await press(dialog, lang, "redirect", S(lang, "choose.actionSubject")).click();
      const step = stepDialog(page, lang);
      await expect(step.getByRole("radio", {name: lang === "fa" ? "آلمان" : "Germany"})).toBeVisible();
      await expect(step.getByRole("radio", {name: lang === "fa" ? "هلند" : "Netherlands"})).toHaveCount(0);
      await expect(step.getByRole("radio", {name: lang === "fa" ? "ایالات متحده" : "United States"})).toHaveCount(0);
      // One location in common is a place, and no Auto or Random: those need two.
      await expect(step.getByRole("radio", {name: S(lang, "destinations.auto")})).toHaveCount(0);
      await expect(step.getByRole("radio", {name: S(lang, "destinations.random")})).toHaveCount(0);
    });

    test("T-166: Redirect before any service is chosen opens the profile's own destinations, not an empty set", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=choose`);
      const dialog = chooseDialog(page, lang);
      await press(dialog, lang, "redirect", S(lang, "choose.actionSubject")).click();
      const step = stepDialog(page, lang);
      await expect(step.getByRole("radio", {name: S(lang, "destinations.auto")})).toBeVisible();
      await expect(step.getByRole("radio", {name: lang === "fa" ? "هلند" : "Netherlands"})).toBeVisible();
      await expect(step.getByText(S(lang, "destinations.none"))).toHaveCount(0);
    });

    test("T-521: a Redirect chosen first goes back to Block when a service that is never proxied joins the selection", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=choose`);
      const dialog = chooseDialog(page, lang);
      const subject = S(lang, "choose.actionSubject");
      await dialog.getByRole("button", {name: toggleName(lang, C.video)}).click();
      await dialog.getByRole("listbox", {name: S(lang, "choose.list", {category: C.video})}).getByRole("option", {name: "Video 1", exact: true}).click();
      await press(dialog, lang, "redirect", subject).click();
      await stepDialog(page, lang).getByRole("radio", {name: S(lang, "destinations.auto")}).click({force: true});
      await stepDialog(page, lang).getByRole("button", {name: S(lang, "choose.useDestination")}).click();
      await expect(press(dialog, lang, "redirect", subject)).toBeChecked();
      await dialog.getByRole("checkbox", {name: S(lang, "choose.selectCategory", {category: C.shop})}).check({force: true});
      await expect(dialog.getByLabel(three(lang, "redirect", subject), {exact: false})).toHaveCount(0);
      await expect(press(dialog, lang, "block", subject)).toBeChecked();
      await dialog.getByRole("button", {name: addName(lang, 2)}).click();
      await expect(dialog).toBeHidden();
      const rows = mock.screens.services.get(PROFILE.home) ?? [];
      expect(rows.find((r) => r.slug === "digikala")).toMatchObject({action: "block", enabled: true});
      expect(rows.find((r) => r.slug === "video-001")).toMatchObject({action: "block", enabled: true});
    });

    test("T-166: a destination that a later service cannot reach is taken back, with a line that says so", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {
        handlers: {
          "GET /profiles/{id}/locations": (call) =>
            (call.query.get("services") ?? "").includes("video-016") ? {body: {locations: [LOCATIONS[0]], auto_random: false}} : {body: {locations: LOCATIONS, auto_random: true}},
        },
      });
      await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=choose`);
      const dialog = chooseDialog(page, lang);
      const subject = S(lang, "choose.actionSubject");
      await press(dialog, lang, "redirect", subject).click();
      await stepDialog(page, lang).getByRole("radio", {name: lang === "fa" ? "هلند" : "Netherlands"}).click({force: true});
      await stepDialog(page, lang).getByRole("button", {name: S(lang, "choose.useDestination")}).click();
      await expect(press(dialog, lang, "redirect", subject)).toBeChecked();
      // The service that can reach Germany only is added to the selection: Netherlands is no longer shared.
      await dialog.getByRole("searchbox", {name: S(lang, "choose.searchLabel")}).fill("Video 16");
      await dialog.getByRole("option", {name: VIDEO_16}).click();
      await expect(press(dialog, lang, "block", subject)).toBeChecked();
      await expect(dialog.getByText(S(lang, "choose.destinationDropped"))).toBeVisible();
      await dialog.getByRole("button", {name: addName(lang, 1)}).click();
      await expect(dialog).toBeHidden();
      expect(mock.screens.services.get(PROFILE.home)?.find((r) => r.slug === "video-016")).toMatchObject({action: "block", enabled: true});
    });

    test("T-521: a selection with a service that is never proxied has no Redirect, with its reason", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=choose`);
      const dialog = chooseDialog(page, lang);
      await dialog.getByRole("checkbox", {name: S(lang, "choose.selectCategory", {category: C.shop})}).check({force: true});
      await expect(press(dialog, lang, "block", S(lang, "choose.actionSubject"))).toBeVisible();
      await expect(dialog.getByLabel(three(lang, "redirect", S(lang, "choose.actionSubject")), {exact: false})).toHaveCount(0);
      await expect(dialog).toContainText(S(lang, "choose.neverProxied", {name: DIGIKALA[lang]}));
      expect(mock.screens.services.get(PROFILE.home)?.some((s) => s.slug === "digikala")).toBe(false);
    });

    test("T-521: a card of a service that is never proxied has Block and Bypass only, and a Redirect that acts as Bypass says so", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      mock.screens.services.get(PROFILE.home)!.push({slug: "digikala", enabled: true, action: "block", location_unavailable: false, iranian_bypass: false});
      await page.goto(profilePath(lang, PROFILE.home, "services"));
      await ready(page);
      const digikala = card(page, DIGIKALA[lang]);
      await expect(press(digikala, lang, "block", DIGIKALA[lang])).toBeVisible();
      await expect(press(digikala, lang, "bypass", DIGIKALA[lang])).toBeVisible();
      await expect(digikala.getByLabel(three(lang, "redirect", DIGIKALA[lang]), {exact: false})).toHaveCount(0);
      await expect(digikala).toContainText(text(lang, "rules", "three.neverProxied", {subject: DIGIKALA[lang]}));
      // Aparat is a Redirect that was set before the rule: it keeps the button and states that it acts as Bypass.
      const aparat = card(page, APARAT[lang]);
      await expect(aparat).toContainText(text(lang, "rules", "three.iranianBypass", {}));
      await expect(aparat.getByLabel(text(lang, "rules", "three.actsAs", {action: action(lang, "bypass")}), {exact: false}).first()).toBeVisible();
    });

    test.describe("a batch the API refuses", () => {
      test.use({allowConsole: [/status of 422/]});

      test("T-521: the dialog stays open with the error and nothing is added", async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL, {
          handlers: {"POST /profiles/{id}/services:batch": {status: 422, body: errorBody("validation_failed", {fields: [{name: "/slugs/0", code: "iranian_name"}]})}},
        });
        await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=choose`);
        const dialog = chooseDialog(page, lang);
        await dialog.getByRole("checkbox", {name: S(lang, "choose.selectCategory", {category: C.shop})}).check({force: true});
        await dialog.getByRole("button", {name: addName(lang, 1)}).click();
        // The sentence of the rule and the name of the service it is about, not the generic "one of the values is not valid".
        await expect(dialog.getByRole("alert")).toContainText(`${DIGIKALA[lang]}: ${ERRORS[lang].fields.iranian_name}`);
        await expect(dialog).toBeVisible();
        expect(mock.screens.services.get(PROFILE.home)?.some((s) => s.slug === "digikala")).toBe(false);
      });
    });

    test("a deprecated service stays on its card with a note, and is not offered in Choose Service", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "services"));
      await ready(page);
      const video4 = card(page, "Video 4");
      await expect(video4).toContainText(S(lang, "card.deprecated"));
      await expect(video4).toContainText(S(lang, "card.deprecatedNote"));
      await expect(video4.getByRole("button", {name: S(lang, "card.remove", {name: "Video 4"})})).toBeVisible();
    });

    test("the page's search keeps the cards whose name matches, and says so when none does", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "services"));
      await ready(page);
      await page.getByRole("searchbox", {name: S(lang, "page.searchLabel")}).fill("tele");
      await expect(screen(page, "profile-services").getByRole("listitem")).toHaveCount(1);
      await page.getByRole("searchbox", {name: S(lang, "page.searchLabel")}).fill("zzz");
      await expect(page.getByText(S(lang, "page.noMatch"))).toBeVisible();
    });

    test("a profile with no service shows the empty state with Add, and a locked one has Add disabled", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.gaming, "services"));
      await expect(page.getByText(S(lang, "page.emptyTitle"))).toBeVisible();
      await expect(addButton(page, lang, "Gaming").first()).toBeEnabled();
      await page.goto(profilePath(lang, PROFILE.office, "services"));
      await expect(page.getByText(S(lang, "page.emptyTitle"))).toBeVisible();
      await expect(addButton(page, lang, "Office")).toBeDisabled();
    });

    test("a locked profile has every control of its cards disabled", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      mock.screens.services.set(PROFILE.office, [{slug: "telegram", enabled: true, action: "block", location_unavailable: false, iranian_bypass: false}]);
      await page.goto(profilePath(lang, PROFILE.office, "services"));
      const telegram = card(page, "Telegram");
      await expect(telegram.getByRole("switch")).toBeDisabled();
      await expect(telegram.getByRole("button", {name: S(lang, "card.remove", {name: "Telegram"})})).toBeDisabled();
      await expect(press(telegram, lang, "bypass", "Telegram")).toBeDisabled();
    });

    test("S3-r2-1: a category draws a step of cards and the rest on request, and focus lands on the first new card", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      // Video 20 to 139 join the six services of the profile: 120 more in Video, none of them deprecated, never proxied or limited.
      const rows = mock.screens.services.get(PROFILE.home)!;
      for (let i = 20; i < 140; i++) {
        rows.push({slug: `video-${String(i).padStart(3, "0")}`, enabled: true, action: "block", location_unavailable: false, iranian_bypass: false});
      }
      await page.goto(profilePath(lang, PROFILE.home, "services"));
      await ready(page);
      const videoCards = grid(page, lang, C.video).getByRole("listitem");
      await expect(videoCards).toHaveCount(48);
      const more = page.getByRole("button", {name: S(lang, "category.showMoreAria", {category: C.video, count: num(lang, 48)})});
      await more.click();
      await expect(videoCards).toHaveCount(96);
      await expect(videoCards.nth(48).locator("input, button").first()).toBeFocused();
      // The last step is what is left (122 in all: the 120 and Video 4 and Aparat), and the button goes.
      const last = page.getByRole("button", {name: S(lang, "category.showMoreAria", {category: C.video, count: num(lang, 26)})});
      await last.click();
      await expect(videoCards).toHaveCount(122);
      await expect(last).toHaveCount(0);
      // Remove all acts on the whole category, not on the cards that were drawn.
      await page.getByRole("button", {name: S(lang, "category.removeAllAria", {category: C.video})}).click();
      await expect(page.getByRole("alertdialog")).toContainText(COUNT(122));
    });

    test("S3-r2-1: a search finds a service the category has not drawn yet", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      const rows = mock.screens.services.get(PROFILE.home)!;
      for (let i = 20; i < 140; i++) {
        rows.push({slug: `video-${String(i).padStart(3, "0")}`, enabled: true, action: "block", location_unavailable: false, iranian_bypass: false});
      }
      await page.goto(profilePath(lang, PROFILE.home, "services"));
      await ready(page);
      await screen(page, "profile-services").getByRole("searchbox", {name: S(lang, "page.searchLabel")}).fill("Video 139");
      await expect(card(page, "Video 139")).toBeVisible();
    });

    test("S3-r2-3: a limited service whose own set is empty has no Redirect on its card, and the others keep theirs", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {
        handlers: {
          "GET /profiles/{id}/locations": (call) =>
            (call.query.get("services") ?? "") === "video-016" ? {body: {locations: [], auto_random: false}} : {body: {locations: LOCATIONS, auto_random: true}},
        },
      });
      mock.screens.services.get(PROFILE.home)!.push({slug: "video-016", enabled: true, action: "block", location_unavailable: false, iranian_bypass: false});
      await page.goto(profilePath(lang, PROFILE.home, "services"));
      await ready(page);
      const limited = card(page, "Video 16");
      await expect(press(limited, lang, "redirect", "Video 16")).toBeDisabled();
      await expect(limited).toContainText(text(lang, "rules", "three.noShared"));
      await expect(press(card(page, "Telegram"), lang, "redirect", "Telegram")).toBeEnabled();
    });

    test("S3-r3-1: the page draws one budget of cards over all its categories, and a category past it shows its header and draws on request", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      // 36 more services in each of five categories: 190 cards in all, which the first paint must not draw.
      const rows = mock.screens.services.get(PROFILE.home)!;
      for (const category of ["social", "audio", "gaming", "shop", "news"]) {
        for (let i = 0; i < 36; i++) {
          const slug = `${category}-${String(i).padStart(2, "0")}`;
          mock.screens.catalogServices.push(serviceFixture(slug, category, `${category} ${i}`));
          rows.push({slug, enabled: true, action: "block", location_unavailable: false, iranian_bypass: false});
        }
      }
      await page.goto(profilePath(lang, PROFILE.home, "services"));
      await ready(page);
      const cards = page.locator('[data-screen="profile-services"] section[data-category] [role="listitem"]');
      await expect(cards.first()).toBeVisible();
      expect(await cards.count()).toBeLessThanOrEqual(48);
      // Shop is past the budget: its header and count are on the page, its cards are not, and its button draws them.
      const shop = page.locator('section[data-category="shop"]');
      await expect(shop.getByRole("heading", {level: 3})).toBeVisible();
      await expect(shop.getByRole("listitem")).toHaveCount(0);
      await shop.getByRole("button", {name: S(lang, "category.showMoreAria", {category: C.shop, count: num(lang, 36)})}).click();
      await expect(shop.getByRole("listitem")).toHaveCount(36);
      await expect(shop.getByRole("listitem").first().locator("input, button").first()).toBeFocused();
    });

    test("S3-r3-2: a limited service asks for its own set when its card comes near the screen, not all at once", async ({page, context, baseURL}) => {
      const asked: string[] = [];
      const mock = await openProfiles(context, baseURL, {
        handlers: {
          "GET /profiles/{id}/locations": (call) => {
            const services = call.query.get("services") ?? "";
            if (services !== "") asked.push(services);
            return {body: {locations: LOCATIONS, auto_random: true}};
          },
        },
      });
      const rows = mock.screens.services.get(PROFILE.home)!;
      for (let i = 20; i < 140; i++) {
        const slug = `video-${String(i).padStart(3, "0")}`;
        mock.screens.catalogServices.find((s) => s.slug === slug)!.region_limited = true;
        rows.push({slug, enabled: true, action: "block", location_unavailable: false, iranian_bypass: false});
      }
      await page.goto(profilePath(lang, PROFILE.home, "services"));
      await ready(page);
      const cards = page.locator('section[data-category="video"] [role="listitem"]');
      await expect(cards).toHaveCount(48);
      // Nearly all of the 48 cards are below the fold, so only a few of them have asked.
      const first = asked.length;
      expect(first).toBeGreaterThan(0);
      expect(first).toBeLessThan(30);
      await cards.last().scrollIntoViewIfNeeded();
      await expect.poll(() => asked.length).toBeGreaterThan(first);
    });

    test.describe("locations that could not be read", () => {
      test.use({allowConsole: [/status of 500/]});

      test("S3-r2-2: Choose Service says so and offers a retry, keeps Redirect, and does not claim there is no shared destination", async ({page, context, baseURL}) => {
        let failing = true;
        await openProfiles(context, baseURL, {
          handlers: {
            "GET /profiles/{id}/locations": (call) =>
              failing && (call.query.get("services") ?? "") !== "" ? {status: 500, body: errorBody("internal")} : {body: {locations: LOCATIONS, auto_random: true}},
          },
        });
        await page.goto(`${profilePath(lang, PROFILE.home, "services")}?serviceDialog=choose`);
        const dialog = chooseDialog(page, lang);
        await dialog.getByRole("searchbox", {name: S(lang, "choose.searchLabel")}).fill("Video 16");
        await dialog.getByRole("option", {name: VIDEO_16}).click();
        await expect(dialog).toContainText(S(lang, "choose.locationsFailed"));
        await expect(dialog).not.toContainText(S(lang, "choose.noShared"));
        const redirect = press(dialog, lang, "redirect", S(lang, "choose.actionSubject"));
        await expect(redirect).toBeEnabled();
        // The retry asks again, and the note goes when the answer is in.
        failing = false;
        await dialog.getByRole("button", {name: S(lang, "choose.retryLocations")}).click();
        await expect(dialog).not.toContainText(S(lang, "choose.locationsFailed"));
        await expect(redirect).toBeEnabled();
        await expect(dialog.getByRole("button", {name: addName(lang, 1)})).toBeEnabled();
      });
    });

    test.describe("a refused write", () => {
      test.use({allowConsole: [/status of 423/]});

      test("puts the card back and says why", async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL, {
          handlers: {"PUT /profiles/{id}/services/{slug}": {status: 423, body: errorBody("profile_locked")}},
        });
        await page.goto(profilePath(lang, PROFILE.home, "services"));
        await ready(page);
        const telegram = card(page, "Telegram");
        await press(telegram, lang, "bypass", "Telegram").click();
        await expect(page.getByText(ERRORS[lang].profile_locked).first()).toBeVisible();
        await expect(telegram).toContainText(action(lang, "block"));
        expect(mock.screens.services.get(PROFILE.home)?.find((s) => s.slug === "telegram")?.action).toBe("block");
      });
    });
  });
}
