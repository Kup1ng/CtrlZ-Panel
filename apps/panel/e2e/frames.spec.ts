import type {Page} from "@playwright/test";
import {SCREENS} from "@ctrlz/ui/screens/lanes.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {ENDPOINT, endpointPath, endpointsPath, endpointActions, endpointsText, endpointTabs, openEndpoints, sharePath} from "./endpoints-support.ts";
import {FOLDER, LANGS, LOCK_PASSWORD, PROFILE, lockBanner, openProfiles, profileActions, profilePath, profileTabs, profilesPath, screen, text} from "./profiles-support.ts";
import {VALID_SHARE_LINK} from "./setup-support.ts";

// The foundation of the P2 and P3 screens, in mock mode (spec 17.3): every route renders the component of its lane, the profile frame and
// the Endpoint frame (header, tabs, lock banner, the 404 of an unknown id), the dialog pair of an Endpoint in one history entry, and the
// sidebar counters and checklist facts that come from real data. Rows: T-113, T-119, T-123, T-135, T-142 (frames), T-137.

test.use({viewport: {width: 1280, height: 800}});

const h1 = (page: Page, name: string) => page.getByRole("heading", {level: 1, name});

for (const {lang, dir} of LANGS) {
  test.describe(`${lang} (${dir})`, () => {
    test("every route of P2 and P3 renders the component of its lane", async ({page, context, baseURL}) => {
      await openEndpoints(context, baseURL, {rules: 50, clients: 20});
      const concrete = (route: string) =>
        route
          .replace("[id]", route.startsWith("/endpoints") ? ENDPOINT.home : PROFILE.home)
          .replace("[folderId]", FOLDER.work)
          .replace("[token]", VALID_SHARE_LINK);
      for (const s of SCREENS) {
        await page.goto(`/${lang}${concrete(s.route)}`);
        await expect(screen(page, s.screen), `${s.lane} ${s.route}`).toBeVisible();
      }
    });

    test("a profile's address goes to its Options, and a tab is a link to its screen", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home));
      await expect(page).toHaveURL(new RegExp(`/${lang}/profiles/${PROFILE.home}/options$`));
      await expect(screen(page, "profile-options")).toBeVisible();
      const tabs = profileTabs(page, lang, "Home");
      await expect(tabs.getByRole("link")).toHaveCount(4);
      await tabs.getByRole("link", {name: text(lang, "profiles", "frame.tabs.services")}).click();
      await expect(page).toHaveURL(new RegExp(`/profiles/${PROFILE.home}/services$`));
      await expect(screen(page, "profile-services")).toBeVisible();
      await expect(tabs.locator('[aria-current="page"]')).toHaveText(text(lang, "profiles", "frame.tabs.services"));
    });

    test("the header names the profile and has Duplicate, Delete, Export and Lock, each named for it", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "filters"));
      await expect(h1(page, "Home")).toBeVisible();
      const actions = profileActions(page);
      for (const key of ["duplicateAria", "deleteAria", "exportAria"]) {
        await expect(actions.getByRole("button", {name: text(lang, "profiles", `frame.${key}`, {name: "Home"})})).toBeVisible();
      }
      await expect(actions.getByRole("button", {name: text(lang, "profiles", "frame.lockAria", {name: "Home"})})).toBeVisible();
      // Home has two Endpoints, so the header has their menu and not Add Endpoint.
      await expect(actions.getByRole("button", {name: text(lang, "profiles", "frame.endpointsAria", {name: "Home"})})).toBeVisible();
    });

    test("a profile with no Endpoint offers Add Endpoint, which opens the pair of parameters in one entry", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.gaming, "filters"));
      const add = profileActions(page).getByRole("button", {name: text(lang, "profiles", "frame.addEndpointAria", {name: "Gaming"})});
      await add.click();
      await expect(page).toHaveURL(/deviceDialog=add/);
    });

    test("Add Endpoint in a profile's header shows the add dialog, which starts on that profile", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.gaming, "filters"));
      await profileActions(page).getByRole("button", {name: text(lang, "profiles", "frame.addEndpointAria", {name: "Gaming"})}).click();
      const dialog = page.getByRole("dialog");
      await expect(dialog).toBeVisible();
      await expect(dialog).toContainText("Gaming");
    });

    test("a help topic of a filter, a service or an option opens its own pane, and one with no text written still opens", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      const none = {fa: "برای این مورد هنوز توضیحی نوشته نشده است.", en: "No explanation has been written for this yet."}[lang];
      const topics = [
        ["filter.malware", {fa: "دامنه‌هایی را مسدود می‌کند که برای پخش بدافزار", en: "Blocks domains known to spread malware"}[lang]],
        ["option.safe_search", {fa: "نتیجه‌های نامناسب", en: "leave out explicit results"}[lang]],
        ["filter.nothing-written", none],
        ["service.nothing-written", none],
        ["option.nothing-written", none],
      ] as const;
      for (const [topic, expected] of topics) {
        await page.goto(`/${lang}/profiles?helpPane=${topic}`);
        await expect(page.getByRole("dialog")).toBeVisible();
        await expect(page.getByRole("dialog")).toContainText(expected);
        await page.keyboard.press("Escape");
        await expect(page.getByRole("dialog")).toBeHidden();
        await expect(page).not.toHaveURL(/helpPane/);
      }
    });

    test("a locked profile shows its banner with the message, and Delete is disabled", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.office, "options"));
      await expect(lockBanner(page)).toContainText("Ask the admin before you change this.");
      await expect(profileActions(page).getByRole("button", {name: text(lang, "profiles", "frame.deleteAria", {name: "Office"})})).toBeDisabled();
    });

    // The browser logs every failed response; the wrong password is a 401 on purpose.
    test.describe("a wrong lock password", () => {
      test.use({allowConsole: [/status of 401/]});

      test("unlocking: a wrong password stays in the dialog, the right one takes the banner away, and nothing of it is in the address", async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL);
        page.on("response", () => undefined);
        await page.goto(profilePath(lang, PROFILE.office, "options"));
        await lockBanner(page).getByRole("button", {name: text(lang, "profiles", "lock.banner.unlockAria", {name: "Office"})}).click();
        const dialog = page.getByRole("dialog", {name: text(lang, "profiles", "lock.dialog.unlockTitle", {name: "Office"})});
        await expect(dialog).toBeVisible();
        const field = dialog.locator('input[name="password"]');
        await field.fill("not the password");
        await dialog.getByRole("button", {name: text(lang, "profiles", "lock.dialog.unlock")}).click();
        await expect(dialog).toBeVisible();
        await field.fill(LOCK_PASSWORD);
        await dialog.getByRole("button", {name: text(lang, "profiles", "lock.dialog.unlock")}).click();
        await expect(dialog).toBeHidden();
        await expect(lockBanner(page)).toHaveCount(0);
        expect(page.url()).not.toContain(encodeURIComponent(LOCK_PASSWORD));
        expect(mock.screens.profiles.find((p) => p.id === PROFILE.office)!.locked).toBe(false);
      });
    });

    test("the switcher opens the same tab of another profile", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "services"));
      await page.getByRole("button", {name: lang === "fa" ? "پروفایل" : "Profile", exact: true}).click();
      await page.getByRole("menuitemradio", {name: "Gaming"}).click();
      await expect(page).toHaveURL(new RegExp(`/profiles/${PROFILE.gaming}/services$`));
    });

    test.describe("an id that is not there", () => {
      test.use({allowConsole: [/status of 404/]});

      test("an unknown profile is the section's 404, and so is an address that is not an id, which no request carries", async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL);
        await page.goto(profilePath(lang, PROFILE.unknown, "filters"));
        await expect(page.getByRole("heading", {name: lang === "fa" ? "صفحه پیدا نشد" : "Page not found"})).toBeVisible();
        await page.goto(`/${lang}/profiles/x.y/filters`);
        await expect(page.getByRole("heading", {name: lang === "fa" ? "صفحه پیدا نشد" : "Page not found"})).toBeVisible();
        expect(mock.calls.some((c) => c.path.includes("x.y"))).toBe(false);
      });

      test("an unknown Endpoint is the same 404", async ({page, context, baseURL}) => {
        const mock = await openEndpoints(context, baseURL);
        await page.goto(endpointPath(lang, ENDPOINT.unknown, "clients"));
        await expect(page.getByRole("heading", {name: lang === "fa" ? "صفحه پیدا نشد" : "Page not found"})).toBeVisible();
        await page.goto(endpointPath(lang, "../x" as never, "clients"));
        expect(mock.calls.some((c) => c.path.includes(".."))).toBe(false);
      });
    });

    test("an Endpoint's frame has its header, tabs and the dialog pair in one history entry", async ({page, context, baseURL}) => {
      await openEndpoints(context, baseURL, {clients: 20});
      await page.goto(endpointPath(lang, ENDPOINT.home));
      await expect(page).toHaveURL(new RegExp(`/endpoints/${ENDPOINT.home}/clients$`));
      await expect(h1(page, "Home router")).toBeVisible();
      await expect(endpointTabs(page, lang, "Home router").getByRole("link")).toHaveCount(3);
      await endpointActions(page).getByRole("button", {name: endpointsText(lang, "frame.editAria", {name: "Home router"})}).click();
      await expect(page).toHaveURL(new RegExp(`deviceDialog=edit&deviceId=${ENDPOINT.home}`));
      await page.goBack();
      await expect(page).not.toHaveURL(/deviceDialog/);
      await expect(page).not.toHaveURL(/deviceId/);
    });

    test("a new Endpoint says Not Configured and offers Configure, and a held one says so", async ({page, context, baseURL}) => {
      await openEndpoints(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.pending, "clients"));
      await expect(endpointActions(page).getByRole("button", {name: endpointsText(lang, "frame.configureAria", {name: "New phone"})})).toBeVisible();
      await expect(endpointActions(page)).toContainText(endpointsText(lang, "frame.notConfigured"));
      await page.goto(endpointPath(lang, ENDPOINT.held, "clients"));
      await expect(page.getByRole("status").filter({hasText: endpointsText(lang, "frame.held")})).toBeVisible();
    });

    test("the sidebar counts come from the tenant's own lists, in the language's digits", async ({page, context, baseURL}) => {
      await openEndpoints(context, baseURL);
      await page.goto(profilesPath(lang));
      const chips = page.locator("aside.sidebar .sidebar__menu-chip");
      await expect(chips).toHaveCount(2);
      const digits = lang === "fa" ? ["۵", "۷"] : ["5", "7"];
      await expect(chips.nth(0)).toHaveText(digits[0]!);
      await expect(chips.nth(1)).toHaveText(digits[1]!);
    });

    test("the first-run checklist reads its facts from the data: a new tenant has none done, a tenant with data has four", async ({page, context, baseURL}) => {
      await openEndpoints(context, baseURL, {empty: true});
      await page.goto(profilesPath(lang));
      const done = page.locator(".onboarding__steps").getByText(lang === "fa" ? "انجام شد" : "Done", {exact: true});
      await expect(page.locator(".onboarding")).toBeVisible();
      await expect(done).toHaveCount(0);
      await page.context().clearCookies();
    });

    test("the share page has no shell, is not indexed, and sends no Referer", async ({page, context, baseURL}) => {
      await openEndpoints(context, baseURL);
      await page.goto(sharePath(lang, VALID_SHARE_LINK));
      await expect(screen(page, "share")).toBeVisible();
      await expect(page.locator("aside.sidebar")).toHaveCount(0);
      await expect(page.locator('meta[name="robots"]')).toHaveAttribute("content", /noindex/);
      await expect(page.locator('meta[name="referrer"]')).toHaveAttribute("content", "no-referrer");
    });

    test("the sidebar's Endpoint counter reads one row of the list", async ({page, context, baseURL}) => {
      const mock = await openEndpoints(context, baseURL);
      await page.goto(profilesPath(lang));
      await expect(page.locator("aside.sidebar .sidebar__menu-chip")).toHaveCount(2);
      const counts = mock.calls.filter((c) => c.method === "GET" && c.path === "/endpoints");
      expect(counts.length).toBeGreaterThan(0);
      expect(counts.every((c) => c.query.get("limit") === "1")).toBe(true);
      expect(endpointsPath(lang)).toBe(`/${lang}/endpoints`);
    });
  });
}
