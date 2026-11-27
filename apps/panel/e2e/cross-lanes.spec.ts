import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {endpointRow, nf} from "./endpoint-screens-support.ts";
import {ENDPOINT, endpointsPath, endpointsText} from "./endpoints-support.ts";
import {LANGS, PROFILE, openProfiles, screen} from "./profiles-support.ts";
import {setupText} from "./setup-support.ts";

// What crosses the lanes of the screens (scr-all): the links between the profile list and the Endpoint list, the Resolvers dialog that opens
// after an Endpoint is made, and the counters that two lists keep for each other. Each lane tests its own screen; these cases walk from one
// lane's screen into another's, in mock mode.

test.use({viewport: {width: 1280, height: 900}});

for (const {lang, dir} of LANGS) {
  test.describe(`${lang} (${dir})`, () => {
    test("a profile row names its Endpoints, and an Endpoint opens on its Clients page", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(`/${lang}/profiles`);
      await expect(screen(page, "profiles-list")).toBeVisible();
      const home = page.getByRole("listitem").filter({has: page.getByRole("link", {name: "Home", exact: true})});
      await home.getByRole("button", {name: new RegExp(nf(lang, 2))}).click();
      await page.getByRole("menuitem", {name: "Home router"}).click();
      await expect(page).toHaveURL(new RegExp(`/endpoints/${ENDPOINT.home}/clients$`));
      await expect(screen(page, "endpoint-clients")).toBeVisible();
    });

    test("an Endpoint row links to its profile, and the profile opens on its Options", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(endpointsPath(lang));
      await expect(screen(page, "endpoints-list")).toBeVisible();
      await endpointRow(page, "Home router").getByRole("link", {name: "Home", exact: true}).click();
      await expect(page).toHaveURL(new RegExp(`/profiles/${PROFILE.home}/options$`));
      await expect(screen(page, "profile-options")).toBeVisible();
    });

    test("an Endpoint made from the list opens its Resolvers dialog, and Help Me Configure goes on from it", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(`${endpointsPath(lang)}?deviceDialog=add`);
      const add = page.getByRole("dialog");
      await add.getByRole("textbox", {name: endpointsText(lang, "dialogs.fields.names")}).fill("Cross lane");
      await add.getByRole("button", {name: endpointsText(lang, "dialogs.add.submit"), exact: true}).click();
      await expect.poll(() => mock.screens.endpoints.some((e) => e.name === "Cross lane")).toBe(true);
      const made = mock.screens.endpoints.find((e) => e.name === "Cross lane")!;
      await expect(page).toHaveURL(new RegExp(`deviceDialog=resolvers&deviceId=${made.id}`));
      // The dialog of the setup lane is the one drawn, with the new Endpoint's name in its title.
      const resolvers = page.getByRole("dialog");
      await expect(resolvers.getByRole("heading", {name: setupText(lang, "resolvers.dialogTitle", {name: "Cross lane"})})).toBeVisible();
      await resolvers.getByRole("button", {name: setupText(lang, "resolvers.configureAria", {name: "Cross lane"})}).click();
      await expect(page).toHaveURL(/deviceDialog=configure/);
    });

    test("a profile row follows an Endpoint that is made on it", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(`${endpointsPath(lang)}?deviceDialog=add`);
      const add = page.getByRole("dialog");
      await add.getByRole("textbox", {name: endpointsText(lang, "dialogs.fields.names")}).fill("Follows");
      await add.getByRole("button", {name: endpointsText(lang, "dialogs.add.submit"), exact: true}).click();
      await expect.poll(() => mock.screens.endpoints.some((e) => e.name === "Follows")).toBe(true);
      const made = mock.screens.endpoints.find((e) => e.name === "Follows")!;
      const profile = mock.screens.profiles.find((p) => p.id === made.profile_id)!;
      expect(profile.endpoints.map((e) => e.id)).toContain(made.id);
      await page.goto(`/${lang}/profiles`);
      const row = page.getByRole("listitem").filter({has: page.getByRole("link", {name: profile.name, exact: true})});
      await row.getByRole("button", {name: new RegExp(nf(lang, profile.counts.endpoints))}).click();
      await expect(page.getByRole("menuitem", {name: "Follows"})).toBeVisible();
    });

    test("the sidebar counter of Endpoints follows an Endpoint that is made", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(`/${lang}/profiles`);
      const before = mock.screens.endpoints.length;
      const sidebar = page.locator("aside.sidebar");
      await expect(sidebar.getByText(nf(lang, before), {exact: true}).first()).toBeVisible();
      await page.goto(`${endpointsPath(lang)}?deviceDialog=add`);
      const add = page.getByRole("dialog");
      await add.getByRole("textbox", {name: endpointsText(lang, "dialogs.fields.names")}).fill("Counted");
      await add.getByRole("button", {name: endpointsText(lang, "dialogs.add.submit"), exact: true}).click();
      await expect.poll(() => mock.screens.endpoints.length).toBe(before + 1);
      await expect(sidebar.getByText(nf(lang, before + 1), {exact: true}).first()).toBeVisible();
    });
  });
}
