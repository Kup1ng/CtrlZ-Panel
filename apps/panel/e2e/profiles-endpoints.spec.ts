import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {ENDPOINT} from "./endpoints-support.ts";
import {profileRow} from "./profiles-list-support.ts";
import {LANGS, PROFILE, openProfiles, profileActions, profilePath, profilesPath, screen, text} from "./profiles-support.ts";

// T-137 (spec p3 10, row "Profiles"): the Endpoints of a profile on the list and in its header. `ProfileRow.endpoints` is filled for every
// role: a profile with Endpoints has a menu that names them and opens one, a profile with none has Add Endpoint, which starts the Endpoint
// dialog on that profile. In mock mode; the dialog itself is P3a's.

test.use({viewport: {width: 1280, height: 800}});

for (const {lang, dir} of LANGS) {
  test.describe(`${lang} (${dir})`, () => {
    test("T-137: on the list, a profile with Endpoints has a menu of them, and a click opens that Endpoint", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilesPath(lang));
      const home = profileRow(page, lang, "Home");
      const trigger = home.getByRole("button", {name: /Home/});
      await expect(trigger).toContainText(lang === "fa" ? "۲ اندپوینت" : "2 Endpoints");
      await trigger.click();
      // The menu is named by the button that opens it ("2 Endpoints, profile Home"), whatever its own label says.
      const menu = page.getByRole("menu", {name: (await trigger.getAttribute("aria-label")) ?? ""});
      await expect(menu.getByRole("menuitem")).toHaveCount(2);
      await expect(menu.getByRole("menuitem", {name: "Home router"})).toBeVisible();
      await menu.getByRole("menuitem", {name: "Laptop"}).click();
      await expect(page).toHaveURL(new RegExp(`/${lang}/endpoints/${ENDPOINT.laptop}/clients$`));
    });

    test("T-137: the menu does not open the profile behind it", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilesPath(lang));
      await profileRow(page, lang, "Home").getByRole("button", {name: /Home/}).click();
      await expect(page.getByRole("menu")).toBeVisible();
      await expect(page).toHaveURL(new RegExp(`/${lang}/profiles$`));
      await page.keyboard.press("Escape");
      await expect(page.getByRole("menu")).toBeHidden();
      await expect(page).toHaveURL(new RegExp(`/${lang}/profiles$`));
    });

    test("T-137: on the list, a profile with none says so and offers Add Endpoint, which starts the dialog on that profile", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilesPath(lang));
      const gaming = profileRow(page, lang, "Gaming");
      await expect(gaming).toContainText(text(lang, "profiles", "list.noEndpoint"));
      const add = gaming.getByRole("link", {name: text(lang, "profiles", "frame.addEndpointAria", {name: "Gaming"})});
      await expect(add).toHaveAttribute("href", new RegExp(`/profiles/${PROFILE.gaming}/options\\?deviceDialog=add$`));
      await add.click();
      // The frame of that profile owns the dialog, so the address is the profile's page with the dialog's parameter.
      await expect(page).toHaveURL(new RegExp(`/${lang}/profiles/${PROFILE.gaming}/options\\?deviceDialog=add$`));
      await expect(screen(page, "profile-options")).toBeVisible();
      await expect(profileActions(page).getByRole("button", {name: text(lang, "profiles", "frame.addEndpointAria", {name: "Gaming"})})).toBeVisible();
    });

    test("T-137: in the header, a profile with Endpoints has their menu and one with none has Add Endpoint", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "filters"));
      const actions = profileActions(page);
      await expect(actions.getByRole("button", {name: text(lang, "profiles", "frame.addEndpointAria", {name: "Home"})})).toHaveCount(0);
      await actions.getByRole("button", {name: text(lang, "profiles", "frame.endpointsAria", {name: "Home"})}).click();
      const menu = page.getByRole("menu", {name: text(lang, "profiles", "frame.endpointsAria", {name: "Home"})});
      await expect(menu.getByRole("menuitem")).toHaveCount(2);
      await expect(menu.getByRole("menuitem", {name: "Home router"})).toBeVisible();
      await page.keyboard.press("Escape");

      await page.goto(profilePath(lang, PROFILE.gaming, "filters"));
      await expect(profileActions(page).getByRole("button", {name: text(lang, "profiles", "frame.addEndpointAria", {name: "Gaming"})})).toBeVisible();
      await expect(profileActions(page).getByRole("button", {name: text(lang, "profiles", "frame.endpointsAria", {name: "Gaming"})})).toHaveCount(0);
    });
  });
}
