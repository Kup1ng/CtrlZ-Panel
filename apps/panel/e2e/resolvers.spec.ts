import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {commonText, configurePath, copyName, resolversPath, twoNodeView} from "./configure-support.ts";
import {ENDPOINT, endpointPath} from "./endpoints-support.ts";
import {LANGS, openProfiles} from "./profiles-support.ts";
import {setupText} from "./setup-support.ts";

// The Resolvers dialog (`deviceDialog=resolvers`, spec p3 10, WF "Endpoints"). Rows: T-239 (the values, the order of the stamps and the guide
// text), T-240 (only the five protocols), T-218 (the way in from a row and the frame), T-544 (the primary first everywhere). Mock mode.

test.use({viewport: {width: 1280, height: 900}});

for (const {lang, dir} of LANGS) {
  test.describe(`${lang} (${dir})`, () => {
    const s = (path: string, values?: Record<string, string | number>) => setupText(lang, path, values);

    test("T-239: Legacy DNS and Secure DNS are sections of one dialog, each value with a Copy button named for it", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(resolversPath(lang));
      const dialog = page.getByRole("dialog");
      await expect(dialog).toBeVisible();
      await expect(dialog.getByRole("heading", {name: s("resolvers.dialogTitle", {name: "Home router"})})).toBeVisible();
      for (const key of ["legacy.title", "secure.title"]) {
        await expect(dialog.getByRole("button", {name: s(`resolvers.${key}`)})).toHaveAttribute("aria-expanded", "true");
      }
      await expect(dialog.getByText("203.0.113.53", {exact: true}).first()).toBeVisible();
      for (const label of ["resolvers.legacy.dns1", "resolvers.legacy.dns2", "resolvers.rows.doh", "resolvers.rows.dot", "resolvers.rows.doq", "resolvers.resolverId"]) {
        await expect(dialog.getByRole("button", {name: copyName(lang, s(label)), exact: true})).toBeVisible();
      }
    });

    test("T-239: a section collapses and opens again", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(resolversPath(lang));
      const dialog = page.getByRole("dialog");
      const legacy = dialog.getByRole("button", {name: s("resolvers.legacy.title")});
      await legacy.click();
      await expect(legacy).toHaveAttribute("aria-expanded", "false");
      await expect(dialog.getByRole("button", {name: copyName(lang, s("resolvers.legacy.dns1")), exact: true})).toBeHidden();
      await legacy.click();
      await expect(dialog.getByRole("button", {name: copyName(lang, s("resolvers.legacy.dns1")), exact: true})).toBeVisible();
    });

    test("T-239: Copy puts the value in the clipboard and says so", async ({page, context, baseURL}) => {
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);
      await openProfiles(context, baseURL);
      await page.goto(resolversPath(lang));
      await page.getByRole("dialog").getByRole("button", {name: copyName(lang, s("resolvers.legacy.dns1")), exact: true}).click();
      await expect(page.getByText(commonText(lang, "copied"), {exact: true})).toBeVisible();
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("203.0.113.53");
    });

    test("S7-r1-8, S7-r1-9: the DoH rows are marked as secrets for a hand copy, the other rows are not, and the copy note is under the sections", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      mock.screens.resolver = twoNodeView();
      await page.goto(resolversPath(lang));
      const dialog = page.getByRole("dialog");
      const rows = dialog.locator(".tech-copy-row");
      for (const key of ["doh", "doh3"] as const) await expect(rows.filter({hasText: s(`resolvers.rows.${key}`)}).first().locator("[data-one-time-secret]")).toHaveCount(1);
      await expect(rows.filter({hasText: s("resolvers.rows.dot")}).first().locator("[data-one-time-secret]")).toHaveCount(0);
      await expect(rows.filter({hasText: s("resolvers.legacy.dns1")}).first().locator("[data-one-time-secret]")).toHaveCount(0);
      await expect(dialog.getByTestId("copy-note")).toHaveText(s("copyNote"));
    });

    test("T-239, T-544: the host name stamp comes first, then the address stamps with the primary's first, under the guide sentence", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      mock.screens.resolver = twoNodeView();
      await page.goto(resolversPath(lang));
      const dialog = page.getByRole("dialog");
      await dialog.getByRole("button", {name: s("resolvers.stamps.title")}).click();
      await expect(dialog.getByTestId("stamp-guide")).toHaveText(s("resolvers.stamps.guide"));
      for (const protocol of ["doh", "dot", "doq"] as const) {
        const section = dialog.getByTestId(`stamps-${protocol}`);
        const name = s(`resolvers.protocols.${protocol}`);
        const names = await section.getByRole("button").evaluateAll((buttons) => buttons.map((b) => b.getAttribute("aria-label")));
        expect(names, protocol).toEqual([
          copyName(lang, s("resolvers.stamps.hostname", {protocol: name})),
          copyName(lang, s("resolvers.stamps.address", {protocol: name, ip: "203.0.113.53"})),
          copyName(lang, s("resolvers.stamps.address", {protocol: name, ip: "203.0.113.54"})),
        ]);
        // The sentence "for apps that take several stamps" sits between the host name stamp and the address stamps.
        const text = await section.innerText();
        expect(text.indexOf(s("resolvers.stamps.several"))).toBeGreaterThan(text.indexOf("sdns://" + protocol + "host"));
        expect(text.indexOf("sdns://" + protocol + "1")).toBeLessThan(text.indexOf("sdns://" + protocol + "2"));
      }
    });

    test("T-544: Bootstrap IPs list the primary first", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      mock.screens.resolver = twoNodeView({bootstrap: ["203.0.113.54", "203.0.113.53"]});
      await page.goto(resolversPath(lang));
      const rows = page.getByRole("dialog").locator(".tech-copy-row");
      const first = rows.filter({hasText: s("resolvers.bootstrap.first")});
      await expect(first).toContainText("203.0.113.53");
      await expect(rows.filter({hasText: s("resolvers.bootstrap.second")})).toContainText("203.0.113.54");
    });

    test("T-240: exactly the five protocols are listed, DoH3 as the DoH address with its own label and no stamp of its own", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      mock.screens.resolver = twoNodeView();
      await page.goto(resolversPath(lang));
      const dialog = page.getByRole("dialog");
      const rows = dialog.locator(".tech-copy-row");
      await expect(rows.filter({hasText: s("resolvers.rows.doh")}).first()).toBeVisible();
      // The DoH and DoH3 rows carry one URL.
      const doh = await rows.filter({hasText: s("resolvers.rows.doh3")}).locator("bdi").first().innerText();
      expect(doh).toBe(mock.screens.resolver.doh_url);
      expect(await dialog.getByRole("button", {name: copyName(lang, s("resolvers.rows.doh3")), exact: true}).count()).toBe(1);
      for (const key of ["doh", "dot", "doq"]) await expect(dialog.getByRole("button", {name: copyName(lang, s("resolvers.rows." + key)), exact: true})).toHaveCount(1);
      // There is no sixth protocol and no stamp group for DoH3.
      await expect(dialog.getByTestId("stamps-doh")).toBeHidden();
      await dialog.getByRole("button", {name: s("resolvers.stamps.title")}).click();
      await expect(dialog.getByTestId("stamps-doh")).toBeVisible();
      await expect(dialog.locator('[data-testid^="stamps-"]')).toHaveCount(3);
      await expect(dialog.getByTestId("stamps-doh3")).toHaveCount(0);
    });

    test("T-240: a protocol that is not in the view's list is not shown", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      mock.screens.resolver = twoNodeView({protocols: ["plain", "doh"]});
      await page.goto(resolversPath(lang));
      const dialog = page.getByRole("dialog");
      await expect(dialog.getByRole("button", {name: copyName(lang, s("resolvers.rows.doh")), exact: true})).toBeVisible();
      for (const key of ["doh3", "dot", "doq"]) await expect(dialog.getByRole("button", {name: copyName(lang, s("resolvers.rows." + key)), exact: true})).toHaveCount(0);
    });

    test("the client picker asks for that client's view", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {clients: 30});
      await page.goto(resolversPath(lang));
      const dialog = page.getByRole("dialog");
      await expect(dialog.getByRole("button", {name: copyName(lang, s("resolvers.resolverId")), exact: true})).toBeVisible();
      const asked = page.waitForRequest((r) => r.url().includes("/resolvers?client=device-3"));
      const field = dialog.getByRole("combobox", {name: s("client.label")});
      await field.click();
      await page.getByRole("option", {name: "device-3", exact: true}).click();
      expect((await asked).url()).toContain("client=device-3");
      await expect(field).toHaveValue("device-3");
    });

    test("Help me configure goes from this dialog to the wizard of the same Endpoint, in one history entry", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(resolversPath(lang));
      const dialog = page.getByRole("dialog");
      await dialog.getByRole("button", {name: s("resolvers.configureAria", {name: "Home router"})}).click();
      await expect(page).toHaveURL(new RegExp(`deviceDialog=configure&deviceId=${ENDPOINT.home}`));
      await expect(page.getByRole("dialog").getByTestId("configure-home")).toBeVisible();
    });

    test("a deployment with no DNS zone says setup is not ready, and offers no values", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {resolverNotReady: true});
      await page.goto(resolversPath(lang));
      const dialog = page.getByRole("dialog");
      await expect(dialog.getByText(s("unavailable.title"))).toBeVisible();
      await expect(dialog.getByRole("button", {name: s("resolvers.configureAria", {name: "Home router"})})).toBeDisabled();
      await expect(dialog.locator(".tech-copy-row")).toHaveCount(0);
    });

    test("an Endpoint that is not the tenant's gives the same not-found text as a missing one, and Escape closes the dialog", async ({page, context, baseURL, guard}) => {
      // The two 404s are the Endpoint and its view: this is the case that causes them.
      guard.allowConsole(/status of 404/);
      await openProfiles(context, baseURL);
      await page.goto(`${endpointPath(lang, ENDPOINT.home, "clients")}?deviceDialog=resolvers&deviceId=${ENDPOINT.unknown}`);
      await expect(page.getByRole("dialog").getByRole("alert")).toBeVisible();
      await page.keyboard.press("Escape");
      await expect(page.getByRole("dialog")).toHaveCount(0);
      await expect(page).not.toHaveURL(/deviceDialog/);
    });

    test("the DoH token is in no address the page uses, and nothing is requested outside the origin", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      const urls: string[] = [];
      page.on("request", (r) => urls.push(r.url()));
      await page.goto(resolversPath(lang));
      await expect(page.getByRole("dialog").getByRole("button", {name: copyName(lang, s("resolvers.rows.doh")), exact: true})).toBeVisible();
      expect(page.url()).not.toContain("TOKEN_TOKEN");
      expect(urls.filter((u) => u.includes("TOKEN_TOKEN"))).toEqual([]);
      const outside = await page.evaluate(() => performance.getEntriesByType("resource").filter((r) => new URL(r.name).origin !== location.origin).length);
      expect(outside).toBe(0);
      // The configure link in the dialog is the same Endpoint's: the page has no other way to the wizard.
      expect(configurePath(lang)).toContain(ENDPOINT.home);
    });
  });
}
