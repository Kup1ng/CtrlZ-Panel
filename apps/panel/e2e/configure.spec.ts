import {readFileSync} from "node:fs";
import path from "node:path";

import type {Page} from "@playwright/test";
import {errorBody} from "@ctrlz/api-client/testing/fixtures.ts";
import {PLATFORMS} from "@ctrlz/ui/setup/platforms.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {commonText, configurePath, copyName, decodeQr, errorText, platformName, resolversPath} from "./configure-support.ts";
import {ENDPOINT, endpointActions, endpointPath, endpointsText} from "./endpoints-support.ts";
import {FOLDER, LANGS, openProfiles, type Lang} from "./profiles-support.ts";
import {setupText} from "./setup-support.ts";

// Help Me Configure (`deviceDialog=configure`, spec p3 8.3, 10): the four entries (T-241), every platform of T-243 in both languages with the
// version picker of T-242, the Apple builder with its warning, Advanced settings and QR (T-245, T-246, T-250, T-251), Copy Setup Link
// (T-241, T-244) and the first-place rule for the values (T-544). Mock mode. The wizard's text is read from the content files, so a case
// asserts the step a person should see, not a string typed twice.

test.use({viewport: {width: 1280, height: 900}});

type Step = {title: string; text: string; show?: string[]; link?: string; verify?: boolean};
type Version = {id: string; name: string; steps: Step[]};
const guide = (lang: Lang, id: string): {versions: Version[]} =>
  JSON.parse(readFileSync(path.join(__dirname, "../../../packages/ui/src/setup/content", lang, `${id}.json`), "utf8")) as {versions: Version[]};

const dialog = (page: Page) => page.getByRole("dialog");

for (const {lang, dir} of LANGS) {
  test.describe(`${lang} (${dir})`, () => {
    const s = (p: string, values?: Record<string, string | number>) => setupText(lang, p, values);

    test("T-241: Help Me Configure has its four entries, and See Resolvers goes to the Resolvers dialog", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(configurePath(lang));
      const home = dialog(page).getByTestId("configure-home");
      for (const entry of ["automatic", "manual", "resolvers", "link"]) await expect(home.getByText(s(`configure.entries.${entry}.title`), {exact: true})).toBeVisible();
      await home.getByText(s("configure.entries.resolvers.title"), {exact: true}).click();
      await expect(page).toHaveURL(new RegExp(`deviceDialog=resolvers&deviceId=${ENDPOINT.home}`));
      await expect(dialog(page).getByTestId("resolver-sections")).toBeVisible();
    });

    test("T-243: Manual Setup lists the fourteen platforms, Automatic Setup only those that have one", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(configurePath(lang));
      await dialog(page).getByText(s("configure.entries.manual.title"), {exact: true}).click();
      const list = dialog(page).getByTestId("platform-list");
      await expect(list.locator("[data-platform]")).toHaveCount(14);
      for (const p of PLATFORMS) await expect(list.locator(`[data-platform="${p.id}"]`)).toHaveText(platformName(lang, p.id));
      await dialog(page).getByTestId("configure-back").click();
      await dialog(page).getByText(s("configure.entries.automatic.title"), {exact: true}).click();
      await expect(list.locator('[data-platform="linux"]')).toHaveCount(0);
      await expect(list.locator('[data-platform="windows"]')).toHaveCount(1);
      await expect(list.locator("[data-platform]")).toHaveCount(13);
    });

    test("T-242: picking a platform in Manual Setup opens its first step, with the platform and step in the address", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(configurePath(lang));
      await dialog(page).getByText(s("configure.entries.manual.title"), {exact: true}).click();
      await dialog(page).locator('[data-platform="android"]').click();
      await expect(page).toHaveURL(/setupOs=android&step=1/);
      await expect(dialog(page).getByTestId("wizard")).toBeVisible();
      await expect(dialog(page).getByRole("heading", {level: 3, name: new RegExp(guide(lang, "android").versions[0]!.steps[0]!.title)})).toBeVisible();
    });

    for (const platform of PLATFORMS) {
      test(`T-243: ${platform.id} has its steps, numbered, one at a time, every version`, async ({page, context, baseURL}) => {
        await openProfiles(context, baseURL);
        const content = guide(lang, platform.id);
        for (const version of content.versions) {
          await page.goto(configurePath(lang, ENDPOINT.home, platform.id, 1));
          const wizard = dialog(page).getByTestId("wizard");
          if (content.versions.length > 1) {
            // A press before the page is hydrated does nothing, so the press and its effect are tried together until the version's first step shows
            // (under load the first press was lost and the steps of the default version were read as this one's).
            await expect(async () => {
              await dialog(page).getByText(version.name, {exact: true}).click();
              await expect(wizard.getByText(version.steps[0]!.title, {exact: false}).first()).toBeVisible({timeout: 2_000});
            }).toPass();
          }
          for (const [index, step] of version.steps.entries()) {
            await expect(wizard, `${platform.id} ${version.id} step ${index + 1}`).toHaveAttribute("data-step", String(index + 1));
            await expect(wizard.getByText(step.title, {exact: false}).first()).toBeVisible();
            await expect(wizard.getByText(step.text, {exact: true})).toBeVisible();
            if (index < version.steps.length - 1) await wizard.getByRole("button", {name: s("wizard.next")}).click();
          }
          // The last step offers Done, and the dots name every step.
          await expect(wizard.getByRole("button", {name: commonText(lang, "done")})).toBeVisible();
          await expect(wizard.getByRole("list", {name: s("wizard.steps")}).getByRole("listitem")).toHaveCount(version.steps.length);
        }
      });
    }

    test("T-242: Windows has a version picker, and choosing a version starts its steps from the first", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(configurePath(lang, ENDPOINT.home, "windows", 3));
      const content = guide(lang, "windows");
      const wizard = dialog(page).getByTestId("wizard");
      await expect(wizard).toHaveAttribute("data-step", "3");
      await dialog(page).getByText(content.versions[1]!.name, {exact: true}).click();
      await expect(wizard).toHaveAttribute("data-step", "1");
      await expect(page).toHaveURL(/step=1/);
      await expect(wizard.getByText(content.versions[1]!.steps[0]!.title).first()).toBeVisible();
    });

    test("T-242: the step is in the address, survives a reload, and one Back leaves the dialog and not the step", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(`${endpointPath(lang, ENDPOINT.home, "clients")}?deviceDialog=configure&deviceId=${ENDPOINT.home}&setupOs=windows&step=1`);
      const wizard = dialog(page).getByTestId("wizard");
      // A press before the page is hydrated does nothing, so the first press is tried until it has moved the step (under load it was lost and
      // the two presses ended on step 2); the second press then follows at once, which the Wizard counts from the step last asked for.
      await expect(async () => {
        await wizard.getByRole("button", {name: s("wizard.next")}).click();
        await expect(wizard).toHaveAttribute("data-step", "2", {timeout: 2_000});
      }).toPass();
      await wizard.getByRole("button", {name: s("wizard.next")}).click();
      await expect(page).toHaveURL(/step=3/);
      await page.reload();
      await expect(dialog(page).getByTestId("wizard")).toHaveAttribute("data-step", "3");
      await page.goBack();
      await expect(dialog(page)).toHaveCount(0);
    });

    test("T-544: a step shows the Resolver view's values with Copy buttons, the primary first", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(configurePath(lang, ENDPOINT.home, "windows", 1));
      // Windows 11, step 3: DNS 1 then DNS 2.
      await dialog(page).getByTestId("wizard").getByRole("button", {name: s("wizard.next")}).click();
      await dialog(page).getByTestId("wizard").getByRole("button", {name: s("wizard.next")}).click();
      const rows = dialog(page).getByTestId("wizard").locator(".tech-copy-row");
      await expect(rows).toHaveCount(2);
      await expect(rows.nth(0)).toContainText("203.0.113.53");
      await expect(rows.nth(1)).toContainText("203.0.113.54");
      await expect(rows.nth(0).getByRole("button", {name: copyName(lang, s("wizard.values.dns1"))})).toBeVisible();
    });

    test("T-544: the Linux drop-in is strict, has the primary first, and is copied as one block", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(configurePath(lang, ENDPOINT.home, "linux", 2));
      const block = dialog(page).getByTestId("copy-block");
      await expect(block).toContainText("DNSOverTLS=yes");
      // S7-r1-10: without it the servers the network hands out are asked as well.
      await expect(block).toContainText("Domains=~.");
      await expect(block).toContainText("DNS=203.0.113.53#r00000001.dns.example.test 203.0.113.54#r00000001.dns.example.test");
      await expect(block).not.toContainText("opportunistic");
    });

    test("T-544: the browser steps give the DoH URL with the host name and no address, as a secret for the clipboard", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(configurePath(lang, ENDPOINT.home, "firefox", 3));
      const row = dialog(page).getByTestId("wizard").locator(".tech-copy-row");
      await expect(row).toContainText("r00000001.dns.example.test");
      await expect(row).not.toContainText("203.0.113");
      expect(page.url()).not.toContain("TOKEN_TOKEN");
    });

    test("S7-r1-9: a value copied in a wizard step is still in the clipboard after Next, and a generator with no token is not a secret", async ({page, context, baseURL}) => {
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);
      await openProfiles(context, baseURL);
      await page.goto(configurePath(lang, ENDPOINT.home, "firefox", 3));
      const wizard = dialog(page).getByTestId("wizard");
      await expect(wizard.getByTestId("copy-note")).toHaveText(s("copyNote"));
      await wizard.getByRole("button", {name: copyName(lang, s("wizard.values.doh_url"))}).click();
      const copied = await page.evaluate(() => navigator.clipboard.readText());
      expect(copied).toContain("r00000001.dns.example.test");
      await wizard.getByRole("button", {name: s("wizard.next")}).click();
      await expect(wizard).toHaveAttribute("data-step", "4");
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(copied);
      // Android's private DNS host name carries no token: no secret mark and no note.
      await page.goto(configurePath(lang, ENDPOINT.home, "android"));
      const block = dialog(page).getByTestId("copy-block");
      await expect(block).toBeVisible();
      await expect(block.locator("[data-one-time-secret]")).toHaveCount(0);
      await expect(dialog(page).getByTestId("copy-note")).toHaveCount(0);
    });

    test("S7-r1-4: the version of a platform is in the address, so a reload opens the same steps", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      const content = guide(lang, "windows");
      await page.goto(configurePath(lang, ENDPOINT.home, "windows", 3));
      await dialog(page).getByText(content.versions[1]!.name, {exact: true}).click();
      await expect(page).toHaveURL(/setupOs=windows-10&step=1/);
      await page.reload();
      await expect(dialog(page).getByTestId("platform-view")).toHaveAttribute("data-platform", "windows");
      await expect(dialog(page).getByText(content.versions[1]!.steps[0]!.title).first()).toBeVisible();
      await page.goto(configurePath(lang, ENDPOINT.home, "windows-10", 5));
      await expect(dialog(page).getByTestId("wizard")).toHaveAttribute("data-step", "5");
      await expect(dialog(page).getByText(content.versions[1]!.steps[4]!.title).first()).toBeVisible();
    });

    test("T-243: a platform set by address sends to the claim of the network, and the share page would have no such button", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(configurePath(lang, ENDPOINT.home, "router", 1));
      const link = dialog(page).getByRole("link", {name: s("wizard.openAddresses")});
      await expect(link).toHaveAttribute("href", new RegExp(`/endpoints/${ENDPOINT.home}/ips\\?ipDialog=claim$`));
    });

    test("T-241: Automatic Setup of Windows 11 gives the generator's text to copy, as a secret", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(configurePath(lang, ENDPOINT.home, "windows"));
      await expect(dialog(page).getByTestId("automatic")).toBeVisible();
      await expect(dialog(page).getByTestId("copy-block")).toContainText("windows-doh");
      await expect(dialog(page).getByRole("button", {name: copyName(lang, s("generators.windows-doh"))})).toBeVisible();
      await dialog(page).getByRole("button", {name: s("configure.startGuide")}).click();
      await expect(page).toHaveURL(/step=1/);
    });

    test("T-241: a platform with no automatic setup goes straight to its steps and says why", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(configurePath(lang, ENDPOINT.home, "linux"));
      await expect(dialog(page).getByText(s("configure.noAutomatic"))).toBeVisible();
    });

    test("a deployment with no zone shows the not-ready state in the wizard too", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {resolverNotReady: true});
      await page.goto(configurePath(lang, ENDPOINT.home, "windows", 1));
      await expect(dialog(page).getByText(s("unavailable.title"))).toBeVisible();
      await expect(dialog(page).getByTestId("wizard")).toHaveCount(0);
    });

    test("an unknown platform in the address opens the four entries, and the dialog still closes with Escape", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(configurePath(lang, ENDPOINT.home, "nonsense", 3));
      await expect(dialog(page).getByTestId("configure-home")).toBeVisible();
      await page.keyboard.press("Escape");
      await expect(dialog(page)).toHaveCount(0);
    });

    test.describe("the Apple builder", () => {
      test("T-251: the unsigned warning is on the screen before the link is made", async ({page, context, baseURL}) => {
        await openProfiles(context, baseURL);
        await page.goto(configurePath(lang, ENDPOINT.home, "ios"));
        const builder = dialog(page).getByTestId("apple-builder");
        await expect(builder.getByTestId("apple-unsigned")).toContainText(s("apple.unsignedTitle"));
        await expect(builder.getByTestId("apple-result")).toHaveCount(0);
      });

      test("T-248: an Endpoint whose resolver changed after a download says the profile must be downloaded again", async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL);
        await page.goto(configurePath(lang, ENDPOINT.home, "ios"));
        await expect(dialog(page).getByTestId("apple-builder")).toBeVisible();
        await expect(dialog(page).getByTestId("apple-stale")).toHaveCount(0);
        mock.screens.endpoints = mock.screens.endpoints.map((e) => (e.id === ENDPOINT.home ? {...e, apple_profile_stale: true} : e));
        await page.goto(configurePath(lang, ENDPOINT.home, "ios"));
        await expect(dialog(page).getByTestId("apple-stale")).toContainText(s("apple.staleTitle"));
      });

      test("T-246, T-250: Advanced settings carry the SSIDs, the domains, the common list and Prevent Disablement into the request", async ({page, context, baseURL}) => {
        await openProfiles(context, baseURL);
        await page.goto(configurePath(lang, ENDPOINT.home, "ios"));
        const builder = dialog(page).getByTestId("apple-builder");
        await builder.getByRole("button", {name: s("apple.advanced")}).click();
        await builder.getByRole("radio", {name: s("resolvers.protocols.dot")}).click();
        await builder.getByRole("textbox", {name: s("apple.ssids")}).fill("Home Wi-Fi");
        await builder.getByRole("textbox", {name: s("apple.ssids")}).press("Enter");
        await builder.getByRole("textbox", {name: s("apple.domains")}).fill("HTTPS://Example.com/path");
        await builder.getByRole("button", {name: s("apple.addTo", {name: s("apple.domains")})}).click();
        await expect(builder.getByRole("row", {name: /example\.com/})).toBeVisible();
        // The label is the switch's own pressable area; the input behind it is not a place a pointer can land.
        await builder.getByText(s("apple.common"), {exact: true}).click();
        await builder.getByText(s("apple.prohibit"), {exact: true}).click();
        await expect(builder.getByRole("switch", {name: new RegExp(s("apple.prohibit"))})).toBeChecked();
        const posted = page.waitForRequest((r) => r.method() === "POST" && r.url().endsWith("/apple-profile"));
        await builder.getByRole("button", {name: s("apple.create")}).click();
        expect((await posted).postDataJSON()).toEqual({
          protocol: "dot",
          excluded_ssids: ["Home Wi-Fi"],
          excluded_domains: ["example.com"],
          exclude_common: true,
          prohibit_disablement: true,
        });
      });

      test("T-245: the QR code decodes to the download link, the Download button points at it, and no request leaves the origin", async ({page, context, baseURL}) => {
        await openProfiles(context, baseURL);
        await page.goto(configurePath(lang, ENDPOINT.home, "mac"));
        const builder = dialog(page).getByTestId("apple-builder");
        await builder.getByRole("button", {name: s("apple.create")}).click();
        const result = builder.getByTestId("apple-result");
        await expect(result).toBeVisible();
        const href = await result.getByTestId("apple-download").getAttribute("href");
        expect(href).toContain("/dl/APPLE_PROFILE_LINK");
        expect(await decodeQr(page)).toBe(href);
        expect(await page.evaluate(() => performance.getEntriesByType("resource").every((r) => new URL(r.name).origin === location.origin))).toBe(true);
        // The link is a secret of the dialog: it is in no address of the page.
        expect(page.url()).not.toContain("APPLE_PROFILE_LINK");
      });

      test("a change to the form drops the link made for the old one", async ({page, context, baseURL}) => {
        await openProfiles(context, baseURL);
        await page.goto(configurePath(lang, ENDPOINT.home, "ios"));
        const builder = dialog(page).getByTestId("apple-builder");
        await builder.getByRole("button", {name: s("apple.create")}).click();
        await expect(builder.getByTestId("apple-result")).toBeVisible();
        await builder.getByRole("radio", {name: s("resolvers.protocols.dot")}).click();
        await expect(builder.getByTestId("apple-result")).toHaveCount(0);
        await expect(builder.getByRole("button", {name: s("apple.create")})).toBeVisible();
      });

      test("a name over 32 bytes is refused before any request, with the reason", async ({page, context, baseURL}) => {
        await openProfiles(context, baseURL);
        await page.goto(configurePath(lang, ENDPOINT.home, "ios"));
        const builder = dialog(page).getByTestId("apple-builder");
        await builder.getByRole("button", {name: s("apple.advanced")}).click();
        const field = builder.getByRole("textbox", {name: s("apple.ssids")});
        await field.fill("ا".repeat(17));
        await field.press("Enter");
        await expect(builder.getByText(s("apple.problems.too_long"))).toBeVisible();
      });

      test("a refusal of the API (setup_unavailable) is worded, and no link is shown", async ({page, context, baseURL, guard}) => {
        guard.allowConsole(/status of 409/);
        await openProfiles(context, baseURL, {handlers: {"POST /endpoints/{id}/apple-profile": {status: 409, body: errorBody("setup_unavailable")}}});
        await page.goto(configurePath(lang, ENDPOINT.home, "ios"));
        const builder = dialog(page).getByTestId("apple-builder");
        await builder.getByRole("button", {name: s("apple.create")}).click();
        await expect(builder.getByText(errorText(lang, "setup_unavailable"))).toBeVisible();
        await expect(builder.getByTestId("apple-result")).toHaveCount(0);
        await expect(builder.getByRole("button", {name: s("apple.create")})).toBeVisible();
      });
    });

    test.describe("Copy Setup Link", () => {
      test("T-241, T-244: the link is made, shown once with a QR, and gone when the dialog is closed and opened again", async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL);
        // The fixture's links end on fixed dates: this case counts only the one it makes.
        mock.screens.shareLinks.clear();
        await page.goto(configurePath(lang));
        await dialog(page).getByText(s("configure.entries.link.title"), {exact: true}).click();
        const panel = dialog(page).getByTestId("share-link-panel");
        await panel.getByRole("button", {name: s("link.create")}).click();
        const result = panel.getByTestId("share-link-result");
        await expect(result).toBeVisible();
        await expect(result).toContainText("/s/");
        expect(await decodeQr(page)).toContain("/s/");
        expect(page.url()).not.toMatch(/\/s\/[A-Za-z0-9_-]{20}/);
        await page.keyboard.press("Escape");
        await page.goto(configurePath(lang));
        await dialog(page).getByText(s("configure.entries.link.title"), {exact: true}).click();
        await expect(dialog(page).getByTestId("share-link-result")).toHaveCount(0);
        // The list keeps the live link, with no value, and can revoke it.
        const revoke = dialog(page).getByRole("region", {name: s("link.activeTitle")}).getByRole("button");
        await expect(revoke).toBeVisible();
        const deleted = page.waitForRequest((r) => r.method() === "DELETE" && r.url().includes("/share-links/"));
        await revoke.click();
        await deleted;
        await expect(dialog(page).getByText(s("link.none"))).toBeVisible();
      });

      test("S7-r1-6, S7-r1-12: a shown link fixes the client and lifetime, carries the copy note, and a revoked link leaves the screen", async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL);
        mock.screens.shareLinks.clear();
        await page.goto(configurePath(lang));
        await dialog(page).getByText(s("configure.entries.link.title"), {exact: true}).click();
        const panel = dialog(page).getByTestId("share-link-panel");
        await panel.getByRole("button", {name: s("link.create")}).click();
        const result = panel.getByTestId("share-link-result");
        await expect(result).toBeVisible();
        await expect(panel.getByRole("combobox", {name: s("link.client")})).toBeDisabled();
        await expect(panel.getByRole("radio", {name: s("link.ttl.168")})).toBeDisabled();
        await expect(result.getByTestId("copy-note")).toHaveText(s("copyNote"));
        await expect(result).toContainText("/s/");
        // The URL is a secret to the clipboard: a hand copy of it is recognised (FE 12.3).
        await expect(result.locator("[data-one-time-secret]")).toHaveCount(1);
        // Revoking the link that is on screen takes it off the screen.
        await panel.getByRole("region", {name: s("link.activeTitle")}).getByRole("button").click();
        await expect(result).toHaveCount(0);
        await expect(panel.getByRole("button", {name: s("link.create")})).toBeVisible();
        await expect(panel.getByRole("radio", {name: s("link.ttl.168")})).toBeEnabled();
      });

      test("T-241: the lifetime and the client are chosen before the link is made", async ({page, context, baseURL}) => {
        await openProfiles(context, baseURL, {clients: 20});
        await page.goto(configurePath(lang));
        await dialog(page).getByText(s("configure.entries.link.title"), {exact: true}).click();
        const panel = dialog(page).getByTestId("share-link-panel");
        await panel.getByRole("radio", {name: s("link.ttl.168")}).click();
        const field = panel.getByRole("combobox", {name: s("link.client")});
        await field.click();
        await page.getByRole("option", {name: "device-2", exact: true}).click();
        const posted = page.waitForRequest((r) => r.method() === "POST" && r.url().endsWith("/share-links"));
        await panel.getByRole("button", {name: s("link.create")}).click();
        expect((await posted).postDataJSON()).toEqual({client: "device-2", ttl_hours: 168});
      });

      test("a deployment with no zone says so and makes no link", async ({page, context, baseURL}) => {
        await openProfiles(context, baseURL, {resolverNotReady: true});
        await page.goto(configurePath(lang));
        await expect(dialog(page).getByText(s("unavailable.title"))).toBeVisible();
      });
    });


    test.describe("the client of Resolvers (S7-r2-6)", () => {
      // The client is chosen in Resolvers and Help me configure opens on it: the title names it, the picker shows it, and every value, generator
      // and profile of the flow is asked with it. The mock gives a client its own host, `<resolver>-<client>.<zone>`, as the API does (SC 3.2).
      const pickInResolvers = async (page: Page) => {
        await page.goto(resolversPath(lang));
        const field = dialog(page).getByRole("combobox", {name: s("client.label")});
        await field.click();
        await page.getByRole("option", {name: "device-3", exact: true}).click();
        await expect(field).toHaveValue("device-3");
        await dialog(page).getByRole("button", {name: s("resolvers.configureAria", {name: "Home router"})}).click();
        await expect(dialog(page).getByTestId("configure-home")).toBeVisible();
      };

      test("the title names the client, the picker keeps it, and the wizard's host and the generator carry it", async ({page, context, baseURL}) => {
        await openProfiles(context, baseURL, {clients: 30});
        await pickInResolvers(page);
        await expect(dialog(page).getByRole("heading", {name: /device-3/})).toBeVisible();
        await expect(dialog(page).getByRole("combobox", {name: s("client.label")})).toHaveValue("device-3");
        // Automatic Setup of Android: the generator is asked with the client.
        const generator = page.waitForRequest((r) => r.url().includes("/generators") && r.url().includes("client=device-3"));
        await dialog(page).getByText(s("configure.entries.automatic.title"), {exact: true}).click();
        await dialog(page).locator('[data-platform="android"]').click();
        await generator;
        // Manual Setup of Android: the host of the step is the client's.
        await dialog(page).getByRole("button", {name: s("configure.startGuide")}).click();
        const steps = guide(lang, "android").versions[0]!.steps;
        const hostStep = steps.findIndex((step) => step.show?.includes("host")) + 1;
        for (let n = 1; n < hostStep; n++) await dialog(page).getByTestId("wizard").getByRole("button", {name: s("wizard.next")}).click();
        await expect(dialog(page).getByTestId("wizard").locator(".tech-copy-row")).toContainText("r00000001-device-3.dns.example.test");
      });

      test("S7-r3-3: a client that is not on the first page still shows in the picker of Help me configure", async ({page, context, baseURL}) => {
        // 1,000 clients, a page of 100: device-902 is found by search in Resolvers, and the picker of the other dialog starts without it.
        await openProfiles(context, baseURL);
        await page.goto(resolversPath(lang));
        const field = dialog(page).getByRole("combobox", {name: s("client.label")});
        await field.fill("device-902");
        await page.getByRole("option", {name: "device-902", exact: true}).click();
        await dialog(page).getByRole("button", {name: s("resolvers.configureAria", {name: "Home router"})}).click();
        await expect(dialog(page).getByTestId("configure-home")).toBeVisible();
        await expect(dialog(page).getByRole("heading", {name: /device-902/})).toBeVisible();
        await expect(dialog(page).getByRole("combobox", {name: s("client.label")})).toHaveValue("device-902");
      });

      test("the Apple profile is asked for with the client", async ({page, context, baseURL}) => {
        await openProfiles(context, baseURL, {clients: 30});
        await pickInResolvers(page);
        await dialog(page).getByText(s("configure.entries.automatic.title"), {exact: true}).click();
        await dialog(page).locator('[data-platform="ios"]').click();
        const posted = page.waitForRequest((r) => r.method() === "POST" && r.url().endsWith("/apple-profile"));
        await dialog(page).getByTestId("apple-builder").getByRole("button", {name: s("apple.create")}).click();
        expect((await posted).postDataJSON()).toEqual({protocol: "doh", client: "device-3"});
      });

      test("a client chosen at the top of Help me configure is asked for too, and Resolvers opened afresh starts on the Endpoint itself", async ({page, context, baseURL}) => {
        await openProfiles(context, baseURL, {clients: 30});
        await page.goto(configurePath(lang));
        const asked = page.waitForRequest((r) => r.url().includes("/resolvers?client=device-2"));
        const field = dialog(page).getByRole("combobox", {name: s("client.label")});
        await field.click();
        await page.getByRole("option", {name: "device-2", exact: true}).click();
        expect((await asked).url()).toContain("client=device-2");
        await expect(dialog(page).getByRole("heading", {name: /device-2/})).toBeVisible();
        await page.keyboard.press("Escape");
        await expect(dialog(page)).toHaveCount(0);
        await page.goto(resolversPath(lang));
        await expect(dialog(page).getByRole("combobox", {name: s("client.label")})).toHaveValue(s("client.self"));
      });
    });

    test.describe("the link panel is held (S7-r2-2, S7-r2-9)", () => {
      // The answer of a link is shown once and lives in the state of its panel. While the call runs, nothing that would take the panel off the screen
      // works (the Back button, the browser's Back, the frame's own close); once the link is shown they ask first.
      const openLinkPanel = async (page: Page, context: Parameters<typeof openProfiles>[0], baseURL: string | undefined) => {
        const mock = await openProfiles(context, baseURL);
        mock.screens.shareLinks.clear();
        await page.goto(configurePath(lang));
        await dialog(page).getByText(s("configure.entries.link.title"), {exact: true}).click();
        return dialog(page).getByTestId("share-link-panel");
      };
      const confirm = (page: Page) => page.getByRole("alertdialog");

      test("Back and the browser's Back do nothing while the link is being made, and the link lands on a screen", async ({page, context, baseURL}) => {
        let release!: () => void;
        const gate = new Promise<void>((resolve) => (release = resolve));
        await page.route(/\/share-links(\?.*)?$/, async (route) => {
          if (route.request().method() !== "POST") return route.fallback();
          await gate;
          return route.fallback();
        });
        const panel = await openLinkPanel(page, context, baseURL);
        const before = page.url();
        await panel.getByRole("button", {name: s("link.create")}).click();
        await expect(dialog(page).getByTestId("configure-back")).toBeDisabled();
        await page.evaluate(() => history.back());
        await page.waitForTimeout(400);
        expect(page.url()).toBe(before);
        await expect(panel).toBeVisible();
        await expect(confirm(page)).toHaveCount(0);
        release();
        await expect(panel.getByTestId("share-link-result")).toBeVisible();
        await expect(dialog(page).getByTestId("configure-back")).toBeEnabled();
      });

      test("Back asks before it drops a link that is shown, and Stay here keeps it", async ({page, context, baseURL}) => {
        const panel = await openLinkPanel(page, context, baseURL);
        await panel.getByRole("button", {name: s("link.create")}).click();
        await expect(panel.getByTestId("share-link-result")).toBeVisible();
        await dialog(page).getByTestId("configure-back").click();
        await expect(confirm(page).getByText(s("leave.title"))).toBeVisible();
        await confirm(page).getByRole("button", {name: s("leave.keep")}).click();
        await expect(confirm(page)).toHaveCount(0);
        await expect(panel.getByTestId("share-link-result")).toBeVisible();
        await dialog(page).getByTestId("configure-back").click();
        await confirm(page).getByRole("button", {name: s("leave.go")}).click();
        await expect(dialog(page).getByTestId("configure-home")).toBeVisible();
        await expect(dialog(page).getByTestId("share-link-panel")).toHaveCount(0);
      });

      test("the browser's Back asks while a link is shown, and leaving closes the dialog with the address as it was", async ({page, context, baseURL}) => {
        const panel = await openLinkPanel(page, context, baseURL);
        await panel.getByRole("button", {name: s("link.create")}).click();
        await expect(panel.getByTestId("share-link-result")).toBeVisible();
        await page.evaluate(() => history.back());
        await expect(confirm(page).getByText(s("leave.title"))).toBeVisible();
        await expect(page).toHaveURL(/deviceDialog=configure/);
        await confirm(page).getByRole("button", {name: s("leave.keep")}).click();
        await expect(panel.getByTestId("share-link-result")).toBeVisible();
        // The guard put its entry back, so a second Back asks again.
        await page.evaluate(() => history.back());
        await confirm(page).getByRole("button", {name: s("leave.go")}).click();
        await expect(dialog(page)).toHaveCount(0);
        await expect(page).not.toHaveURL(/deviceDialog/);
        await expect(page).toHaveURL(/\/clients/);
      });

      // The X and Escape are the dialog's own close, but while a link is shown they go through the same question as the browser's Back, and the guard's
      // extra history entry is given back before the dialog goes (S7-r3-2). Once for a dialog opened by address, once for one this tab pushed.
      const shownLink = async (page: Page) => {
        const panel = dialog(page).getByTestId("share-link-panel");
        await panel.getByRole("button", {name: s("link.create")}).click();
        await expect(panel.getByTestId("share-link-result")).toBeVisible();
        return panel;
      };
      const pushedLink = async (page: Page, context: Parameters<typeof openProfiles>[0], baseURL: string | undefined) => {
        const mock = await openProfiles(context, baseURL);
        mock.screens.shareLinks.clear();
        await page.goto(endpointPath(lang, ENDPOINT.home, "clients"));
        await endpointActions(page).getByRole("button", {name: endpointsText(lang, "frame.resolversAria", {name: "Home router"})}).click();
        await dialog(page).getByRole("button", {name: s("resolvers.configureAria", {name: "Home router"})}).click();
        await dialog(page).getByText(s("configure.entries.link.title"), {exact: true}).click();
        return shownLink(page);
      };
      const closers = {
        "the X": (page: Page) => dialog(page).getByRole("button", {name: commonText(lang, "close"), exact: true}).click(),
        Escape: (page: Page) => page.keyboard.press("Escape"),
      };

      for (const [how, close] of Object.entries(closers)) {
        test(`${how} asks before it closes a dialog opened by address with a link shown, and Stay here keeps both`, async ({page, context, baseURL}) => {
          await openLinkPanel(page, context, baseURL);
          const panel = await shownLink(page);
          await close(page);
          await expect(confirm(page).getByText(s("leave.title"))).toBeVisible();
          await confirm(page).getByRole("button", {name: s("leave.keep")}).click();
          await expect(confirm(page)).toHaveCount(0);
          await expect(panel.getByTestId("share-link-result")).toBeVisible();
          await expect(page).toHaveURL(/deviceDialog=configure/);
          await close(page);
          await confirm(page).getByRole("button", {name: s("leave.go")}).click();
          await expect(dialog(page)).toHaveCount(0);
          await expect(page).not.toHaveURL(/deviceDialog/);
          await expect(page).toHaveURL(/\/clients/);
        });

        test(`${how} asks and closes a dialog this tab pushed, and Back afterwards does not open it again`, async ({page, context, baseURL}) => {
          const panel = await pushedLink(page, context, baseURL);
          await close(page);
          await expect(confirm(page).getByText(s("leave.title"))).toBeVisible();
          await confirm(page).getByRole("button", {name: s("leave.keep")}).click();
          await expect(confirm(page)).toHaveCount(0);
          await expect(panel.getByTestId("share-link-result")).toBeVisible();
          await close(page);
          await confirm(page).getByRole("button", {name: s("leave.go")}).click();
          await expect(dialog(page)).toHaveCount(0);
          await expect(page).not.toHaveURL(/deviceDialog/);
          await page.goBack();
          await expect(dialog(page)).toHaveCount(0);
          await expect(page).not.toHaveURL(/deviceDialog/);
        });
      }

      test("the Apple profile link is held the same way: Back and the version picker wait for the answer and ask once it is shown", async ({page, context, baseURL}) => {
        let release!: () => void;
        const gate = new Promise<void>((resolve) => (release = resolve));
        await page.route(/\/apple-profile$/, async (route) => {
          if (route.request().method() !== "POST") return route.fallback();
          await gate;
          return route.fallback();
        });
        await openProfiles(context, baseURL);
        await page.goto(configurePath(lang, ENDPOINT.home, "apple-tv"));
        const builder = dialog(page).getByTestId("apple-builder");
        await builder.getByRole("button", {name: s("apple.create")}).click();
        await expect(dialog(page).getByTestId("configure-back")).toBeDisabled();
        await expect(dialog(page).getByRole("radio", {name: guide(lang, "apple-tv").versions[1]!.name})).toBeDisabled();
        await expect(dialog(page).getByRole("button", {name: s("configure.startGuide")})).toBeDisabled();
        release();
        await expect(builder.getByTestId("apple-result")).toBeVisible();
        // The client picker of the dialog is held with it: a change of client would reload the flow and take the link away.
        await expect(dialog(page).getByRole("combobox", {name: s("client.label")})).toBeDisabled();
        await dialog(page).getByRole("radio", {name: guide(lang, "apple-tv").versions[1]!.name}).click();
        await expect(page.getByRole("alertdialog").getByText(s("leave.title"))).toBeVisible();
        await page.getByRole("alertdialog").getByRole("button", {name: s("leave.keep")}).click();
        await expect(builder.getByTestId("apple-result")).toBeVisible();
      });
    });

    test("S7-r2-8: the Download button saves the profile and does not navigate the panel away", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(configurePath(lang, ENDPOINT.home, "mac"));
      const builder = dialog(page).getByTestId("apple-builder");
      await builder.getByRole("button", {name: s("apple.create")}).click();
      const link = builder.getByTestId("apple-download");
      await expect(link).toBeVisible();
      // A desktop browser: the answer of an error would be a failed download, not the panel replaced by JSON. (An Apple touch device opens it in a tab of its own.)
      await expect(link).toHaveAttribute("download", "");
      await expect(link).not.toHaveAttribute("target", /./);
    });

    test("S7-r2-5: a folder of the profile goes into the Apple request as from_folder_id", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(configurePath(lang, ENDPOINT.home, "ios"));
      const builder = dialog(page).getByTestId("apple-builder");
      await builder.getByRole("button", {name: s("apple.advanced")}).click();
      await builder.getByRole("button", {name: new RegExp(s("apple.folder"))}).click();
      await page.getByRole("option", {name: "Work"}).click();
      const posted = page.waitForRequest((r) => r.method() === "POST" && r.url().endsWith("/apple-profile"));
      await builder.getByRole("button", {name: s("apple.create")}).click();
      expect((await posted).postDataJSON()).toEqual({protocol: "doh", from_folder_id: FOLDER.work});
    });

    test("the Resolvers button of the Endpoint frame opens the Resolvers dialog, and Help me configure there opens this wizard", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.home, "clients"));
      await page.getByRole("button", {name: endpointsText(lang, "frame.resolversAria", {name: "Home router"})}).click();
      await expect(page).toHaveURL(new RegExp(`deviceDialog=resolvers&deviceId=${ENDPOINT.home}`));
      await expect(dialog(page).getByTestId("resolver-sections")).toBeVisible();
      await dialog(page).getByRole("button", {name: s("resolvers.configureAria", {name: "Home router"})}).click();
      await expect(dialog(page).getByTestId("configure-home")).toBeVisible();
      await dialog(page).getByRole("button", {name: commonText(lang, "close")}).first().click();
      await expect(dialog(page)).toHaveCount(0);
    });
  });
}
