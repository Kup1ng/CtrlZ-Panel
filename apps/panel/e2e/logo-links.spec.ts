import type {Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {err, fieldText} from "./account-support.ts";
import {LANGS, openProfiles, profilesPath} from "./profiles-support.ts";
import {apiDocsPath, apiText, docsPath, logoButton, openLogoMenu, shellText, statusPath} from "./s8-support.ts";

// The logo menu and what it reaches (spec p3 10, FE 8.3; Plan T-125): Docs and Status are pages of the panel, Request Feature and Contact open a
// dialog that posts `/feedback`, and no entry, page or index in the shell links outside the origin. Mock mode.

test.beforeEach(({guard}) => guard.allowConsole(/status of (422|429|503)/));

/** Every address the page links to: an `<a href>` or a menu item with one, as written in the document. */
const hrefs = (page: Page) => page.evaluate(() => [...document.querySelectorAll("[href]")].map((el) => el.getAttribute("href") ?? ""));
const isInternal = (href: string) => href.startsWith("/") && !href.startsWith("//") || href.startsWith("#");

for (const {lang, dir} of LANGS) {
  test.describe(`logo menu, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 900}});
    const S = (path: string, values?: Record<string, string | number>) => shellText(lang, path, values);
    const A = (path: string, values?: Record<string, string | number>) => apiText(lang, path, values);
    const dialog = (page: Page) => page.getByRole("dialog");
    const open = async (page: Page) => {
      await page.goto(profilesPath(lang));
      await openLogoMenu(page, lang);
    };

    test("T-125: the menu has Docs, Status, Request Feature and Contact beside the version, language and theme, and every address is inside the panel", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await open(page);
      const menu = page.getByRole("menu");
      for (const key of ["docs", "status", "feature", "contact"]) await expect(menu.getByRole("menuitem", {name: S(`logoMenu.${key}`)})).toBeVisible();
      await expect(menu.getByRole("menuitemradio")).toHaveCount(5);
      for (const href of await menu.evaluate((el) => [...el.querySelectorAll("[href]")].map((a) => a.getAttribute("href") ?? ""))) expect(isInternal(href), href).toBe(true);
      await expect(menu.getByRole("menuitem", {name: S("logoMenu.docs")})).toHaveAttribute("href", new RegExp(`/${lang}/docs$|^/docs$`));
      await expect(menu.getByRole("menuitem", {name: S("logoMenu.status")})).toHaveAttribute("href", new RegExp(`/${lang}/status$|^/status$`));
    });

    test("T-125: Docs and Status open pages of the panel", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await open(page);
      await page.getByRole("menuitem", {name: S("logoMenu.docs")}).click();
      await expect(page).toHaveURL(new RegExp(`${docsPath(lang)}$`));
      await expect(page.getByRole("heading", {level: 1, name: A("docsPage.title")})).toBeVisible();
      await logoButton(page, lang).click();
      await page.getByRole("menuitem", {name: S("logoMenu.status")}).click();
      await expect(page).toHaveURL(new RegExp(`${statusPath(lang)}$`));
      await expect(page.getByRole("heading", {level: 1, name: A("statusPage.title")})).toBeVisible();
    });

    test("T-125: no page the menu reaches, and not the shell around them, links outside the origin", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      for (const path of [profilesPath(lang), docsPath(lang), statusPath(lang), apiDocsPath(lang)]) {
        await page.goto(path);
        await expect(page.locator("main, [data-screen]").first()).toBeVisible();
        const links = await hrefs(page);
        expect(links.length, path).toBeGreaterThan(0);
        for (const href of links) expect(isInternal(href), `${path}: ${href}`).toBe(true);
        expect(await page.locator("[target=_blank]").count(), `${path}: a link that opens another window`).toBe(0);
      }
    });

    test("T-125: the Docs index lists the guides of the panel, each one a link inside it", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(docsPath(lang));
      await expect(page.locator("[data-docs-section]")).toHaveCount(2);
      for (const id of ["profiles", "endpoints", "apiDocs", "apiTokens", "status"]) {
        const link = page.getByRole("link", {name: new RegExp(A(`docsPage.entries.${id}.title`))}).first();
        await expect(link).toBeVisible();
        expect(isInternal((await link.getAttribute("href")) ?? ""), id).toBe(true);
      }
      await page.getByRole("link", {name: new RegExp(A("docsPage.entries.apiDocs.title"))}).first().click();
      await expect(page).toHaveURL(new RegExp(`${apiDocsPath(lang)}$`));
    });

    for (const kind of ["feature", "contact"] as const) {
      test(`T-125: ${kind === "feature" ? "Request Feature" : "Contact"} posts the message with its line breaks, and nothing else`, async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL);
        await open(page);
        await page.getByRole("menuitem", {name: S(`logoMenu.${kind}`)}).click();
        const box = dialog(page);
        await expect(box.getByRole("heading", {name: S(`feedback.${kind}.title`)})).toBeVisible();
        await box.getByRole("textbox", {name: S(`feedback.${kind}.label`)}).fill("  first line\n\nsecond line  ");
        await box.getByRole("button", {name: S("feedback.send")}).click();
        await expect(page.getByText(S(`feedback.${kind}.sent`))).toBeVisible();
        await expect(dialog(page)).toHaveCount(0);
        expect(mock.screens.feedback).toEqual([{kind, body: "first line\n\nsecond line"}]);
        // The draft went with the dialog.
        await logoButton(page, lang).click();
        await page.getByRole("menuitem", {name: S(`logoMenu.${kind}`)}).click();
        await expect(dialog(page).getByRole("textbox", {name: S(`feedback.${kind}.label`)})).toHaveValue("");
      });
    }

    test("T-125: an empty message, or one of blanks, is refused on the field before any request", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await open(page);
      await page.getByRole("menuitem", {name: S("logoMenu.feature")}).click();
      const box = dialog(page);
      await box.getByRole("button", {name: S("feedback.send")}).click();
      await expect(box.getByText(fieldText(lang, "required"))).toBeVisible();
      await box.getByRole("textbox").fill("  \n \t ");
      await box.getByRole("button", {name: S("feedback.send")}).click();
      await expect(box.getByText(fieldText(lang, "required"))).toBeVisible();
      expect(mock.count("POST /feedback")).toBe(0);
    });

    test("T-125: a message over 4,000 characters is refused, with the count in view", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await open(page);
      await page.getByRole("menuitem", {name: S("logoMenu.contact")}).click();
      const box = dialog(page);
      await box.getByRole("textbox").fill("x".repeat(4001));
      await expect(box.getByTestId("feedback-body")).toBeVisible();
      await box.getByRole("button", {name: S("feedback.send")}).click();
      await expect(box.getByText(fieldText(lang, "too_long"))).toBeVisible();
      expect(mock.count("POST /feedback")).toBe(0);
    });

    // S8-r1-1: the API's `multiline` pattern refuses a format character as the first one, and a message pasted from Telegram opens with a direction mark.
    test("T-125: a message that opens with direction marks is sent without them, and the marks inside it stay", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await open(page);
      await page.getByRole("menuitem", {name: S("logoMenu.contact")}).click();
      const box = dialog(page);
      await box.getByRole("textbox", {name: S("feedback.contact.label")}).fill("‏‎  سلام\n‏دنیا");
      await box.getByRole("button", {name: S("feedback.send")}).click();
      await expect(dialog(page)).toHaveCount(0);
      expect(mock.screens.feedback).toEqual([{kind: "contact", body: "سلام\n‏دنیا"}]);
    });

    test("T-125: a message of direction marks alone is refused as missing, before any request", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await open(page);
      await page.getByRole("menuitem", {name: S("logoMenu.feature")}).click();
      const box = dialog(page);
      await box.getByRole("textbox").fill("‏‎‍؜");
      await box.getByRole("button", {name: S("feedback.send")}).click();
      await expect(box.getByText(fieldText(lang, "required"))).toBeVisible();
      expect(mock.count("POST /feedback")).toBe(0);
    });

    test("T-125: the twenty a day is the ordinary wait: the message stays and the button waits", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {handlers: {"POST /feedback": err(429, "rate_limited", {retry_after_s: 30})}});
      await open(page);
      await page.getByRole("menuitem", {name: S("logoMenu.feature")}).click();
      const box = dialog(page);
      await box.getByRole("textbox").fill("Please add X");
      await box.getByRole("button", {name: S("feedback.send")}).click();
      await expect(box.getByRole("button", {name: S("feedback.send")})).toHaveCount(0);
      await expect(box.locator("button[type=submit]")).toBeDisabled();
      await expect(box.getByRole("textbox")).toHaveValue("Please add X");
    });

    test("T-125: Escape closes the dialog without sending, and the focus goes back to the menu button", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await open(page);
      await page.getByRole("menuitem", {name: S("logoMenu.contact")}).click();
      await dialog(page).getByRole("textbox").fill("draft");
      await page.keyboard.press("Escape");
      await expect(dialog(page)).toHaveCount(0);
      expect(mock.count("POST /feedback")).toBe(0);
      await expect(logoButton(page, lang)).toBeFocused();
    });

    // S8-r1-3: below 768 px the menu is inside a full-screen sheet; a route change from it must not leave the sheet over the new page.
    test.describe("on a phone", () => {
      test.use({viewport: {width: 375, height: 800}});

      for (const entry of ["docs", "status"] as const) {
        test(`T-125: ${entry} closes the panel over the page it opens`, async ({page, context, baseURL}) => {
          await openProfiles(context, baseURL);
          await open(page);
          await page.getByRole("menuitem", {name: S(`logoMenu.${entry}`)}).click();
          await expect(page).toHaveURL(new RegExp(`${entry === "docs" ? docsPath(lang) : statusPath(lang)}$`));
          await expect(page.getByRole("heading", {level: 1, name: A(entry === "docs" ? "docsPage.title" : "statusPage.title")})).toBeVisible();
          // The logo button lives in the panel, so with the panel closed no visible one is left.
          await expect(logoButton(page, lang)).toHaveCount(0);
          await expect(page.getByRole("button", {name: S("sidebar.openMenu")})).toBeVisible();
        });
      }
    });
  });
}
