import {readFileSync} from "node:fs";

import type {Page} from "@playwright/test";
import {errorBody} from "@ctrlz/api-client/testing/fixtures.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {digits, header, openMenu, profileFile, profileRow, profileRows, regionName, rowNames, searchField} from "./profiles-list-support.ts";
import {LANGS, PROFILE, openProfiles, profileActions, profilePath, profilesPath, screen, text, type Lang} from "./profiles-support.ts";

// The profile list and its dialogs (package S1 of P2, spec p2 9.1 and 9.2), in mock mode: T-127, T-128, T-129, T-131, T-132, T-133, T-134,
// T-135 and T-136. Each case names its rows. The header's Endpoint menu and Add Endpoint (T-137) are in profiles-endpoints.spec.ts.

test.use({viewport: {width: 1280, height: 800}});

const dialogNamed = (page: Page, lang: Lang, key: string, values: Record<string, string | number> = {}) =>
  page.getByRole("dialog", {name: text(lang, "profiles", key, values), exact: true});

const flaggedToast = (lang: Lang) => (lang === "fa" ? /مقصد فعلاً در دسترس نیست/ : /not available yet and acts? as Bypass/);

for (const {lang, dir} of LANGS) {
  test.describe(`${lang} (${dir})`, () => {
    test("T-127: a row has the name, the Endpoint line, four counters in the language's digits and the flag of a redirecting Default Rule", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 200});
      await page.goto(profilesPath(lang));
      await expect(screen(page, "profiles-list")).toBeVisible();
      await expect(profileRows(page, lang)).toHaveCount(5);

      const home = profileRow(page, lang, "Home");
      const enabled = mock.screens.filters.get(PROFILE.home)!.filter((f) => f.enabled).length;
      const expected = {filters: enabled, services: mock.screens.services.get(PROFILE.home)!.length, rules: 200, options: Object.keys(mock.screens.options.get(PROFILE.home)!).filter((k) => k !== "default_location_unavailable").length};
      for (const tab of ["filters", "services", "rules", "options"] as const) {
        const name = text(lang, "profiles", "counters.aria", {label: text(lang, "profiles", `counters.${tab}`), name: "Home", count: digits(lang, expected[tab])});
        await expect(home.getByRole("link", {name})).toBeVisible();
      }
      // Two Endpoints: the line is a menu button that counts them.
      await expect(home.getByRole("button", {name: /Home/})).toContainText(lang === "fa" ? "۲ اندپوینت" : "2 Endpoints");

      // Travel redirects to Germany: the flag is decoration, so the same fact is in the link's name.
      const travel = profileRow(page, lang, "Travel");
      await expect(travel.locator("[data-row-main]")).toContainText(regionName(lang, "DE"));
      await expect(travel.locator(".flag")).toHaveCount(1);
      // A row with no redirect has no badge.
      await expect(home.locator(".flag")).toHaveCount(0);

      // Status is a word, not only a colour or an icon.
      await expect(profileRow(page, lang, "Office")).toContainText(text(lang, "profiles", "list.locked"));
      await expect(profileRow(page, lang, "Gaming")).toContainText(text(lang, "profiles", "list.disabled"));
      await expect(profileRow(page, lang, "پروفایل فارسی")).toBeVisible();
    });

    test("T-135: a click on the row opens Options, and a click on a counter opens that tab", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {rules: 200});
      await page.goto(profilesPath(lang));
      const home = profileRow(page, lang, "Home");
      const box = (await home.boundingBox())!;
      // The empty middle of the row, away from the name, the Endpoint line and the counters.
      await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
      await expect(page).toHaveURL(new RegExp(`/${lang}/profiles/${PROFILE.home}/options$`));
      await expect(screen(page, "profile-options")).toBeVisible();
      await page.goBack();
      await expect(screen(page, "profiles-list")).toBeVisible();
      for (const [tab, segment] of [["filters", "filters"], ["services", "services"], ["rules", "custom-rules"], ["options", "options"]] as const) {
        await profileRow(page, lang, "Home").getByRole("link", {name: new RegExp(text(lang, "profiles", `counters.${tab}`))}).click();
        await expect(page).toHaveURL(new RegExp(`/profiles/${PROFILE.home}/${segment}$`));
        await page.goBack();
        await expect(screen(page, "profiles-list")).toBeVisible();
      }
    });

    test("S1-r3-4: at 1024px a locked, disabled profile with no Endpoint keeps all it shows inside its row", async ({page, context, baseURL}) => {
      // A list width a little over the one-line breakpoint (the window is 1024 and the sidebar takes 280): the row has the least room here.
      await page.setViewportSize({width: 1024, height: 800});
      const mock = await openProfiles(context, baseURL, {rules: 200});
      const gaming = mock.screens.profiles.find((p) => p.name === "Gaming")!;
      gaming.locked = true;
      gaming.lock_message = "Ask the admin";
      await page.goto(profilesPath(lang));
      const row = profileRow(page, lang, "Gaming");
      await expect(row).toContainText(text(lang, "profiles", "list.locked"));
      await expect(row).toContainText(text(lang, "profiles", "list.disabled"));
      await expect(row.getByRole("link", {name: text(lang, "profiles", "frame.addEndpointAria", {name: "Gaming"})})).toBeVisible();
      const box = (await row.boundingBox())!;
      expect(box.height).toBeGreaterThanOrEqual(75);
      // Nothing the row draws is outside it, however many lines the Endpoint line needs.
      const outside = await row.evaluate((el) => {
        const frame = el.getBoundingClientRect();
        return [...el.querySelectorAll<HTMLElement>("*")]
          .filter((child) => child.getClientRects().length > 0 && !child.closest(".sr-only"))
          .map((child) => ({child, rect: child.getBoundingClientRect()}))
          .filter(({rect}) => rect.width > 0 && (rect.top < frame.top - 1 || rect.bottom > frame.bottom + 1 || rect.left < frame.left - 1 || rect.right > frame.right + 1))
          .map(({child}) => child.tagName.toLowerCase() + "." + child.className);
      });
      expect(outside).toEqual([]);
    });

    test("T-128: the search finds a profile by name, Persian letters included, and says when none matches", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilesPath(lang));
      const field = await searchField(page, lang);
      await field.fill("gam");
      await expect(profileRows(page, lang)).toHaveCount(1);
      await expect(profileRow(page, lang, "Gaming")).toBeVisible();
      // Arabic yeh and kaf are read as the Persian letters.
      await field.fill("پروفايل");
      await expect(profileRow(page, lang, "پروفایل فارسی")).toBeVisible();
      await field.fill("nothing like it");
      await expect(page.getByText(text(lang, "profiles", "list.searchEmpty"))).toBeVisible();
      await field.fill("");
      await expect(profileRows(page, lang)).toHaveCount(5);
    });

    test("T-128: the menu sorts by name with the locale's collation and by last change, and says which is on", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(profilesPath(lang));
      const collator = new Intl.Collator(lang);
      const byName = mock.screens.profiles.map((p) => p.name).toSorted(collator.compare);
      const byChange = mock.screens.profiles.toSorted((a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at) || collator.compare(a.name, b.name)).map((p) => p.name);

      await expect.poll(() => rowNames(page, lang)).toEqual(byChange);
      let menu = await openMenu(page, lang);
      // The current choice is said in words.
      await expect(menu.getByRole("menuitem", {name: text(lang, "profiles", "list.menu.sortChangedOn")})).toBeVisible();
      await menu.getByRole("menuitem", {name: text(lang, "profiles", "list.menu.sortName")}).click();
      await expect.poll(() => rowNames(page, lang)).toEqual(byName);
      await expect(page.getByRole("status").filter({hasText: text(lang, "profiles", "list.sortBy.name")})).toBeVisible();
      menu = await openMenu(page, lang);
      await expect(menu.getByRole("menuitem", {name: text(lang, "profiles", "list.menu.sortNameOn")})).toBeVisible();
      await menu.getByRole("menuitem", {name: text(lang, "profiles", "list.menu.sortChanged")}).click();
      await expect.poll(() => rowNames(page, lang)).toEqual(byChange);
    });

    test("T-128: the menu has Import, and the + button opens the add dialog", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilesPath(lang));
      const menu = await openMenu(page, lang);
      await menu.getByRole("menuitem", {name: text(lang, "profiles", "list.menu.import")}).click();
      await expect(page).toHaveURL(/profileDialog=import/);
      await expect(dialogNamed(page, lang, "dialogs.import.title")).toBeVisible();
      await page.keyboard.press("Escape");
      await expect(page).not.toHaveURL(/profileDialog/);
      await page.getByRole("button", {name: text(lang, "profiles", "list.create"), exact: true}).click();
      await expect(page).toHaveURL(/profileDialog=add/);
      await expect(dialogNamed(page, lang, "dialogs.add.title")).toBeVisible();
    });

    test("a tenant with no profile sees the empty state, and its button opens the add dialog", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {empty: true});
      await page.goto(profilesPath(lang));
      await expect(page.getByText(text(lang, "profiles", "list.empty"))).toBeVisible();
      await page.getByRole("button", {name: text(lang, "profiles", "list.create"), exact: true}).nth(1).click();
      await expect(dialogNamed(page, lang, "dialogs.add.title")).toBeVisible();
    });

    test.describe("the list cannot be read", () => {
      test.use({allowConsole: [/status of 500/]});

      test("a failed read shows the section's error with Retry, and Retry asks again", async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL, {handlers: {"GET /profiles": {status: 500, body: errorBody("internal")}}});
        await page.goto(profilesPath(lang));
        await expect(page.getByRole("alert").filter({hasText: /req-fixture-1/})).toBeVisible();
        const before = mock.calls.filter((c) => c.method === "GET" && c.path === "/profiles").length;
        await page.getByRole("button", {name: lang === "fa" ? "تلاش دوباره" : "Try again"}).click();
        await expect.poll(() => mock.calls.filter((c) => c.method === "GET" && c.path === "/profiles").length).toBeGreaterThan(before);
      });
    });

    test("a dialog address that is not one of the five opens nothing, and a direct link to one opens it", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(`${profilesPath(lang)}?profileDialog=nonsense`);
      await expect(screen(page, "profiles-list")).toBeVisible();
      await expect(page.getByRole("dialog")).toHaveCount(0);
      await page.goto(`${profilesPath(lang)}?profileDialog=add`);
      await expect(dialogNamed(page, lang, "dialogs.add.title")).toBeVisible();
      await page.reload();
      await expect(dialogNamed(page, lang, "dialogs.add.title")).toBeVisible();
    });

    // ---- Add: T-129, T-136 ----

    test("T-129: the add dialog offers the seven types as cards with their text, and creates the one chosen", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(`${profilesPath(lang)}?profileDialog=add`);
      const dialog = dialogNamed(page, lang, "dialogs.add.title");
      await expect(dialog.getByRole("radio")).toHaveCount(7);
      for (const kind of ["custom", "developer", "gaming", "kids", "privacy", "productivity", "vpn_replacement"]) {
        await expect(dialog.getByRole("radio", {name: new RegExp(`^${text(lang, "profiles", `kinds.${kind}.name`)}`)})).toBeAttached();
        await expect(dialog.getByText(text(lang, "profiles", `kinds.${kind}.text`), {exact: true})).toBeVisible();
      }
      // The first type is chosen, so a name alone is enough.
      await expect(dialog.getByRole("radio", {name: new RegExp(`^${text(lang, "profiles", "kinds.custom.name")}`)})).toBeChecked();
      await dialog.getByRole("radio", {name: new RegExp(`^${text(lang, "profiles", "kinds.kids.name")}`)}).check({force: true});
      await dialog.getByRole("textbox", {name: text(lang, "profiles", "dialogs.add.name")}).fill("  Study ");
      await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.add.submit")}).click();
      await expect(dialog).toBeHidden();
      await expect(page).not.toHaveURL(/profileDialog/);
      const posts = mock.calls.filter((c) => c.method === "POST" && c.path === "/profiles");
      expect(posts.map((c) => c.body)).toEqual([{name: "Study", kind: "kids"}]);
    });

    test("T-136: the new profile is first, with a highlight and the word New, until the list is left", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(`${profilesPath(lang)}?profileDialog=add`);
      const dialog = dialogNamed(page, lang, "dialogs.add.title");
      await dialog.getByRole("textbox", {name: text(lang, "profiles", "dialogs.add.name")}).fill("Zebra");
      await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.add.submit")}).click();
      await expect(dialog).toBeHidden();
      await expect.poll(async () => (await rowNames(page, lang))[0]).toBe("Zebra");
      const first = profileRows(page, lang).first();
      await expect(first).toContainText(text(lang, "profiles", "list.new"));
      await expect(first).toHaveAttribute("data-highlighted", "true");
      // Sorting by name does not take it from the top.
      const menu = await openMenu(page, lang);
      await menu.getByRole("menuitem", {name: text(lang, "profiles", "list.menu.sortName")}).click();
      await expect.poll(async () => (await rowNames(page, lang))[0]).toBe("Zebra");
      // Leaving the list ends the highlight.
      await profileRow(page, lang, "Home").getByRole("link", {name: new RegExp(text(lang, "profiles", "counters.filters"))}).click();
      await expect(screen(page, "profile-filters")).toBeVisible();
      await page.goBack();
      await expect(profileRow(page, lang, "Zebra")).not.toContainText(text(lang, "profiles", "list.new"));
    });

    test("T-129: an empty name is refused under the field before any request, and a name over 64 characters too", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(`${profilesPath(lang)}?profileDialog=add`);
      const dialog = dialogNamed(page, lang, "dialogs.add.title");
      const name = dialog.getByRole("textbox", {name: text(lang, "profiles", "dialogs.add.name")});
      await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.add.submit")}).click();
      await expect(dialog.getByText(lang === "fa" ? "این مقدار الزامی است." : /required/i).first()).toBeVisible();
      await name.fill("x".repeat(65));
      await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.add.submit")}).click();
      await expect(name).toHaveAttribute("aria-invalid", "true");
      expect(mock.calls.filter((c) => c.method === "POST" && c.path === "/profiles")).toHaveLength(0);
    });

    test("T-129: the type of a profile whose destinations are not available yet is made, and a toast says they act as Bypass", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {noLocations: true});
      await page.goto(`${profilesPath(lang)}?profileDialog=add`);
      const dialog = dialogNamed(page, lang, "dialogs.add.title");
      await dialog.getByRole("radio", {name: new RegExp(`^${text(lang, "profiles", "kinds.vpn_replacement.name")}`)}).check({force: true});
      await dialog.getByRole("textbox", {name: text(lang, "profiles", "dialogs.add.name")}).fill("Away");
      await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.add.submit")}).click();
      await expect(page.getByText(flaggedToast(lang)).first()).toBeVisible();
    });

    test("a limit on profiles shows the capacity notice in the dialog and keeps what was typed", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 422/);
      await openProfiles(context, baseURL, {limits: {max_profiles: 5}});
      await page.goto(`${profilesPath(lang)}?profileDialog=add`);
      const dialog = dialogNamed(page, lang, "dialogs.add.title");
      await dialog.getByRole("textbox", {name: text(lang, "profiles", "dialogs.add.name")}).fill("One more");
      await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.add.submit")}).click();
      await expect(dialog.getByText(lang === "fa" ? /به سقف/ : /reached the limit/).first()).toBeVisible();
      await expect(dialog.getByRole("textbox", {name: text(lang, "profiles", "dialogs.add.name")})).toHaveValue("One more");
    });

    // ---- Import: T-134 ----

    test("T-134: a file is read, sent as base64 with an Idempotency-Key, and the profile it makes is first", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(`${profilesPath(lang)}?profileDialog=import`);
      const dialog = dialogNamed(page, lang, "dialogs.import.title");
      const submit = dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.import.submit"), exact: true});
      // Nothing chosen: Import is off.
      await expect(submit).toBeDisabled();
      const file = profileFile("Imported");
      await dialog.locator('input[type="file"]').setInputFiles(file);
      await expect(dialog.getByText("profile.json")).toBeVisible();
      await expect(submit).toBeEnabled();
      await submit.click();
      await expect(dialog).toBeHidden();
      const posts = mock.calls.filter((c) => c.method === "POST" && c.path === "/profiles:import");
      expect(posts).toHaveLength(1);
      expect(Buffer.from((posts[0]!.body as {document: string}).document, "base64").toString("utf8")).toBe(file.buffer.toString("utf8"));
      expect(posts[0]!.headers["idempotency-key"]).toMatch(/^[0-9a-f-]{36}$/);
      await expect.poll(async () => (await rowNames(page, lang))[0]).toBe("Imported");
      await expect(page.getByText(text(lang, "profiles", "dialogs.import.imported", {name: "Imported"}))).toBeVisible();
    });

    test("T-134: a file over 4 MiB is refused in the dialog and nothing is sent", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(`${profilesPath(lang)}?profileDialog=import`);
      const dialog = dialogNamed(page, lang, "dialogs.import.title");
      await dialog.locator('input[type="file"]').setInputFiles({name: "big.json", mimeType: "application/json", buffer: Buffer.alloc(4 * 1024 * 1024 + 1, 32)});
      await expect(dialog.getByText(text(lang, "profiles", "dialogs.import.tooLarge"))).toBeVisible();
      await expect(dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.import.submit"), exact: true})).toBeDisabled();
      expect(mock.calls.filter((c) => c.path === "/profiles:import")).toHaveLength(0);
    });

    test.describe("a file the API refuses", () => {
      test.use({allowConsole: [/status of 422/]});

      test("T-134: each problem is a sentence with its JSON pointer in Tech, and the file stays chosen for a new try", async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL, {
          handlers: {
            "POST /profiles:import": {
              status: 422,
              body: errorBody("validation_failed", {
                fields: [
                  {name: "/rules/12/pattern", code: "pattern_star_count"},
                  {name: "/services/3/slug", code: "unknown"},
                  {name: "", code: "format_unknown"},
                ],
              }),
            },
          },
        });
        await page.goto(`${profilesPath(lang)}?profileDialog=import`);
        const dialog = dialogNamed(page, lang, "dialogs.import.title");
        await dialog.locator('input[type="file"]').setInputFiles(profileFile("Bad"));
        await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.import.submit"), exact: true}).click();
        const problems = dialog.getByTestId("import-problems");
        await expect(problems).toBeVisible();
        await expect(problems.locator("bdi[dir=ltr]").filter({hasText: "/rules/12/pattern"})).toBeVisible();
        await expect(problems.locator("bdi[dir=ltr]").filter({hasText: "/services/3/slug"})).toBeVisible();
        // The whole file is named in words, and no code is shown raw.
        await expect(problems).toContainText(text(lang, "profiles", "dialogs.import.wholeFile"));
        await expect(problems).not.toContainText("pattern_star_count");
        await expect(problems).not.toContainText("format_unknown");
        await expect(dialog.getByText("profile.json")).toBeVisible();
        // A retry of the same file keeps its key (a replay), and another file gets another.
        await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.import.submit"), exact: true}).click();
        await expect.poll(() => mock.calls.filter((c) => c.path === "/profiles:import").length).toBe(2);
        const [first, second] = mock.calls.filter((c) => c.path === "/profiles:import");
        expect(second!.headers["idempotency-key"]).toBe(first!.headers["idempotency-key"]);
        await dialog.locator('input[type="file"]').setInputFiles(profileFile("Other"));
        await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.import.submit"), exact: true}).click();
        await expect.poll(() => mock.calls.filter((c) => c.path === "/profiles:import").length).toBe(3);
        expect(mock.calls.filter((c) => c.path === "/profiles:import")[2]!.headers["idempotency-key"]).not.toBe(first!.headers["idempotency-key"]);
      });
    });

    test("T-134: a big file is a job, followed in its own dialog until it is done, with no job id in the address", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(`${profilesPath(lang)}?profileDialog=import`);
      const dialog = dialogNamed(page, lang, "dialogs.import.title");
      await dialog.locator('input[type="file"]').setInputFiles(profileFile("Huge", {pad: "x".repeat(6_000)}));
      await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.import.submit"), exact: true}).click();
      await expect(dialog).toBeHidden();
      const job = dialogNamed(page, lang, "dialogs.job.import");
      await expect(job).toBeVisible();
      await expect(job.getByText(lang === "fa" ? "تمام شد" : "Done", {exact: true})).toBeVisible({timeout: 15_000});
      // The address holds no job id.
      expect(page.url()).not.toMatch(/jb|job/i);
    });

    // A 409 job_running (T-192), the job paths of Import and Duplicate and a locked profile in the Delete dialog are in profiles.jobs.spec.ts.


    // ---- Duplicate: T-131 ----

    test("T-131: Duplicate asks for a name, makes the copy, says so, and opens the list with the copy first", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.office, "options"));
      // Office is locked: reading is allowed, so it can be copied.
      await profileActions(page).getByRole("button", {name: text(lang, "profiles", "frame.duplicateAria", {name: "Office"})}).click();
      await expect(page).toHaveURL(/profileDialog=duplicate/);
      const dialog = dialogNamed(page, lang, "dialogs.duplicate.title", {name: "Office"});
      const field = dialog.getByRole("textbox", {name: text(lang, "profiles", "dialogs.duplicate.name")});
      await expect(field).toHaveValue(text(lang, "profiles", "dialogs.duplicate.defaultName", {name: "Office"}));
      await field.fill("Office at home");
      await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.duplicate.submit")}).click();
      await expect(page).toHaveURL(new RegExp(`/${lang}/profiles$`));
      await expect(page.getByText(text(lang, "profiles", "dialogs.duplicate.done", {name: "Office at home"}))).toBeVisible();
      await expect.poll(async () => (await rowNames(page, lang))[0]).toBe("Office at home");
      await expect(profileRows(page, lang).first()).toHaveAttribute("data-highlighted", "true");
      const posts = mock.calls.filter((c) => c.method === "POST" && c.path.endsWith(":duplicate"));
      expect(posts).toHaveLength(1);
      expect(posts[0]!.path).toBe(`/profiles/${PROFILE.office}:duplicate`);
      expect(posts[0]!.body).toEqual({name: "Office at home"});
      expect(posts[0]!.headers["idempotency-key"]).toMatch(/^[0-9a-f-]{36}$/);
    });

    test.describe("a copy the API refuses", () => {
      test.use({allowConsole: [/status of 422/]});

      test("T-525: a rule that redirects an Iranian name is named by its pointer, with what to do first", async ({page, context, baseURL}) => {
        await openProfiles(context, baseURL, {
          handlers: {"POST /profiles/{id}:duplicate": {status: 422, body: errorBody("validation_failed", {fields: [{name: "/rules/4/action", code: "iranian_name"}, {name: "/services/aparat/action", code: "iranian_name"}]})}},
        });
        await page.goto(`${profilePath(lang, PROFILE.home, "options")}?profileDialog=duplicate`);
        const dialog = dialogNamed(page, lang, "dialogs.duplicate.title", {name: "Home"});
        await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.duplicate.submit")}).click();
        const note = dialog.getByTestId("duplicate-iranian");
        await expect(note).toContainText(text(lang, "profiles", "dialogs.duplicate.iranianTitle"));
        await expect(note.locator("bdi[dir=ltr]").filter({hasText: "/rules/4/action"})).toBeVisible();
        await expect(note.locator("bdi[dir=ltr]").filter({hasText: "/services/aparat/action"})).toBeVisible();
        await expect(dialog).toBeVisible();
      });
    });

    // ---- Delete: T-132 ----

    test("T-132: Delete asks first, then removes the profile and goes back to the list", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.gaming, "options"));
      await profileActions(page).getByRole("button", {name: text(lang, "profiles", "frame.deleteAria", {name: "Gaming"})}).click();
      const dialog = page.getByRole("alertdialog", {name: text(lang, "profiles", "dialogs.delete.title", {name: "Gaming"})});
      await expect(dialog).toBeVisible();
      await expect(dialog).toContainText(text(lang, "profiles", "dialogs.delete.text", {name: "Gaming"}));
      expect(mock.calls.filter((c) => c.method === "DELETE")).toHaveLength(0);
      // Cancel changes nothing.
      await dialog.getByRole("button", {name: lang === "fa" ? "انصراف" : "Cancel"}).click();
      await expect(dialog).toBeHidden();
      expect(mock.calls.filter((c) => c.method === "DELETE")).toHaveLength(0);
      await profileActions(page).getByRole("button", {name: text(lang, "profiles", "frame.deleteAria", {name: "Gaming"})}).click();
      await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.delete.submit")}).click();
      await expect(page).toHaveURL(new RegExp(`/${lang}/profiles$`));
      await expect(page.getByText(text(lang, "profiles", "dialogs.delete.done", {name: "Gaming"}))).toBeVisible();
      await expect(profileRows(page, lang)).toHaveCount(4);
      expect(mock.calls.filter((c) => c.method === "DELETE").map((c) => c.path)).toEqual([`/profiles/${PROFILE.gaming}`]);
    });

    test("T-132: a profile an Endpoint uses says so, names the Endpoints as links, and cannot be deleted", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(`${profilePath(lang, PROFILE.home, "options")}?profileDialog=delete`);
      const dialog = page.getByRole("alertdialog", {name: text(lang, "profiles", "dialogs.delete.title", {name: "Home"})});
      const note = dialog.getByTestId("delete-in-use");
      await expect(note).toContainText(text(lang, "profiles", "dialogs.delete.inUseTitle"));
      await expect(note.getByRole("link", {name: "Home router"})).toHaveAttribute("href", /\/endpoints\/.+\/clients$/);
      await expect(note.getByRole("link", {name: "Laptop"})).toBeVisible();
      await expect(dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.delete.submit")})).toBeDisabled();
      expect(mock.calls.filter((c) => c.method === "DELETE")).toHaveLength(0);
    });

    test.describe("the page's copy of a profile is out of date", () => {
      test.use({allowConsole: [/status of 409/]});

      test("T-132: a 409 profile_in_use from the API reads the same way", async ({page, context, baseURL}) => {
        await openProfiles(context, baseURL, {handlers: {"DELETE /profiles/{id}": {status: 409, body: errorBody("profile_in_use")}}});
        await page.goto(`${profilePath(lang, PROFILE.gaming, "options")}?profileDialog=delete`);
        const dialog = page.getByRole("alertdialog", {name: text(lang, "profiles", "dialogs.delete.title", {name: "Gaming"})});
        await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.delete.submit")}).click();
        await expect(dialog.getByTestId("delete-in-use")).toBeVisible();
        await expect(dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.delete.submit")})).toBeDisabled();
      });
    });

    // ---- Export: T-133 ----

    test("T-133: Export saves the profile's document as a JSON file named for it", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.home, "options"));
      const [download] = await Promise.all([
        page.waitForEvent("download"),
        profileActions(page).getByRole("button", {name: text(lang, "profiles", "frame.exportAria", {name: "Home"})}).click(),
      ]);
      expect(download.suggestedFilename()).toBe("ctrlz-profile-Home.json");
      const saved = JSON.parse(readFileSync((await download.path())!, "utf8")) as {format: string; version: number; name: string};
      expect(saved).toMatchObject({format: "ctrlz-profile", version: 1, name: "Home"});
      // The document has no id, no lock and no hash.
      expect(JSON.stringify(saved)).not.toMatch(/lock|hash|tenant/i);
    });

    test("every control of the list and its dialogs is named for its subject", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilesPath(lang));
      for (const name of ["Home", "Office", "Gaming", "Travel"]) {
        const row = profileRow(page, lang, name);
        for (const button of await row.getByRole("button").all()) expect(await button.getAttribute("aria-label")).toContain(name);
        for (const link of await row.locator("a.row-counter").all()) expect(await link.getAttribute("aria-label")).toContain(name);
      }
      await expect(page.getByRole("button", {name: header(lang, "more")})).toBeVisible();
    });
  });
}
