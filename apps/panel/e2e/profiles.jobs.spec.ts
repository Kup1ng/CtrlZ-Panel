import type {Page} from "@playwright/test";
import {errorBody} from "@ctrlz/api-client/testing/fixtures.ts";
import {profileFixture, uid} from "@ctrlz/api-client/testing/screenFixtures.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {digits, jobReads, profileFile, profileRows, rowNames, sidebarProfilesLink} from "./profiles-list-support.ts";
import {LANGS, PROFILE, openProfiles, profileActions, profilePath, profilesPath, text, type Lang, type ScreensMock} from "./profiles-support.ts";

// The job paths of Import and Duplicate, and the answers that need a closer look (package S1 of P2, round 1): the job that ends while its
// dialog is closed (S1-r1-1, 2, 9, 12), a 409 `job_running` that does not start the request (S1-r1-10), a locked profile in the Delete dialog
// (S1-r1-13), the Idempotency-Key of a file (S1-r1-4), the 100 problems of a file (S1-r1-5), the digits of the hints (S1-r1-3) and the
// names that carry their visible text (S1-r1-7). Round 2: the job dialog and its announcements do not come back with the screen (S1-r2-1),
// a job that ends with the session is not followed into the next one (S1-r2-4) and a job the API no longer knows is not polled (S1-r2-5).
// Round 3: a job that goes 404 under an open dialog is said to be gone (S1-r3-3), and an answer after the session ended is dropped (S1-r3-5).

test.use({viewport: {width: 1280, height: 800}});

const dialogNamed = (page: Page, lang: Lang, key: string, values: Record<string, string | number> = {}) =>
  page.getByRole("dialog", {name: text(lang, "profiles", key, values), exact: true});

const flaggedToast = (lang: Lang) => (lang === "fa" ? /مقصد فعلاً در دسترس نیست/ : /not available yet and acts? as Bypass/);
const submitImport = (lang: Lang) => text(lang, "profiles", "dialogs.import.submit");

/**
 * The job that Import or Duplicate started ends the way a real one does: running on its first read, then done with the profile it made
 * (`Job.profile_id`) and `flagged` destinations, so a case can see what the screen does with both.
 */
function jobMakes(mock: ScreensMock, name: string, flagged: number, decoy?: string) {
  mock.on("GET /jobs/{id}", () => {
    const s = mock.screens;
    const job = s.job!;
    s.jobReads++;
    if (s.jobReads === 1) s.job = {...job, state: "running"};
    else if (job.state !== "done") {
      const made = profileFixture(++s.nextId, {name});
      s.profiles.unshift(made);
      // A profile that another session made meanwhile, ahead of it in the list.
      if (decoy) s.profiles.unshift(profileFixture(++s.nextId, {name: decoy}));
      s.job = {...job, state: "done", progress: job.total, profile_id: made.id, result: {created: 1, updated: 0, skipped: 0, conflict: 0, flagged, items: []}};
    }
    return {body: s.job};
  });
}

/** A running job that the tenant already has, of a kind that no profile dialog makes. */
function runningJob(mock: ScreensMock, kind: "rules_batch" | "upload") {
  mock.screens.job = {id: uid("jb", 700), kind, state: "running", progress: 0, total: 5000, profile_id: PROFILE.home};
  mock.screens.jobReads = 0;
}

for (const {lang, dir} of LANGS) {
  test.describe(`${lang} (${dir})`, () => {
    test("S1-r1-1: an Import job that ends after its dialog was closed still toasts the Bypass destinations, refreshes the list and marks the new profile", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      jobMakes(mock, "From a big file", 3);
      await page.goto(`${profilesPath(lang)}?profileDialog=import`);
      const dialog = dialogNamed(page, lang, "dialogs.import.title");
      await dialog.locator('input[type="file"]').setInputFiles(profileFile("Huge", {pad: "x".repeat(6_000)}));
      await dialog.getByRole("button", {name: submitImport(lang), exact: true}).click();
      const job = dialogNamed(page, lang, "dialogs.job.import");
      await expect(job).toBeVisible();
      // The dialog is closed while the job runs: "keep going in the background".
      await job.getByRole("button", {name: text(lang, "jobs", "dialog.background"), exact: true}).click();
      await expect(job).toBeHidden();
      // Nothing has the dialog open, and the end of the job is still seen.
      await expect(page.getByText(flaggedToast(lang)).first()).toBeVisible({timeout: 15_000});
      await expect.poll(async () => (await rowNames(page, lang))[0], {timeout: 15_000}).toBe("From a big file");
      await expect(profileRows(page, lang).first()).toHaveAttribute("data-highlighted", "true");
      await expect(profileRows(page, lang).first()).toContainText(text(lang, "profiles", "list.new"));
    });

    test("S1-r1-2: the profile a job made is the one Job.profile_id names, even when another profile appeared ahead of it", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      jobMakes(mock, "The imported one", 0, "Made elsewhere");
      await page.goto(`${profilesPath(lang)}?profileDialog=import`);
      const dialog = dialogNamed(page, lang, "dialogs.import.title");
      await dialog.locator('input[type="file"]').setInputFiles(profileFile("Huge", {pad: "x".repeat(6_000)}));
      await dialog.getByRole("button", {name: submitImport(lang), exact: true}).click();
      const job = dialogNamed(page, lang, "dialogs.job.import");
      await expect(job.getByText(text(lang, "jobs", "state.done"), {exact: true})).toBeVisible({timeout: 15_000});
      await job.getByRole("button", {name: text(lang, "jobs", "dialog.close"), exact: true}).last().click();
      await expect.poll(async () => (await rowNames(page, lang)).includes("Made elsewhere")).toBe(true);
      // Exactly one row is marked, and it is the one the job made, which is first of the marked and of the list.
      await expect(page.locator('[role=listitem][data-highlighted="true"]')).toHaveCount(1);
      await expect(profileRows(page, lang).first()).toHaveAttribute("data-highlighted", "true");
      expect((await rowNames(page, lang))[0]).toBe("The imported one");
    });

    test("S1-r1-8: a Duplicate that answers 202 opens the job dialog, toasts the Bypass destinations, and the copy is first in the list after the page moved on", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      jobMakes(mock, "Home, again", 2);
      mock.on("POST /profiles/{id}:duplicate", () => {
        mock.screens.job = {id: uid("jb", 701), kind: "duplicate", state: "queued", progress: 0, total: 5000};
        mock.screens.jobReads = 0;
        return {status: 202, body: mock.screens.job};
      });
      await page.goto(`${profilePath(lang, PROFILE.home, "options")}?profileDialog=duplicate`);
      const dialog = dialogNamed(page, lang, "dialogs.duplicate.title", {name: "Home"});
      await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.duplicate.submit")}).click();
      const job = dialogNamed(page, lang, "dialogs.job.duplicate");
      await expect(job).toBeVisible();
      await expect(job.getByText(text(lang, "jobs", "state.done"), {exact: true})).toBeVisible({timeout: 15_000});
      await expect(page.getByText(flaggedToast(lang)).first()).toBeVisible();
      await job.getByRole("button", {name: text(lang, "jobs", "dialog.close"), exact: true}).last().click();
      await expect(job).toBeHidden();
      // The profile's page is left for the list by a move inside the app, and the mark is there.
      await sidebarProfilesLink(page, lang).click();
      await expect.poll(async () => (await rowNames(page, lang))[0]).toBe("Home, again");
      await expect(profileRows(page, lang).first()).toHaveAttribute("data-highlighted", "true");
    });

    test("S1-r1-9: once the job has ended and its dialog is closed, nothing asks for the job again", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      jobMakes(mock, "Carried over", 0);
      await page.goto(`${profilesPath(lang)}?profileDialog=import`);
      const dialog = dialogNamed(page, lang, "dialogs.import.title");
      await dialog.locator('input[type="file"]').setInputFiles(profileFile("Huge", {pad: "x".repeat(6_000)}));
      await dialog.getByRole("button", {name: submitImport(lang), exact: true}).click();
      const job = dialogNamed(page, lang, "dialogs.job.import");
      await job.getByRole("button", {name: text(lang, "jobs", "dialog.background"), exact: true}).click();
      await expect(job).toBeHidden();
      await expect.poll(async () => (await rowNames(page, lang))[0], {timeout: 15_000}).toBe("Carried over");
      // After the end the follower is gone: no further read of the job.
      const reads = () => mock.calls.filter((c) => c.method === "GET" && /^\/jobs\/[^/]+$/.test(c.path)).length;
      const before = reads();
      await page.waitForTimeout(2_500);
      expect(reads()).toBe(before);
    });

    test.describe("a job is already running", () => {
      test.use({allowConsole: [/status of 409/]});

      test("S1-r1-10: Import keeps its file and says the request was not started, and the running job opens under its own title when asked", async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL, {handlers: {"POST /profiles:import": {status: 409, body: errorBody("job_running")}}});
        runningJob(mock, "rules_batch");
        await page.goto(`${profilesPath(lang)}?profileDialog=import`);
        const dialog = dialogNamed(page, lang, "dialogs.import.title");
        await dialog.locator('input[type="file"]').setInputFiles(profileFile());
        await dialog.getByRole("button", {name: submitImport(lang), exact: true}).click();
        // The form stays, with its file, and no job dialog is opened on its own.
        await expect(dialog.getByTestId("job-running")).toContainText(text(lang, "profiles", "dialogs.jobRunning.text"));
        await expect(dialog.getByText("profile.json")).toBeVisible();
        await expect(dialogNamed(page, lang, "dialogs.job.import")).toHaveCount(0);
        await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.jobRunning.show")}).click();
        // The title is that of the running job (a rules batch), not "Importing a profile".
        await expect(page.getByRole("dialog", {name: text(lang, "jobs", "kind.rules_batch"), exact: true})).toBeVisible();
        await expect(dialogNamed(page, lang, "dialogs.job.import")).toHaveCount(0);
      });

      test("S1-r1-10: Duplicate keeps its name and says the request was not started", async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL, {handlers: {"POST /profiles/{id}:duplicate": {status: 409, body: errorBody("job_running")}}});
        runningJob(mock, "upload");
        await page.goto(`${profilePath(lang, PROFILE.home, "options")}?profileDialog=duplicate`);
        const dialog = dialogNamed(page, lang, "dialogs.duplicate.title", {name: "Home"});
        const field = dialog.getByRole("textbox", {name: text(lang, "profiles", "dialogs.duplicate.name")});
        await field.fill("Kept name");
        await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.duplicate.submit")}).click();
        await expect(dialog.getByTestId("job-running")).toBeVisible();
        await expect(field).toHaveValue("Kept name");
        await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.jobRunning.show")}).click();
        await expect(page.getByRole("dialog", {name: text(lang, "jobs", "kind.upload"), exact: true})).toBeVisible();
      });
    });

    // ---- Delete: S1-r1-13 ----

    test.describe("a locked profile", () => {
      test.use({allowConsole: [/status of 423/]});

      test("S1-r1-13: Delete opened by its address says the profile is locked and stays off", async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL);
        await page.goto(`${profilePath(lang, PROFILE.office, "options")}?profileDialog=delete`);
        const dialog = page.getByRole("alertdialog", {name: text(lang, "profiles", "dialogs.delete.title", {name: "Office"})});
        await expect(dialog.getByTestId("delete-locked")).toContainText(text(lang, "profiles", "dialogs.delete.lockedText"));
        await expect(dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.delete.submit")})).toBeDisabled();
        expect(mock.calls.filter((c) => c.method === "DELETE")).toHaveLength(0);
      });

      test("S1-r1-13: a 423 on Delete (a lock taken meanwhile) reads the same way", async ({page, context, baseURL}) => {
        await openProfiles(context, baseURL, {handlers: {"DELETE /profiles/{id}": {status: 423, body: errorBody("profile_locked")}}});
        await page.goto(`${profilePath(lang, PROFILE.gaming, "options")}?profileDialog=delete`);
        const dialog = page.getByRole("alertdialog", {name: text(lang, "profiles", "dialogs.delete.title", {name: "Gaming"})});
        await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.delete.submit")}).click();
        await expect(dialog.getByTestId("delete-locked")).toBeVisible();
        await expect(dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.delete.submit")})).toBeDisabled();
      });
    });

    test.describe("the page's copy of a profile is out of date", () => {
      test.use({allowConsole: [/status of 409/]});

      test("S1-r1-13: a refusal is forgotten when the dialog is closed with Back", async ({page, context, baseURL}) => {
        await openProfiles(context, baseURL, {handlers: {"DELETE /profiles/{id}": {status: 409, body: errorBody("profile_in_use")}}});
        await page.goto(profilePath(lang, PROFILE.gaming, "options"));
        const open = () => profileActions(page).getByRole("button", {name: text(lang, "profiles", "frame.deleteAria", {name: "Gaming"})}).click();
        const dialog = page.getByRole("alertdialog", {name: text(lang, "profiles", "dialogs.delete.title", {name: "Gaming"})});
        await open();
        await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.delete.submit")}).click();
        await expect(dialog.getByTestId("delete-in-use")).toBeVisible();
        await page.goBack();
        await expect(dialog).toBeHidden();
        await open();
        await expect(dialog.getByTestId("delete-in-use")).toHaveCount(0);
        await expect(dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.delete.submit")})).toBeEnabled();
      });
    });

    // ---- Import: S1-r1-3, 4, 5 ----

    test("S1-r1-3: the limits in the hints are written in the digits of the language", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(`${profilesPath(lang)}?profileDialog=add`);
      const add = dialogNamed(page, lang, "dialogs.add.title");
      await expect(add).toContainText(lang === "fa" ? `از ۱ تا ${digits(lang, 64)} نویسه.` : "1 to 64 characters.");
      if (lang === "fa") await expect(add).not.toContainText("64");
      await page.goto(`${profilesPath(lang)}?profileDialog=import`);
      const imp = dialogNamed(page, lang, "dialogs.import.title");
      await expect(imp).toContainText(lang === "fa" ? `تا ${digits(lang, 4)} مگابایت` : "up to 4 MB");
      if (lang === "fa") await expect(imp).not.toContainText("4 مگابایت");
    });

    test.describe("a file the API refuses", () => {
      test.use({allowConsole: [/status of (409|422)/]});

      test("S1-r1-4: two files of the same name and length are two requests, with two keys", async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL, {handlers: {"POST /profiles:import": {status: 422, body: errorBody("validation_failed", {fields: [{name: "/rules/1/pattern", code: "pattern_star_count"}]})}}});
        await page.goto(`${profilesPath(lang)}?profileDialog=import`);
        const dialog = dialogNamed(page, lang, "dialogs.import.title");
        const submit = dialog.getByRole("button", {name: submitImport(lang), exact: true});
        await dialog.locator('input[type="file"]').setInputFiles(profileFile("Aaaa"));
        await submit.click();
        await expect.poll(() => mock.calls.filter((c) => c.path === "/profiles:import").length).toBe(1);
        // The same size, the same name, one letter changed.
        await dialog.locator('input[type="file"]').setInputFiles(profileFile("Aaab"));
        await submit.click();
        await expect.poll(() => mock.calls.filter((c) => c.path === "/profiles:import").length).toBe(2);
        const [first, second] = mock.calls.filter((c) => c.path === "/profiles:import");
        expect(second!.headers["idempotency-key"]).not.toBe(first!.headers["idempotency-key"]);
      });

      test("S1-r1-4: a 409 idempotency_key_reused is followed by a new key on the next press", async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL, {handlers: {"POST /profiles:import": {status: 409, body: errorBody("idempotency_key_reused")}}});
        await page.goto(`${profilesPath(lang)}?profileDialog=import`);
        const dialog = dialogNamed(page, lang, "dialogs.import.title");
        const submit = dialog.getByRole("button", {name: submitImport(lang), exact: true});
        await dialog.locator('input[type="file"]').setInputFiles(profileFile());
        await submit.click();
        await expect.poll(() => mock.calls.filter((c) => c.path === "/profiles:import").length).toBe(1);
        await expect(submit).toBeEnabled();
        await submit.click();
        await expect.poll(() => mock.calls.filter((c) => c.path === "/profiles:import").length).toBe(2);
        const [first, second] = mock.calls.filter((c) => c.path === "/profiles:import");
        expect(second!.headers["idempotency-key"]).not.toBe(first!.headers["idempotency-key"]);
      });

      test("S1-r1-5: the 100 problems of a file are all listed, with a line that there may be more", async ({page, context, baseURL}) => {
        const fields = Array.from({length: 100}, (_, i) => ({name: `/rules/${i}/pattern`, code: "pattern_star_count"}));
        await openProfiles(context, baseURL, {handlers: {"POST /profiles:import": {status: 422, body: errorBody("validation_failed", {fields})}}});
        await page.goto(`${profilesPath(lang)}?profileDialog=import`);
        const dialog = dialogNamed(page, lang, "dialogs.import.title");
        await dialog.locator('input[type="file"]').setInputFiles(profileFile());
        await dialog.getByRole("button", {name: submitImport(lang), exact: true}).click();
        const problems = dialog.getByTestId("import-problems");
        await expect(problems.locator("li")).toHaveCount(100);
        await expect(problems).toContainText(text(lang, "profiles", "dialogs.import.more"));
      });
    });

    // ---- Duplicate: S1-r1-6 ----

    test.describe("a copy the API refuses", () => {
      test.use({allowConsole: [/status of 422/]});

      test("S1-r1-6: the refusal links to the Rules and Services tabs of the profile, where the rows are marked", async ({page, context, baseURL}) => {
        await openProfiles(context, baseURL, {
          handlers: {"POST /profiles/{id}:duplicate": {status: 422, body: errorBody("validation_failed", {fields: [{name: "/rules/137/action", code: "iranian_name"}]})}},
        });
        await page.goto(`${profilePath(lang, PROFILE.home, "options")}?profileDialog=duplicate`);
        const dialog = dialogNamed(page, lang, "dialogs.duplicate.title", {name: "Home"});
        await dialog.getByRole("button", {name: text(lang, "profiles", "dialogs.duplicate.submit")}).click();
        const note = dialog.getByTestId("duplicate-iranian");
        await expect(note.getByRole("link", {name: text(lang, "profiles", "dialogs.duplicate.iranianRules")})).toHaveAttribute("href", new RegExp(`/${lang}/profiles/${PROFILE.home}/custom-rules$`));
        await expect(note.getByRole("link", {name: text(lang, "profiles", "dialogs.duplicate.iranianServices")})).toHaveAttribute("href", new RegExp(`/${lang}/profiles/${PROFILE.home}/services$`));
      });
    });

    // ---- Names: S1-r1-7 ----

    test("S1-r1-7: the Endpoint menu, Add Endpoint and the counters are named with the words they show (label in name)", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(profilesPath(lang));
      await expect(profileRows(page, lang)).toHaveCount(5);
      const controls = profileRows(page, lang).locator("button[aria-label], a[aria-label]");
      expect(await controls.count()).toBeGreaterThan(8);
      for (const control of await controls.all()) {
        const visible = ((await control.innerText()) ?? "").replace(/\s+/g, " ").trim();
        const label = (await control.getAttribute("aria-label")) ?? "";
        if (visible) expect(label, `the name of "${visible}"`).toContain(visible);
      }
    });

    // ---- Round 2: the follower and the screens that come and go ----

    test("S1-r2-1: a job dialog left open is not open when the screen comes back, and the end of the job is not announced a second time", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      jobMakes(mock, "Imported once", 3);
      await page.goto(`${profilesPath(lang)}?profileDialog=import`);
      const dialog = dialogNamed(page, lang, "dialogs.import.title");
      await dialog.locator('input[type="file"]').setInputFiles(profileFile("Huge", {pad: "x".repeat(6_000)}));
      await dialog.getByRole("button", {name: submitImport(lang), exact: true}).click();
      const job = dialogNamed(page, lang, "dialogs.job.import");
      await expect(job.getByText(text(lang, "jobs", "state.done"), {exact: true})).toBeVisible({timeout: 15_000});
      const toast = page.getByText(flaggedToast(lang)).first();
      await expect(toast).toBeVisible();
      // The dialog is NOT closed. Its modal makes the sidebar inert, so the person leaves the way a modal allows (the browser's Back, a link
      // from outside): two client-side moves, to Endpoints and back, with the router the page itself uses.
      const move = (path: string) => page.evaluate((to) => (window as unknown as {next: {router: {push: (p: string) => void}}}).next.router.push(to), path);
      await move(`/${lang}/endpoints`);
      await page.waitForURL(/\/endpoints/);
      await move(`/${lang}/profiles`);
      await page.waitForURL(new RegExp(`/${lang}/profiles$`));
      await expect(profileRows(page, lang).first()).toBeVisible();
      await expect(dialogNamed(page, lang, "dialogs.job.import")).toHaveCount(0);
      await page.waitForTimeout(1_500);
      // The toast of the first visit may still be on screen; a second one would make two.
      expect(await page.getByText(flaggedToast(lang)).count()).toBeLessThanOrEqual(1);
      // The profile was marked once, in the first visit; the list was left, so the mark is gone and does not come back.
      await expect(page.locator('[role=listitem][data-highlighted="true"]')).toHaveCount(0);
    });

    test.describe("a job the API no longer knows", () => {
      test.use({allowConsole: [/status of 404/]});

      test("S1-r2-5: a 404 on the job, with its dialog closed, ends the follower: no more reads of it", async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL);
        let reads = 0;
        mock.on("GET /jobs/{id}", () => {
          reads++;
          // The first answer says running, and the job is swept before the second (24 hours, or its profile deleted).
          return reads === 1 ? {body: {...mock.screens.job!, state: "running"}} : {status: 404, body: errorBody("not_found")};
        });
        await page.goto(`${profilesPath(lang)}?profileDialog=import`);
        const dialog = dialogNamed(page, lang, "dialogs.import.title");
        await dialog.locator('input[type="file"]').setInputFiles(profileFile("Huge", {pad: "x".repeat(6_000)}));
        await dialog.getByRole("button", {name: submitImport(lang), exact: true}).click();
        const job = dialogNamed(page, lang, "dialogs.job.import");
        await job.getByRole("button", {name: text(lang, "jobs", "dialog.background"), exact: true}).click();
        await expect(job).toBeHidden();
        await expect.poll(() => jobReads(mock.calls), {timeout: 15_000}).toBe(2);
        // Two seconds is the poll's interval: three of them with nothing asked.
        await page.waitForTimeout(6_500);
        expect(jobReads(mock.calls)).toBe(2);
      });

      test("S1-r3-3: a 404 on a job whose dialog is open ends the spinner and the polling, and the dialog says the job is gone", async ({page, context, baseURL}) => {
        const mock = await openProfiles(context, baseURL);
        let reads = 0;
        mock.on("GET /jobs/{id}", () => {
          reads++;
          // It answered running once, and then the job is swept or its profile deleted in another tab.
          return reads === 1 ? {body: {...mock.screens.job!, state: "running"}} : {status: 404, body: errorBody("not_found")};
        });
        await page.goto(`${profilesPath(lang)}?profileDialog=import`);
        const dialog = dialogNamed(page, lang, "dialogs.import.title");
        await dialog.locator('input[type="file"]').setInputFiles(profileFile("Huge", {pad: "x".repeat(6_000)}));
        await dialog.getByRole("button", {name: submitImport(lang), exact: true}).click();
        const job = dialogNamed(page, lang, "dialogs.job.import");
        await expect(job).toBeVisible();
        await expect(job.getByRole("alert")).toBeVisible({timeout: 15_000});
        await expect(job.getByText(text(lang, "jobs", "state.running"), {exact: true})).toHaveCount(0);
        await expect(job.getByRole("button", {name: text(lang, "jobs", "dialog.background"), exact: true})).toHaveCount(0);
        // The dialog's own Close button (the corner X has the same name and no text).
        const closeName = text(lang, "jobs", "dialog.close");
        await expect(job.getByRole("button", {name: closeName, exact: true}).filter({hasText: closeName})).toBeVisible();
        const after = jobReads(mock.calls);
        await page.waitForTimeout(4_500);
        expect(jobReads(mock.calls)).toBe(after);
      });
    });

    test("S1-r2-4: the idle cover takes the followed job with the session: after Continue no job dialog opens and nothing asks for the job", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      mock.on("GET /jobs/{id}", () => ({body: {...mock.screens.job!, state: "running"}}));
      await page.clock.install();
      await page.goto(`${profilesPath(lang)}?profileDialog=import`);
      const dialog = dialogNamed(page, lang, "dialogs.import.title");
      await dialog.locator('input[type="file"]').setInputFiles(profileFile("Huge", {pad: "x".repeat(6_000)}));
      await dialog.getByRole("button", {name: submitImport(lang), exact: true}).click();
      const job = dialogNamed(page, lang, "dialogs.job.import");
      await expect(job).toBeVisible();
      // Past the idle limit with no input: the page is covered, with the job dialog still marked open in the store.
      await page.clock.runFor(2 * 60 * 60_000 + 60_000);
      await expect(page.locator(".shell-page")).toHaveCount(0);
      const before = jobReads(mock.calls);
      await page.getByRole("button", {name: lang === "fa" ? "ادامه" : "Continue"}).click();
      await expect(page.locator(".shell-page")).toBeVisible();
      await page.clock.runFor(10_000);
      await expect(dialogNamed(page, lang, "dialogs.job.import")).toHaveCount(0);
      // Whoever is at the page now is not told about, or asked for, the job of the session that was covered.
      expect(jobReads(mock.calls)).toBe(before);
    });

    test("S1-r3-5: an Import that answers after the session ended is not announced, marked or followed for whoever comes next", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      let release!: () => void;
      const gate = new Promise<void>((resolve) => (release = resolve));
      let sent = false;
      // The POST is accepted before the session ends and answers after it.
      await page.route("**/profiles:import", async (route) => {
        sent = true;
        await gate;
        await route.fallback();
      });
      await page.clock.install();
      await page.goto(`${profilesPath(lang)}?profileDialog=import`);
      const dialog = dialogNamed(page, lang, "dialogs.import.title");
      await dialog.locator('input[type="file"]').setInputFiles(profileFile("Imported"));
      await dialog.getByRole("button", {name: submitImport(lang), exact: true}).click();
      await expect.poll(() => sent).toBe(true);
      await page.clock.runFor(2 * 60 * 60_000 + 60_000);
      await expect(page.locator(".shell-page")).toHaveCount(0);
      release();
      await expect.poll(() => mock.calls.filter((c) => c.method === "POST" && c.path === "/profiles:import").length).toBe(1);
      await page.getByRole("button", {name: lang === "fa" ? "ادامه" : "Continue"}).click();
      await expect(page.locator(".shell-page")).toBeVisible();
      await page.clock.runFor(1_000);
      await expect(page.getByText(text(lang, "profiles", "dialogs.import.imported", {name: "Imported"}))).toHaveCount(0);
      await expect(page.locator('[role=listitem][data-highlighted="true"]')).toHaveCount(0);
      await expect(dialogNamed(page, lang, "dialogs.job.import")).toHaveCount(0);
    });
  });
}
