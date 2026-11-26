import {readFileSync} from "node:fs";

import type {BrowserContext, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {profileRow} from "./profiles-list-support.ts";
import {profilesPath, text} from "./profiles-support.ts";

// Stack mode (spec 17.1, 17.7; p2 10.6 "Stack mode: create from a type"), the Add dialog of the Profiles list (package S1 of P2, S1-r2-3)
// against the real API behind Caddy at https://panel.localhost. The mock cannot catch the drift that matters here: a `kind` or a body shape
// that the backend refuses or reads differently. So the dialog is driven as a person does, and the proof is on the wire and in the list the
// API gives back: the request carries the chosen `kind` and the trimmed name, the answer is the profile with that kind, and the row is first
// in the list with the word "New" (T-136).
//
// NOT RUN: written under D69 (no stack on the developer's machine) and first run on the Compose stack of GitHub Actions after the merge, as
// ci-web.sh step 10f does for the other stack specs (CTRLZ_WEB_STACK=1, after the seed of scripts/e2e-seed.mjs). It skips itself unless
// E2E_MODE=stack.
//
//   E2E_MODE=stack E2E_SEED_FILE=<private dir>/seed.json pnpm exec playwright test e2e/profiles.stack.spec.ts
//
// The seeded user is shared with the other stack files, so a test removes the profile it made in a `finally` block, through the API, whatever
// its page did. A profile it could not name (the page failed before the answer) is found by its unique name in the list.

test.skip(process.env.E2E_MODE !== "stack", "needs the Compose stack and a seeded user");

// The real API answers 401 where the mock fulfils quietly: the anonymous /me probe of the login page. Only 401 is allowed.
test.beforeEach(({guard}) => guard.allowConsole(/status of 401/));

type Seed = {user: {phone: string; password: string}};
const seed = ((): Seed => {
  const file = process.env.E2E_SEED_FILE;
  if (file) return JSON.parse(readFileSync(file, "utf8")) as Seed;
  return {user: {phone: process.env.E2E_PHONE ?? "", password: process.env.E2E_PASSWORD ?? ""}};
})();

async function signIn(page: Page, lang: "fa" | "en") {
  await page.goto(`/${lang}/login`);
  const submit = page.locator('form button[type="submit"]');
  await expect(submit.first()).toBeEnabled();
  await page.locator('input[name="phone"]').fill(seed.user.phone);
  await page.locator('input[name="password"]').fill(seed.user.password);
  await submit.first().click();
  await page.waitForURL(`**/${lang}/profiles`);
}

type ApiProfile = {id: string; name: string; kind: string};

/** Deletes every profile of the seeded user whose name starts with `prefix`; each delete must answer 204 and none may be left. */
async function removeProfiles(context: BrowserContext, prefix: string) {
  const request = context.request;
  const list = async () => ((await (await request.get("/api/v1/profiles")).json()) as {items: ApiProfile[]}).items.filter((p) => p.name.startsWith(prefix));
  for (const p of await list()) expect((await request.delete(`/api/v1/profiles/${p.id}`)).status(), "delete the profile the test made").toBe(204);
  expect(await list(), "no profile of the test is left on the seeded user").toEqual([]);
}

test.describe("Add profile against the real API", () => {
  const lang = "en";
  const added = (key: string) => text(lang, "profiles", `dialogs.add.${key}`);

  // One case per kind that differs in what the backend seeds for it, and one that has none: `custom` makes an empty profile, `kids` a
  // profile with filters already on. The names are unique per run, so a failed earlier run does not make a conflict.
  for (const kind of ["kids", "custom"] as const) {
    test(`create from a type: ${kind} sends its kind and the name, and the profile comes first in the list`, async ({page, context}) => {
      test.setTimeout(90_000);
      const prefix = `CTRLZ-STACK-${kind}-`;
      const name = `${prefix}${Date.now().toString(36)}`;
      let body: {name?: string; kind?: string} | null = null;
      page.on("request", (request) => {
        if (request.method() === "POST" && new URL(request.url()).pathname === "/api/v1/profiles") body = request.postDataJSON() as typeof body;
      });
      try {
        await signIn(page, lang);
        await page.goto(`${profilesPath(lang)}?profileDialog=add`);
        const dialog = page.getByRole("dialog", {name: added("title"), exact: true});
        await dialog.getByRole("textbox", {name: added("name")}).fill(`  ${name} `);
        await dialog.getByRole("radio", {name: new RegExp(`^${text(lang, "profiles", `kinds.${kind}.name`)}`)}).check({force: true});
        const answer = page.waitForResponse((r) => r.request().method() === "POST" && new URL(r.url()).pathname === "/api/v1/profiles");
        await dialog.getByRole("button", {name: added("submit"), exact: true}).click();
        // The API's own answer decides: 201 with the profile of that kind and the name, trimmed.
        const response = await answer;
        expect(response.status()).toBe(201);
        const created = ((await response.json()) as {profile: ApiProfile}).profile;
        expect(created).toMatchObject({name, kind});
        expect(body).toEqual({name, kind});
        // The dialog is gone, and the list the API gives back has it first with the highlight and the word "New".
        await expect(dialog).toBeHidden();
        const row = profileRow(page, lang, name);
        await expect(row).toBeVisible();
        await expect(row).toHaveAttribute("data-highlighted", "true");
        await expect(row).toContainText(text(lang, "profiles", "list.new"));
        const listed = ((await (await context.request.get("/api/v1/profiles")).json()) as {items: ApiProfile[]}).items;
        expect(listed.find((p) => p.id === created.id)).toMatchObject({name, kind});
      } finally {
        await removeProfiles(context, prefix);
      }
    });
  }

  test("a name of 64 characters, the limit of the form, is accepted by the API too", async ({page, context}) => {
    test.setTimeout(90_000);
    // The form refuses 65 and sends nothing, so only the edge it lets through can show a disagreement with the API: if the backend's limit
    // were lower, this one would answer 422 and the dialog would stay open.
    const prefix = "CTRLZ-STACK-max-";
    const name = `${prefix}${"x".repeat(64 - prefix.length)}`;
    expect(name).toHaveLength(64);
    try {
      await signIn(page, lang);
      await page.goto(`${profilesPath(lang)}?profileDialog=add`);
      const dialog = page.getByRole("dialog", {name: added("title"), exact: true});
      await dialog.getByRole("textbox", {name: added("name")}).fill(name);
      const answer = page.waitForResponse((r) => r.request().method() === "POST" && new URL(r.url()).pathname === "/api/v1/profiles");
      await dialog.getByRole("button", {name: added("submit"), exact: true}).click();
      expect((await answer).status(), "the form's 64 and the API's limit agree").toBe(201);
      await expect(dialog).toBeHidden();
    } finally {
      await removeProfiles(context, prefix);
    }
  });
});
