import {readFileSync} from "node:fs";

import type {Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import data from "../../../packages/ui/src/docs/publicApi.generated.json";
import type {PublicApi} from "../../../packages/ui/src/docs/apiDocsModel.ts";
import {LANGS, openProfiles} from "./profiles-support.ts";
import {apiDocsPath, apiText, shellText, statusPath} from "./s8-support.ts";

// The API documentation (spec p3 6.5, 10; Plan T-320) and the Status page (spec p3 10; Plan T-125). The documentation is drawn from the generated
// reference with our own components, offline; the status page says whether the panel answers, in an icon and a word, and says "not reported" for
// what P4 and P5 have not given it yet.

test.beforeEach(({guard}) => guard.allowConsole(/status of (500|502|503)/));

const api = data as unknown as PublicApi;
const TAGS = [...new Set(api.operations.map((op) => op.tag))];

for (const {lang, dir} of LANGS) {
  test.describe(`API docs, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 900}});
    const A = (path: string, values?: Record<string, string | number>) => apiText(lang, path, values);
    const search = async (page: Page, query: string) => {
      const field = page.getByRole("searchbox", {name: shellText(lang, "header.search")}).first();
      if (!(await field.isVisible())) await page.getByRole("button", {name: shellText(lang, "header.search"), exact: true}).click();
      await field.fill(query);
    };

    test("T-320: the page lists every group of the document with its operations, and says how many", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(apiDocsPath(lang));
      await expect(page.getByRole("heading", {level: 1, name: A("apiDocsPage.title")})).toBeVisible();
      await expect(page.getByTestId("docs-count")).toBeVisible();
      for (const tag of TAGS) await expect(page.getByRole("button", {name: new RegExp(`^${tag}\\b`)}).first()).toBeVisible();
      await expect(page.getByRole("region", {name: A("apiDocsPage.about")})).toContainText(api.title);
      await expect(page.getByRole("region", {name: A("apiDocsPage.about")})).toContainText("Authorization: Bearer ctz_YOUR_TOKEN");
    });

    test("T-320: an operation opens to its token, parameters, answers and an example request with a placeholder token and this page's address", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(apiDocsPath(lang));
      const group = api.operations.find((op) => op.id === "getLimits")!;
      await page.getByRole("button", {name: new RegExp(`^${group.tag}\\b`)}).first().click();
      await page.getByRole("button", {name: /GET\s*\/account\/limits/}).click();
      const body = page.locator('[data-operation="getLimits"]');
      await expect(body).toBeVisible();
      await expect(body.getByRole("heading", {name: A("reference.responses")})).toBeVisible();
      const example = body.getByTestId("copy-block");
      await expect(example).toContainText("Bearer $CTRLZ_TOKEN");
      await expect(example).toContainText(`${new URL(page.url()).origin}${api.server}/account/limits`);
      // The reference text is the document's own and is drawn left to right in both languages.
      await expect(body.locator('[lang="en"]').first()).toHaveAttribute("dir", "ltr");
    });

    // S8-r2-1: a copied example of an operation that needs Idempotency-Key must carry it, or the server refuses the request.
    test("T-320: the example of an operation with a required Idempotency-Key header carries that header", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(apiDocsPath(lang));
      const op = api.operations.find((o) => o.method === "POST" && o.path === "/endpoints")!;
      await page.getByRole("button", {name: new RegExp(`^${op.tag}\\b`)}).first().click();
      await page.getByRole("button", {name: /POST\s*\/endpoints(?!\/)/}).first().click();
      const example = page.locator(`[data-operation="${op.id}"]`).getByTestId("copy-block");
      await expect(example).toContainText('-H "Idempotency-Key: $(uuidgen)"');
    });

    test("T-320: a body opens its schemas in place, and a request body names its fields with their types", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(apiDocsPath(lang));
      const op = api.operations.find((o) => o.request?.ref && api.schemas[o.request.ref]?.fields?.some((f) => f.ref && api.schemas[f.ref]?.fields?.length))!;
      await page.getByRole("button", {name: new RegExp(`^${op.tag}\\b`)}).first().click();
      await page.getByRole("button", {name: new RegExp(`${op.method}\\s*${op.path.replace(/[{}]/g, ".")}`)}).first().click();
      const body = page.locator(`[data-operation="${op.id}"]`);
      await expect(body.getByRole("heading", {name: A("reference.request")})).toBeVisible();
      const nested = api.schemas[op.request!.ref!]!.fields!.find((f) => f.ref && api.schemas[f.ref]?.fields?.length)!;
      await body.locator(`[data-field="${nested.name}"]`).first().getByRole("button", {name: A("reference.showSchema", {name: nested.ref!})}).click();
      await expect(body.locator(`[data-field="${nested.name}"]`).first().getByRole("button", {name: A("reference.hideSchema", {name: nested.ref!})})).toBeVisible();
    });

    test("T-320: the search narrows the operations by path and opens the groups that match", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(apiDocsPath(lang));
      await search(page, "account/limits");
      const found = api.operations.filter((op) => `${op.method} ${op.path} ${op.id} ${op.summary} ${op.tag}`.toLowerCase().includes("account/limits")).length;
      await expect(page.getByTestId("docs-count")).toContainText(String(found));
      await expect(page.getByRole("button", {name: /GET\s*\/account\/limits/})).toBeVisible();
      await expect(page.getByRole("button", {name: /^endpoints\b/})).toHaveCount(0);
      await search(page, "zzz-no-such-operation");
      await expect(page.getByText(A("apiDocsPage.noMatch"))).toBeVisible();
    });

    test("T-320: the OpenAPI file can be saved, as the YAML a client generator reads, without a request to the API", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(apiDocsPath(lang));
      await expect(page.getByTestId("docs-count")).toBeVisible();
      const before = mock.calls.length;
      await page.getByRole("button", {name: shellText(lang, "header.more")}).click();
      const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("menuitem", {name: A("apiDocsPage.download")}).click()]);
      expect(download.suggestedFilename()).toBe("ctrlz-public-api.yaml");
      const saved = readFileSync((await download.path())!, "utf8");
      expect(saved).toMatch(/^openapi: 3\./m);
      expect(saved).toContain("/endpoints:");
      expect(mock.calls.length).toBe(before);
    });

    test("T-320: the page asks the API for nothing of its own and has no address outside the panel", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(apiDocsPath(lang));
      await expect(page.getByTestId("docs-count")).toBeVisible();
      expect(mock.calls.filter((c) => !["/me", "/notifications", "/announcements", "/profiles", "/endpoints"].some((p) => c.path.startsWith(p))).map((c) => `${c.method} ${c.path}`)).toEqual([]);
      for (const href of await page.evaluate(() => [...document.querySelectorAll("[href]")].map((el) => el.getAttribute("href") ?? ""))) expect(href.startsWith("/") && !href.startsWith("//") || href.startsWith("#"), href).toBe(true);
    });
  });

  test.describe(`Status, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 900}});
    const A = (path: string, values?: Record<string, string | number>) => apiText(lang, path, values);

    test("T-125: an answering panel is Healthy in an icon and a word, and the pair and the analytics say they are not reported", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(statusPath(lang));
      await expect(page.getByRole("heading", {level: 1, name: A("statusPage.title")})).toBeVisible();
      await expect(page.getByRole("heading", {name: A("statusPage.summary.ok")})).toBeVisible();
      // S8-r2-3: the live region holds the level and not the time of the check, which changes every 30 seconds.
      const live = page.getByTestId("status-summary").getByRole("status");
      await expect(live).toHaveText(A("statusPage.summary.ok"));
      const panel = page.locator('[data-status-row="panel"]');
      await expect(panel.getByTestId("status-chip")).toContainText(A("statusPage.level.ok"));
      await expect(panel.getByTestId("status-chip").locator("svg")).toHaveCount(1);
      for (const id of ["dns", "analytics"]) await expect(page.locator(`[data-status-row="${id}"]`).getByTestId("status-chip")).toContainText(A("statusPage.level.unknown"));
    });

    test("T-125: the probe is the public config route, so the page does not keep the session alive by asking", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(statusPath(lang));
      await expect(page.getByRole("heading", {name: A("statusPage.summary.ok")})).toBeVisible();
      expect(mock.count("GET /auth/config")).toBe(1);
      await page.getByRole("button", {name: A("statusPage.checkNow")}).click();
      await expect.poll(() => mock.count("GET /auth/config")).toBe(2);
    });

    test("T-125: a panel that cannot reach its API is Unreachable, and one that answers with an error is Troubled", async ({page, context, baseURL}) => {
      let status = 502;
      await openProfiles(context, baseURL, {handlers: {"GET /auth/config": () => ({status, body: {code: "internal", message: "x", request_id: "r-1"}})}});
      await page.goto(statusPath(lang));
      await expect(page.getByRole("heading", {name: A("statusPage.summary.down")})).toBeVisible();
      await expect(page.locator('[data-status-row="panel"]').getByTestId("status-chip")).toContainText(A("statusPage.level.down"));
      status = 500;
      await page.getByRole("button", {name: A("statusPage.checkNow")}).click();
      await expect(page.getByRole("heading", {name: A("statusPage.summary.degraded")})).toBeVisible();
    });
  });
}
