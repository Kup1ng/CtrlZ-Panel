import type {ScreenState} from "@ctrlz/api-client/testing/screenMock.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {err} from "./account-support.ts";
import {sharePath} from "./endpoints-support.ts";
import {LANGS, openProfiles, screen} from "./profiles-support.ts";
import {retryLabel} from "./s8-support.ts";
import {DEAD_SHARE_LINK, VALID_SHARE_LINK, setupText} from "./setup-support.ts";

// The share page (spec p3 7.1, 7.2, 10; Plan T-244; wireframe note "Endpoints"): /s/[token] with no shell and no session. What it must keep: the
// link's value goes in the body of one POST and in no URL, no query and no Referer; the page asks ONCE per load, because each open spends a
// use; every dead link looks the same; and the setup it shows is the one of the Endpoint the link belongs to.

test.beforeEach(({guard}) => guard.allowConsole(/status of (404|409|429|500|503)/));

const STATUS_404 = {status: 404, body: {code: "not_found", message: "not found", request_id: "r-1"}};

for (const {lang, dir} of LANGS) {
  test.describe(`share page, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 900}});
    const S = (path: string, values?: Record<string, string | number>) => setupText(lang, path, values);

    test("T-244: the page has no shell, is not indexed, and shows the Endpoint's name, its type and when the link ends", async ({page, context, baseURL}) => {
      const holder: {screens?: ScreenState} = {};
      const mock = await openProfiles(context, baseURL, {
        handlers: {"POST /public/share": () => ({body: {endpoint: {name: "Home router", type: "pfsense"}, resolvers: holder.screens!.resolver, expires_at: new Date(Date.now() + 86_400_000).toISOString()}})},
      });
      holder.screens = mock.screens;
      await page.goto(sharePath(lang, VALID_SHARE_LINK));
      const share = screen(page, "share");
      await expect(share).toBeVisible();
      await expect(page.getByRole("heading", {level: 1, name: "Home router"})).toBeVisible();
      await expect(share.getByText(S("share.types.pfsense"), {exact: true})).toBeVisible();
      await expect(page.getByTestId("share-expiry")).toBeVisible();
      await expect(page.getByTestId("share-expiry")).not.toContainText("{");
      await expect(page.locator("aside.sidebar")).toHaveCount(0);
      await expect(page.locator("header.page-header")).toHaveCount(0);
      await expect(page.locator('meta[name="robots"]')).toHaveAttribute("content", /noindex/);
      await expect(page.locator('meta[name="referrer"]')).toHaveAttribute("content", "no-referrer");
      // The page holds no profile, claim, client, account or other Endpoint (spec 7.2): it asks for none of them.
      await expect(page.getByTestId("share-setup")).toBeVisible();
    });

    test("T-244: the link's value is sent in one POST body and appears in no URL the page requests, and no request carries it as a Referer", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      const seen: {url: string; referer: string | undefined; method: string; type: string}[] = [];
      page.on("request", (request) => seen.push({url: request.url(), referer: request.headers().referer, method: request.method(), type: request.resourceType()}));
      await page.goto(sharePath(lang, VALID_SHARE_LINK));
      await expect(page.getByTestId("share-setup")).toBeVisible();
      // Walk the page: the other tab and back, so every request it can make has been made.
      await page.getByRole("radio", {name: S("resolvers.title")}).click();
      await expect(page.getByTestId("resolver-sections")).toBeVisible();

      const own = new URL(page.url());
      expect(own.pathname).toBe(`/${lang}/s/${VALID_SHARE_LINK}`);
      for (const request of seen.filter((r) => new URL(r.url).pathname !== own.pathname)) {
        expect(request.url, `${request.method} ${request.url}`).not.toContain(VALID_SHARE_LINK);
        // The stylesheet and the font are asked for before the meta tag is parsed, so the policy comes in the response header of the page itself
        // (next.config.ts headers, S8-r2-5), and every request it makes, whatever its type, carries no Referer with the link.
        expect(request.referer ?? "", `${request.method} ${request.url}`).not.toContain(VALID_SHARE_LINK);
      }
      const posts = mock.calls.filter((c) => c.method === "POST" && c.path === "/public/share");
      expect(posts).toHaveLength(1);
      expect(posts[0]!.body).toEqual({link: VALID_SHARE_LINK});
      expect(posts[0]!.query.size).toBe(0);
      // No other call of the page is an API call that needs a session: it asked for the share and nothing else.
      expect(mock.calls.filter((c) => !c.path.startsWith("/public/")).map((c) => `${c.method} ${c.path}`)).toEqual([]);
      // The address is where the visitor arrived with it, and the one place it is allowed to be (spec 7.2). Nothing else of the browser keeps it.
      const kept = await page.evaluate(async () => JSON.stringify({local: {...localStorage}, session: {...sessionStorage}, cookie: document.cookie, name: window.name, caches: await caches.keys(), databases: (await indexedDB.databases()).map((d) => d.name)}));
      expect(kept).not.toContain(VALID_SHARE_LINK);
    });

    test("T-244: each load spends one use, whatever the visitor does on the page", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(sharePath(lang, VALID_SHARE_LINK));
      await expect(page.getByTestId("share-setup")).toBeVisible();
      await page.getByRole("radio", {name: S("resolvers.title")}).click();
      await page.getByRole("radio", {name: S("wizard.title")}).click();
      await page.evaluate(() => window.dispatchEvent(new Event("focus")));
      await page.evaluate(() => window.dispatchEvent(new Event("online")));
      expect(mock.count("POST /public/share")).toBe(1);
    });

    test("T-244: the Resolvers of the Endpoint are on the second tab, with the values of the link's Resolver view", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(sharePath(lang, VALID_SHARE_LINK));
      await page.getByRole("radio", {name: S("resolvers.title")}).click();
      const sections = page.getByTestId("resolver-sections");
      await expect(sections).toBeVisible();
      await expect(sections).toContainText(mock.screens.resolver.resolver_id);
    });

    test("T-244: every dead link is the same page, and says all the reasons in one sentence", async ({page, context, baseURL}) => {
      // The server gives one 404 for an unknown, expired, revoked or used-up link and for a gone Endpoint (spec 7.1), so the page cannot tell them
      // apart either, and a well-formed value that the mock does not know is the case of all of them.
      await openProfiles(context, baseURL);
      await page.goto(sharePath(lang, DEAD_SHARE_LINK));
      await expect(page.getByRole("heading", {name: S("share.notFoundTitle")})).toBeVisible();
      await expect(page.getByText(S("share.notFoundText"))).toBeVisible();
      for (const word of lang === "fa" ? ["منقضی", "لغو", "دفعات"] : ["expired", "revoked", "uses"]) expect(S("share.notFoundText")).toContain(word);
      await expect(page.getByTestId("share-setup")).toHaveCount(0);
      await expect(page.getByRole("button", {name: retryLabel(lang)})).toHaveCount(0);
    });

    test("T-244: an unknown link and one the server refuses as expired, revoked or used up are the one page", async ({page, context, baseURL}) => {
      // Both are the server's single 404 (spec 7.1: the oracle test of RULES 4 holds the bytes), so the page has nothing to tell them apart by.
      await openProfiles(context, baseURL, {handlers: {"POST /public/share": STATUS_404}});
      await page.goto(sharePath(lang, VALID_SHARE_LINK));
      await expect(page.getByRole("heading", {name: S("share.notFoundTitle")})).toBeVisible();
      const refused = await screen(page, "share").innerText();
      await page.goto(sharePath(lang, DEAD_SHARE_LINK));
      await expect(page.getByRole("heading", {name: S("share.notFoundTitle")})).toBeVisible();
      expect(await screen(page, "share").innerText()).toBe(refused);
    });

    test("T-244: a value that cannot be a link is the same page and makes no request", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(`/${lang}/s/not-a-link`);
      await expect(page.getByRole("heading", {name: S("share.notFoundTitle")})).toBeVisible();
      expect(mock.count("POST /public/share")).toBe(0);
    });

    test("T-244: an Endpoint that is not ready says so, spends no use, and Retry asks again", async ({page, context, baseURL}) => {
      let calls = 0;
      const holder: {screens?: ScreenState} = {};
      const mock = await openProfiles(context, baseURL, {
        handlers: {"POST /public/share": () => (++calls === 1 ? err(409, "setup_unavailable") : {body: {endpoint: {name: "Home router", type: "router"}, resolvers: holder.screens!.resolver, expires_at: new Date(Date.now() + 86_400_000).toISOString()}})},
      });
      holder.screens = mock.screens;
      await page.goto(sharePath(lang, VALID_SHARE_LINK));
      await expect(page.getByRole("heading", {name: S("share.notReadyTitle")})).toBeVisible();
      await expect(page.getByText(S("share.notReadyText"))).toBeVisible();
      await page.getByRole("button", {name: retryLabel(lang)}).click();
      await expect(page.getByTestId("share-setup")).toBeVisible();
      expect(mock.count("POST /public/share")).toBe(2);
    });

    test("a busy server is an error with Retry, and the page asks again only when the visitor does", async ({page, context, baseURL}) => {
      let calls = 0;
      const holder: {screens?: ScreenState} = {};
      const mock = await openProfiles(context, baseURL, {
        handlers: {"POST /public/share": () => (++calls === 1 ? err(500, "internal") : {body: {endpoint: {name: "Home router", type: "router"}, resolvers: holder.screens!.resolver, expires_at: new Date(Date.now() + 86_400_000).toISOString()}})},
      });
      holder.screens = mock.screens;
      await page.goto(sharePath(lang, VALID_SHARE_LINK));
      // Next keeps its own route announcer, which is a second role=alert (empty until a navigation is announced): the page's alert is the one with the error.
      await expect(page.locator("[role=alert]:not(#__next-route-announcer__)")).toBeVisible();
      // Nothing asks again by itself.
      await page.waitForTimeout(1200);
      expect(mock.count("POST /public/share")).toBe(1);
      await page.getByRole("button", {name: retryLabel(lang)}).click();
      await expect(page.getByTestId("share-setup")).toBeVisible();
      expect(mock.count("POST /public/share")).toBe(2);
    });

    test("the corner offers the theme without cost, and warns that another language opens the link again", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(sharePath(lang, VALID_SHARE_LINK));
      await expect(page.getByTestId("share-setup")).toBeVisible();
      await page.getByRole("button", {name: S("share.corner")}).click();
      const menu = page.getByRole("menu");
      await expect(menu.getByText(S("share.languageUse"))).toHaveCount(1);
      await menu.getByRole("menuitemradio", {name: lang === "fa" ? "تیره" : "Dark"}).click();
      await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
      expect(mock.count("POST /public/share")).toBe(1);
    });

    test("T-244: the Apple profile of the link is asked with the link in the body and nothing else of the account", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(sharePath(lang, VALID_SHARE_LINK));
      await page.getByTestId("configure-home").getByText(S("configure.entries.automatic.title"), {exact: true}).click();
      await page.getByTestId("platform-list").locator('[data-platform="ios"]').click();
      await page.getByRole("button", {name: S("apple.create")}).click();
      await expect(page.getByTestId("apple-result")).toBeVisible();
      const posts = mock.calls.filter((c) => c.path === "/public/share/apple-profile");
      expect(posts).toHaveLength(1);
      expect((posts[0]!.body as {link: string}).link).toBe(VALID_SHARE_LINK);
      expect(posts[0]!.query.size).toBe(0);
      expect(mock.calls.filter((c) => !c.path.startsWith("/public/")).map((c) => c.path)).toEqual([]);
    });
  });
}
