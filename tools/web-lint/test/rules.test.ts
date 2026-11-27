import {fileURLToPath} from "node:url";

import {ESLint} from "eslint";
import {beforeAll, describe, expect, it} from "vitest";

// One passing and one failing sample for each rule of spec 16.1 that is a plugin of ours or a core
// rule we switch on (a rule that silently never fires is worse than none). The samples run through
// the real eslint.config.mjs, so they prove the wiring too: the files each rule applies to, and the
// files that are exempt.

const root = fileURLToPath(new URL("../../..", import.meta.url));
let eslint: ESLint;
beforeAll(() => {
  eslint = new ESLint({cwd: root});
});

async function lint(code: string, filePath = "packages/ui/src/sample.tsx"): Promise<string[]> {
  const [result] = await eslint.lintText(code, {filePath});
  return (result?.messages ?? []).map((m) => `${m.ruleId ?? "parse"}: ${m.message}`);
}

async function fails(rule: string, code: string, filePath?: string) {
  const found = await lint(code, filePath);
  expect(found.some((m) => m.startsWith(`${rule}:`)), `${rule} did not report: ${code}\n${found.join("\n")}`).toBe(true);
}
async function passes(rule: string, code: string, filePath?: string) {
  const found = (await lint(code, filePath)).filter((m) => m.startsWith(`${rule}:`));
  expect(found, `${rule} reported: ${code}`).toEqual([]);
}

describe("ctrlz/hugeicons-only-in-allowlist", () => {
  const rule = "ctrlz/hugeicons-only-in-allowlist";
  it("fails outside the two files", async () => {
    await fails(rule, `import {Home01Icon} from "@hugeicons/core-free-icons";`);
    await fails(rule, `import {HugeiconsIcon} from "@hugeicons/react";`, "apps/panel/src/app/x.tsx");
    await fails(rule, `export {A} from "@hugeicons/core-free-icons";`);
    await fails(rule, `const m = await import("@hugeicons/react");`);
  });
  it("passes in the allowlisted files and for other imports", async () => {
    await passes(rule, `import {HugeiconsIcon} from "@hugeicons/react";`, "packages/icons/src/Icon.tsx");
    await passes(rule, `import {A} from "@hugeicons/core-free-icons";`, "packages/icons/src/hugeicons.ts");
    await passes(rule, `import {Icon} from "@ctrlz/icons/Icon.tsx";`);
  });
});

describe("ctrlz/no-physical-style", () => {
  const rule = "ctrlz/no-physical-style";
  it("fails on physical edges in a style object", async () => {
    await fails(rule, `const a = <div style={{left: 0}} />;`);
    await fails(rule, `const a = <div style={{marginLeft: 4, color: "red"}} />;`);
    await fails(rule, `const a = <div style={{textAlign: "right"}} />;`);
    await fails(rule, `const a = {style: {paddingRight: 8}};`);
    await fails(rule, `const s: CSSProperties = {borderLeft: "1px solid"};`);
    await fails(rule, `const a = <div style={{"marginLeft": 1}} />;`);
  });
  it("passes logical ones and objects that are not styles", async () => {
    await passes(rule, `const a = <div style={{insetInlineStart: 0, marginInlineEnd: 4, textAlign: "start"}} />;`);
    await passes(rule, `const a = {left: 1, right: 2};`);
    await passes(rule, `const a = <div style={{justifySelf: "start"}} />;`);
  });
});

describe("ctrlz/no-protocol-relative-url (the //host half of no-external-url)", () => {
  const rule = "ctrlz/no-protocol-relative-url";
  it("fails on //host", async () => {
    await fails(rule, `const a = "//cdn.example.com/x.js";`);
    await fails(rule, `const a = '<script src="//cdn.example.com/x.js">';`);
    await fails(rule, "const a = `//cdn.example.com/${x}`;");
  });
  it("passes a path, a comment-like text and a full URL left to the other rule", async () => {
    await passes(rule, `const a = "/fonts/DanaVF.woff2";`);
    await passes(rule, `const a = "a//b";`);
    await passes(rule, `const a = "//";`);
  });
});

describe("the http(s) half of no-external-url, and the other bans of banned.ts, through the config", () => {
  it("fails on a URL and passes the allowlisted file", async () => {
    await fails("no-restricted-syntax", `const a = "https://cdn.example.com/x.js";`);
    await passes("no-restricted-syntax", `const a = "https://example.com";`, "packages/ui/src/proxy/csp.ts");
  });
});

describe("ctrlz/no-physical-arrow", () => {
  const rule = "ctrlz/no-physical-arrow";
  it("fails on a literal arrow key", async () => {
    await fails(rule, `if (e.key === "ArrowLeft") go();`);
    await fails(rule, `const keys = {ArrowRight: next};`);
  });
  it("passes in useDirectionalKeys and for the vertical arrows", async () => {
    await passes(rule, `const next = d === "rtl" ? "ArrowLeft" : "ArrowRight";`, "packages/ui/src/hooks/useDirectionalKeys.ts");
    await passes(rule, `if (e.key === "ArrowDown") go();`);
    await passes(rule, `import {ArrowLeft01Icon} from "x";`);
  });
});

describe("ctrlz/no-email", () => {
  const rule = "ctrlz/no-email";
  it("fails on an email field, a name and a word", async () => {
    await fails(rule, `const a = <input type="email" />;`);
    await fails(rule, `const emailAddress = 1;`);
    await fails(rule, `const a = "Your Email";`);
    await fails(rule, `const a = "ایمیل";`);
  });
  it("passes a phone field", async () => {
    await passes(rule, `const a = <input type="tel" />;`);
    await passes(rule, `const phone = "09120000000";`);
  });
});

describe("ctrlz/no-secret-param", () => {
  const rule = "ctrlz/no-secret-param";
  it("fails when a secret rides in the URL", async () => {
    await fails(rule, `const d = useUrlDialog("ticket");`);
    await fails(rule, `const v = searchParams.get("code");`);
    await fails(rule, `url.searchParams.set("token", t);`);
    await fails(rule, `const p = new URLSearchParams({password: p});`);
    await fails(rule, "const u = `/x?token=${t}`;");
    await fails(rule, `const u = "/x#secret=abc";`);
  });
  it("passes other parameters, other maps and look-alike names", async () => {
    await fails("ctrlz/no-secret-param", `const v = params.get("secret");`);
    await passes(rule, `const d = useUrlDialog("helpPane");`);
    await passes(rule, `const v = searchParams.get("next");`);
    await passes(rule, `const v = cache.get("token");`);
    await passes(rule, `const v = searchParams.get("page"); const w = searchParams.get("sort");`);
    await passes(rule, "const u = `/x?next=${n}&page=2#top`;");
  });
  // gate-r9-6: the names that the screens actually carry, not only the five exact words.
  it("fails for the usual spellings of a one-time value (gate-r9-6)", async () => {
    for (const name of ["totp_code", "invite_code", "recovery_code", "otp", "challenge", "invite", "reset_ticket", "new_password", "inviteCode", "x-token", "OTP", "challenge_id", "passcode", "codes"]) {
      await fails(rule, `params.set("${name}", v);`);
      await fails(rule, `const v = searchParams.get("${name}");`);
      await fails(rule, `const v = url.searchParams.has("${name}");`);
      await fails(rule, `const d = useUrlDialog("${name}");`);
      await fails(rule, `const p = new URLSearchParams({"${name}": v}); const q = new URLSearchParams({${name.replace(/\W/g, "_")}: v});`);
      await fails(rule, "const u = `/x?" + name + "=${v}`;");
      await fails(rule, `const u = "/x?a=1&${name}=abc";`);
      await fails(rule, `const u = "/x#${name}=abc";`);
    }
  });
});

// gate-r22-8: a query key stays in the cache and is readable there, so it holds no secret.
describe("ctrlz/no-secret-param, in a query key (gate-r22-8)", () => {
  const rule = "ctrlz/no-secret-param";
  it("fails when a key holds a name or a value that reads as a secret", async () => {
    await fails(rule, `const q = useQuery({queryKey: ["reset", ticket], queryFn});`);
    await fails(rule, `const q = useQuery({queryKey: ["totp-setup", otpauthUri, secret], queryFn});`);
    await fails(rule, `const q = useQuery({queryKey: ["x", form.password], queryFn});`);
    await fails(rule, "const q = useQuery({queryKey: [`x-${token}`], queryFn});");
    await fails(rule, `const q = useQuery({queryKey: ["x", {code}], queryFn});`);
    await fails(rule, `const q = useQuery({queryKey: ["x", {a: inviteCode}], queryFn});`);
    await fails(rule, `const q = useQuery({queryKey: keys.detail(ticket), queryFn});`);
    await fails(rule, `const q = useQuery({queryKey: keys.detail(id, otp), queryFn});`);
    await fails(rule, `client.setQueryData(["reset", ticket], value);`);
    await fails(rule, `await client.prefetchQuery({queryKey: ["x", token], queryFn});`);
    await fails(rule, `client.invalidateQueries({queryKey: ["x", challenge]});`);
  });
  it("passes the keys that the app has, and a callee that only has a word in its name", async () => {
    await passes(rule, `const q = useQuery({queryKey: ["account", "passkeys"], queryFn});`);
    await passes(rule, `const q = useQuery({queryKey: passkeyKeys.list, queryFn});`);
    await passes(rule, `const q = useQuery({queryKey: ["notifications", "list"], queryFn});`);
    await passes(rule, `const q = useQuery({queryKey: keys.detail(profileId), queryFn});`);
    await passes(rule, `const q = useQuery({queryKey: passKey(profileId), queryFn});`);
    await passes(rule, `client.setQueryData(meKeys.all, me);`);
    await passes(rule, `const ticket = 1; const q = useQuery({queryKey: ["me"], queryFn: () => ticket});`);
  });
});

describe("ctrlz/no-storage", () => {
  const rule = "ctrlz/no-storage";
  it("fails outside the reviewed files", async () => {
    await fails(rule, `const v = localStorage.getItem("k");`);
    await fails(rule, `sessionStorage.setItem("k", "1");`);
    await fails(rule, `const v = window.localStorage;`);
  });
  it("fails for a cookie, IndexedDB, CacheStorage and the Cookie Store, which keep a one-time value as well (gate-r1-20)", async () => {
    await fails(rule, `document.cookie = "ctrlz_totp=" + secret;`);
    await fails(rule, `const c = document.cookie;`);
    await fails(rule, `window.document.cookie = "a=b";`);
    await fails(rule, `document["cookie"] = "a=b";`);
    await fails(rule, `const db = indexedDB.open("x");`);
    await fails(rule, `const db = window.indexedDB;`);
    await fails(rule, `const c = await caches.open("x");`);
    await fails(rule, `await cookieStore.set("a", "b");`);
  });
  it("fails for the system clipboard, which keeps a copied secret after the screen is gone (gate-r5-8)", async () => {
    await fails(rule, `await navigator.clipboard.writeText(secret);`);
    await fails(rule, `await window.navigator.clipboard.writeText(secret);`);
    await fails(rule, `const text = await navigator.clipboard.readText();`);
    await fails(rule, `await navigator["clipboard"].writeText(secret);`);
  });
  it("passes in a reviewed file, and for what is not storage", async () => {
    await passes(rule, `await navigator.clipboard.writeText("");`, "packages/api-client/src/clipboard.ts");
    await passes(rule, `await copyOneTimeSecret(secret);`);
    await passes(rule, `const v = localStorage.getItem("k");`, "packages/ui/src/hooks/useHaptics.ts");
    await passes(rule, `document.cookie = "sidebar_state=true";`, "packages/ui/src/shell/AppShell.tsx");
    await passes(rule, `document.cookie = "ctrlz_theme=dark";`, "packages/ui/src/theme/useTheme.ts");
    await passes(rule, `const t = document.title; const q = document.querySelector("a");`);
  });
});

describe("no-console (ctrlz/no-console of the table)", () => {
  it("fails in shipped code, passes in a test", async () => {
    await fails("no-console", `console.log("x");`);
    await passes("no-console", `console.log("x");`, "packages/ui/src/sample.test.ts");
  });
});

describe("ctrlz/no-raw-text", () => {
  const rule = "ctrlz/no-raw-text";
  it("fails on text with a letter and on string props", async () => {
    await fails(rule, `const a = <p>Hello</p>;`);
    await fails(rule, `const a = <p>سلام</p>;`);
    await fails(rule, `const a = <p>{"Save"}</p>;`);
    await fails(rule, `const a = <button aria-label="Close" />;`);
    await fails(rule, `const a = <input placeholder={open ? "Search" : t("x")} />;`);
    await fails(rule, `const a = <Image alt="logo" />;`);
  });
  it("passes t(), Tech, digits, symbols and non-text props", async () => {
    await passes(rule, `const a = <p>{t("hello")}</p>;`);
    await passes(rule, `const a = <Tech>example.com</Tech>;`);
    await passes(rule, `const a = <p>{"12"} / 3 -</p>;`);
    await passes(rule, `const a = <button aria-label={t("close")} className="x y" />;`);
    await passes(rule, `const a = <p>Hello</p>;`, "packages/ui/src/sample.test.tsx");
  });
});

describe("ctrlz/reduced-motion", () => {
  const rule = "ctrlz/reduced-motion";
  it("fails on a moving class with no partner", async () => {
    await fails(rule, `const a = <div className="transition-colors" />;`);
    await fails(rule, `const a = <div className="flex animate-spin" />;`);
    await fails(rule, `const a = <div className={cn("hover:transition-opacity", x && "p-2")} />;`);
    await fails(rule, "const a = <div className={`transition ${x}`} />;");
    await fails(rule, `const v = tv({base: "transition-transform"});`);
  });
  it("passes with a motion-reduce partner, motion-safe, none, Spinner and Skeleton", async () => {
    await passes(rule, `const a = <div className="transition-colors motion-reduce:transition-none" />;`);
    await passes(rule, `const a = <div className={cn("animate-spin", x && "motion-reduce:animate-none")} />;`);
    await passes(rule, `const a = <div className="motion-safe:animate-spin" />;`);
    await passes(rule, `const a = <div className="transition-none animate-none" />;`);
    await passes(rule, `const a = <Spinner className="animate-spin" />;`);
    await passes(rule, `const a = <Skeleton className="animate-pulse" />;`);
    await passes(rule, `const a = <div className="transitions-are-nice" />;`);
  });
});

describe("ctrlz/use-on-press", () => {
  const rule = "ctrlz/use-on-press";
  it("fails on onClick for a HeroUI component", async () => {
    await fails(rule, `import {Button} from "@heroui/react"; const a = <Button onClick={go} />;`);
    await fails(rule, `import {Dropdown} from "@heroui/react"; const a = <Dropdown.Item onClick={go} />;`);
    await fails(rule, `import {Sidebar} from "@heroui-pro/react"; const a = <Sidebar.Item onClick={go} />;`);
  });
  it("passes onPress, and onClick on a native element or our own component", async () => {
    await passes(rule, `import {Button} from "@heroui/react"; const a = <Button onPress={go} />;`);
    await passes(rule, `const a = <button type="button" onClick={go} />;`);
    await passes(rule, `import {Row} from "./Row.tsx"; const a = <Row onClick={go} />;`);
  });
});

describe("ctrlz/no-next-fetch", () => {
  const rule = "ctrlz/no-next-fetch";
  it("fails in a Server Component and a Route Handler under app/", async () => {
    await fails(rule, `export default async function Page() { const r = await fetch("/api/v1/x"); return null; }`, "apps/panel/src/app/[locale]/page.tsx");
    await fails(rule, `export async function GET() { return fetch("/x"); }`, "apps/panel/src/app/health/route.ts");
    await fails(rule, `export default async function Page() { await globalThis.fetch("/x"); return null; }`, "apps/admin/src/app/[locale]/page.tsx");
  });
  it("passes a client component, and files outside app/", async () => {
    await passes(rule, `"use client";\nexport default function C() { void fetch("/x"); return null; }`, "apps/panel/src/app/[locale]/c.tsx");
    await passes(rule, `export const load = () => fetch("/x");`, "packages/api-client/src/x.ts");
  });
});

describe("e2e specs use the guard (wp12-r1-4, spec 17.2)", () => {
  const rule = "no-restricted-imports";
  const spec = "apps/panel/e2e/sample.spec.ts";
  it("fails a value import of test or expect from Playwright, in any spelling", async () => {
    await fails(rule, `import {test, expect} from "@playwright/test";`, spec);
    await fails(rule, `import {test as base} from "@playwright/test";`, spec);
    await fails(rule, `import {expect} from "@playwright/test";`, "apps/admin/e2e/sample.spec.ts");
    await fails(rule, `import * as pw from "@playwright/test";`, spec);
    await fails(rule, `export {test} from "@playwright/test";`, spec);
  });
  it("passes the guard, and Playwright's types", async () => {
    await passes(rule, `import {expect, test} from "@ctrlz/ui/testing/guard.ts";`, spec);
    await passes(rule, `import type {BrowserContext, Page} from "@playwright/test";`, spec);
    await passes(rule, `import {type Page} from "@playwright/test";`, spec);
  });
  it("leaves the harness itself alone: the guard and the routes cases need Playwright's own test", async () => {
    await passes(rule, `import {expect, test as base} from "@playwright/test";`, "packages/ui/src/testing/guard.ts");
    await passes(rule, `import {expect, test} from "@playwright/test";`, "packages/ui/src/testing/routesSpec.ts");
  });
});

describe("a spec that turns the CSP check off (gate-r3-5)", () => {
  const rule = "no-restricted-syntax";
  const spec = "apps/panel/e2e/x.spec.ts";
  it("fails for the bypassCSP option and for the CDP call", async () => {
    await fails(rule, `test.use({bypassCSP: true});`, spec);
    await fails(rule, `const c = await guard.newContext({bypassCSP: true});`, spec);
    await fails(rule, `const o = {"bypassCSP": true};`, spec);
    await fails(rule, `await cdp.send("Page.setBypassCSP", {enabled: true});`, spec);
  });
  it("passes for the options that do not touch it", async () => {
    await passes(rule, `test.use({allowConsole: [/x/], viewport: {width: 375, height: 800}});`, spec);
  });
});

describe("a spec that replaces the guard fixture or drops its records (gate-r12-2)", () => {
  const rule = "no-restricted-syntax";
  const spec = "apps/panel/e2e/x.spec.ts";
  it("fails for test.extend over guard, context, page, browser or request, and for test.use of one", async () => {
    await fails(rule, `const t = test.extend({guard: [async ({}, use) => use({}), {auto: true}]});`, spec);
    await fails(rule, `const t = test.extend({guard: async ({}, use) => use(stub)});`, spec);
    await fails(rule, `const t = base.extend({"guard": async ({}, use) => use(stub)});`, spec);
    await fails(rule, `const t = test.extend({context: async ({browser}, use) => use(await browser.newContext())});`, spec);
    await fails(rule, `const t = test.extend({page: async ({}, use) => use(stub)});`, spec);
    await fails(rule, `const t = test.extend({browser: async ({}, use) => use(stub)});`, spec);
    await fails(rule, `test.use({page: stub});`, spec);
    await fails(rule, `const t = test.extend({guard: 1}); `, "packages/ui/src/proxy/xSpec.ts");
    await fails(rule, `const t = test.extend({guard: 1}); `, "packages/ui/src/testing/helper.ts");
  });
  it("fails for removeAllListeners and unrouteAll on a page or a context", async () => {
    await fails(rule, `page.removeAllListeners();`, spec);
    await fails(rule, `context.removeAllListeners("request");`, spec);
    await fails(rule, `await page.unrouteAll();`, spec);
    await fails(rule, `await context.unrouteAll({behavior: "ignoreErrors"});`, spec);
  });
  it("fails for page.setContent and for document.open, write and writeln, in a spec or inside page.evaluate (gate-r28-2)", async () => {
    await fails(rule, `await page.setContent("<p>x</p>");`, spec);
    await fails(rule, `await frame.setContent(html, {waitUntil: "load"});`, spec);
    await fails(rule, `await page.evaluate(() => { document.open(); document.write(html); document.close(); });`, spec);
    await fails(rule, `await page.evaluate((h) => document.writeln(h), html);`, spec);
    await fails(rule, `await page.evaluate(() => window.document.open());`, spec);
    await fails(rule, `await page.setContent("<p>x</p>");`, "packages/ui/src/proxy/xSpec.ts");
    await fails(rule, `await page.setContent("<p>x</p>");`, "packages/ui/src/testing/helper.ts");
  });
  it("passes for page.route with goto, a file write, and the guard itself", async () => {
    await passes(rule, `await page.route("**/x", (r) => r.fulfill({body: "<p>x</p>"})); await page.goto("/x");`, spec);
    await passes(rule, `stream.write("x"); await fs.writeFile("a", "b");`, spec);
  });
  it("passes for a fixture with another name, test.use options, one listener and one route, and for the guard itself", async () => {
    await passes(rule, `const t = test.extend({signedInPage: async ({page}, use) => use(page)});`, spec);
    await passes(rule, `test.use({viewport: {width: 375, height: 800}, locale: "en"});`, spec);
    await passes(rule, `page.off("request", handler); await page.unroute("**/x");`, spec);
    await passes(rule, `export const test = base.extend({guard: [async ({}, use) => use(g), {auto: true}]});`, "packages/ui/src/testing/guard.ts");
  });
});

describe("a browser context that a spec opens by hand (gate-r1-5, gate-r1-7)", () => {
  const rule = "no-restricted-syntax";
  const spec = "apps/panel/e2e/x.spec.ts";
  it("fails for browser.newContext, browser.newPage, context.browser() and a launch", async () => {
    await fails(rule, `const c = await browser.newContext({baseURL});`, spec);
    await fails(rule, `const p = await browser.newPage();`, spec);
    await fails(rule, `export const c = await context.browser()!.newContext();`, spec);
    await fails(rule, `export const c = await context.browser()?.newContext();`, spec);
    await fails(rule, `const b = await chromium.launch();`, spec);
    await fails(rule, `const c = await chromium.launchPersistentContext("x");`, spec);
  });
  it("passes for the guard's second context, a second page of the guarded context and the API request context", async () => {
    await passes(rule, `const c = await guard.newContext(); const p = await c.newPage();`, spec);
    await passes(rule, `const p = await context.newPage();`, spec);
    await passes(rule, `const r = await playwrightRequest.newContext({baseURL});`, spec);
  });
});

// gate-r4-2, gate-r4-4: the guard-bypass rules cover every place a browser test can live, not only apps/*/e2e. The shared spec bodies in
// packages/ui are where the largest browser tests are since WP5, and a case added there ran with no guard and no lint error.
describe("the guard rules cover the shared spec bodies and the harness (gate-r4-2, gate-r4-4)", () => {
  const places = ["packages/ui/src/proxy/probeSpec.ts", "packages/ui/src/testing/probeSpec.ts", "packages/ui/src/testing/helper.ts", "apps/admin/e2e/probe.spec.ts"];

  it("fails a value import of test or expect from Playwright in each of them", async () => {
    for (const place of places) await fails("no-restricted-imports", `import {test, expect} from "@playwright/test";`, place);
  });
  it("fails a browser that is opened by hand, and the CSP bypass, in each of them", async () => {
    for (const place of places) {
      await fails("no-restricted-syntax", `export const c = async (browser) => browser.newContext({bypassCSP: true});`, place);
      await fails("no-restricted-syntax", `export const c = async (browser) => browser.newContext();`, place);
      await fails("no-restricted-syntax", `export const b = () => chromium.launch();`, place);
    }
  });
  it("still bans what the shipped-code lists ban, in a shared spec body", async () => {
    await fails("no-restricted-imports", `import {useTheme} from "@heroui/react";`, "packages/ui/src/proxy/probeSpec.ts");
    await fails("no-restricted-imports", `import {test} from "@playwright/test";`, "packages/ui/src/proxy/probeSpec.ts");
  });
  it("passes the guard, Playwright's types and the vitest unit tests of the harness", async () => {
    for (const place of places) {
      await passes("no-restricted-imports", `import {expect, test} from "../testing/guard.ts";\nimport type {Page} from "@playwright/test";`, place);
      await passes("no-restricted-syntax", `export const c = async (guard) => guard.newContext();`, place);
    }
    await passes("no-restricted-imports", `import {test} from "@playwright/test";`, "packages/ui/src/testing/guard.ts");
    await passes("no-restricted-syntax", `export const c = async (browser) => browser.newContext();`, "packages/ui/src/testing/guardLogic.test.ts");
  });
  it("lets routesSpec.ts import Playwright's own test, but not take a page, a context or a browser fixture", async () => {
    const file = "packages/ui/src/testing/routesSpec.ts";
    await passes("no-restricted-imports", `import {expect, test} from "@playwright/test";`, file);
    await passes("no-restricted-syntax", `test("x", async ({request}) => { await request.get("/"); });`, file);
    await fails("no-restricted-syntax", `test("x", async ({page}) => { await page.goto("/"); });`, file);
    await fails("no-restricted-syntax", `test("x", async ({context, request}) => { void context; });`, file);
    await fails("no-restricted-syntax", `test("x", async ({browser}) => { await browser.newContext(); });`, file);
  });
});
