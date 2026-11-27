import type {ChildProcess} from "node:child_process";

import type {Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {VERIFY_HOST_RE, VERIFY_ORIGIN, VERIFY_PORT, configurePath, stubVerify, type VerifyScenario} from "./configure-support.ts";
import {ENDPOINT} from "./endpoints-support.ts";
import {LANGS, openProfiles, type Handlers} from "./profiles-support.ts";
import {claimsFixture} from "@ctrlz/api-client/testing/screenFixtures.ts";
import {MAX_MS, POLL_MS} from "@ctrlz/ui/setup/verifyModel.ts";
import {startNext, stop, waitUntilUp} from "./realServer.ts";
import {setupText} from "./setup-support.ts";

// The setup verification (spec p3 8.4, Plan T-236): three states by the Plan's definitions against the stub of the verify zone, a fresh
// 26-character label for every probe, success only after two matches in a row, and the manual check in place of the probe when the
// installation has no `CTRLZ_VERIFY_ORIGIN`. The stub is a route of the page: the probe is a request to another origin by design, so the
// guard of 17.2 records it and each case acknowledges it with `guard.consume("external")` and checks that it was the verify zone only.
//
// The shared server of the run has no verify origin (the proxy's policy is `connect-src 'self'`), so the cases of the probe run against a
// server of their own with it set, as verify-origin.spec.ts does for the wrong values.

const LAST_STEP = {windows: 6} as const;
const s = (lang: "fa" | "en", path: string, values?: Record<string, string | number>) => setupText(lang, path, values);
const status = (page: Page) => page.getByTestId("verify-status");
const lastStep = (lang: "fa" | "en") => configurePath(lang, ENDPOINT.home, "windows", LAST_STEP.windows);

for (const {lang} of LANGS) {
  test.describe(`${lang}: no verify origin`, () => {
    test("T-236: without CTRLZ_VERIFY_ORIGIN the probe is hidden and a lookup by hand is shown", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      const response = await page.goto(lastStep(lang));
      expect(response?.headers()["content-security-policy"] ?? "").toContain("connect-src 'self'");
      expect(response?.headers()["content-security-policy"] ?? "").not.toContain(".verify.");
      const manual = page.getByRole("dialog").getByTestId("verify-manual");
      await expect(manual).toBeVisible();
      await expect(page.getByTestId("verify")).toHaveCount(0);
      // `myip` is answered only for an identified Endpoint; a `verify` name gets the node's own address from any resolver.
      await expect(manual.locator(".tech-copy-row").first()).toContainText("nslookup myip.dns.example.test");
      await expect(manual.locator(".tech-copy-row").nth(1)).toContainText("dig myip.dns.example.test");
      await expect(manual).not.toContainText(".verify.");
      await expect(manual.getByRole("button", {name: /./})).toHaveCount(2);
    });

    test("T-237: in private CA mode (no verify origin, a certificate no browser trusts) no probe is made and the manual check says why", async ({page, context, baseURL, guard}) => {
      await openProfiles(context, baseURL);
      await page.goto(lastStep(lang));
      const manual = page.getByRole("dialog").getByTestId("verify-manual");
      await expect(manual).toBeVisible();
      await expect(manual).toContainText(s(lang, "verify.manualHint"));
      await expect(page.getByTestId("verify")).toHaveCount(0);
      await expect(page.getByTestId("verify-status")).toHaveCount(0);
      // The page asks no other origin, so a name under the verify zone is never fetched.
      expect(guard.consume("external")).toEqual([]);
    });

    test("T-236: the manual check never says that an answer with a node address proves the Endpoint", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(lastStep(lang));
      const manual = page.getByTestId("verify-manual");
      await expect(manual).not.toContainText("203.0.113.53");
      await expect(manual).not.toContainText("203.0.113.54");
      await expect(manual.getByText(s(lang, "verify.manualResult"), {exact: true})).toBeVisible();
    });

    test("S7-r2-7: the manual check lists the networks this Endpoint holds, to compare, and does not call any answer this Endpoint's", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(lastStep(lang));
      const manual = page.getByTestId("verify-manual");
      // An address in the answer says that some Endpoint of the service holds the claim of the network, not which one.
      await expect(manual.getByText(s(lang, "verify.manualResult"), {exact: true})).toBeVisible();
      await expect(manual).not.toContainText(s(lang, "verify.states.success"));
      const claims = manual.getByTestId("verify-claims");
      await expect(claims).toContainText(s(lang, "verify.manualClaims"));
      // The node compiles the active claim and the one in its grace (spec p3 3.3, 4.1), so both answer and both are listed, the grace one marked with its end.
      // A claim waiting for proof or suspended identifies nobody (S7-r3-1).
      await expect(claims).toContainText("203.0.113.7/32");
      const grace = claims.getByRole("listitem").filter({hasText: "192.0.2.0/28"});
      await expect(grace).toContainText(s(lang, "verify.manualGraceUntil", {date: "@@"}).split("@@")[0]!.trim());
      await expect(claims.getByRole("listitem").filter({hasText: "203.0.113.7/32"})).not.toContainText(s(lang, "verify.manualGrace"));
      for (const other of ["198.51.100.0/24", "192.0.2.64/26"]) await expect(claims).not.toContainText(other);
      await expect(claims).toContainText(s(lang, "verify.manualCompare"));
    });

    test("S7-r3-1: an Endpoint whose only claim is in its grace lists it, and does not say that the answer is another Endpoint's", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      const grace = claimsFixture().find((claim) => claim.state === "grace")!;
      mock.screens.claims.set(ENDPOINT.laptop, [grace]);
      await page.goto(configurePath(lang, ENDPOINT.laptop, "windows", LAST_STEP.windows));
      const claims = page.getByTestId("verify-manual").getByTestId("verify-claims");
      await expect(claims).toContainText(grace.cidr);
      await expect(claims).toContainText(s(lang, "verify.manualCompare"));
      await expect(claims).not.toContainText(s(lang, "verify.manualNoClaims"));
    });

    test("S7-r2-7: an Endpoint that holds no network says that an address belongs to another one", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(configurePath(lang, ENDPOINT.laptop, "windows", LAST_STEP.windows));
      const claims = page.getByTestId("verify-manual").getByTestId("verify-claims");
      await expect(claims).toContainText(s(lang, "verify.manualNoClaims"));
      await expect(claims).not.toContainText(s(lang, "verify.manualCompare"));
    });
  });
}

test.describe("with a verify origin", () => {
  test.describe.configure({mode: "serial", timeout: 120_000});
  const base = `http://localhost:${VERIFY_PORT}`;
  test.use({baseURL: base});
  let server: ChildProcess;

  test.beforeAll(async () => {
    server = startNext(VERIFY_PORT, {CTRLZ_VERIFY_ORIGIN: VERIFY_ORIGIN, CTRLZ_LAB: "1"});
    await waitUntilUp(base, server);
  });
  test.afterAll(() => {
    if (server) stop(server);
  });

  for (const {lang} of LANGS) {
    const run = async (page: Page, context: Parameters<typeof openProfiles>[0], script: VerifyScenario[], handlers?: Handlers) => {
      await openProfiles(context, base, handlers ? {handlers} : {});
      const labels = await stubVerify(page, script);
      await page.goto(lastStep(lang));
      await page.getByTestId("verify").getByRole("button", {name: s(lang, "verify.start")}).click();
      return labels;
    };
    const outside = (guard: {consume: (k: "external") => string[]}, labels: string[]) => {
      const origins = guard.consume("external");
      expect(origins.length).toBeGreaterThan(0);
      for (const origin of new Set(origins)) expect(new URL(origin).hostname, origin).toMatch(VERIFY_HOST_RE);
      expect(labels.length).toBeGreaterThan(0);
    };

    test(`${lang}: the policy of the page allows the verify origin and nothing else (T-238)`, async ({page, context, guard}) => {
      await openProfiles(context, base);
      const response = await page.goto(lastStep(lang));
      const csp = response?.headers()["content-security-policy"] ?? "";
      expect(csp).toContain(`connect-src 'self' ${VERIFY_ORIGIN}`);
      await expect(page.getByTestId("verify")).toBeVisible();
      await expect(page.getByTestId("verify-manual")).toHaveCount(0);
      expect(guard.consume("external")).toEqual([]);
    });

    test(`${lang}: pending until the name reaches the service, with a fresh 26-character label for every probe`, async ({page, context, guard}) => {
      const labels = await run(page, context, ["unseen"]);
      await expect(status(page)).toHaveAttribute("data-state", "pending");
      await expect(status(page)).toContainText(s(lang, "verify.states.pending"));
      await expect.poll(() => labels.length, {timeout: 12_000}).toBeGreaterThanOrEqual(2);
      expect(new Set(labels).size).toBe(labels.length);
      for (const label of labels) expect(label).toMatch(/^[a-z2-7]{26}$/);
      await page.getByTestId("verify").getByRole("button", {name: s(lang, "verify.stop")}).click();
      outside(guard, labels);
    });

    test(`${lang}: partial when the label was seen but through another Endpoint`, async ({page, context, guard}) => {
      const labels = await run(page, context, ["other"]);
      await expect(status(page)).toHaveAttribute("data-state", "partial");
      await expect(status(page)).toContainText(s(lang, "verify.states.partial"));
      await page.getByTestId("verify").getByRole("button", {name: s(lang, "verify.stop")}).click();
      outside(guard, labels);
    });

    // T-557 (D55): the incomplete state for an Endpoint with Plain DNS says what an unidentified device gets, by the switch of free DNS, and gives the way out.
    test(`${lang}: T-557: partial says that a device on an unclaimed network gets free DNS, and offers to prove the claim that waits`, async ({page, context, guard}) => {
      const labels = await run(page, context, ["other"]);
      await expect(status(page)).toHaveAttribute("data-state", "partial");
      const note = page.getByTestId("verify-partial-plain");
      await expect(note).toContainText(s(lang, "verify.freeDns.on"));
      await expect(note).not.toContainText(s(lang, "verify.freeDns.off"));
      await note.getByRole("button", {name: s(lang, "verify.freeDns.prove")}).click();
      await expect(page).toHaveURL(/ipDialog=proof(:|%3A)/);
      outside(guard, labels);
    });

    test(`${lang}: T-557: with no claim waiting the button adds a network, and with the switch off the text says refused`, async ({page, context, guard}) => {
      const labels = await run(page, context, ["other"], {
        "GET /endpoints/{id}/ip-claims": {body: {claims: []}},
        "GET /public/free-dns": {body: {enabled: false}},
      });
      await expect(status(page)).toHaveAttribute("data-state", "partial");
      const note = page.getByTestId("verify-partial-plain");
      await expect(note).toContainText(s(lang, "verify.freeDns.off"));
      await expect(note).not.toContainText(s(lang, "verify.freeDns.on"));
      await note.getByRole("button", {name: s(lang, "verify.freeDns.add")}).click();
      await expect(page).toHaveURL(/ipDialog=claim$/);
      outside(guard, labels);
    });

    test.describe(`${lang}: switch unknown`, () => {
      test.use({allowConsole: [/status of 5\d\d/]});
      test("T-557: when the route cannot be read, partial says nothing about free DNS or refusal and keeps the button", async ({page, context, guard}) => {
        const labels = await run(page, context, ["other"], {"GET /public/free-dns": {status: 503, body: {code: "service_unavailable"}}});
        await expect(status(page)).toHaveAttribute("data-state", "partial");
        const note = page.getByTestId("verify-partial-plain");
        await expect(note.getByRole("button")).toBeVisible();
        await expect(note.locator("p")).toHaveCount(0);
        outside(guard, labels);
      });
    });

    test(`${lang}: success only after two matches in a row, and it names the protocol`, async ({page, context, guard}) => {
      const labels = await run(page, context, ["match", "match"]);
      await expect(status(page)).toHaveAttribute("data-state", "confirming");
      await expect(status(page)).toHaveAttribute("data-state", "success", {timeout: 12_000});
      await expect(status(page)).toContainText(s(lang, "verify.states.success"));
      await expect(status(page)).toContainText(s(lang, "verify.protocols.doh"));
      expect(labels).toHaveLength(2);
      // It stops asking once it has succeeded.
      await page.waitForTimeout(3500);
      expect(labels).toHaveLength(2);
      outside(guard, labels);
    });

    test(`${lang}: one match and then a miss is not success`, async ({page, context, guard}) => {
      const labels = await run(page, context, ["match", "unseen"]);
      await expect(status(page)).toHaveAttribute("data-state", "confirming");
      await expect(status(page)).toHaveAttribute("data-state", "pending", {timeout: 12_000});
      await page.getByTestId("verify").getByRole("button", {name: s(lang, "verify.stop")}).click();
      outside(guard, labels);
    });

    test(`${lang}: an answer that is not the node's (a captive portal's page) is pending, never a match`, async ({page, context, guard}) => {
      const labels = await run(page, context, ["junk"]);
      await expect(status(page)).toHaveAttribute("data-state", "pending");
      await page.getByTestId("verify").getByRole("button", {name: s(lang, "verify.stop")}).click();
      outside(guard, labels);
    });


    test(`${lang}: nothing seen for two minutes is a timeout, and it stops asking (S7-r2-5)`, async ({page, context, guard}) => {
      await openProfiles(context, base);
      const labels = await stubVerify(page, ["unseen"]);
      // The page's clock is the test's: the two minutes pass in one call. Installed before the page loads, so every timer of the probe is on it.
      await page.clock.install();
      await page.goto(lastStep(lang));
      await page.getByTestId("verify").getByRole("button", {name: s(lang, "verify.start")}).click();
      await expect(status(page)).toHaveAttribute("data-state", "pending");
      await page.clock.runFor(MAX_MS + POLL_MS * 2);
      await expect(status(page)).toHaveAttribute("data-state", "timeout", {timeout: 15_000});
      await expect(status(page)).toContainText(s(lang, "verify.states.timeout"));
      // The probes that were in flight have answered, and no new one starts afterwards.
      const asked = labels.length;
      expect(asked).toBeGreaterThan(1);
      await page.clock.runFor(POLL_MS * 4);
      await page.waitForTimeout(500);
      expect(labels).toHaveLength(asked);
      // A new check starts from the beginning, with the button that says so.
      await page.getByTestId("verify").getByRole("button", {name: s(lang, "verify.again")}).click();
      await expect(status(page)).toHaveAttribute("data-state", "pending");
      await expect.poll(() => labels.length).toBeGreaterThan(asked);
      await page.getByTestId("verify").getByRole("button", {name: s(lang, "verify.stop")}).click();
      outside(guard, labels);
    });

    test(`${lang}: Stop ends the check, and Start begins a new one with new labels`, async ({page, context, guard}) => {
      const labels = await run(page, context, ["unseen"]);
      await expect(status(page)).toHaveAttribute("data-state", "pending");
      await expect.poll(() => labels.length).toBeGreaterThanOrEqual(1);
      await page.getByTestId("verify").getByRole("button", {name: s(lang, "verify.stop")}).click();
      await expect(status(page)).toHaveAttribute("data-state", "idle");
      const stopped = labels.length;
      await page.waitForTimeout(3600);
      expect(labels).toHaveLength(stopped);
      await page.getByTestId("verify").getByRole("button", {name: s(lang, "verify.start")}).click();
      await expect(status(page)).toHaveAttribute("data-state", "pending");
      await expect.poll(() => labels.length).toBeGreaterThan(stopped);
      expect(new Set(labels).size).toBe(labels.length);
      await page.getByTestId("verify").getByRole("button", {name: s(lang, "verify.stop")}).click();
      outside(guard, labels);
    });

    test(`${lang}: closing the dialog ends the check: no probe is sent after it`, async ({page, context, guard}) => {
      const labels = await run(page, context, ["unseen"]);
      await expect(status(page)).toHaveAttribute("data-state", "pending");
      await expect.poll(() => labels.length).toBeGreaterThanOrEqual(1);
      await page.keyboard.press("Escape");
      await expect(page.getByRole("dialog")).toHaveCount(0);
      const asked = labels.length;
      await page.waitForTimeout(7000);
      expect(labels).toHaveLength(asked);
      outside(guard, labels);
    });

    test(`${lang}: a probe that fails to connect is pending and the check goes on`, async ({page, context, guard}) => {
      await openProfiles(context, base);
      let asked = 0;
      await page.route(/^https:\/\/[a-z2-7]{26}\.verify\.dns\.example\.test\/v/, (route) => {
        asked++;
        return route.abort("connectionrefused");
      });
      await page.goto(lastStep(lang));
      await page.getByTestId("verify").getByRole("button", {name: s(lang, "verify.start")}).click();
      await expect(status(page)).toHaveAttribute("data-state", "pending");
      await expect.poll(() => asked, {timeout: 12_000}).toBeGreaterThanOrEqual(2);
      await page.getByTestId("verify").getByRole("button", {name: s(lang, "verify.stop")}).click();
      guard.consume("external");
      guard.consume("console");
    });
  }
});
