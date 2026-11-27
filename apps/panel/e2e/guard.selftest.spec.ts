import type {Page} from "@playwright/test";
import {installApiMock} from "@ctrlz/api-client/testing/mock.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

// Spec 17.2, wp12-r1-5: the guard is a test fixture, and a fixture that never fires looks the same as
// one that has nothing to report. Each check is proved twice, and neither proof needs a screen.
//
//   "records ..."   the guard sees the problem: the test causes it on purpose, takes it with
//                   guard.consume, and asserts what it took. A recorder that broke fails here.
//   "fails on ..."  the guard enforces what it recorded: `test.fail()` expects the test to fail with
//                   the problem left in place, so an end-of-test check that was removed shows up as
//                   an unexpected pass. Every console error the browser adds on its own is allowed,
//                   so that only the check under test can be the reason it fails.
//
// The pages are served by `page.route` from the base URL's own origin, so no app is needed. A host
// under `.invalid` can never resolve (RFC 2606), so an external request here goes nowhere even
// where the guard is the thing under test.

const EXTERNAL = "https://guard-selftest.invalid";
// A data: image is no request, and `img-src 'none'` still refuses it: a violation with no network.
const PIXEL = "data:image/gif;base64,R0lGODlhAQABAAAAACw=";
const CSP = {"content-security-policy": "img-src 'none'"};
const LIST_RULES = JSON.stringify({prefetch: [{source: "list", urls: [`${EXTERNAL}/spec-prefetch?t=secret`]}], prerender: [{urls: [`${EXTERNAL}/spec-prerender`]}]});
// The rule of the finding: no URL in it at all, and every external <a> of the page becomes a request when it is hovered (or at once).
const DOCUMENT_RULES = JSON.stringify({prefetch: [{source: "document", where: {selector_matches: "a"}, eagerness: "immediate"}]});
const BROWSER_NOISE =/Failed to load resource|CORS|net::|WebSocket|Refused to|violates the following Content Security Policy/;

async function serve(page: Page) {
  const html = (body: string) => `<!doctype html><meta charset="utf-8"><title>guard selftest</title>${body}`;
  await page.route("**/guard-selftest/**", (route) => {
    const name = new URL(route.request().url()).pathname.split("/").pop();
    if (name === "csp") return route.fulfill({contentType: "text/html", headers: CSP, body: html(`<img alt="" src="${PIXEL}">`)});
    // The policy is on the frame and not on the top document: a sentinel read from the main frame alone misses it.
    if (name === "frame") return route.fulfill({contentType: "text/html", headers: CSP, body: html(`<img alt="" src="${PIXEL}">`)});
    // gate-r2-4: a hint written in the HTML, and one in the Link header of the document. Chrome under Playwright never connects for either.
    if (name === "hint-html") return route.fulfill({contentType: "text/html", body: html(`<link rel="preconnect" href="${EXTERNAL}"><p>quiet</p>`)});
    if (name === "hint-header") return route.fulfill({contentType: "text/html", headers: {link: `<${EXTERNAL}>; rel=preconnect`}, body: html("<p>quiet</p>")});
    if (name === "hint-same") return route.fulfill({contentType: "text/html", headers: {link: "</guard-selftest/quiet>; rel=prefetch"}, body: html('<link rel="dns-prefetch" href="/"><link rel="preconnect" href="data:,x"><link rel="stylesheet" href="data:text/css,p{}">')});
    // gate-r26-1: speculation rules. A list rule names a URL; a document rule names none and works on the page's own links; a header names a file.
    if (name === "spec-list") return route.fulfill({contentType: "text/html", body: html(`<script type="speculationrules">${LIST_RULES}</script><p>quiet</p>`)});
    if (name === "spec-document") return route.fulfill({contentType: "text/html", body: html(`<a href="${EXTERNAL}/docs?ref=panel">docs</a><script type="speculationrules">${DOCUMENT_RULES}</script>`)});
    if (name === "spec-header") return route.fulfill({contentType: "text/html", headers: {"speculation-rules": '"/guard-selftest/rules.json"'}, body: html("<p>quiet</p>")});
    if (name === "rules.json") return route.fulfill({contentType: "application/speculationrules+json", body: DOCUMENT_RULES});
    if (name === "outer") return route.fulfill({contentType: "text/html", body: html(`<iframe src="/guard-selftest/frame" title="inner"></iframe>`)});
    return route.fulfill({contentType: "text/html", body: html("<p>quiet</p>")});
  });
}

const open = async (page: Page, name: string) => {
  await serve(page);
  await page.goto(`/guard-selftest/${name}`);
};

/** Takes recorded items until `count` have come, since a console or page error reaches Node a moment after it happens. */
async function take(read: () => string[], count: number): Promise<string[]> {
  const seen: string[] = [];
  await expect.poll(() => (seen.push(...read()), seen.length)).toBeGreaterThanOrEqual(count);
  return seen;
}

test.describe("the guard records", () => {
  test("a request to another origin, and refuses it", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "quiet");
    const outcome = await page.evaluate((url) => fetch(url).then(() => "reached", () => "refused"), `${EXTERNAL}/x`);
    expect(outcome).toBe("refused");
    expect(guard.consume("external")).toEqual([EXTERNAL]);
  });

  test("an external request that a mock route answers (wp12-r1-6)", async ({page, context, guard}) => {
    guard.allowConsole(/./);
    await installApiMock(context);
    await open(page, "quiet");
    // The path holds /api/v1/, so the mock's glob takes the request and the guard's route never sees it.
    await page.evaluate((url) => fetch(url).catch(() => "failed"), `${EXTERNAL}/api/v1/ping`);
    expect(guard.consume("external")).toEqual([EXTERNAL]);
  });

  test("a WebSocket, whatever its target", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "quiet");
    await page.evaluate((url) => void new WebSocket(url).addEventListener("error", () => {}), `wss://guard-selftest.invalid/s`);
    expect(await take(() => guard.consume("external"), 1)).toContain("ws");
  });

  test("a CSP violation on every load of a page, not only the last (reload and navigation)", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "csp");
    await page.reload();
    await page.goto("/guard-selftest/csp");
    const seen = await take(() => guard.consume("csp"), 3);
    expect(seen).toHaveLength(3);
    for (const directive of seen) expect(directive).toMatch(/^img-src/);
  });

  test("a CSP violation inside an iframe", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "outer");
    const seen = await take(() => guard.consume("csp"), 1);
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatch(/^img-src/);
  });

  test("a console error", async ({page, guard}) => {
    await open(page, "quiet");
    await page.evaluate(() => console.error("guard selftest: console"));
    expect(await take(() => guard.consume("console"), 1)).toEqual([expect.stringContaining("guard selftest: console")]);
  });

  // gate-r4-5: Chrome writes the whole URL of a blocked request into the console, and the failure message of a test ends up in a CI log, so a
  // ticket or a phone number in a query must not survive in what the guard keeps. A real CSP refusal is used, not a made-up message.
  test("the origin of a URL in a console or page error, and not its path or query (gate-r4-5)", async ({page, guard}) => {
    await serve(page);
    await page.route("**/guard-selftest/connect", (route) =>
      route.fulfill({contentType: "text/html", headers: {"content-security-policy": "connect-src 'none'"}, body: "<!doctype html><title>t</title><p>quiet</p>"}));
    await page.goto("/guard-selftest/connect");
    const secret = `${EXTERNAL}/collect?ticket=SECRET123&phone=09120000000#frag-xyz`;
    await page.evaluate((url) => fetch(url).catch(() => undefined), secret);
    const raised = page.waitForEvent("pageerror");
    await page.evaluate((url) => void setTimeout(() => { throw new Error(`sent ${url}`); }, 0), secret);
    await raised;
    await page.evaluate((url) => console.error(`manual ${url}`), secret);
    // The last one that the page wrote is the marker: messages reach Node in order, so everything before it has arrived.
    const consoleErrors: string[] = [];
    await expect.poll(() => (consoleErrors.push(...guard.consume("console")), consoleErrors.some((m) => m.startsWith("manual")))).toBe(true);
    const pageErrors = await take(() => guard.consume("pageerror"), 1);
    guard.consume("csp");
    guard.consume("external");
    const all = [...consoleErrors, ...pageErrors].join("\n");
    for (const part of ["SECRET123", "09120000000", "frag-xyz", "/collect"]) expect(all, part).not.toContain(part);
    expect(all).toContain(EXTERNAL);
    expect(consoleErrors.some((m) => /Refused to connect|violates/.test(m)), "the real CSP message is among them").toBe(true);
  });

  test("an uncaught page error", async ({page, guard}) => {
    await open(page, "quiet");
    const raised = page.waitForEvent("pageerror");
    await page.evaluate(() => void setTimeout(() => { throw new Error("guard selftest: page"); }, 0));
    await raised;
    expect(await take(() => guard.consume("pageerror"), 1)).toEqual([expect.stringContaining("guard selftest: page")]);
  });

  test("its init script in the page, so that the CSP check is not blind", async ({page}) => {
    await open(page, "quiet");
    expect(await page.evaluate(() => (window as unknown as {__ctrlzGuardOn?: boolean}).__ctrlzGuardOn)).toBe(true);
  });

  test("a console error that a test allowed is not recorded", async ({page, guard}) => {
    guard.allowConsole(/guard selftest: allowed/);
    await open(page, "quiet");
    await page.evaluate(() => console.error("guard selftest: allowed"));
    await page.waitForTimeout(200);
    expect(guard.consume("console")).toEqual([]);
  });
});

test.describe("the guard fails the test on", () => {
  test("a request to another origin", async ({page, guard}) => {
    test.fail();
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "quiet");
    await page.evaluate((url) => fetch(url).catch(() => "refused"), `${EXTERNAL}/x`);
  });

  test("a Content-Security-Policy violation", async ({page, guard}) => {
    test.fail();
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "csp");
    // The event is asynchronous, so give it the time the real tests give a page before they end.
    await page.waitForTimeout(300);
  });

  test("a console error", async ({page}) => {
    test.fail();
    await open(page, "quiet");
    await page.evaluate(() => console.error("guard selftest: left in place"));
    await page.waitForTimeout(300);
  });

  test("an uncaught page error", async ({page}) => {
    test.fail();
    await open(page, "quiet");
    const raised = page.waitForEvent("pageerror");
    await page.evaluate(() => void setTimeout(() => { throw new Error("guard selftest: left in place"); }, 0));
    await raised;
  });
});

// gate-r1-6: a WebRTC peer connection is no request for Playwright and no directive of the CSP covers it, so the
// constructor reports itself. The page is on `.invalid`, so no packet could leave even where the guard is broken.
test.describe("the guard records a peer connection", () => {
  test("an RTCPeerConnection, whatever its servers", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "quiet");
    await page.evaluate(() => {
      new RTCPeerConnection().close();
      new RTCPeerConnection({iceServers: [{urls: "stun:guard-selftest.invalid:3478"}]}).close();
    });
    expect(await take(() => guard.consume("external"), 2)).toEqual(["rtc", "rtc"]);
  });

  test("an RTCPeerConnection that is still an RTCPeerConnection (instanceof and static members work)", async ({page, guard}) => {
    await open(page, "quiet");
    const shape = await page.evaluate(() => {
      const pc = new RTCPeerConnection();
      const ok = pc instanceof RTCPeerConnection && typeof RTCPeerConnection.generateCertificate === "function";
      pc.close();
      return ok;
    });
    expect(shape).toBe(true);
    guard.consume("external");
  });
});


// gate-r21-2: the policy's `connect-src` lets through every origin it lists, and the verify wildcard of P4 will list one that covers `wss:` and
// WebTransport as well as `fetch`. WebTransport is no Playwright request, and WebSocketStream to a name that does not resolve is no `websocket`
// event, so a session to such an origin would leave nothing. The page below lists the target in its own policy, so no CSP violation can
// stand in for the record, and the name is on `.invalid`, so no packet could leave even where the guard is broken.
const LISTED = "connect-src https://guard-selftest.invalid wss://guard-selftest.invalid";
async function openListed(page: Page) {
  await serve(page);
  await page.route("**/guard-selftest/listed", (route) =>
    route.fulfill({contentType: "text/html", headers: {"content-security-policy": LISTED}, body: "<!doctype html><title>t</title><p>quiet</p>"}));
  await page.goto("/guard-selftest/listed");
}
const OPEN_WEBTRANSPORT = (url: string) => {
  const session = new WebTransport(url);
  session.ready.catch(() => {});
  session.closed.catch(() => {});
};
const OPEN_WEBSOCKETSTREAM = (url: string) => {
  const stream = new (window as unknown as {WebSocketStream: new (u: string) => {opened: Promise<unknown>; closed: Promise<unknown>}}).WebSocketStream(url);
  stream.opened.catch(() => {});
  stream.closed.catch(() => {});
};

test.describe("the guard records the other long-lived connections (gate-r21-2)", () => {
  test("a WebTransport session to an origin that the page's policy lists", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await openListed(page);
    await page.evaluate(OPEN_WEBTRANSPORT, `${EXTERNAL}/wt`);
    expect(await take(() => guard.consume("external"), 1)).toEqual(["wt"]);
    expect(guard.consume("csp")).toEqual([]);
  });

  test("a WebSocketStream to a name that does not resolve", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await openListed(page);
    expect(await page.evaluate(() => typeof (window as unknown as {WebSocketStream?: unknown}).WebSocketStream), "this browser has WebSocketStream").toBe("function");
    await page.evaluate(OPEN_WEBSOCKETSTREAM, "wss://guard-selftest.invalid/s");
    expect(await take(() => guard.consume("external"), 1)).toEqual(["ws"]);
    expect(guard.consume("csp")).toEqual([]);
  });

  test("a WebTransport that is still a WebTransport (instanceof and its constructor)", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await openListed(page);
    const shape = await page.evaluate(() => {
      const session = new WebTransport("https://guard-selftest.invalid/wt");
      session.ready.catch(() => {});
      session.closed.catch(() => {});
      return session instanceof WebTransport && session.constructor === WebTransport && "datagrams" in session;
    });
    expect(shape).toBe(true);
    expect(await take(() => guard.consume("external"), 1)).toEqual(["wt"]);
  });
});

test.describe("the guard fails the test on a long-lived connection (gate-r21-2)", () => {
  test("a WebTransport session to a listed origin", async ({page}) => {
    test.fail();
    await openListed(page);
    await page.evaluate(OPEN_WEBTRANSPORT, `${EXTERNAL}/wt`);
    await page.waitForTimeout(300);
  });

  test("a WebSocketStream to a listed name that does not resolve", async ({page}) => {
    test.fail();
    await openListed(page);
    await page.evaluate(OPEN_WEBSOCKETSTREAM, "wss://guard-selftest.invalid/s");
    await page.waitForTimeout(300);
  });
});

// gate-r22-9: fetchLater() queues a request that the browser sends once the document is gone (or `activateAfter` has passed). It is not window.fetch,
// Playwright reports no request for it and the console has no line, and `connect-src` applies to it only when the policy refuses the origin. So with a
// listed origin (the verify wildcard) it left nothing. The origin is on `.invalid`, so no packet could leave even where the guard is broken.
type FetchLater = (input: string, init?: {method?: string; body?: string; activateAfter?: number}) => {activated: boolean};
const QUEUE_FETCHLATER = (url: string) => (window as unknown as {fetchLater: FetchLater}).fetchLater(url, {method: "POST", body: "x", activateAfter: 600_000});

test.describe("the guard records a request that fetchLater() queues (gate-r22-9)", () => {
  test("to another origin that the page's policy lists, at the call", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await openListed(page);
    expect(await page.evaluate(() => typeof (window as unknown as {fetchLater?: unknown}).fetchLater), "this browser has fetchLater").toBe("function");
    await page.evaluate(QUEUE_FETCHLATER, "https://guard-selftest.invalid/t");
    expect(await take(() => guard.consume("external"), 1)).toEqual(["later:https://guard-selftest.invalid"]);
    expect(guard.consume("csp")).toEqual([]);
  });

  test("with a Request, a URL object and a protocol-relative URL that the browser refuses as insecure", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await openListed(page);
    await page.evaluate(() => {
      const later = (window as unknown as {fetchLater: (i: unknown, o?: unknown) => unknown}).fetchLater;
      later(new Request("https://guard-selftest.invalid/a", {method: "POST", body: "x"}), {activateAfter: 600_000});
      later(new URL("https://guard-selftest.invalid/c"), {method: "POST", body: "x", activateAfter: 600_000});
      // On an http page this one is http and Chrome throws for it: the call is still reported, because it was made. Through Caddy the page is
      // https, the same URL is https, nothing throws, and the record names that scheme (found by the first run through Caddy).
      try {
        later("//guard-selftest.invalid/b", {method: "POST", body: "x", activateAfter: 600_000});
      } catch {
        /* SecurityError: fetchLater was passed an insecure URL */
      }
    });
    const pageScheme = await page.evaluate(() => location.protocol);
    expect(await take(() => guard.consume("external"), 3)).toEqual(["later:https://guard-selftest.invalid", "later:https://guard-selftest.invalid", `later:${pageScheme}//guard-selftest.invalid`]);
  });

  test("is still the browser's fetchLater: it returns a result, and the page's own origin is no record", async ({page, guard}) => {
    await openUnloadPage(page, "connect-src 'self'");
    // The result is an object with an `activated` getter on its prototype, so it is read in the page.
    const activated = await page.evaluate((url) => typeof (window as unknown as {fetchLater: FetchLater}).fetchLater(url, {method: "POST", body: "x", activateAfter: 600_000}).activated, "/guard-selftest/own");
    expect(activated).toBe("boolean");
    expect(guard.consume("external")).toEqual([]);
    expect(guard.consume("csp")).toEqual([]);
  });
});

test.describe("the guard fails the test on a request that fetchLater() queues (gate-r22-9)", () => {
  test("to a listed origin, never sent while the test runs", async ({page}) => {
    test.fail();
    await openListed(page);
    await page.evaluate(QUEUE_FETCHLATER, "https://guard-selftest.invalid/t");
    await page.waitForTimeout(300);
  });
});

// gate-r1-5, gate-r1-7: a second context is under the same checks, and one opened by hand is refused.
test.describe("the guard covers a second context", () => {
  test("a request to another origin, a CSP violation and a console error in a context from guard.newContext()", async ({guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    const second = await guard.newContext();
    const tab = await second.newPage();
    await open(tab, "csp");
    const outcome = await tab.evaluate((url) => fetch(url).then(() => "reached", () => "refused"), `${EXTERNAL}/x`);
    expect(outcome).toBe("refused");
    expect(guard.consume("external")).toEqual([EXTERNAL]);
    expect((await take(() => guard.consume("csp"), 1))[0]).toMatch(/^img-src/);
    await tab.evaluate(() => console.error("guard selftest: second context"));
    expect(await take(() => guard.consume("console"), 1)).toEqual([expect.stringContaining("guard selftest: second context")]);
  });

  test("a WebRTC attempt in a second context", async ({guard}) => {
    const tab = await (await guard.newContext()).newPage();
    await open(tab, "quiet");
    await tab.evaluate(() => void new RTCPeerConnection().close());
    expect(await take(() => guard.consume("external"), 1)).toEqual(["rtc"]);
  });
});

test.describe("the guard fails the test on", () => {
  test("a WebRTC peer connection", async ({page}) => {
    test.fail();
    await open(page, "quiet");
    await page.evaluate(() => void new RTCPeerConnection().close());
    await page.waitForTimeout(300);
  });

  test("an external request in a second context", async ({guard}) => {
    test.fail();
    guard.allowConsole(BROWSER_NOISE);
    const tab = await (await guard.newContext()).newPage();
    await open(tab, "quiet");
    await tab.evaluate((url) => fetch(url).catch(() => "refused"), `${EXTERNAL}/x`);
  });

  test("a context opened with browser.newContext(), which no check covers", async ({browser}) => {
    test.fail();
    // eslint-disable-next-line no-restricted-syntax -- the case under test: the end-of-test check must refuse what lint also refuses.
    const bare = await browser.newContext();
    await bare.newPage();
  });

  // gate-r25-1: the lint rule matches the word `browser` only, and the old stray check saw only contexts still open at the end. The guard now wraps
  // the worker's browser for the length of the test, so a spelling that lint does not know, closed before the end, still fails the test.
  test("a context opened through an alias of the browser and closed before the end", async ({page}) => {
    test.fail();
    const b = page.context().browser()!;
    const other = await b.newContext();
    await (await other.newPage()).goto("about:blank");
    await other.close();
  });

  test("a context opened through a renamed browser fixture and closed before the end", async ({browser: br}) => {
    test.fail();
    const other = await br.newContext();
    await other.close();
  });

  test("a page opened with browser.newPage() through an alias and closed before the end", async ({page}) => {
    test.fail();
    const b = page.context().browser()!;
    const tab = await b.newPage();
    await tab.close();
  });

  test("the guard's own second context is no stray, and the wrap is gone for guard.newContext()", async ({guard, page}) => {
    const second = await guard.newContext();
    await second.newPage();
    await second.close();
    // The wrap is on the worker's browser for this test, and the guard's own method bypasses it.
    expect(Object.getOwnPropertyDescriptor(page.context().browser()!, "newContext"), "the browser is wrapped while the test runs").toBeDefined();
  });

  // The option no longer exists (gate-r1-4), so naming it changes nothing: the request is still refused and recorded.
  test.describe("an origin that a test tries to allow with the removed allowedOrigins option", () => {
    test.use({allowedOrigins: [EXTERNAL]} as never);
    test("is still external", async ({page, guard}) => {
      test.fail();
      guard.allowConsole(BROWSER_NOISE);
      await open(page, "quiet");
      await page.evaluate((url) => fetch(url).catch(() => "refused"), `${EXTERNAL}/x`);
    });
  });
});

// gate-r5-1: guard.newContext() relies on the Playwright runner to give a second context the options of the project and of test.use
// (runBeforeCreateBrowserContext merges them into every context a test creates; viewport, locale, colour scheme, ignoreHTTPSErrors, and so on).
// A review feared that browser.newContext() gets the defaults instead, so a second page would be drawn at 1280 px in another locale, or fail on the
// self-signed certificate of the Caddy run. It does not today; this case fails on the day a Playwright version stops merging them. The options are
// set with test.use, the way a project sets them, and the second page must report the same. ignoreHTTPSErrors has no effect on http, so it is
// not observed here.
test.describe("a second context is the same kind of visitor as the first (gate-r5-1)", () => {
  test.use({viewport: {width: 611, height: 703}, locale: "fa-IR", colorScheme: "dark", ignoreHTTPSErrors: true});
  const probe = (page: Page) => page.evaluate(() => ({width: innerWidth, height: innerHeight, language: navigator.language, dark: matchMedia("(prefers-color-scheme: dark)").matches}));

  test("viewport, locale and colour scheme", async ({page, guard}) => {
    await open(page, "quiet");
    const first = await probe(page);
    expect(first).toEqual({width: 611, height: 703, language: "fa-IR", dark: true});
    const tab = await (await guard.newContext()).newPage();
    await open(tab, "quiet");
    expect(await probe(tab)).toEqual(first);
  });

  test("an option that the caller passes still wins", async ({page, guard}) => {
    await open(page, "quiet");
    const tab = await (await guard.newContext({viewport: {width: 420, height: 600}})).newPage();
    await open(tab, "quiet");
    expect(await probe(tab)).toMatchObject({width: 420, height: 600, language: "fa-IR", dark: true});
  });
});

// gate-r5-2: the guard excuses a policy-less self-test page only when a mock route made it. It relies on Playwright reporting no server address
// for a fulfilled response and one for a real answer, so that fact is pinned here: if it changed, the excuse would go to every page or to none.
test.describe("the guard tells a mock route's answer from a server's (gate-r5-2)", () => {
  test("a fulfilled document has no server address, and the app's own answer has one", async ({page}) => {
    await serve(page);
    const [mocked] = await Promise.all([page.waitForResponse((r) => r.url().endsWith("/guard-selftest/quiet")), page.goto("/guard-selftest/quiet")]);
    expect(await mocked.serverAddr()).toBeNull();
    // /logo.png is a plain file of the app: any answer of the real server has an address.
    const [served] = await Promise.all([page.waitForResponse((r) => r.url().endsWith("/logo.png")), page.evaluate(() => void fetch("/logo.png"))]);
    expect(await served.serverAddr()).not.toBeNull();
  });
});

// gate-r3-5: Chrome's bypass of the CSP stops every violation from being raised, so the CSP check would pass on a broken page. The guard refuses
// the option, from `test.use`, from the config and from `guard.newContext`. Each case would pass if the refusal were removed, and test.fail()
// makes that an unexpected pass. The page serves a policy that its own image breaks, which is what the bypass would hide.
test.describe("the guard fails the test on bypassCSP", () => {
  test.describe("set with test.use", () => {
    // eslint-disable-next-line no-restricted-syntax -- the case under test: lint refuses the word in specs, the guard refuses the option.
    test.use({bypassCSP: true});
    // The guard refuses while the fixture is set up, before the body of the test runs, so the expectation is on the group.
    test.fail();
    test("the whole test", async ({page, guard}) => {
      guard.allowConsole(BROWSER_NOISE);
      await open(page, "csp");
    });
  });

  test("set on a second context", async ({guard}) => {
    test.fail();
    // eslint-disable-next-line no-restricted-syntax -- same.
    const second = await guard.newContext({bypassCSP: true});
    await second.newPage();
  });

  test("and without it the same page does raise a violation, which the guard records", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "csp");
    expect(await take(() => guard.consume("csp"), 1)).toHaveLength(1);
  });
});

// gate-r3-4: a document with no policy raises no violation, so the CSP check alone is green on it. The guard also records an HTML document of
// the app that arrived without a policy that has a nonce. The page is served from a name that is not one of the guard's own self-test pages.
test.describe("the guard records an HTML document with no policy", () => {
  const serveBare = (page: Page, policy?: string) =>
    page.route("**/bare-document", (route) => route.fulfill({contentType: "text/html", headers: policy ? {"content-security-policy": policy} : {}, body: "<!doctype html><title>bare</title><p>quiet</p>"}));

  test("one with no policy, and one whose policy has no nonce", async ({page, guard}) => {
    await serveBare(page);
    await page.goto("/bare-document");
    expect(guard.consume("policy")).toEqual(["200 /bare-document"]);
    await page.unroute("**/bare-document");
    await serveBare(page, "default-src 'none'");
    await page.goto("/bare-document");
    expect(guard.consume("policy")).toEqual(["200 /bare-document"]);
  });

  test("and not one that has a nonce", async ({page, guard}) => {
    await serveBare(page, "default-src 'none'; script-src 'self' 'nonce-abc'");
    await page.goto("/bare-document");
    expect(guard.consume("policy")).toEqual([]);
  });

  // gate-r12-1: a nonce and no weak script-src are not enough when script-src-attr lets handlers run, or when no directive limits scripts at all.
  test("one that has a nonce and lets inline event handlers run, and one that has a nonce and limits no script", async ({page, guard}) => {
    for (const policy of ["default-src 'none'; script-src 'self' 'nonce-abc'; style-src 'nonce-abc'; script-src-attr 'unsafe-inline'", "style-src 'nonce-abc'; img-src 'self'"]) {
      await serveBare(page, policy);
      await page.goto("/bare-document");
      expect(guard.consume("policy"), policy).toEqual(["200 /bare-document"]);
      await page.unroute("**/bare-document");
    }
  });

  test("and fails the test on a policy with no script limit", async ({page}) => {
    test.fail();
    await serveBare(page, "style-src 'nonce-abc'; img-src 'self'");
    await page.goto("/bare-document");
  });

  test("and fails the test on it", async ({page}) => {
    test.fail();
    await serveBare(page);
    await page.goto("/bare-document");
  });

  // gate-r9-3: next dev's policy has a nonce on script-src, and 'unsafe-inline' for styles, under which a style with no nonce raises no violation.
  const DEV_POLICY = "default-src 'none'; script-src 'self' 'nonce-abc' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; style-src-elem 'self' 'unsafe-inline'";

  test("one under the dev policy, whose nonce-less <style> raises no violation of its own", async ({page, guard}) => {
    await page.route("**/bare-document", (route) =>
      route.fulfill({contentType: "text/html", headers: {"content-security-policy": DEV_POLICY}, body: "<!doctype html><title>dev</title><style>p{color:red}</style><p>quiet</p>"}));
    await page.goto("/bare-document");
    expect(guard.consume("csp"), "the browser allows the style, which is why the policy itself has to be checked").toEqual([]);
    expect(guard.consume("policy")).toEqual(["200 /bare-document"]);
  });

  test("and fails the test on it under the dev policy", async ({page}) => {
    test.fail();
    await serveBare(page, DEV_POLICY);
    await page.goto("/bare-document");
  });
});

// gate-r2-3: the constructor is not the only way to a peer connection. `RTCPeerConnection.prototype.constructor` and `pc.constructor` are the
// native function, and a STUN server is contacted when ICE gathering starts, which a method call does. The page is on `.invalid`, so no packet
// could leave even where the guard is broken.
const STUN = {iceServers: [{urls: "stun:guard-selftest.invalid:3478"}]};

test.describe("the guard records a peer connection that was not built with the global name", () => {
  test("one built from RTCPeerConnection.prototype.constructor, and one from an instance's constructor", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "quiet");
    await page.evaluate((config) => {
      const Native = RTCPeerConnection.prototype.constructor as typeof RTCPeerConnection;
      const first = new Native(config);
      const second = new (first.constructor as typeof RTCPeerConnection)(config);
      first.close();
      second.close();
    }, STUN);
    expect(await take(() => guard.consume("external"), 2)).toEqual(["rtc", "rtc"]);
  });

  test("a call that starts ICE gathering, on a connection that was built earlier", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "quiet");
    await page.evaluate(() => void ((window as unknown as {pc: RTCPeerConnection}).pc = new RTCPeerConnection()));
    expect(await take(() => guard.consume("external"), 1)).toEqual(["rtc"]);
    for (const call of ["createOffer", "setLocalDescription", "setConfiguration", "createAnswer"] as const) {
      await page.evaluate(
        ([method, config]) => {
          const pc = (window as unknown as {pc: RTCPeerConnection}).pc;
          // The call may be refused by the connection's state: the report comes before it, which is the point.
          return (method === "setConfiguration" ? Promise.resolve().then(() => pc.setConfiguration(config)) : (pc as unknown as Record<string, () => Promise<unknown>>)[method]!()).catch(() => {});
        },
        [call, STUN] as const,
      );
      expect(await take(() => guard.consume("external"), 1), call).toEqual(["rtc"]);
    }
  });
});

test.describe("the guard fails the test on", () => {
  test("a peer connection built from the prototype's constructor", async ({page}) => {
    test.fail();
    await open(page, "quiet");
    await page.evaluate((config) => void new (RTCPeerConnection.prototype.constructor as typeof RTCPeerConnection)(config).close(), STUN);
    await page.waitForTimeout(300);
  });
});

// gate-r2-4: a resource hint to another origin. No CSP directive covers it, and the browser of Playwright never acts on one.
test.describe("the guard records a resource hint to another origin", () => {
  test("a link that a script inserts or changes, for the rels that only open a connection", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "quiet");
    await page.evaluate((url) => {
      for (const rel of ["preconnect", "dns-prefetch"]) {
        const link = document.createElement("link");
        link.rel = rel;
        link.href = url;
        document.head.append(link);
      }
      // Added with a rel that fetches nothing and changed afterwards.
      const later = document.createElement("link");
      later.rel = "help";
      later.href = url + "/later";
      document.head.append(later);
      later.rel = "preconnect";
    }, EXTERNAL);
    expect(await take(() => guard.consume("external"), 3)).toEqual(Array(3).fill(`hint:${EXTERNAL}`));
  });

  test("a link in the HTML of the page", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "hint-html");
    expect(await take(() => guard.consume("external"), 1)).toEqual([`hint:${EXTERNAL}`]);
  });

  test("a hint in the Link header of a document", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "hint-header");
    expect(await take(() => guard.consume("external"), 1)).toEqual([`hint:${EXTERNAL}`]);
  });

  test("a link inside a subtree that is added at once", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "quiet");
    await page.evaluate((url) => {
      const holder = document.createElement("div");
      holder.innerHTML = `<p><link rel="preconnect" href="${url}"></p>`;
      document.body.append(holder);
    }, EXTERNAL);
    expect(await take(() => guard.consume("external"), 1)).toEqual([`hint:${EXTERNAL}`]);
  });

  test("and not one to the page's own origin, nor a data: target, nor another kind of link", async ({page, guard}) => {
    await open(page, "hint-same");
    await page.evaluate(() => {
      const link = document.createElement("link");
      link.rel = "preconnect";
      link.href = "/";
      document.head.append(link);
    });
    await page.waitForTimeout(300);
    expect(guard.consume("external")).toEqual([]);
  });
});

test.describe("the guard fails the test on", () => {
  test("a resource hint that a script inserts", async ({page, guard}) => {
    test.fail();
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "quiet");
    await page.evaluate((url) => document.head.insertAdjacentHTML("beforeend", `<link rel="dns-prefetch" href="${url}">`), EXTERNAL);
    await page.waitForTimeout(300);
  });

  test("a resource hint in the HTML", async ({page, guard}) => {
    test.fail();
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "hint-html");
    await page.waitForTimeout(300);
  });

  test("a resource hint in a Link header", async ({page, guard}) => {
    test.fail();
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "hint-header");
    await page.waitForTimeout(300);
  });
});

// gate-r26-1: Chrome sends the prefetch and prerender requests of a speculation rule set outside every check: Playwright fires no request event
// for them, connect-src does not cover them, no violation follows, and a document rule holds no URL. The guard reads the rule sets themselves.
test.describe("the guard records a speculation rule set", () => {
  test("an inline list rule in the HTML, by origin and never by path or query", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "spec-list");
    expect(await take(() => guard.consume("external"), 1)).toEqual([`spec:${EXTERNAL}`]);
  });

  test("a document rule, which has no URL and works on the page's own links", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "spec-document");
    expect(await take(() => guard.consume("external"), 1)).toEqual(["spec:document"]);
  });

  test("a Speculation-Rules header on a document", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "spec-header");
    expect(await take(() => guard.consume("external"), 1)).toEqual([`spec:${new URL(page.url()).origin}`]);
  });

  test("a rule set that a script adds, one whose type changes afterwards, one whose text is filled in or changed", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "quiet");
    await page.evaluate(
      async ({rules}) => {
        const add = (type: string, text: string | null) => {
          const script = document.createElement("script");
          script.type = type;
          if (text !== null) script.textContent = text;
          document.head.append(script);
          return script;
        };
        add("speculationrules", rules);
        add("application/json", rules).type = "speculationrules";
        add("speculationrules", null).textContent = rules;
        // A text node that is changed in place is a characterData record on the text, not on the script. The first text is an empty rule set
        // (`rules`, no origin) and is judged on its own because the change comes a task later. It is not whitespace, which would make Chrome raise
        // its own JSON error.
        const inPlace = add("speculationrules", "{}");
        await new Promise((resolve) => setTimeout(resolve, 100));
        (inPlace.firstChild as Text).data = rules;
      },
      {rules: LIST_RULES},
    );
    expect((await take(() => guard.consume("external"), 5)).sort()).toEqual([...Array(4).fill(`spec:${EXTERNAL}`), "spec:rules"]);
  });

  test("and not a script of another type, or an empty rule script", async ({page, guard}) => {
    await open(page, "quiet");
    await page.evaluate(({rules}) => {
      for (const type of ["application/json", "text/plain", "module"]) {
        const script = document.createElement("script");
        script.type = type;
        script.textContent = type === "module" ? "export {}" : rules;
        document.head.append(script);
      }
      const empty = document.createElement("script");
      empty.type = "speculationrules";
      document.head.append(empty);
    }, {rules: LIST_RULES});
    await page.waitForTimeout(300);
    expect(guard.consume("external")).toEqual([]);
  });
});

test.describe("the guard fails the test on a speculation rule set", () => {
  test("in the HTML of the page", async ({page, guard}) => {
    test.fail();
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "spec-list");
    await page.waitForTimeout(300);
  });

  test("that is a document rule over an external link", async ({page, guard}) => {
    test.fail();
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "spec-document");
    await page.waitForTimeout(300);
  });

  test("that a response header adds", async ({page, guard}) => {
    test.fail();
    guard.allowConsole(BROWSER_NOISE);
    await open(page, "spec-header");
    await page.waitForTimeout(300);
  });
});

// gate-r15-2: closing the window fires `pagehide` in the last document of every test, and Playwright closes the context only after the
// guard has read its records. So the guard unloads the pages itself before it reads them. `guard.unload()` is that step called early, which
// lets a test see what a handler did; the end-of-test twins below leave the handler's work unread and need the step to run by itself.
const BEACON = `${EXTERNAL}/beacon`;
const WHEN_THE_WINDOW_CLOSES = {
  beacon: (url: string) => window.addEventListener("pagehide", () => void navigator.sendBeacon(url, "x")),
  keepaliveFetch: (url: string) => window.addEventListener("pagehide", () => void fetch(url, {keepalive: true}).catch(() => {})),
  consoleError: () => window.addEventListener("pagehide", () => console.error("guard selftest: pagehide")),
  // Same origin, so only the policy of the page (`connect-src 'none'`) refuses it. Chrome writes that refusal to the console, and does not run
  // the `securitypolicyviolation` event of a document that is going away: the message is what the guard reads (guardLogic.cspDirectiveOfConsole).
  violation: () => window.addEventListener("pagehide", () => void fetch("/guard-selftest/own", {keepalive: true}).catch(() => {})),
  // The nonce class (gate-r27-2): a library that puts its styles back when the page goes away would do the first.
  styleWithoutNonce: () =>
    window.addEventListener("pagehide", () => {
      const style = document.createElement("style");
      style.textContent = "p{color:red}";
      document.head.append(style);
    }),
  scriptWithoutNonce: () =>
    window.addEventListener("pagehide", () => {
      const script = document.createElement("script");
      script.textContent = "void 0";
      document.head.append(script);
    }),
};

async function openUnloadPage(page: Page, policy?: string) {
  await serve(page);
  await page.route("**/guard-selftest/unload", (route) =>
    route.fulfill({contentType: "text/html", headers: policy ? {"content-security-policy": policy} : {}, body: "<!doctype html><title>unload</title><button>x</button><p>quiet</p>"}));
  await page.goto("/guard-selftest/unload");
}

const NO_CONNECT = "connect-src 'none'";
const NONCE_ONLY = "script-src 'nonce-guardselftest'; style-src 'nonce-guardselftest'; style-src-elem 'nonce-guardselftest'";

test.describe("the guard records what a page does while it unloads (gate-r15-2)", () => {
  test("a beacon to another origin", async ({page, guard}) => {
    await openUnloadPage(page);
    await page.evaluate(WHEN_THE_WINDOW_CLOSES.beacon, BEACON);
    // Nothing yet: the handler has not run, so this is what the end-of-test check saw before gate-r15-2.
    expect(guard.consume("external")).toEqual([]);
    await guard.unload();
    expect(guard.consume("external")).toEqual([`beacon:${EXTERNAL}`]);
    expect(page.isClosed()).toBe(true);
  });

  test("a CSP violation raised from pagehide, from the message Chrome writes for it", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await openUnloadPage(page, NO_CONNECT);
    await page.evaluate(WHEN_THE_WINDOW_CLOSES.violation);
    expect(guard.consume("csp")).toEqual([]);
    await guard.unload();
    expect(guard.consume("csp")).toEqual(["connect-src"]);
  });

  // gate-r27-2: Chrome words the refusal of an inline style, script or event handler without the nonce differently (no colon, single quotes). The
  // console allowance below matches the word 'violates', so the failure of the twin has to come from the csp record and from nothing else.
  test("a style without the nonce, added from pagehide, is a style-src-elem violation (gate-r27-2)", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await openUnloadPage(page, NONCE_ONLY);
    await page.evaluate(WHEN_THE_WINDOW_CLOSES.styleWithoutNonce);
    expect(guard.consume("csp")).toEqual([]);
    await guard.unload();
    expect(guard.consume("csp")).toEqual(["style-src-elem"]);
  });

  test("a script without the nonce, added from pagehide, is a script-src-elem violation (gate-r27-2)", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await openUnloadPage(page, NONCE_ONLY);
    await page.evaluate(WHEN_THE_WINDOW_CLOSES.scriptWithoutNonce);
    await guard.unload();
    expect(guard.consume("csp")).toEqual([expect.stringMatching(/^script-src/)]);
  });

  test("a keepalive fetch to another origin, and one to the page's own origin is let through", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await openUnloadPage(page);
    await page.evaluate(WHEN_THE_WINDOW_CLOSES.keepaliveFetch, `${EXTERNAL}/keepalive`);
    await page.evaluate(WHEN_THE_WINDOW_CLOSES.keepaliveFetch, "/guard-selftest/own");
    await guard.unload();
    expect(guard.consume("external")).toEqual([`beacon:${EXTERNAL}`]);
  });

  test("a console error raised from pagehide", async ({page, guard}) => {
    await openUnloadPage(page);
    await page.evaluate(WHEN_THE_WINDOW_CLOSES.consoleError);
    await guard.unload();
    expect(guard.consume("console")).toEqual([expect.stringContaining("guard selftest: pagehide")]);
  });

  test("a page that asks 'leave this page?' is still unloaded, and so are the pages of a second context", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await openUnloadPage(page);
    // Chrome asks only a page that has had a gesture.
    await page.getByRole("button", {name: "x"}).click();
    await page.evaluate(() => window.addEventListener("beforeunload", (e) => e.preventDefault()));
    await page.evaluate(WHEN_THE_WINDOW_CLOSES.beacon, BEACON);
    const other = await guard.newContext();
    const second = await other.newPage();
    await openUnloadPage(second);
    await second.evaluate(WHEN_THE_WINDOW_CLOSES.beacon, `${EXTERNAL}/second`);
    await guard.unload();
    expect(guard.consume("external")).toEqual([`beacon:${EXTERNAL}`, `beacon:${EXTERNAL}`]);
    expect([page.isClosed(), second.isClosed()]).toEqual([true, true]);
  });

  // P1 gate: a test that ends while a navigation it held was refused leaves the tab on Chrome's error page (`chrome-error://chromewebdata/`,
  // whose origin reads "null"). It holds no document of ours, so no handler of ours can run on it, and a close that waits for a question
  // there sometimes never ended: wp8-r11-4 failed one run in two with "pages that would not close". Such a page is closed plainly, and the
  // end-of-test check of this test is the proof: it fails with the same message if the page is reported as stuck.
  test("a page left on the browser's error page closes without being reported as stuck", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await serve(page);
    await page.route("**/guard-selftest/refused", (route) => route.abort());
    await page.goto("/guard-selftest/refused").catch(() => undefined);
    expect(page.url()).not.toMatch(/^https?:/);
    await guard.unload();
    expect(page.isClosed()).toBe(true);
  });
});

test.describe("the guard fails the test on what a page does while it unloads (gate-r15-2)", () => {
  test("a beacon to another origin, behind a beforeunload question", async ({page}) => {
    test.fail();
    await openUnloadPage(page);
    await page.getByRole("button", {name: "x"}).click();
    await page.evaluate(() => window.addEventListener("beforeunload", (e) => e.preventDefault()));
    await page.evaluate(WHEN_THE_WINDOW_CLOSES.beacon, BEACON);
  });

  test("a keepalive fetch to another origin", async ({page, guard}) => {
    test.fail();
    guard.allowConsole(BROWSER_NOISE);
    await openUnloadPage(page);
    await page.evaluate(WHEN_THE_WINDOW_CLOSES.keepaliveFetch, `${EXTERNAL}/keepalive`);
  });

  test("a console error", async ({page}) => {
    test.fail();
    await openUnloadPage(page);
    await page.evaluate(WHEN_THE_WINDOW_CLOSES.consoleError);
  });

  test("a CSP violation", async ({page, guard}) => {
    test.fail();
    guard.allowConsole(BROWSER_NOISE);
    await openUnloadPage(page, NO_CONNECT);
    await page.evaluate(WHEN_THE_WINDOW_CLOSES.violation);
  });

  // The console allowance matches 'violates', so only the csp record can fail this test (gate-r27-2).
  test("a style without the nonce, with the console allowed", async ({page, guard}) => {
    test.fail();
    guard.allowConsole(BROWSER_NOISE);
    await openUnloadPage(page, NONCE_ONLY);
    await page.evaluate(WHEN_THE_WINDOW_CLOSES.styleWithoutNonce);
  });
});

// gate-r16-2: a spec that closes a page, or a `guard.newContext()` context, by hand ends its documents without `runBeforeUnload`, and what their
// `pagehide` handlers did would never reach Node (the measurement behind gate-r15-2). So the guard puts its own unloading in front of both closes.
test.describe("the guard records what a page does while a spec closes it itself (gate-r16-2)", () => {
  test("page.close()", async ({page, guard}) => {
    await openUnloadPage(page);
    await page.evaluate(WHEN_THE_WINDOW_CLOSES.beacon, BEACON);
    await page.close();
    expect(page.isClosed()).toBe(true);
    expect(guard.consume("external")).toEqual([`beacon:${EXTERNAL}`]);
  });

  test("page.close() behind a beforeunload question, and a console error", async ({page, guard}) => {
    await openUnloadPage(page);
    await page.getByRole("button", {name: "x"}).click();
    await page.evaluate(() => window.addEventListener("beforeunload", (e) => e.preventDefault()));
    await page.evaluate(WHEN_THE_WINDOW_CLOSES.consoleError);
    await page.close({runBeforeUnload: false});
    expect(guard.consume("console")).toEqual([expect.stringContaining("guard selftest: pagehide")]);
  });

  test("context.close() on a guard.newContext() context, with a page in it", async ({guard}) => {
    const other = await guard.newContext();
    const second = await other.newPage();
    await openUnloadPage(second);
    await second.evaluate(WHEN_THE_WINDOW_CLOSES.beacon, `${EXTERNAL}/second`);
    await other.close();
    expect(second.isClosed()).toBe(true);
    expect(guard.consume("external")).toEqual([`beacon:${EXTERNAL}`]);
  });

  test("a CSP refusal from pagehide, in a page that the spec closed", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await openUnloadPage(page, NO_CONNECT);
    await page.evaluate(WHEN_THE_WINDOW_CLOSES.violation);
    await page.close();
    expect(guard.consume("csp")).toEqual(["connect-src"]);
  });
});

test.describe("the guard fails the test on what a page does while a spec closes it itself (gate-r16-2)", () => {
  test("a beacon, page.close()", async ({page}) => {
    test.fail();
    await openUnloadPage(page);
    await page.evaluate(WHEN_THE_WINDOW_CLOSES.beacon, BEACON);
    await page.close();
  });

  test("a beacon, context.close() on a guard.newContext() context", async ({guard}) => {
    test.fail();
    const other = await guard.newContext();
    const second = await other.newPage();
    await openUnloadPage(second);
    await second.evaluate(WHEN_THE_WINDOW_CLOSES.beacon, `${EXTERNAL}/second`);
    await other.close();
  });
});

// gate-r23-2: most documents of a test end by a navigation or a reload, not by a close, and Chrome drops what such a document does from `pagehide`
// on (its binding calls, its console messages, its requests). The init script keeps those in sessionStorage and the next document hands them over.
// Each way of ending a document is run with a beacon, a keepalive fetch, an XHR, a fetchLater (where Chrome has it), a console error and an uncaught
// error raised from pagehide, and the twins below prove the end-of-test check fails on them.
// Each one returns once the next document has loaded, so what it hands over has been asked for.
const NEXT = "**/guard-selftest/quiet";
const ENDINGS = {
  "location.assign": async (page: Page) => void (await Promise.all([page.waitForURL(NEXT), page.evaluate(() => location.assign("/guard-selftest/quiet"))])),
  "page.goto": (page: Page) => page.goto("/guard-selftest/quiet").then(() => undefined),
  "location.reload": async (page: Page) => void (await Promise.all([page.waitForEvent("load"), page.evaluate(() => location.reload())])),
  "a link": async (page: Page) =>
    void (await Promise.all([
      page.waitForURL(NEXT),
      page.evaluate(() => {
        const a = document.createElement("a");
        a.href = "/guard-selftest/quiet";
        document.body.append(a);
        a.click();
      }),
    ])),
} as const;

const WHEN_THE_DOCUMENT_ENDS = {
  ...WHEN_THE_WINDOW_CLOSES,
  xhr: (url: string) =>
    window.addEventListener("pagehide", () => {
      const x = new XMLHttpRequest();
      x.open("GET", url);
      x.send();
    }),
  // A throw, not a rejected promise: the `error` event of a throw runs inside the dispatch, while a timer or a rejection of a dying document never does.
  uncaught: () =>
    window.addEventListener("pagehide", () => {
      throw new Error("guard selftest: pagehide throw");
    }),
};

// Waits until the next document has started and its hand-over has been delivered: any evaluate is a round trip, so a binding call on its way arrives first.
async function afterTheNextDocument(page: Page) {
  await page.evaluate(() => 0);
  await page.waitForTimeout(100);
  await page.evaluate(() => 0);
}

test.describe("the guard records what a document does from pagehide on when a navigation or a reload ends it (gate-r23-2)", () => {
  for (const [how, end] of Object.entries(ENDINGS)) {
    test(`a beacon and a keepalive fetch to another origin, ended by ${how}`, async ({page, guard}) => {
      guard.allowConsole(BROWSER_NOISE);
      await openUnloadPage(page);
      await page.evaluate(WHEN_THE_DOCUMENT_ENDS.beacon, `${EXTERNAL}/beacon`);
      await page.evaluate(WHEN_THE_DOCUMENT_ENDS.keepaliveFetch, `${EXTERNAL}/keep`);
      await page.evaluate(WHEN_THE_DOCUMENT_ENDS.keepaliveFetch, "/guard-selftest/own");
      expect(guard.consume("external")).toEqual([]);
      await end(page);
      await afterTheNextDocument(page);
      expect(guard.consume("external").sort()).toEqual([`beacon:${EXTERNAL}`, `beacon:${EXTERNAL}`]);
    });

    test(`a console error and an uncaught error, ended by ${how}`, async ({page, guard}) => {
      await openUnloadPage(page);
      await page.evaluate(WHEN_THE_DOCUMENT_ENDS.consoleError);
      await page.evaluate(WHEN_THE_DOCUMENT_ENDS.uncaught);
      await end(page);
      await afterTheNextDocument(page);
      expect(guard.consume("console")).toEqual([expect.stringContaining("guard selftest: pagehide")]);
      expect(guard.consume("pageerror")).toEqual([expect.stringContaining("pagehide throw")]);
    });
  }

  test("an XHR to another origin", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await openUnloadPage(page);
    await page.evaluate(WHEN_THE_DOCUMENT_ENDS.xhr, `${EXTERNAL}/xhr`);
    await ENDINGS["page.goto"](page);
    await afterTheNextDocument(page);
    expect(guard.consume("external")).toEqual([`beacon:${EXTERNAL}`]);
  });

  test("an own-origin handler that logs nothing and a navigation record nothing", async ({page, guard}) => {
    await openUnloadPage(page);
    await page.evaluate(WHEN_THE_DOCUMENT_ENDS.keepaliveFetch, "/guard-selftest/own");
    await ENDINGS["location.assign"](page);
    await afterTheNextDocument(page);
    expect(guard.consume("external")).toEqual([]);
    expect(guard.consume("console")).toEqual([]);
    // The list is read once: a later document does not hear it again.
    await ENDINGS["location.reload"](page);
    await afterTheNextDocument(page);
    expect(guard.consume("external")).toEqual([]);
    expect(await page.evaluate(() => sessionStorage.getItem("ctrlz_guardPending"))).toBeNull();
  });
});

test.describe("the guard fails the test on what a document did from pagehide on when a navigation or a reload ended it (gate-r23-2)", () => {
  for (const [how, end] of Object.entries(ENDINGS)) {
    test(`a beacon, ended by ${how}`, async ({page, guard}) => {
      test.fail();
      guard.allowConsole(BROWSER_NOISE);
      await openUnloadPage(page);
      await page.evaluate(WHEN_THE_DOCUMENT_ENDS.beacon, `${EXTERNAL}/beacon`);
      await end(page);
      await afterTheNextDocument(page);
    });

    test(`a console error, ended by ${how}`, async ({page}) => {
      test.fail();
      await openUnloadPage(page);
      await page.evaluate(WHEN_THE_DOCUMENT_ENDS.consoleError);
      await end(page);
      await afterTheNextDocument(page);
    });
  }
});

// gate-r24-2: sessionStorage belongs to one origin. When the navigation that ends a document fails (an aborted or held request, a network error),
// the next document is Chrome's error page, which cannot read what the old document kept from pagehide. The guard takes such a tab back to a page of
// the app before it closes it, so the next document of the origin hands the records over; if it cannot, the test fails with a named message.
const ABORTED = "**/guard-selftest/aborted";
async function endOnTheErrorPage(page: Page) {
  // page.route, not context.route: a route of the page wins over one of the context, and serve() has put a catch-all on the page.
  await page.route(ABORTED, (route) => route.abort());
  await page.goto("/guard-selftest/aborted").catch(() => {});
  await expect.poll(() => page.url(), {message: "the tab must be on Chrome's error page for this case"}).toMatch(/^chrome-error:/);
}

test.describe("the guard records what a document did from pagehide on when the next document is Chrome's error page (gate-r24-2)", () => {
  test("a beacon to another origin and a console error", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await openUnloadPage(page);
    await page.evaluate(WHEN_THE_DOCUMENT_ENDS.beacon, `${EXTERNAL}/beacon`);
    await page.evaluate(WHEN_THE_DOCUMENT_ENDS.consoleError);
    await endOnTheErrorPage(page);
    await guard.unload();
    expect(guard.consume("external")).toEqual([`beacon:${EXTERNAL}`]);
    expect(guard.consume("console")).toEqual([expect.stringContaining("guard selftest: pagehide")]);
  });

  // gate-r27-1: the take-back navigation is answered with the proxy's 404 and Chrome writes it to the console as an error. These cases have
  // nothing wrong in them and allow no console pattern, so they fail if the guard's own error is counted (BROWSER_NOISE would have hidden it).
  test("a test with nothing wrong that ends on about:blank after a document of the app passes (gate-r27-1)", async ({page, guard}) => {
    await openUnloadPage(page);
    await page.goto("about:blank");
    await guard.unload();
    expect(guard.consume("console")).toEqual([]);
    expect(guard.consume("external")).toEqual([]);
  });

  test("a test with nothing wrong that ends on Chrome's error page passes (gate-r27-1)", async ({page, guard}) => {
    await openUnloadPage(page);
    await endOnTheErrorPage(page);
    await guard.unload();
    expect(guard.consume("console")).toEqual([]);
    expect(guard.consume("external")).toEqual([]);
  });

  test("the same two endings pass at the end of the test, with no unload call and no allowance (gate-r27-1)", async ({page}) => {
    await openUnloadPage(page);
    await endOnTheErrorPage(page);
  });

  test("a tab that never showed a document of the app is closed as before", async ({page, guard}) => {
    await page.goto("about:blank");
    await guard.unload();
    expect(guard.consume("external")).toEqual([]);
    expect(page.isClosed()).toBe(true);
  });
});

test.describe("the guard fails the test on what a document did from pagehide on when the next document is Chrome's error page (gate-r24-2)", () => {
  test("a beacon", async ({page}) => {
    test.fail();
    await openUnloadPage(page);
    await page.evaluate(WHEN_THE_DOCUMENT_ENDS.beacon, `${EXTERNAL}/beacon`);
    await endOnTheErrorPage(page);
  });

  test("a console error", async ({page}) => {
    test.fail();
    await openUnloadPage(page);
    await page.evaluate(WHEN_THE_DOCUMENT_ENDS.consoleError);
    await endOnTheErrorPage(page);
  });

  // The tab cannot be taken back to the app, so nothing can be said about what the old document kept: that is a failure, not a pass.
  test("a tab that cannot be taken back to the app", async ({page}) => {
    test.fail();
    await openUnloadPage(page);
    // Before the tab is on the error page: adding a route to a tab that is already there does not return.
    await page.route("**/_next/static/guard-forward", (route) => route.abort());
    await endOnTheErrorPage(page);
  });
});

// gate-r28-2: the document-open steps erase every listener of the document and the window. Playwright's page.setContent and a spec's own
// document.open do exactly that, so the init script loses its securitypolicyviolation listener while its marker (a window property) survives and
// the "unguarded" check passes. Chrome still writes each violation to the console, which the guard reads at all times and merges with the events.
const REWRITE = {
  // The case under test: lint refuses document.open in a spec, and the guard must not depend on that.
  documentOpen: () => {
    /* eslint-disable no-restricted-syntax */
    document.open();
    document.write('<!doctype html><html><head><title>rewritten</title></head><body><p>quiet</p></body></html>');
    /* eslint-enable no-restricted-syntax */
    document.close();
  },
};
const STYLE_NO_NONCE = () => {
  const style = document.createElement("style");
  style.textContent = "p{color:red}";
  document.head.append(style);
};

test.describe("the guard sees a CSP violation on a document that was reopened (gate-r28-2)", () => {
  test("page.setContent, then a style without the nonce", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await openUnloadPage(page, NONCE_ONLY);
    // eslint-disable-next-line no-restricted-syntax -- the case under test.
    await page.setContent('<!doctype html><html><head><title>fixture</title></head><body><p>quiet</p></body></html>');
    // The marker of the init script is a window property and survives, which is why the unguarded check cannot tell.
    expect(await page.evaluate(() => (window as unknown as {__ctrlzGuardOn?: boolean}).__ctrlzGuardOn)).toBe(true);
    await page.evaluate(STYLE_NO_NONCE);
    await guard.unload();
    expect(guard.consume("csp")).toEqual(["style-src-elem"]);
  });

  test("document.open and document.write, then a style without the nonce", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await openUnloadPage(page, NONCE_ONLY);
    await page.evaluate(REWRITE.documentOpen);
    await page.evaluate(STYLE_NO_NONCE);
    await guard.unload();
    expect(guard.consume("csp")).toEqual(["style-src-elem"]);
  });

  // The listener still works before the document is reopened, and the console message is the same violation: one record, never two.
  test("a violation before and one after the document is reopened are two records, not four", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await openUnloadPage(page, NONCE_ONLY);
    await page.evaluate(STYLE_NO_NONCE);
    await expect.poll(() => guard.consume("csp").length, {message: "the listener's own record"}).toBe(1);
    await page.evaluate(REWRITE.documentOpen);
    await page.evaluate(STYLE_NO_NONCE);
    await guard.unload();
    expect(guard.consume("csp")).toEqual(["style-src-elem"]);
  });

  test("a violation that the listener saw is one record, whatever the console says", async ({page, guard}) => {
    guard.allowConsole(BROWSER_NOISE);
    await openUnloadPage(page, NONCE_ONLY);
    await page.evaluate(STYLE_NO_NONCE);
    await page.evaluate(STYLE_NO_NONCE);
    await guard.unload();
    expect(guard.consume("csp")).toEqual(["style-src-elem", "style-src-elem"]);
  });
});

test.describe("the guard fails the test on a violation on a document that was reopened (gate-r28-2)", () => {
  // The console allowance matches 'violates', so only the csp record can fail these tests.
  test("page.setContent, then a style without the nonce", async ({page, guard}) => {
    test.fail();
    guard.allowConsole(BROWSER_NOISE);
    await openUnloadPage(page, NONCE_ONLY);
    // eslint-disable-next-line no-restricted-syntax -- the case under test.
    await page.setContent('<!doctype html><html><head><title>fixture</title></head><body><p>quiet</p></body></html>');
    await page.evaluate(STYLE_NO_NONCE);
  });

  test("document.open, then a style without the nonce", async ({page, guard}) => {
    test.fail();
    guard.allowConsole(BROWSER_NOISE);
    await openUnloadPage(page, NONCE_ONLY);
    await page.evaluate(REWRITE.documentOpen);
    await page.evaluate(STYLE_NO_NONCE);
  });
});
