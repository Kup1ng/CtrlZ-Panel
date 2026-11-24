import {expect, test as base, type Browser, type BrowserContext, type BrowserContextOptions, type Dialog, type Page} from "@playwright/test";

import {THEME_COOKIE} from "../theme/config.ts";
import {cspDirectiveOfConsole, documentWithoutPolicy, externalHintOrigins, HINT_RELS, isExternal, isForwardPathNoise, isNetworkUrl, isUnexpectedConsoleError, originOf, redactUrls, speculationHeaderTargets, type TrailEntry} from "./guardLogic.ts";
import {readMatrix, type Matrix} from "./matrix.ts";

// Spec 17.2. Every test of ours imports `test` and `expect` from here instead of from
// `@playwright/test`, and so runs under three checks it cannot forget to ask for:
//
//   1. no request leaves the origins the test may talk to (the request is aborted and its origin kept),
//   2. no Content-Security-Policy violation event fired in any frame of any page,
//   3. no console error and no uncaught page error.
//
// How each is recorded, and why (wp12-r1-5, wp12-r1-6): requests are read from the context's own
// `request` event, which fires whoever fulfils the request, so a mock that answers a `/api/v1/` path on
// a foreign host cannot hide it; the route only aborts. Violations are sent to Node through a context
// binding, because a value kept in the page is lost with the document on a reload or a redirect and is
// never read from an iframe. `guard.consume` hands a recorded kind to a test that causes it on purpose
// (guard.selftest.spec.ts proves each check works that way, and fails on the others).
//
// A WebSocket, a WebSocketStream, a WebTransport session and a WebRTC peer connection count as external whatever their target: P1 opens none. None is a
// request to Playwright, and the CSP has no directive for WebRTC (Chrome ignores `webrtc`), so a STUN or TURN server built
// at run time would pass the policy and every other check; the constructors report themselves instead (gate-r1-6).
// The constructor is not the only way in: `RTCPeerConnection.prototype.constructor` and `pc.constructor` name the native one, and a
// connection that is built that way starts ICE gathering with a method call. So the prototype's constructor is the trap too, and the
// methods that start gathering report themselves (gate-r2-3).
//
// `fetchLater()` (Chrome) is the odd one: the browser sends the queued request after the document is gone, with no `request` event and no console line, so a
// target that `connect-src` lists (the verify wildcard) would pass every check. The call is reported at call time when its origin is not the
// page's, as `later:<origin>` (gate-r22-9).
//
// A resource hint (`<link rel=preconnect>` or `dns-prefetch`, from the HTML, a script, React DOM's `preconnect()` or a `Link` response
// header) makes a visitor's browser open a connection to another origin. No CSP directive covers it and Playwright's browser never acts
// on one, so it shows in no request and no violation. The init script watches the DOM for such a link and the context reads the `Link`
// header of every document (gate-r2-4).
//
// Speculation rules are the same kind of hole, and a wider one (gate-r26-1). A `<script type="speculationrules">` or a `Speculation-Rules` response
// header makes Chrome prefetch or prerender a URL with no `request` event, no violation (connect-src does not cover it and CSP 3 dropped
// prefetch-src) and, for a document rule over the page's own `<a>` links, with no URL in any script at all. A visitor's browser would contact
// an external host on hover. P1 uses no rule set, so any one, from a script element (added, or its type or text changed) or from a header on a
// document, is recorded as `spec:<origins>` (origins only, `document` for a document rule), and fails the test.
//
// Every page of a test is under the checks: the `context` fixture is armed, and a second context comes from
// `guard.newContext()`, which arms it the same way. A context that a spec opens by hand with `browser.newContext()` is
// not armed. For the length of each test the guard wraps the worker's `browser.newContext` and `browser.newPage` (and so also what
// `context.browser()` returns, which is the same object, whatever the spec calls it), records every context made through them, and the
// end-of-test check fails for any that was not armed, closed or not. ESLint refuses the plain spelling in `apps/*/e2e` as well
// (gate-r1-5, gate-r1-7, gate-r25-1).
//
// The checks run after the last document has gone, too. Closing a window fires `pagehide` in each test's last document, and that is the usual
// moment for a beacon, a `keepalive` fetch, a clipboard write or a stray error. Playwright closes the context only after this fixture is
// done, so the end-of-test step first closes every open page itself, with `runBeforeUnload` and any question accepted, waits for the
// page's `close` event (the console messages and binding calls of its last document arrive before it) and only then reads the records
// (gate-r15-2). `guard.unload()` does the same early, for a test that asserts what such a handler did. A spec that closes a page, or a
// `guard.newContext()` context, by hand goes through the same step first: `watch` and `arm` put it in front of `page.close()` and
// `context.close()`, so a close that a spec asks for skips nothing (gate-r16-2).
//
// A document that ends by a navigation or a reload (`page.goto`, `location.assign`, `location.reload`, a link: most documents of a test, the logout path
// above all) is another matter. Chrome drops what such a document does from `pagehide` on: its binding calls, its console messages and its requests reach
// neither Playwright nor this fixture (measured with the installed Chrome under Playwright 1.65, gate-r23-2). So from `pagehide` on the init script
// also keeps each beacon, `keepalive` fetch, XHR and `fetchLater` origin, each `console.error` text and each uncaught error in this tab's
// sessionStorage (`ctrlz_guardPending`), and the next document of the tab hands them over at its start through `__ctrlzGuardLate`. A navigation to
// another origin is a request, which the context records itself. sessionStorage belongs to one origin, so when the navigation that ends the document
// fails (an aborted or held request, a network error) the next document is Chrome's error page and cannot read the list. A tab that ends there, or on
// about:blank, after a document of the app is therefore taken back once to a page of the app before it is closed, and the test fails with a named
// message if it cannot get there (gate-r24-2). What cannot be seen on that path: a CSP violation raised from `pagehide` (its event
// never runs and Chrome writes no message that arrives), and an image, a form post or a navigation started from `pagehide`. The CSP is what stops those
// in production, and the violation is not recorded for a document that ends by a navigation, so nothing here claims it is.
//
// Measured with the installed Chrome under Playwright 1.65, and why it is done this way: navigating to about:blank delivers nothing from the old document,
// and a close without `runBeforeUnload` loses its binding calls. And no request of a dying document reaches the context's `request` event,
// so a beacon, a `keepalive` fetch or an XHR to another origin would be invisible: the init script reports those three itself, but only
// from `pagehide` on (earlier they are seen as requests). An image, a form post or a navigation started from `pagehide` is not covered: the
// CSP (`img-src`, `form-action`) is what stops them in production, and its violations are recorded.
//
// A test that causes a console error on purpose (the browser logs every failed response, so a mocked
// 503 does) says so with `guard.allowConsole(/status of 503/)` or `test.use({allowConsole: [...]})`.
// There is no way to allow an external request: the fix is to stop making it. Nor is there a way to switch the CSP check off:
// `bypassCSP` fails the test, and ESLint refuses the word in a spec (gate-r3-5).

// What a flow wrote on its way, for expectNoSecretResidue (gate-r17-5). A snapshot of the page a flow ends on sees only the last address and the
// last history entry, and a router.replace to the next page has by then replaced the one that held a secret for a moment. So the guard keeps, for the
// whole test and for every page of it: each history.pushState and replaceState call (address and state, from the init script through a context
// binding, so it survives a full load), the URL of every frame navigation, and every console message of any level and every page error. The text is
// raw, because the check has to find a secret in it, and it never leaves this process: the failure names the place and the position of the secret.
const trails = new WeakMap<Page, TrailEntry[]>();
const TRAIL_LIMIT = 20_000;
// A path that the proxy answers itself with a plain 404 (no markup, the full header set) for a navigation, so the guard can take a tab back to the
// app's origin cheaply at the end of a test (gate-r24-2). Nothing here depends on it being a 404: any document of the origin hands the records over.
const FORWARD_PATH = "/_next/static/guard-forward";
const isGuardForwardNoise = (type: string, text: string, url: string) => isForwardPathNoise(type, text, url, FORWARD_PATH);

/** What the guard recorded for the test that this page belongs to, or undefined for a page that no guard watches. */
export function residueTrail(page: Page): readonly TrailEntry[] | undefined {
  return trails.get(page);
}

type Options = {
  /** Console errors that this test causes on purpose. */
  allowConsole: RegExp[];
};

/** What the guard records. `csp` holds the violated directive, `external` the origin, `console` and `pageerror` the cut text. */
export type GuardKind = "external" | "csp" | "console" | "pageerror" | "policy";

/** What the init script reports through the network binding: a constructor that always means a connection out. */
const NET_KINDS = ["ws", "rtc", "wt", "hint", "beacon", "later", "spec"] as const;

export type Guard = {
  /** Allow one more console error pattern for the rest of this test. */
  allowConsole(pattern: RegExp): void;
  /** The origins that were refused so far. */
  readonly external: readonly string[];
  /**
   * Takes what was recorded for one kind, and clears it so the end-of-test check does not fail on it.
   * For a test that causes the problem on purpose and asserts that the guard saw it.
   */
  consume(kind: GuardKind): string[];
  /**
   * A second browser context under the same checks, for a test that needs a visitor with no cookies beside the
   * signed-in one. It is closed when the test ends. Never open one with `browser.newContext()`.
   */
  newContext(options?: BrowserContextOptions): Promise<BrowserContext>;
  /**
   * Closes every open page of every armed context the way closing the window does (`beforeunload` is accepted, then `pagehide` runs) and
   * waits until what those handlers did has been recorded. The end-of-test check calls it, so a test needs it only to assert what a
   * handler did, with `guard.consume`. The pages are closed afterwards: a test that calls it is over with them.
   */
  unload(): Promise<void>;
};

type Fixtures = {
  guard: Guard;
  /** The width, language and theme of the matrix project this test runs in, or null in another project. */
  matrix: Matrix | null;
};

export const test = base.extend<Fixtures & Options>({
  allowConsole: [[], {option: true}],

  // Playwright reads the fixtures a function needs from its first parameter, so an empty pattern stays.
  matrix: async ({}, use, testInfo) => {
    await use(readMatrix(testInfo.project.metadata));
  },

  guard: [
    async ({context, browser, baseURL, allowConsole, bypassCSP, matrix}, use) => {
      // Chrome's bypass turns CSP enforcement off, so a blocked script or style raises no violation and the check below is green on a page
      // that is broken in production. It is a Playwright option (`test.use`, the config, or newContext), and there is no reason for it (gate-r3-5).
      expect(bypassCSP, "bypassCSP is on: it switches the CSP check of spec 17.2 off, so fix the page and never the check").toBeFalsy();
      // The base URL only: there is no way to allow another origin (spec 17.2), and isVerifyProbe is the one designed exception.
      const allowed = new Set(baseURL ? [new URL(baseURL).origin] : []);
      const external: string[] = [];
      const consoleErrors: string[] = [];
      const pageErrors: string[] = [];
      const cspViolations: string[] = [];
      // The two ways a CSP violation reaches Node, counted per page. The event listener of the init script is lost when a document is
      // reopened (page.setContent and document.open erase every listener of the document and the window), while Chrome still writes the message
      // to the console for each violation. So the console is read at all times, and what lands in `cspViolations` is the larger of the two counts
      // of a page: a violation that both channels saw is one record, and one that only the console saw is still a record (gate-r28-2).
      // The console message is logged before the event runs, so a count read while an event is still on its way would be one too high: the
      // merge is settled only where the page's records are complete (its close, the end of the test, guard.unload()), and an event that comes
      // after a settle takes the place of the record that the console already made.
      const cspSeen = new Map<Page, {events: number; console: string[]; pushed: number}>();
      const cspOf = (page: Page) => {
        let seen = cspSeen.get(page);
        if (!seen) cspSeen.set(page, (seen = {events: 0, console: [], pushed: 0}));
        return seen;
      };
      const settleCsp = (page?: Page) => {
        for (const seen of page ? [cspOf(page)] : cspSeen.values()) {
          const want = Math.max(seen.events, seen.console.length);
          // The directives of the events are already in the list, so the console names the extra records, the latest ones first.
          for (; seen.pushed < want; seen.pushed++) cspViolations.push(seen.console[seen.console.length - (want - seen.pushed)] ?? "unknown");
        }
      };
      const noPolicy: string[] = [];
      // Judgements of the no-policy check that still wait for an answer from the browser.
      const pending = new Set<Promise<void>>();
      const patterns = [...allowConsole];
      const trail: TrailEntry[] = [];
      const note = (kind: TrailEntry["kind"], text: string) => {
        if (trail.length < TRAIL_LIMIT) trail.push({kind, text: text.slice(0, 8000)});
      };
      const pages = new Set<Page>();
      const armed = new Set<BrowserContext>();
      const opened: BrowserContext[] = [];
      // Every context that anything but guard.newContext() makes on the worker's browser during this test, kept whether or not it is
      // closed later. A lint rule can only match the name `browser`; an alias (`page.context().browser()!` in a variable, a renamed fixture,
      // a helper's parameter) passes it, and a context the spec closes before the end is out of reach of browser.contexts() (gate-r25-1).
      const handMade = new Set<BrowserContext>();
      const nativeNewContext = browser.newContext.bind(browser) as Browser["newContext"];
      const nativeNewPage = browser.newPage.bind(browser) as Browser["newPage"];
      // Put back exactly what was there: the browser object lives for the whole worker.
      const ownBefore = {
        newContext: Object.getOwnPropertyDescriptor(browser, "newContext"),
        newPage: Object.getOwnPropertyDescriptor(browser, "newPage"),
      };
      // Pages that the guard is closing right now, whoever asked for it: for these only, the console is read for a CSP refusal.
      const dying = new Set<Page>();
      // The close that Playwright gave each page, before `watch` put the guard's own in front of it.
      const plainClose = new WeakMap<Page, Page["close"]>();
      // The origin of the last http(s) document each page showed.
      const lastAppOrigin = new WeakMap<Page, string>();
      // Tabs that ended on a document of no origin after one of ours, and could not be taken back to the app to hand over what that document kept.
      const unforwarded: string[] = [];

      const watch = (page: Page) => {
        if (pages.has(page)) return;
        pages.add(page);
        trails.set(page, trail);
        page.on("framenavigated", (frame) => {
          note("navigated", frame.url());
          // Where a document of the app last was, so a tab that ends on Chrome's error page or about:blank can be taken back there (gate-r24-2).
          if (frame === page.mainFrame() && /^https?:/.test(frame.url())) lastAppOrigin.set(page, originOf(frame.url()));
        });
        // A spec that closes a page itself (`page.close()`) would end the document without `runBeforeUnload`, and what its `pagehide` handlers
        // did would never reach Node (measured in gate-r15-2). So the page's own close goes through the same step as the end-of-test one (gate-r16-2).
        const original = page.close.bind(page);
        plainClose.set(page, original);
        page.close = async (options) => {
          await unloadPage(page);
          return original(options);
        };
        page.on("websocket", () => external.push("ws"));
        page.on("pageerror", (e) => {
          note("pageerror", e.message);
          pageErrors.push(redactUrls(e.message));
        });
        page.on("console", (m) => {
          note("console", m.text());
          // The event of a violation raised from pagehide never runs (it is a queued task), and a document that was reopened has lost its
          // listener, but Chrome still writes the message (gate-r15-2, gate-r28-2). Counted here, merged with the events in settleCsp.
          const directive = m.type() === "error" ? cspDirectiveOfConsole(m.text()) : undefined;
          if (directive) cspOf(page).console.push(directive);
          // The proxy's plain 404 for the guard's own take-back navigation (unloadPage) is a console error in Chrome, and it is the guard's doing,
          // not the app's: without this a test with nothing wrong fails when its tab ends on about:blank or Chrome's error page (gate-r27-1).
          // The message text holds no URL, so the location Chrome attaches to it is what names the path.
          if (isGuardForwardNoise(m.type(), m.text(), m.location().url)) return;
          if (m.type() === "error" && isUnexpectedConsoleError(m.text(), patterns)) consoleErrors.push(redactUrls(m.text()));
        });
      };

      // Everything the three checks need from one context, so a second context gets exactly the same.
      const arm = async (target: BrowserContext) => {
        armed.add(target);
        // The same for a context that a spec closes by hand, the `guard.newContext()` one above all: its open pages are unloaded first (gate-r16-2).
        const originalClose = target.close.bind(target);
        target.close = async (options) => {
          for (const page of target.pages()) await unloadPage(page);
          return originalClose(options);
        };
        // Theme comes from the cookie, as it does for a visitor (spec 17.1). Only a matrix project
        // sets it: a functional spec chooses its own.
        if (matrix && baseURL) await target.addCookies([{name: THEME_COOKIE, value: matrix.theme, url: baseURL}]);

        // Recording and refusing are two jobs. The record is the context's `request` event, which sees
        // every request whoever answers it (a mock route included). The route below runs only when no
        // later route has taken the request, and then stops it.
        target.on("request", (request) => {
          const url = request.url();
          if (isExternal(url, allowed)) external.push(originOf(url));
        });
        await target.route("**/*", (route) => {
          if (!isExternal(route.request().url(), allowed)) return route.fallback();
          return route.abort();
        });

        // A policy that blocks a script also stops that script from reporting anything, so the event is
        // sent out of the page the moment it fires, from every frame, through a binding that belongs to
        // the context and so outlives each document.
        await target.exposeBinding("__ctrlzGuardCsp", (source, directive: unknown) => {
          const seen = cspOf(source.page);
          seen.events += 1;
          if (seen.pushed < seen.events) {
            cspViolations.push(String(directive).slice(0, 80));
            seen.pushed += 1;
          }
        });
        // Chrome reports no WebSocket to Playwright when the name does not resolve, and reports no peer connection at
        // all, so `page.on("websocket")` alone would miss them. The constructors report themselves.
        const recordNet = (kind: unknown, detail: unknown) => {
          const known = NET_KINDS.find((k) => k === kind) ?? "net";
          // A hint names the origin it points at, which is all that is kept of it (originOf): the path may hold a token.
          // A speculation rule set is already cut to origins, `document` or `rules` by whoever reports it (the init script, the header reader).
          external.push(known === "spec" ? `spec:${String(detail).slice(0, 200)}` : known === "hint" || known === "beacon" || known === "later" ? `${known}:${originOf(String(detail))}` : known);
        };
        await target.exposeBinding("__ctrlzGuardNet", (_source, kind: unknown, detail: unknown) => recordNet(kind, detail));
        // What a document did from pagehide on and ended by a navigation or a reload: Chrome drops the binding calls, the console messages and the
        // requests of such a document, so the init script keeps them in this tab's sessionStorage and the next document hands them over here (gate-r23-2).
        await target.exposeBinding("__ctrlzGuardLate", (_source, kind: unknown, detail: unknown) => {
          const text = String(detail).slice(0, 2000);
          if (kind === "console") {
            note("console", text);
            if (isUnexpectedConsoleError(text, patterns)) consoleErrors.push(redactUrls(text));
          } else if (kind === "pageerror") {
            note("pageerror", text);
            pageErrors.push(redactUrls(text));
          } else recordNet(kind, detail);
        });
        await target.exposeBinding("__ctrlzGuardTrail", (_source, text: unknown) => note("history", String(text)));
        // A hint in a `Link` header is read by the browser and never by the page, so it is read here. Only a document's counts.
        target.on("response", (response) => {
          if (response.request().resourceType() !== "document") return;
          // The CSP check only sees what a policy blocks, and a document with no policy blocks nothing: it must have one, with a nonce (gate-r3-4).
          const own = new URL(response.url());
          const status = response.status();
          const judge = (answeredByRoute: boolean) => documentWithoutPolicy(status, response.headers()["content-type"], response.headers()["content-security-policy"], own.pathname, answeredByRoute);
          if (isNetworkUrl(response.url()) && allowed.has(own.origin) && judge(false)) {
            const entry = `${status} ${own.pathname}`.slice(0, 80);
            if (judge(true)) {
              noPolicy.push(entry);
            } else {
              // Only a page of the guard's own self-tests may be excused, and only when a mock route made it: a response from a real
              // server has a server address, and one that cannot be asked about counts as real. The end-of-test check waits for this (gate-r5-2).
              pending.add(response.serverAddr().then((addr) => addr === null, () => false).then((mocked) => void (mocked || noPolicy.push(entry))));
            }
          }
          const link = response.headers()["link"];
          if (link) for (const origin of externalHintOrigins(link, response.url(), allowed)) external.push(`hint:${origin}`);
          // The same for a rule set that a header hands the browser: it names JSON files, and the page never sees the header (gate-r26-1).
          const rules = response.headers()["speculation-rules"];
          if (rules !== undefined) external.push(`spec:${speculationHeaderTargets(rules, response.url()).join(" ")}`);
        });
        await target.addInitScript((hintRels: readonly string[]) => {
          const w = window as unknown as Record<string, unknown> & {__ctrlzGuardCsp?: (d: string) => void; __ctrlzGuardNet?: (k: string, detail?: string) => void; __ctrlzGuardTrail?: (t: string) => void; __ctrlzGuardLate?: (k: string, d: string) => void};
          w.__ctrlzGuardOn = true;
          // Every history entry that is written, with its address and its state, for the residue check (gate-r17-5). Installed before any script of
          // the page, so the router that keeps its own reference to these methods keeps ours.
          for (const method of ["pushState", "replaceState"] as const) {
            const native = history[method];
            history[method] = function (this: History, state: unknown, unused: string, url?: string | URL | null) {
              try {
                let json = "";
                try {
                  json = JSON.stringify(state) ?? "";
                } catch {
                  /* a state that cannot be serialised: the browser refuses it as well */
                }
                w.__ctrlzGuardTrail?.(method + " " + (url == null ? "" : String(url)) + " " + json);
              } catch {
                /* the record is a check, never a reason for the page to break */
              }
              return native.call(this, state, unused, url);
            };
          }
          document.addEventListener("securitypolicyviolation", (e) => w.__ctrlzGuardCsp?.(e.effectiveDirective));
          // A Proxy keeps the static members (generateCertificate) and instanceof working. A Proxy with no `get` trap hands back the
          // native prototype, whose `constructor` is the native function: that is the way round the trap, so it is replaced too.
          const wrapped = new Set<unknown>();
          const trap = (name: string, kind: string, methods: readonly string[]) => {
            const Native = w[name] as (new (...args: unknown[]) => unknown) | undefined;
            if (typeof Native !== "function") return;
            const proxy = new Proxy(Native, {
              construct(t, args, newTarget) {
                w.__ctrlzGuardNet?.(kind);
                return Reflect.construct(t, args, newTarget);
              },
            });
            w[name] = proxy;
            const proto = Native.prototype as Record<string, unknown>;
            Object.defineProperty(proto, "constructor", {value: proxy, writable: true, configurable: true});
            // These start ICE gathering (and a connection to a STUN or TURN server) on any peer connection, however it was built.
            // The prototype is shared by the prefixed name, so a method is wrapped once.
            if (wrapped.has(proto)) return;
            wrapped.add(proto);
            for (const method of methods) {
              const original = proto[method];
              if (typeof original !== "function") continue;
              proto[method] = function (this: unknown, ...args: unknown[]) {
                w.__ctrlzGuardNet?.(kind);
                return (original as (...a: unknown[]) => unknown).apply(this, args);
              };
            }
          };
          // A request that a dying document starts reaches no `request` event (measured), so the three ways to send one without a
          // response are reported here, once pagehide has begun: before that the context's own record sees them.
          //
          // The same dying document, when a navigation or a reload ends it (not a close), delivers none of it: the binding call, the request and the
          // console message are all dropped (measured, gate-r23-2). So from pagehide on every one of them is also kept in sessionStorage, and the next
          // document of the tab forwards and clears the list at its start. A document that is closed instead reaches Node through the binding and its
          // list is never read, and a page restored from the back/forward cache lived through its pagehide, so its list is cleared. The key is one of
          // ours (ctrlz_*), so the residue check accepts it, and it holds origins and error text only, never a body.
          let leaving = false;
          const PENDING = "ctrlz_guardPending";
          const readPending = (): [string, string][] => {
            try {
              const list: unknown = JSON.parse(sessionStorage.getItem(PENDING) ?? "[]");
              return Array.isArray(list) ? (list as [string, string][]) : [];
            } catch {
              return [];
            }
          };
          const keep = (kind: string, detail: string) => {
            try {
              const list = readPending();
              if (list.length < 100) list.push([kind, detail.slice(0, 2000)]);
              sessionStorage.setItem(PENDING, JSON.stringify(list));
            } catch {
              /* storage refused: the binding call is all there is */
            }
          };
          const forwardPending = () => {
            try {
              const list = readPending();
              if (!list.length) return true;
              if (typeof w.__ctrlzGuardLate !== "function") return false;
              sessionStorage.removeItem(PENDING);
              for (const [kind, detail] of list) w.__ctrlzGuardLate(kind, detail);
            } catch {
              /* no storage in this document (an opaque origin): nothing was kept here either */
            }
            return true;
          };
          if (!forwardPending()) document.addEventListener("DOMContentLoaded", () => void forwardPending());
          window.addEventListener("pagehide", () => void (leaving = true), true);
          window.addEventListener(
            "pageshow",
            (e) => {
              leaving = false;
              if (e.persisted) {
                try {
                  sessionStorage.removeItem(PENDING);
                } catch {
                  /* see above */
                }
              }
            },
            true,
          );
          const nativeError = console.error;
          console.error = function (this: Console, ...args: unknown[]) {
            if (leaving) {
              try {
                keep("console", args.map((a) => (a instanceof Error ? a.message : typeof a === "string" ? a : typeof a === "object" ? JSON.stringify(a) ?? "" : String(a))).join(" "));
              } catch {
                /* a value that cannot be written out: the message still goes to the console */
              }
            }
            return nativeError.apply(this, args);
          };
          const lateError = (e: Event) => {
            if (!leaving) return;
            const detail = e as ErrorEvent & PromiseRejectionEvent;
            keep("pageerror", String(detail.message ?? (detail.reason instanceof Error ? detail.reason.message : detail.reason)));
          };
          window.addEventListener("error", lateError);
          window.addEventListener("unhandledrejection", lateError);
          const foreignOrigin = (target: unknown): string | null => {
            try {
              const url = new URL(String(target instanceof Request ? target.url : target), document.baseURI);
              return /^https?:$/.test(url.protocol) && url.origin !== location.origin ? url.origin : null;
            } catch {
              return null; // not a URL: the browser refuses it as well
            }
          };
          const outgoing = (target: unknown) => {
            if (!leaving) return;
            const origin = foreignOrigin(target);
            if (!origin) return;
            w.__ctrlzGuardNet?.("beacon", origin);
            keep("beacon", origin);
          };
          // fetchLater() queues a request that the browser sends when the document is destroyed, or once `activateAfter` has passed. It does not go
          // through window.fetch and no request event of Playwright follows it, so it is reported at the call, not at the send (gate-r22-9).
          const nativeLater = (window as unknown as {fetchLater?: (...a: unknown[]) => unknown}).fetchLater;
          if (typeof nativeLater === "function")
            (w as Record<string, unknown>).fetchLater = function (this: unknown, input: unknown, init?: unknown) {
              const origin = foreignOrigin(input);
              if (origin) {
                w.__ctrlzGuardNet?.("later", origin);
                if (leaving) keep("later", origin);
              }
              return nativeLater.call(this, input, init);
            };
          const beacon = navigator.sendBeacon;
          if (typeof beacon === "function")
            navigator.sendBeacon = function (this: Navigator, url: string | URL, data?: BodyInit | null) {
              outgoing(url);
              return beacon.call(this, url, data);
            };
          const nativeFetch = window.fetch;
          window.fetch = function (this: unknown, input: RequestInfo | URL, init?: RequestInit) {
            outgoing(input);
            return nativeFetch.call(this, input, init);
          };
          const open = XMLHttpRequest.prototype.open;
          XMLHttpRequest.prototype.open = function (this: XMLHttpRequest, method: string, url: string | URL, ...rest: unknown[]) {
            outgoing(url);
            return (open as (...a: unknown[]) => void).call(this, method, url, ...rest);
          } as typeof XMLHttpRequest.prototype.open;
          trap("WebSocket", "ws", []);
          // The same reasoning covers the other two ways a page opens a long-lived connection: neither is a Playwright request, a handshake that
          // succeeds leaves no trace, and `connect-src` lets through any origin it lists (the verify wildcard, once P4 sets one). WebSocketStream
          // reaches `page.on("websocket")` only when the host answers; a name that does not resolve is silent (gate-r21-2).
          trap("WebSocketStream", "ws", []);
          trap("WebTransport", "wt", []);
          trap("RTCPeerConnection", "rtc", ["setLocalDescription", "createOffer", "createAnswer", "setConfiguration"]);
          trap("webkitRTCPeerConnection", "rtc", []);

          // A resource hint to another origin (gate-r2-4). Every link that is added, or whose rel or href changes, is judged once for
          // each value; the page's own origin and a target that is not a network URL are no hint.
          const seen = new WeakMap<Element, string>();
          const judgeLink = (el: Element) => {
            const rel = (el.getAttribute("rel") ?? "").toLowerCase().split(/\s+/);
            const href = el.getAttribute("href");
            if (!href || !rel.some((token) => hintRels.includes(token))) return;
            let target: URL;
            try {
              target = new URL(href, document.baseURI);
            } catch {
              return;
            }
            if (!/^(https?|wss?):$/.test(target.protocol) || target.origin === location.origin) return;
            if (seen.get(el) === target.href) return;
            seen.set(el, target.href);
            w.__ctrlzGuardNet?.("hint", target.origin);
          };
          // A speculation rule set (gate-r26-1). Any set is a failure, so the detail only tells failures apart: the origins of a list rule's
          // URLs (never the path or query, which may hold a token) and `document` for a rule that picks links from the page. An empty script is
          // no rule set yet (the parser inserts the element before its text), so it waits for the text, which arrives as a childList record.
          const specSeen = new WeakMap<Element, string>();
          const judgeScript = (el: Element) => {
            if (el.localName !== "script" || (el.getAttribute("type") ?? "").trim().toLowerCase() !== "speculationrules") return;
            const text = el.textContent ?? "";
            if (!text.trim() || specSeen.get(el) === text) return;
            specSeen.set(el, text);
            const targets = new Set<string>();
            const walk = (value: unknown) => {
              if (Array.isArray(value)) value.forEach(walk);
              else if (value && typeof value === "object") {
                const rule = value as Record<string, unknown>;
                if (rule.where !== undefined || rule.source === "document") targets.add("document");
                if (Array.isArray(rule.urls))
                  for (const u of rule.urls) {
                    try {
                      targets.add(new URL(String(u), document.baseURI).origin);
                    } catch {
                      targets.add("rules");
                    }
                  }
                Object.values(rule).forEach(walk);
              }
            };
            try {
              walk(JSON.parse(text));
            } catch {
              /* not JSON: the browser ignores it, and it is still reported as a rule set that somebody wrote */
            }
            w.__ctrlzGuardNet?.("spec", targets.size ? [...targets].join(" ") : "rules");
          };
          const judge = (el: Element) => {
            if (el.localName === "link") judgeLink(el);
            else judgeScript(el);
          };
          const sweep = (root: ParentNode) => root.querySelectorAll("link, script").forEach(judge);
          new MutationObserver((records) => {
            for (const record of records) {
              if (record.type === "attributes") judge(record.target as Element);
              else if (record.type === "characterData") {
                // The text of a script changed in place (script.firstChild.data = ...): the element is the parent.
                if (record.target.parentElement) judgeScript(record.target.parentElement);
              } else {
                // Text added to a script element: the record's target is the script itself.
                if (record.target.nodeType === 1) judgeScript(record.target as Element);
                record.addedNodes.forEach((node) => {
                  if (node.nodeType !== 1) return;
                  judge(node as Element);
                  sweep(node as Element);
                });
              }
            }
          }).observe(document, {childList: true, subtree: true, attributes: true, attributeFilter: ["rel", "href", "type"], characterData: true});
          document.addEventListener("DOMContentLoaded", () => sweep(document));
        }, [...HINT_RELS]);

        target.pages().forEach(watch);
        target.on("page", watch);
      };

      await arm(context);

      // The pages are closed one by one, with a `beforeunload` question accepted: the app arms one while a dialog holds a secret (useLeaveGuard)
      // and an unanswered question would keep the page, and its `pagehide`, from ever running. The `close` event comes after the console
      // messages and binding calls of the dying document (measured, five of five), so waiting for it is what makes the records complete. A
      // page that has not closed within the limit is closed without the question, and what its handlers did is then lost, which is said in
      // the failure and not hidden.
      const stuck: string[] = [];
      // A close of a tab that sits on Chrome's error page right after a refused navigation sometimes does not return until the browser closes (measured
      // in gate-r24-2, with the plain close, no question asked). Such a tab has no document of ours to unload, so the close is not waited for longer
      // than a few seconds: the context closes it at the end of the test.
      const closeQuickly = async (close: () => Promise<void>) => {
        let timer: ReturnType<typeof setTimeout> | undefined;
        await Promise.race([close().catch(() => {}), new Promise<void>((resolve) => void (timer = setTimeout(resolve, 5_000)))]);
        clearTimeout(timer);
      };
      const unloadPage = async (page: Page) => {
        if (page.isClosed() || dying.has(page)) return;
        const close = plainClose.get(page) ?? page.close.bind(page);
        dying.add(page);
        try {
          // A tab that is on about:blank or on Chrome's error page (a refused navigation) has no document of ours: nothing of ours can run
          // on pagehide, and a close that waits for a question there sometimes never ended (wp8-r11-4, one run in two). Closed plainly.
          if (!/^https?:/.test(page.url())) {
            // But a tab that showed one of our documents before it got here may hold what that document wrote from pagehide, in the
            // sessionStorage of the app's origin, which Chrome's error page and about:blank cannot read. The next document of the origin hands it
            // over at its start, so the tab goes back once to a page of the app (the proxy's plain 404 under /_next/static is the cheapest, and
            // it has no markup of its own) before it is closed. If it cannot get there, the test says so and does not pass (gate-r24-2).
            const origin = lastAppOrigin.get(page);
            if (origin && !page.isClosed()) {
              const landed = await page
                .goto(`${origin}${FORWARD_PATH}`, {waitUntil: "domcontentloaded", timeout: 10_000})
                .then(() => /^https?:/.test(page.url()))
                .catch(() => false);
              if (landed) {
                // Any evaluate is a round trip, so the binding call of the hand-over arrives before the records are read.
                await page.evaluate(() => 0).catch(() => {});
              } else {
                unforwarded.push(origin);
                await closeQuickly(close);
                return;
              }
            } else {
              await closeQuickly(close);
              return;
            }
          }
          const closed = new Promise<void>((resolve) => page.once("close", () => resolve()));
          const accept = (dialog: Dialog) => void dialog.accept().catch(() => {});
          page.on("dialog", accept);
          try {
            await close({runBeforeUnload: true});
            let timer: ReturnType<typeof setTimeout> | undefined;
            const late = new Promise<"late">((resolve) => void (timer = setTimeout(() => resolve("late"), 10_000)));
            const outcome = await Promise.race([closed, late]);
            clearTimeout(timer);
            if (outcome === "late") {
              stuck.push(originOf(page.url()));
              await close().catch(() => {});
            }
          } catch {
            await close().catch(() => {});
          } finally {
            page.off("dialog", accept);
          }
        } finally {
          dying.delete(page);
          // The page is closed: everything it logged has arrived, so the two CSP counts can be merged.
          settleCsp(page);
        }
      };
      const unload = async () => {
        for (const target of armed) {
          for (const page of target.pages()) await unloadPage(page);
        }
        await Promise.all(pending);
        settleCsp();
      };

      // browser.newPage() makes its context through this.newContext() in current Playwright, so the first wrapper already sees it; the second one
      // keeps the record complete for a version that does not, and the Set makes the double entry harmless.
      browser.newContext = (async (options?: BrowserContextOptions) => {
        const created = await nativeNewContext(options);
        handMade.add(created);
        return created;
      }) as Browser["newContext"];
      browser.newPage = (async (options?: Parameters<Browser["newPage"]>[0]) => {
        const created = await nativeNewPage(options);
        handMade.add(created.context());
        return created;
      }) as Browser["newPage"];
      const restoreBrowser = () => {
        for (const key of ["newContext", "newPage"] as const) {
          const before = ownBefore[key];
          if (before) Object.defineProperty(browser, key, before);
          else delete (browser as unknown as Record<string, unknown>)[key];
        }
      };

      const recorded: Record<GuardKind, string[]> = {external, csp: cspViolations, console: consoleErrors, pageerror: pageErrors, policy: noPolicy};

      await use({
        allowConsole: (pattern) => void patterns.push(pattern),
        get external() {
          return external;
        },
        consume: (kind) => recorded[kind].splice(0),
        newContext: async (options) => {
          expect(options?.bypassCSP, "bypassCSP on a second context switches the CSP check of spec 17.2 off").toBeFalsy();
          // The project's and test.use's options reach this call too: the runner merges them into every context made during the test
          // (runBeforeCreateBrowserContext in playwright/lib/index.js), which the self-test "the same kind of visitor" pins (gate-r5-1).
          const created = await nativeNewContext({baseURL, ...options});
          opened.push(created);
          await arm(created);
          return created;
        },
        unload,
      });

      restoreBrowser();
      // A page that has a real document must have run the init script. The evaluate is also a round
      // trip, so a binding call still on its way is delivered before the check below. A page that is
      // closed or on its way to another document cannot be asked, and is skipped.
      await Promise.all(pending);
      const unguarded: string[] = [];
      for (const page of pages) {
        if (page.isClosed() || !/^https?:/.test(page.url())) continue;
        const on = await page.evaluate(() => (window as unknown as {__ctrlzGuardOn?: boolean}).__ctrlzGuardOn === true).catch(() => true);
        if (!on) unguarded.push(originOf(page.url()));
      }
      // Last, so that what the unloading handlers did lands in the records read below (gate-r15-2).
      await unload();
      // A context that was not armed ran with none of the checks, open or closed: every one made through the wrapped browser is recorded
      // above, and browser.contexts() adds any that came by another road.
      const strays = [...new Set([...handMade, ...browser.contexts()])].filter((c) => !armed.has(c));
      const unarmed = strays.length;
      // Closed here so that one stray context fails its own test and not every later test of the worker.
      await Promise.all([...opened, ...strays].map((c) => c.close().catch(() => {})));
      expect(unarmed, "browser contexts opened with browser.newContext(): use guard.newContext(), which arms the three checks (spec 17.2)").toBe(0);
      expect(stuck, "pages that would not close for the guard within 10 s: what they do on pagehide went unchecked (gate-r15-2)").toEqual([]);
      expect(unforwarded, "tabs that ended on Chrome's error page or about:blank after a document of the app, and that the guard could not take back to the app: what that document did from pagehide on went unchecked (gate-r24-2)").toEqual([]);
      expect(unguarded, "pages the guard's init script did not run in: the CSP check would have been blind").toEqual([]);
      expect(external, "requests to another origin (spec 17.2)").toEqual([]);
      expect(cspViolations, "Content-Security-Policy violations (spec 17.2)").toEqual([]);
      expect(noPolicy, "HTML documents that arrived with no Content-Security-Policy, or with one that has no nonce or lets code or styles run without it (next dev's policy, a script-src-attr that allows inline handlers, a policy that limits no script or style): the violation check is blind on them (gate-r3-4, gate-r9-3, gate-r12-1)").toEqual([]);
      expect(pageErrors, "uncaught page errors").toEqual([]);
      expect(consoleErrors, "console errors").toEqual([]);
    },
    {auto: true},
  ],
});

export {expect};
