import type {Page} from "@playwright/test";

import {expect, residueTrail} from "./guard.ts";
import type {TrailEntry} from "./guardLogic.ts";

// Spec 14.4 and R21: a ticket, a code, a secret or a password lives in component state and is never in a URL, in browser storage or in a cache.
// The lint rules (`ctrlz/no-storage`, `ctrlz/no-secret-param`) read only our own source, so a helper that the allow-list admits, a dependency or a
// router call could still put one there and every test would stay green. This reads what the browser really holds, after a flow, for the strings
// that the test typed or received (gate-r16-8).
//
// A snapshot is one moment: the address and history entry the page ends on. A flow that has moved on (router.replace to /profiles) has replaced
// the entry that held a secret for a while, and a console.log of a dependency is in no storage at all. So the check also reads the trail that the
// guard keeps for the whole test: every history.pushState and replaceState call, every frame navigation, every console message and page error
// (gate-r17-5). Storage and cookies are still read from the page, because they survive a soft navigation and are state.

/** What a page holds that outlives a render, as plain text. */
export type ResidueSnapshot = {
  url: string;
  historyState: string;
  cookie: string;
  windowName: string;
  /** `[key, value]` of every item. */
  local: [string, string][];
  session: [string, string][];
  /** The names and request URLs of every Cache Storage cache, and the names of the IndexedDB databases. */
  caches: string[];
  databases: string[];
};

/**
 * Storage keys that our own code writes: all start with `ctrlz.` or `ctrlz_` (tools/web-lint/storage-allow.txt names the files, and each says what its
 * key holds). A key outside this shape is a finding of its own, because the allow-list reviewed those files and not an unknown writer.
 */
export const OWN_STORAGE_KEY = /^ctrlz[._][\w.-]+$/;

/**
 * Cookies that script can see: the two the page writes itself (storage-allow.txt: AppShell.tsx and useTheme.ts), and the session cookies, which are
 * HttpOnly in production and so never listed there. The mock sets them from script (`addCookies` as a visible cookie), so a run in mock mode sees them.
 */
const OWN_COOKIE = /^(sidebar_state|ctrlz_theme|__Host-ctrlz_(session|refresh|admin))$/;

/**
 * A history record is `<method> <address> <JSON state>` (guard.ts). The address is up to the first space; whatever follows is the state. An address
 * that itself held a space would put its tail into the state, which can only make an entry judged where it could have been exempt, never the reverse.
 */
function historyParts(text: string): {address: string; state: string} {
  const rest = text.slice(text.indexOf(" ") + 1);
  const cut = rest.indexOf(" ");
  return cut === -1 ? {address: rest, state: ""} : {address: rest.slice(0, cut), state: rest.slice(cut + 1)};
}

/** The part of an address entry that is its address: a navigation is only an address, a history call has its state beside it. */
function addressOf(entry: TrailEntry): string | undefined {
  if (entry.kind === "navigated") return entry.text;
  if (entry.kind === "history") return historyParts(entry.text).address;
  return undefined;
}

/**
 * A secret that the visitor arrives with in the address, the token of an invite link (`/invite#TOKEN`): the test opens that address, so the first
 * navigation holds it, and Next's own first replaceState writes the same address back. Those two kinds of entry are the link and not a leak. The page
 * is then meant to strip it (InviteFlow does, with one replaceState), so from the first address entry that no longer holds the secret, every entry
 * is judged like any other.
 *
 * What the exemption covers is narrow on purpose (gate-r18-5): only a navigation, and a history call whose address holds the secret and whose state
 * does not. A console message or a page error is never part of the link, and a history call that puts the secret into its state is a leak even when
 * its address is the link. Returns, for each secret that was named, the index of the first entry that is judged whatever its kind, and `exempted`
 * says whether one entry before that index is the link. A page that never strips it is caught by the address check on the snapshot, which has no exemption.
 */
function arrivalExemptions(trail: readonly TrailEntry[], secrets: readonly string[], arrivedWith: readonly string[]) {
  const from = new Map<number, number>();
  secrets.forEach((_, i) => from.set(i, 0));
  for (const value of arrivedWith) {
    const at = secrets.indexOf(value);
    if (at === -1) throw new Error("arrivedWith names a string that is not one of the secrets: it would exempt nothing");
    const holdsIt = (text: string) => spellings(value).some((form) => text.includes(form));
    const stripped = trail.findIndex((entry) => {
      const address = addressOf(entry);
      return address !== undefined && !holdsIt(address);
    });
    from.set(at, stripped === -1 ? trail.length : stripped);
  }
  const exempted = (entry: TrailEntry, i: number, secret: number): boolean => {
    if (i >= from.get(secret)!) return false;
    if (entry.kind === "navigated") return true;
    if (entry.kind !== "history") return false;
    return !spellings(secrets[secret]!).some((form) => historyParts(entry.text).state.includes(form));
  };
  return exempted;
}

const TRAIL_PLACE: Record<TrailEntry["kind"], string> = {
  history: "a history.pushState or replaceState call",
  navigated: "the address of a navigation",
  console: "a console message",
  pageerror: "a page error",
};

/** The spellings in which a secret could be written: as it is, and percent-encoded (an address bar, a cookie). */
function spellings(secret: string): string[] {
  return [...new Set([secret, encodeURIComponent(secret), encodeURI(secret)])];
}

/**
 * What in the snapshot holds a secret or breaks the key rule. The answer names the place and the position of the secret in the list, never the
 * secret, because a failing test prints it.
 */
export function findResidue(snapshot: ResidueSnapshot, secrets: readonly string[], trail: readonly TrailEntry[] = [], arrivedWith: readonly string[] = []): string[] {
  secrets.forEach((secret, i) => {
    // An empty or very short string is in every text: the check would be red for no reason, or vacuous if it were skipped.
    if (secret.length < 4) throw new Error(`secret #${i} is shorter than 4 characters: pass what the test typed or received, not a fragment`);
  });
  const found: string[] = [];
  const holds = (text: string) => secrets.findIndex((secret) => spellings(secret).some((form) => text.includes(form)));
  const check = (place: string, text: string) => {
    const at = holds(text);
    if (at !== -1) found.push(`${place} holds secret #${at}`);
  };
  check("the address", snapshot.url);
  check("history.state", snapshot.historyState);
  check("window.name", snapshot.windowName);
  for (const pair of snapshot.cookie.split(/;\s*/).filter(Boolean)) {
    const name = pair.split("=")[0] ?? "";
    check(`the cookie ${name}`, pair);
    if (!OWN_COOKIE.test(name)) found.push(`the cookie ${name} is not one that our code writes`);
  }
  for (const [store, items] of [
    ["localStorage", snapshot.local],
    ["sessionStorage", snapshot.session],
  ] as const) {
    for (const [key, value] of items) {
      check(`${store} key ${key}`, key);
      check(`${store} value of ${key}`, value);
      if (!OWN_STORAGE_KEY.test(key)) found.push(`${store} key ${key} is not one that our code writes`);
    }
  }
  // One line for each place and secret, at the first entry that holds it: a console that repeats a secret would otherwise fill the failure.
  const reported = new Set<string>();
  const exempt = arrivalExemptions(trail, secrets, arrivedWith);
  trail.forEach((entry, i) => {
    // Every secret on its own: an entry that holds the invite code of the link and, in its state, a password must still be reported for the password.
    secrets.forEach((secret, at) => {
      if (!spellings(secret).some((form) => entry.text.includes(form)) || exempt(entry, i, at)) return;
      const once = `${entry.kind}/${at}`;
      if (reported.has(once)) return;
      reported.add(once);
      found.push(`${TRAIL_PLACE[entry.kind]} (entry #${i} of the flow's record) holds secret #${at}`);
    });
  });
  for (const url of snapshot.caches) check("Cache Storage", url);
  for (const name of snapshot.databases) check("an IndexedDB database name", name);
  if (snapshot.caches.length > 0) found.push("Cache Storage has entries: the apps write none");
  if (snapshot.databases.length > 0) found.push("IndexedDB has databases: the apps write none");
  return found;
}

/** Reads what the page holds. Plain data, so it can cross `evaluate`. */
async function snapshotOf(page: Page): Promise<ResidueSnapshot> {
  return page.evaluate(async () => {
    const items = (store: Storage): [string, string][] => {
      const out: [string, string][] = [];
      for (let i = 0; i < store.length; i++) {
        const key = store.key(i)!;
        out.push([key, store.getItem(key) ?? ""]);
      }
      return out;
    };
    const safe = <T>(read: () => T, fallback: T): T => {
      try {
        return read();
      } catch {
        return fallback;
      }
    };
    const caches: string[] = [];
    try {
      for (const name of await window.caches.keys()) {
        const cache = await window.caches.open(name);
        caches.push(name, ...(await cache.keys()).map((request) => request.url));
      }
    } catch {
      /* no Cache Storage on this origin: nothing to read */
    }
    let databases: string[] = [];
    try {
      databases = (await indexedDB.databases()).map((d) => d.name ?? "");
    } catch {
      /* not available: nothing to read */
    }
    return {
      url: location.href,
      historyState: safe(() => JSON.stringify(history.state) ?? "", ""),
      cookie: document.cookie,
      windowName: window.name,
      local: safe(() => items(localStorage), []),
      session: safe(() => items(sessionStorage), []),
      caches,
      databases,
    };
  });
}

/**
 * Fails when the page's address, history state, script-visible cookies, window name, localStorage, sessionStorage, Cache Storage or IndexedDB hold
 * one of `secrets`, or when a storage key or a script-visible cookie is not one of ours. Call it at the end of a flow that handled the secrets, on
 * any page of the test: the record of what the flow wrote on its way (history calls, navigations, console) is the guard's and covers every page.
 */
export async function expectNoSecretResidue(page: Page, secrets: readonly string[], what = "the flow", options: {arrivedWith?: readonly string[]} = {}): Promise<void> {
  const snapshot = await snapshotOf(page);
  // Read after the evaluate: it is a round trip, so a binding call that was still on its way has been delivered.
  const trail = residueTrail(page);
  expect(trail, "the page is not under the guard: the record of what the flow wrote is missing (import test from guard.ts)").toBeDefined();
  expect(trail!.some((entry) => entry.kind === "navigated"), "the guard recorded no navigation: the record is not working, and a clean result would mean nothing").toBe(true);
  expect(findResidue(snapshot, secrets, trail, options.arrivedWith), `what ${what} left behind in the browser (spec 14.4, R21)`).toEqual([]);
}
