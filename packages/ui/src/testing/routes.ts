import {readdirSync, statSync} from "node:fs";
import {join, sep} from "node:path";

// Spec 17.3 `routes.spec.ts` (T-414, T-438): the page list of an app is read from its `app/` tree
// and compared with the screens of spec 19. A page that is not in the list fails the run, so no
// stray marketing, billing or Storage Region page can ship by accident. Node only, no Playwright.

const PAGE_FILE = /^(page\.(tsx|ts|jsx|js|mdx)|route\.(ts|js))$/;

/** Every page and route handler under `appDir`, as a path from it with forward slashes, route groups still in. */
export function pageFiles(appDir: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) walk(full);
      else if (PAGE_FILE.test(name)) out.push(full.slice(appDir.length).split(sep).filter(Boolean).join("/"));
    }
  };
  walk(appDir);
  return out.sort();
}

/**
 * The URL paths the files under `appDir` serve, with the locale segment written `[locale]`.
 * `(group)` segments and `@slot` segments do not appear in a URL, so they are dropped. A catch-all
 * is kept as `[...rest]`. `/` is the app root.
 */
export function listRoutes(appDir: string): string[] {
  return pageFiles(appDir).map(routeOf).sort();
}

/** The URL path a page file serves, locale as `[locale]`: `[locale]/(shell)/profiles/page.tsx` is `/[locale]/profiles`. */
export function routeOf(file: string): string {
  const segments = file.split("/").slice(0, -1).filter((s) => !/^\(.*\)$/.test(s) && !s.startsWith("@"));
  return `/${segments.join("/")}`;
}

/** `/[locale]/profiles` to `/profiles`. The root of a locale is `/`. */
export function withoutLocale(route: string): string {
  const rest = route.replace(/^\/\[locale\]/, "");
  return rest === "" ? "/" : rest;
}

/** The routes in `found` that are not in `allowed`. Both are without the locale. */
export function strayRoutes(found: readonly string[], allowed: readonly string[]): string[] {
  const ok = new Set(allowed);
  return found.filter((route) => !ok.has(route));
}

/**
 * The pages of spec 19.1, without the locale. The dialogs and panes that spec lists are query
 * parameters of these pages, not pages. A line for a route that no work package has built yet is
 * allowed: the list says what may exist, and `routes.spec.ts` does not say what must.
 */
export const PANEL_ROUTES = [
  "/",
  "/login",
  "/register",
  "/invite",
  "/forgot-password",
  "/change-password",
  "/suspended",
  "/profiles",
  // P2 (spec p2 9): a profile's pages. `/profiles/[id]` redirects to its Options.
  "/profiles/[id]",
  "/profiles/[id]/filters",
  "/profiles/[id]/filters/third-party",
  "/profiles/[id]/services",
  "/profiles/[id]/custom-rules",
  "/profiles/[id]/custom-rules/[folderId]",
  "/profiles/[id]/options",
  "/endpoints",
  // P3 (spec p3 10): an Endpoint's pages. `/endpoints/[id]` redirects to its Clients.
  "/endpoints/[id]",
  "/endpoints/[id]/clients",
  "/endpoints/[id]/ips",
  "/endpoints/[id]/schedule",
  // The share page of a link: no shell, no session (spec p3 7.2).
  "/s/[token]",
  // The logo menu's pages (P3, T-125).
  "/docs",
  "/docs/api",
  "/status",
  "/analytics/statistics",
  "/analytics/activity-log",
  "/analytics/domain-test",
  "/preferences/api",
  "/preferences/account",
  // Any unknown path: the not-found page inside the shell (spec 8.7).
  "/[...rest]",
] as const;

/**
 * Pages of the `(lab)` group. They answer 404 unless CTRLZ_LAB is "1" (spec 6.3, 8.10), which
 * production Compose never sets, and `routes.spec.ts` checks the group's layout still says so.
 * `feedback-lab` is WP7's, and spec 19.1 does not list it: it holds the samples of the dialogs,
 * states and rows that the specs of 17.3 drive.
 */
export const PANEL_LAB_ROUTES = ["/virtual-lab", "/token-lab", "/feedback-lab"] as const;

/** The pages of spec 19.2 and p4-nodes 10.1. `/` redirects to `/overview`. */
export const ADMIN_ROUTES = [
  "/",
  "/login",
  "/setup",
  "/overview",
  "/nodes",
  // The enrolment page and the detail page of one node (p4-nodes 10.1), both under the Nodes sidebar entry.
  "/nodes/enrol",
  "/nodes/[id]",
  "/pair",
  "/domain",
  "/runbook",
  "/users",
  "/invites",
  "/sms",
  "/settings",
  "/audit",
  // Any unknown path.
  "/[...rest]",
] as const;

/**
 * The pages that the proxy sends to login without a session cookie (15.4) are listed by hand in `proxy/prefixes.ts`, while the pages that need a
 * session are the ones of the `(shell)` group. Nothing else ties the two, so a screen of a later phase that is added to the group and to the
 * allowlist but not to the prefixes would be served to a visitor with no cookie as a 200 shell, and `next` would be dropped from the login after it
 * (gate-r2-10, gate-r2-15, gate-r2-19). Returns what is wrong, one line each; empty when the two agree.
 *
 * - A page of the `(shell)` group is on a prefix or under one.
 * - A page of any other group is not, except the routes in `outside` (the admin's `/setup` is gated and sits in `(auth)`).
 * - Every prefix has a page, once the app has any page in the group (the admin has none until WP10).
 */
export function gateProblems(files: readonly string[], prefixes: readonly string[], outside: readonly string[] = []): string[] {
  const under = (route: string, prefix: string) => route === prefix || route.startsWith(`${prefix}/`);
  const gated = (route: string) => prefixes.some((prefix) => under(route, prefix));
  const problems: string[] = [];
  const shell = files.filter((file) => file.split("/").includes("(shell)"));
  for (const file of files) {
    const route = withoutLocale(routeOf(file));
    const inShell = shell.includes(file);
    if (inShell && !gated(route)) problems.push(`${route} is a page of the (shell) group but no protected prefix covers it: add it to proxy/prefixes.ts`);
    if (!inShell && gated(route) && !outside.includes(route)) problems.push(`${route} is under a protected prefix but is not in the (shell) group: move the page or list it as an exception`);
  }
  if (shell.length > 0) {
    const routes = files.map((file) => withoutLocale(routeOf(file)));
    for (const prefix of prefixes) {
      if (!routes.some((route) => under(route, prefix))) problems.push(`${prefix} is a protected prefix and has no page: remove it from proxy/prefixes.ts, or build the page`);
    }
  }
  return problems;
}

/**
 * Every app that has a page has its own `global-error.tsx`, built with inline `style` attributes and no `<style>` element (gate-r7-1).
 * Next's built-in fatal page puts a `<style>` element in its head with no nonce, and the CSP's `style-src-elem` allows only the nonce, so a
 * render error would raise a violation and show an unstyled page. `source` is the file's text, or null when the app has none. An app with no
 * page yet (the admin before WP10) is asked for nothing.
 */
export function fatalProblems(hasPages: boolean, source: string | null): string[] {
  if (!hasPages) return [];
  if (source === null) return ["src/app has no global-error.tsx: Next's built-in fatal page has a <style> element with no nonce, which the CSP refuses (15.2)"];
  const problems: string[] = [];
  if (/<style[\s>]/.test(source)) problems.push("global-error.tsx renders a <style> element, which the CSP refuses without a nonce: use style attributes");
  if (/dangerouslySetInnerHTML/.test(source)) problems.push("global-error.tsx uses dangerouslySetInnerHTML: its content would not carry the nonce either");
  return problems;
}
