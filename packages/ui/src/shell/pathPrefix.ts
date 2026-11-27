/**
 * True when `pathname` is `prefix` or a path below it, cut at a segment: `/change-password` and `/change-password/x` match, `/change-password-x` does
 * not. A bare `startsWith(prefix)` also matches a name that merely starts with the same letters, which has no page and falls to the catch-all
 * (gate-r22-7). `pathname` is next-intl's, with no locale. One helper for the gate, the nav and the signed-in auth pages, and
 * `pathPrefix.test.ts` fails on a bare `pathname.startsWith(` in the shell.
 */
export function isOnOrUnder(pathname: string, prefix: string): boolean {
  return pathname === prefix || pathname.startsWith(`${prefix}/`);
}

/**
 * True when `pathname` is exactly the page `page` (a trailing slash is the same page). For a page that has no child routes, such as
 * /change-password, /suspended and /setup: a path below it has no page and falls to the catch-all, which renders the signed-in shell, so
 * the gate must still send that visitor on. `isOnOrUnder` is for the nav, where children are real (gate-r23-6).
 */
export function isOnPage(pathname: string, page: string): boolean {
  return pathname === page || pathname === `${page}/`;
}
