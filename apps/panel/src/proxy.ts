import {parseVerifyOrigins} from "@ctrlz/ui/proxy/csp.ts";
import {createProxy} from "@ctrlz/ui/proxy/createProxy.ts";
import {PANEL_PROTECTED_PREFIXES, PANEL_SESSION_COOKIES} from "@ctrlz/ui/proxy/prefixes.ts";

export default createProxy({
  app: "panel",
  protectedPrefixes: PANEL_PROTECTED_PREFIXES,
  sessionCookies: PANEL_SESSION_COOKIES,
  // A comma list of at most two origins (the zone, and the previous zone during a transition, p4-nodes 10.3), written by the domain apply step.
  // Absent until a zone is set. A wrong value throws when this file loads, and Next loads this file before it applies the matcher, so
  // every page and every route of Next answers 500, `/icon.png` (a route in src/app) included. The process stays up, and
  // only the files of public/ (`/logo.png`) are still served. A healthcheck must therefore ask for a page such as
  // `/fa/login`, never for a file of public/ (spec 15.3, 15.5; verifyOrigin.spec.ts starts a server with a wrong value).
  verifyOrigins: parseVerifyOrigins(process.env.CTRLZ_VERIFY_ORIGIN),
});

// Next reads this from the file itself, so it has to be a literal. It excludes files, never a folder:
// a path under an excluded folder that is not a file would reach the App Router without the CSP, and
// the nonce would be the client's. The file of public/ and the root metadata route are the whole list (`_next/static/` is
// not on it: createProxy lets it through with the headers). Add a line here for each new file in
// public/ or root metadata file (a test requests every one, and fails on a name that matches no
// file). A dotted path such as /fa/profiles/x.y still runs the proxy.
export const config = {
  matcher: ["/((?!logo\\.png$|icon\\.png$).*)"],
};
