import {parseVerifyOrigin} from "@ctrlz/ui/proxy/csp.ts";
import {createProxy} from "@ctrlz/ui/proxy/createProxy.ts";
import {PANEL_PROTECTED_PREFIXES, PANEL_SESSION_COOKIES} from "@ctrlz/ui/proxy/prefixes.ts";

export default createProxy({
  protectedPrefixes: PANEL_PROTECTED_PREFIXES,
  sessionCookies: PANEL_SESSION_COOKIES,
  // Absent in P1. A wrong value throws here, so the app does not start.
  verifyOrigin: parseVerifyOrigin(process.env.CTRLZ_VERIFY_ORIGIN),
});

// Next reads this from the file itself, so it has to be a literal. Files in
// public/ and root metadata files are listed by name: next-intl would redirect
// them to /fa/... A dotted path such as /fa/profiles/x.y still runs the proxy.
// Add a line here for each new file in public/ (a test requests every one).
export const config = {
  matcher: ["/((?!api/|_next/|logos/|logo\.png$|icon\.png$|favicon\.ico$).*)"],
};
