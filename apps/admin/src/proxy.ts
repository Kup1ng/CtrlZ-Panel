import {createProxy} from "@ctrlz/ui/proxy/createProxy.ts";
import {ADMIN_PROTECTED_PREFIXES, ADMIN_SESSION_COOKIES} from "@ctrlz/ui/proxy/prefixes.ts";

// The admin never passes verifyOrigin: its policy has no extra origin.
export default createProxy({
  protectedPrefixes: ADMIN_PROTECTED_PREFIXES,
  sessionCookies: ADMIN_SESSION_COOKIES,
});

// See apps/panel/src/proxy.ts. Same exclusions, since both apps ship the same
// public/ names.
export const config = {
  matcher: ["/((?!api/|_next/|logos/|logo\.png$|icon\.png$|favicon\.ico$).*)"],
};
