import {isOnPage} from "./pathPrefix.ts";

// The pages of the auth layout a signed-in user lands on. Their /me is live, so the login-page reset must not
// drop it (wp4-r14-1). Every other page of the layout is one a visitor without a session sees. `pathname` has
// no locale (next-intl's usePathname).
export const SIGNED_IN_AUTH_PATHS = ["/change-password", "/suspended"] as const;

export const isSignedInAuthPath = (pathname: string) =>
  SIGNED_IN_AUTH_PATHS.some((p) => isOnPage(pathname, p));
