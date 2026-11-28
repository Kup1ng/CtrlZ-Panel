"use client";

import {useLoginSessionReset} from "@ctrlz/api-client/hooks/me.ts";
import {usePathname} from "@ctrlz/i18n/navigation.ts";

import {isSignedInAuthPath} from "./signedInAuthPaths.ts";

// Mounted once by the layout of the pages a visitor without a session sees (WP8: login, register, invite,
// forgot password), so no sign-in path has to remember to clear what the previous visit left in this tab:
// the "saved language applied" flag (wp4-r7-2) and the previous account's cached data (wp4-r14-1). It renders
// nothing.
export function LoginSessionReset() {
  useLoginSessionReset({signedIn: isSignedInAuthPath(usePathname())});
  return null;
}
