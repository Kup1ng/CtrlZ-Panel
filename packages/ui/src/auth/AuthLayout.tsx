import {Logo} from "@ctrlz/icons/generated/brand/Logo.tsx";
import {getTranslations} from "next-intl/server";
import type {ReactNode} from "react";

import {LoginSessionReset} from "../shell/LoginSessionReset.tsx";
import {AuthCorner} from "./AuthCorner.tsx";

// Spec 10: a centred column of at most 400px, the logo above it, the language switch at the corner,
// and no shell. WF has no note for these pages (AUTH finding 9), so each is a `no reference` row of
// docs/wireframes/p1-comparison.md (T-480, spec 17.6). The rows are still to be added there by the orchestrator:
// WP8 hands over six (login, register, invite, forgot password, change password, suspended).
// An async server component with `getTranslations`: `useTranslations` in a server component pulls next-intl's error
// text, with a documentation link, into the server bundle, and the URL check of 16.2 refuses a new link. The only
// client parts are the corner menu and the session reset (which clears the saved-language flag of this tab, so a
// session that ended on its own cannot leave the next user's language behind, wp4-r7-2).

export async function AuthLayout({children}: {children: ReactNode}) {
  const c = await getTranslations("common");
  return (
    <div className="relative flex min-h-dvh flex-col items-center px-4 pt-20 pb-10 sm:pt-28">
      <div className="absolute end-4 top-4">
        <AuthCorner />
      </div>
      <main id="main" className="flex w-full max-w-[400px] flex-col gap-6">
        <div className="flex flex-col items-center gap-2">
          <Logo aria-hidden className="size-12" />
          <span className="text-lg font-semibold">{c("appName")}</span>
        </div>
        {children}
      </main>
      <LoginSessionReset />
    </div>
  );
}
