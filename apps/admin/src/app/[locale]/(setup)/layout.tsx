import {Logo} from "@ctrlz/icons/generated/brand/Logo.tsx";
import {AuthCorner} from "@ctrlz/ui/auth/AuthCorner.tsx";
import {getTranslations} from "next-intl/server";
import type {ReactNode} from "react";

// Spec 11.2. The forced setup of a first admin: the same look as the login column, a little wider for the stepper.
// It is its own group and not `(auth)` because a visitor here HAS a session (restricted to setup, T-323): the auth
// layout's session reset would clear the `/me` the page has just fetched, and the shell's gate would send the admin
// straight back here. The page mounts the session binding itself (`SessionBinding`), as the panel's change-password
// page does, so a refused session, a back/forward restore and another admin's sign-in end it like any other page.
export default async function SetupLayout({children}: {children: ReactNode}) {
  const c = await getTranslations("common");
  return (
    <div className="relative flex min-h-dvh flex-col items-center px-4 pt-20 pb-10 sm:pt-28">
      <div className="absolute end-4 top-4">
        <AuthCorner />
      </div>
      <main id="main" className="flex w-full max-w-[520px] flex-col gap-6">
        <div className="flex flex-col items-center gap-2">
          <Logo aria-hidden className="size-12" />
          <span className="text-lg font-semibold">{c("appName")}</span>
        </div>
        {children}
      </main>
    </div>
  );
}
