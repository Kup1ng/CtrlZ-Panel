"use client";

import {Skeleton} from "@heroui/react";
import {useQueryClient} from "@tanstack/react-query";
import {adoptServerThemeMode, onThemeModeChange} from "../theme/useTheme.ts";
import {leaveUnauthorizedAdminSession, useAdminIdentityGuard, useAdminSession} from "@ctrlz/api-client/admin/session.ts";
import {useSession, useSessionBinding} from "@ctrlz/api-client/hooks/me.ts";
import {updatePreferences} from "@ctrlz/api-client/hooks/preferences.ts";
import {isOnLoginPath, isSessionEnding, logoutLocal, takeLocaleSync} from "@ctrlz/api-client/session.ts";
import {isLocale} from "@ctrlz/i18n/locale.ts";
import {usePathname, useRouter} from "@ctrlz/i18n/navigation.ts";
import {useLocale, useTranslations} from "next-intl";
import {useEffect, useRef, type ReactNode} from "react";

import {SectionError} from "../feedback/SectionError.tsx";
import {useApp} from "../providers/appContext.tsx";
import {currentNext} from "./currentNext.ts";
import {onLocaleChange} from "./localeSwitch.ts";
import {isOnPage} from "./pathPrefix.ts";
import {createThemeWriter, type ThemeWriter} from "./themeWriter.ts";
import {keepRetry} from "../admin/shared/restoreFocus.ts";

// Spec 14.4. A convenience, not the gate: the API refuses what the session may not
// do, and the proxy has already sent a visitor with no cookie to the login page.
// The gate reads `/me`, shows a skeleton while that loads, and leaves for the page
// that fits the answer. It also wires the three things that depend on who is
// signed in and that `packages/ui` could not do without the API client: the
// preference writes of the language and theme switches (spec 4.2, 5.1), the saved
// language applied once after login (4.2), and the server's theme winning over the
// cookie (5.1 step 5).

// The radius rule (spec 6): boxes take the box radius, and the thin lines the control formula
// (the control ratio and cap TOKENS of tokens.css times the height, written in --spacing like HeroUI
// does), never a typed ratio and never HeroUI's own scale. The lint ban on `rounded-[...]` without a
// --radius- token (banned.ts) keeps it that way.
function GateSkeleton() {
  const c = useTranslations("common");
  return (
    <div role="status" aria-busy="true" className="flex flex-col gap-4 p-6">
      <span className="sr-only">{c("loading")}</span>
      <Skeleton className="h-8 w-1/3 rounded-[min(calc(var(--spacing)*8*var(--radius-control-ratio)),var(--radius-control-cap))]" />
      <Skeleton className="h-4 w-2/3 rounded-[min(calc(var(--spacing)*4*var(--radius-control-ratio)),var(--radius-control-cap))]" />
      <Skeleton className="h-40 w-full rounded-(--radius-box)" />
    </div>
  );
}

function GateError({error, onRetry}: {error: unknown; onRetry: () => unknown}) {
  // Spec 8.7: the section error, with Retry and the request_id to quote. It carries its own role="alert".
  return <SectionError error={error} onRetry={keepRetry(onRetry)} className="p-6" />;
}

function PanelGate({children}: {children: ReactNode}) {
  const locale = useLocale();
  const pathname = usePathname();
  const router = useRouter();
  const queryClient = useQueryClient();
  const {status, me, error, retry} = useSession();

  useSessionBinding({locale, currentNext: () => currentNext("panel")});

  // One writer for the tab: the theme PATCHes go out one at a time, and the server's theme is adopted
  // only while none is pending, so two quick switches end on the last choice (wp4-r6-2).
  const themeWriter = useRef<ThemeWriter>(undefined);
  themeWriter.current ??= createThemeWriter({
    write: (mode) => updatePreferences(queryClient, {theme: mode}),
    adoptServerMode: adoptServerThemeMode,
  });

  const ready = status === "ready";

  // Spec 4.2 and 5.1: a signed-in language or theme switch is saved. Registered here
  // because this is the one place that knows a session is live.
  useEffect(() => {
    if (!ready) return;
    const offLocale = onLocaleChange(async (next) => void (await updatePreferences(queryClient, {locale: next}, {immediate: true})));
    const writer = themeWriter.current;
    const offTheme = onThemeModeChange((mode) => writer?.request(mode));
    return () => {
      offLocale();
      offTheme();
    };
  }, [ready, queryClient]);

  // The server's theme wins over the cookie when it changes (another device).
  const serverTheme = me?.user.theme;
  useEffect(() => {
    if (serverTheme) themeWriter.current?.adopt(serverTheme);
  }, [serverTheme]);

  // Spec 4.2: once per tab session, the saved language replaces the one in the URL.
  const savedLocale = me?.user.locale;
  useEffect(() => {
    if (!ready || !savedLocale || !takeLocaleSync()) return;
    if (isLocale(savedLocale) && savedLocale !== locale) {
      const {pathname: path, search, hash} = window.location;
      // A full load, not router.replace: a client navigation would drop the theme classes (4.2).
      window.location.replace(`${path.replace(/^\/[a-z]{2}(?=\/|$)/, `/${savedLocale}`)}${search}${hash}`);
    }
  }, [ready, savedLocale, locale]);

  useEffect(() => {
    if (status === "anonymous") {
      if (isOnLoginPath() || isSessionEnding()) return;
      // No broadcast: this tab only saw an error, which is not proof that the session ended, and a
      // "logout" message takes every other tab down, live ones included (wp4-r15-1). They learn it
      // themselves at their next /me, as the binding's own leave does.
      logoutLocal({queryClient, locale}, {broadcast: false, next: currentNext("panel")});
    } else if (status === "restricted" && !isOnPage(pathname, "/change-password")) {
      router.replace("/change-password");
    } else if (status === "suspended" && !isOnPage(pathname, "/suspended")) {
      router.replace("/suspended");
    }
  }, [status, pathname, router, queryClient, locale]);

  if (status === "error") return <GateError error={error} onRetry={retry} />;
  if (!ready) return <GateSkeleton />;
  return children;
}

// Admin: no refresh and no BroadcastChannel (spec 13, 14.4). A 401 from `/me`, or from any other admin
// call (the guard watches the caches, wp4-r6-4), leaves for the login page with the "session ended"
// marker (`?ended=1`, 11.4), and tells no other tab: they find out at their next `/me`, on focus.
function AdminGate({children}: {children: ReactNode}) {
  const locale = useLocale();
  const pathname = usePathname();
  const router = useRouter();
  const queryClient = useQueryClient();
  const {status, error, retry} = useAdminSession();
  useAdminIdentityGuard({locale, currentNext: () => currentNext("admin")});

  useEffect(() => {
    if (status === "anonymous") {
      if (isOnLoginPath() || isSessionEnding()) return;
      leaveUnauthorizedAdminSession({queryClient, locale}, currentNext("admin"));
    } else if (status === "setup" && !isOnPage(pathname, "/setup")) {
      router.replace("/setup");
    }
  }, [status, pathname, router, queryClient, locale]);

  if (status === "error") return <GateError error={error} onRetry={retry} />;
  if (status !== "ready") return <GateSkeleton />;
  return children;
}

/** Which gate mounts is the app of AppProviders (wp4-r5-9): no prop, so none can be forgotten. */
export function SessionGate({children}: {children: ReactNode}) {
  const app = useApp();
  return app === "admin" ? <AdminGate>{children}</AdminGate> : <PanelGate>{children}</PanelGate>;
}
