"use client";

import {Toast} from "@heroui/react";
import {QueryClientProvider} from "@tanstack/react-query";
import {useRouter} from "@ctrlz/i18n/navigation.ts";
import {reactAriaLocale, type Locale} from "@ctrlz/i18n/locale.ts";
import type {AppId} from "@ctrlz/i18n/namespaces.ts";
import {ADMIN_PRESENCE_KEY, browserPresence, getIdleState, idlePauseMs, sessionIdleMs, subscribeIdleState, watchActivity} from "@ctrlz/api-client/activity.ts";
import {makeQueryClient} from "@ctrlz/api-client/queryDefaults.ts";
import {Fragment, useCallback, useEffect, useRef, useState, useSyncExternalStore, type ReactNode} from "react";
import {I18nProvider, RouterProvider} from "react-aria-components";

import {EnsureTheme} from "../theme/EnsureTheme.tsx";
import {AppContextProvider} from "./appContext.tsx";
import {focusMainWhenBack, observeDocument} from "./focusMain.ts";
import {IdleCover} from "./IdleCover.tsx";

// Spec 4.3. RouterProvider is the one routing wire: Sidebar.MenuItem,
// Navbar.Item and Navbar.MenuItem all defer to it, so AppLayout never gets
// `navigate`. next-intl's router adds the locale prefix itself, so hrefs in our
// code are written without it ("/profiles").

export function AppProviders({app, locale, children}: {app: AppId; locale: Locale; children: ReactNode}) {
  const router = useRouter();
  const [client] = useState(makeQueryClient);
  // Input is what the presence gate of the query defaults reads. Here, not in a gate, so that the
  // admin app (same provider) is covered as well as the panel and the login pages. The window is the
  // app's own: it must stay under that app's idle limit, and the admin's is 15 min (wp4-r4-3). The cover
  // limit is that idle limit itself: past it the page stops showing the account (wp4-r6-3).
  // The admin session is one cookie shared by every admin tab, so its presence is shared too (wp4-r9-3).
  useEffect(
    () =>
      watchActivity(client, window, {
        idleMs: idlePauseMs(app),
        coverMs: sessionIdleMs(app),
        shared: app === "admin" ? browserPresence(ADMIN_PRESENCE_KEY) : undefined,
      }),
    [client, app],
  );
  const idle = useSyncExternalStore(subscribeIdleState, getIdleState, getIdleState);
  // The cover's Continue button unmounts with the cover, so focus is on <body> when the page comes back:
  // move it to the page region once that exists (wp4-r9-1).
  const wasCovered = useRef(false);
  useEffect(() => {
    if (idle.covered) {
      wasCovered.current = true;
      return;
    }
    if (!wasCovered.current) return;
    wasCovered.current = false;
    return focusMainWhenBack(document, observeDocument);
  }, [idle.covered]);

  const navigate = useCallback((href: string) => router.push(href), [router]);
  // A real <a href> opened in a new tab must keep the language.
  const useHref = useCallback((href: string) => (href.startsWith("/") ? `/${locale}${href}` : href), [locale]);

  return (
    <I18nProvider locale={reactAriaLocale[locale]}>
      <EnsureTheme />
      <RouterProvider navigate={navigate} useHref={useHref}>
        <QueryClientProvider client={client}>
          <AppContextProvider value={app}>
            {/* Bottom, like WF's notice at the foot of the page. Below md the toast takes the full width. */}
            <Toast.Provider placement="bottom" width="min(460px, calc(100vw - 32px))" />
            {/* Covered: everything below is unmounted, open dialogs and one-time secrets with it. The epoch
                makes the page that comes back a fresh mount, so it asks /me again. */}
            {idle.covered ? <IdleCover /> : <Fragment key={idle.epoch}>{children}</Fragment>}
          </AppContextProvider>
        </QueryClientProvider>
      </RouterProvider>
    </I18nProvider>
  );
}
