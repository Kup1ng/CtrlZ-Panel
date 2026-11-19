"use client";

import {Toast} from "@heroui/react";
import {QueryClient, QueryClientProvider} from "@tanstack/react-query";
import {useRouter} from "@ctrlz/i18n/navigation.ts";
import {reactAriaLocale, type Locale} from "@ctrlz/i18n/locale.ts";
import {useCallback, useState, type ReactNode} from "react";
import {I18nProvider, RouterProvider} from "react-aria-components";

// Spec 4.3. RouterProvider is the one routing wire: Sidebar.MenuItem,
// Navbar.Item and Navbar.MenuItem all defer to it, so AppLayout never gets
// `navigate`. next-intl's router adds the locale prefix itself, so hrefs in our
// code are written without it ("/profiles").

/**
 * Retry rule of spec 14.4: network errors and 503 only, twice at most, never a
 * 4xx. `status` is the field of the API client's ApiError; a fetch that never
 * reached the server throws a TypeError without one.
 */
function shouldRetry(failureCount: number, error: unknown): boolean {
  if (failureCount >= 2) return false;
  const status = (error as {status?: unknown} | null)?.status;
  if (typeof status === "number") return status === 503;
  return error instanceof TypeError;
}

function makeClient() {
  return new QueryClient({
    defaultOptions: {
      // Memory only, no persister. Revocation should show, so /me refetches on focus
      // (its hook sets that itself); other queries keep the default.
      queries: {retry: shouldRetry, staleTime: 30_000, refetchOnWindowFocus: false},
    },
  });
}

export function AppProviders({locale, children}: {locale: Locale; children: ReactNode}) {
  const router = useRouter();
  const [client] = useState(makeClient);

  const navigate = useCallback((href: string) => router.push(href), [router]);
  // A real <a href> opened in a new tab must keep the language.
  const useHref = useCallback((href: string) => (href.startsWith("/") ? `/${locale}${href}` : href), [locale]);

  return (
    <I18nProvider locale={reactAriaLocale[locale]}>
      <RouterProvider navigate={navigate} useHref={useHref}>
        <QueryClientProvider client={client}>
          {/* Bottom, like WF's notice at the foot of the page. Below md the toast takes the full width. */}
          <Toast.Provider placement="bottom" width="min(460px, calc(100vw - 32px))" />
          {children}
        </QueryClientProvider>
      </RouterProvider>
    </I18nProvider>
  );
}
