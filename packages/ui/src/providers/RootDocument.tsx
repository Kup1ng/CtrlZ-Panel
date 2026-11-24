import {dirOf, isLocale} from "@ctrlz/i18n/locale.ts";
import {pickNamespaces, type AppId} from "@ctrlz/i18n/namespaces.ts";
import {cookies, headers} from "next/headers";
import {notFound} from "next/navigation";
import {NextIntlClientProvider} from "next-intl";
import {getMessages} from "next-intl/server";
import type {ReactNode} from "react";

import {dana} from "../fonts/dana.ts";
import {parseThemeMode, THEME_COOKIE} from "../theme/config.ts";
import {themeHtmlProps} from "../theme/html.ts";
import {ThemeScript} from "../theme/ThemeScript.tsx";
import {AppProviders} from "./AppProviders.tsx";

// Spec 4.3. The body of both apps' `[locale]/layout.tsx`, which is the root
// layout (there is no app/layout.tsx, because next/root-params reads [locale]
// from it). A Server Component: it reads the theme cookie and the nonce, which
// the client cannot.

export async function RootDocument({
  app,
  locale,
  children,
}: {
  app: AppId;
  locale: string;
  children: ReactNode;
}) {
  if (!isLocale(locale)) notFound();

  const [store, requestHeaders, messages] = await Promise.all([cookies(), headers(), getMessages()]);
  // `light` and `dark` render their final classes here, so the first paint needs
  // no script. `system` and no cookie render none, and ThemeScript decides.
  const theme = themeHtmlProps(parseThemeMode(store.get(THEME_COOKIE)?.value));
  // The proxy sets x-nonce on the request, next to the CSP header (spec 15).
  const nonce = requestHeaders.get("x-nonce") ?? undefined;

  return (
    <html
      lang={locale}
      dir={dirOf(locale)}
      className={[dana.variable, theme.className].filter(Boolean).join(" ")}
      data-theme={theme["data-theme"]}
      // ThemeScript adds the theme classes before React hydrates.
      suppressHydrationWarning
    >
      <head>
        {/* React Aria injects one <style> element (touch-action for pressables) and reads
            its nonce from this tag. Without it the strict style-src-elem of spec 15
            blocks the element: measured in a production build, one violation on every
            page. The nonce is already in every script tag of the same document. */}
        {nonce ? <meta name="csp-nonce" content={nonce} /> : null}
        <ThemeScript nonce={nonce} />
      </head>
      <body className="bg-background text-foreground">
        <NextIntlClientProvider messages={pickNamespaces(messages, app) as never}>
          <AppProviders locale={locale}>{children}</AppProviders>
        </NextIntlClientProvider>
      </body>
    </html>
  );
}
