import {defineRouting} from "next-intl/routing";

export const routing = defineRouting({
  locales: ["fa", "en"],
  defaultLocale: "fa",
  localePrefix: "always",
  // The URL alone decides. Persian is the default for everyone until a user
  // picks otherwise, whatever the browser's Accept-Language says.
  localeDetection: false,
  // No NEXT_LOCALE cookie and no hreflang: this is a private dashboard.
  localeCookie: false,
  alternateLinks: false,
});
