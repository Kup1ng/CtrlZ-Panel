// The augmentation file is never imported, so each entry point pulls it into the program.
// eslint-disable-next-line @typescript-eslint/triple-slash-reference
/// <reference path="./types.d.ts" />
import {routing} from "./routing.ts";

export type Locale = (typeof routing.locales)[number];

export const locales = routing.locales;
export const defaultLocale: Locale = routing.defaultLocale;

export function isLocale(value: unknown): value is Locale {
  return typeof value === "string" && (locales as readonly string[]).includes(value);
}

// The extensions are explicit so that a browser's default never decides the
// calendar or the digits. React Aria derives the writing direction, and so the
// arrow keys of its widgets, from this string.
export const reactAriaLocale = {
  fa: "fa-IR-u-ca-persian-nu-arabext",
  en: "en-US-u-ca-gregory-nu-latn",
} as const satisfies Record<Locale, string>;

export const dirOf = (l: Locale) => (l === "fa" ? "rtl" : "ltr");

// Every date and time in the product is shown in Iran's zone, on the server
// and in the browser alike, so a render never differs between the two.
export const TIME_ZONE = "Asia/Tehran";

// Language names are written in their own language, so the switch reads the
// same whichever language is active.
export const localeAutonym = {fa: "فارسی", en: "English"} as const satisfies Record<Locale, string>;
