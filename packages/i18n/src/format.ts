import {useLocale} from "next-intl";
import {useMemo} from "react";

import {isLocale, reactAriaLocale, TIME_ZONE, type Locale} from "./locale.ts";

// This is the only file that may call Intl (lint rule no-format-bypass). A
// format that ignores reactAriaLocale could show Gregorian dates or Latin
// digits in Persian.

export type DateInput = Date | number | string;

const PLACEHOLDER = "\u2014";

function toDate(value: DateInput): Date | undefined {
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? undefined : d;
}

type RelativeUnit = Intl.RelativeTimeFormatUnit;

// Thresholds in seconds, ascending: the first row whose limit is above the
// distance gives the unit. A month is 30.44 days and a year 365.25 days, which
// is close enough for "3 months ago" and does not depend on the calendar.
const RELATIVE_STEPS: readonly (readonly [limit: number, unit: RelativeUnit, size: number])[] = [
  [60, "second", 1],
  [3_600, "minute", 60],
  [86_400, "hour", 3_600],
  [86_400 * 45, "day", 86_400],
  [86_400 * 365.25, "month", 86_400 * 30.44],
  [Infinity, "year", 86_400 * 365.25],
];

export function createAppFormat(locale: Locale) {
  const tag = reactAriaLocale[locale];
  const timeZone = TIME_ZONE;

  const dateFmt = new Intl.DateTimeFormat(tag, {dateStyle: "medium", timeZone});
  const dateTimeFmt = new Intl.DateTimeFormat(tag, {dateStyle: "medium", timeStyle: "short", timeZone});
  const timeFmt = new Intl.DateTimeFormat(tag, {timeStyle: "short", timeZone});
  const numberFmt = new Intl.NumberFormat(tag);
  const percentFmt = new Intl.NumberFormat(tag, {style: "percent", maximumFractionDigits: 0});
  const relativeFmt = new Intl.RelativeTimeFormat(tag, {numeric: "auto"});
  const regionNames = new Intl.DisplayNames(tag, {type: "region"});
  const listFmt = new Intl.ListFormat(tag, {style: "long", type: "conjunction"});

  return {
    locale,
    /** Calendar date: Jalali in `fa`, Gregorian in `en`. */
    date: (value: DateInput) => {
      const d = toDate(value);
      return d ? dateFmt.format(d) : PLACEHOLDER;
    },
    dateTime: (value: DateInput) => {
      const d = toDate(value);
      return d ? dateTimeFmt.format(d) : PLACEHOLDER;
    },
    time: (value: DateInput) => {
      const d = toDate(value);
      return d ? timeFmt.format(d) : PLACEHOLDER;
    },
    /** Other options build a one-off formatter, so call it for rare cases only. */
    number: (value: number, options?: Intl.NumberFormatOptions) =>
      options ? new Intl.NumberFormat(tag, options).format(value) : numberFmt.format(value),
    /** `0.5` gives 50%. */
    percent: (fraction: number) => percentFmt.format(fraction),
    /** "3 minutes ago" or "in 2 days", with the unit chosen from the distance. */
    relative: (value: DateInput, now: DateInput = Date.now()) => {
      const d = toDate(value);
      const n = toDate(now);
      if (!d || !n) return PLACEHOLDER;
      const seconds = (d.getTime() - n.getTime()) / 1000;
      const abs = Math.abs(seconds);
      const [, unit, size] = RELATIVE_STEPS.find(([limit]) => abs < limit)!;
      // Under 10 seconds reads as "now" in both languages.
      if (abs < 10) return relativeFmt.format(0, "second");
      return relativeFmt.format(Math.round(seconds / size), unit);
    },
    /** "a, b and c" (in Persian "a، b و c") in the active language. */
    list: (items: readonly string[]) => listFmt.format(items),
    /** Country name in the active language, from an ISO 3166 alpha-2 code. */
    regionName: (code: string) => regionNames.of(code.toUpperCase()) ?? code,
  };
}

export type AppFormat = ReturnType<typeof createAppFormat>;

/** Works in Server and Client Components, through next-intl's `useLocale`. */
export function useAppFormat(): AppFormat {
  const raw = useLocale();
  const locale: Locale = isLocale(raw) ? raw : "fa";
  return useMemo(() => createAppFormat(locale), [locale]);
}
