import {CalendarDateTime, fromDate, toCalendarDate, toTime, toZoned, type CalendarDate, type Time} from "@internationalized/date";

// The date and time maths of the calendar with a clock (expiry of a rule, spec p2 3.7, T-184). The value of the picker is a JS `Date`, an
// instant, because that is what the API takes (RFC 3339) and what a test can compare. The calendar and the clock show it in the product's
// zone (Asia/Tehran, i18n/locale.ts) and in the person's calendar: React Aria draws a Jalali month in `fa` from the same Gregorian
// `CalendarDate` that this file hands it, so nothing here knows about Jalali.
//
// "Past" and "too far" are the API's refusals of an expiry (`in_past`, `out_of_range`: after now and at most a year ahead), said before the
// request. The API decides, and its answer is shown if the clock of the browser and the server disagree.

export const MAX_EXPIRY_DAYS = 365;

/** The four shortcuts of the expiry menu. `1m` is 30 days, as the API counts it. */
export const EXPIRY_SHORTCUTS = ["1h", "1d", "1w", "1m"] as const;
export type ExpiryShortcut = (typeof EXPIRY_SHORTCUTS)[number];

const SHORTCUT_MS: Record<ExpiryShortcut, number> = {
  "1h": 3_600_000,
  "1d": 86_400_000,
  "1w": 7 * 86_400_000,
  "1m": 30 * 86_400_000,
};

export const shortcutDate = (shortcut: ExpiryShortcut, now: Date): Date => new Date(now.getTime() + SHORTCUT_MS[shortcut]);

/** The date and the time of day of an instant, in `timeZone`. */
export function splitDateTime(value: Date, timeZone: string): {date: CalendarDate; time: Time} {
  const zoned = fromDate(value, timeZone);
  return {date: toCalendarDate(zoned), time: toTime(zoned)};
}

/** The instant of a date and a time of day in `timeZone`. A time that does not exist (a clock change) moves forward, as `toZoned` does. */
export function joinDateTime(date: CalendarDate, time: Time, timeZone: string): Date {
  return toZoned(new CalendarDateTime(date.year, date.month, date.day, time.hour, time.minute, 0, 0), timeZone, "compatible").toDate();
}

export type ExpiryProblem = "past" | "tooFar";

export function expiryProblem(value: Date, now: Date): ExpiryProblem | null {
  if (value.getTime() <= now.getTime()) return "past";
  if (value.getTime() > now.getTime() + MAX_EXPIRY_DAYS * 86_400_000) return "tooFar";
  return null;
}

/** The request member for an expiry: a shortcut goes as `expires_in` (the API counts from its own clock), a picked time as `expires_at` in UTC. */
export function expiryBody(value: {shortcut: ExpiryShortcut} | {at: Date} | null): {expires_in?: ExpiryShortcut; expires_at?: string} {
  if (!value) return {};
  return "shortcut" in value ? {expires_in: value.shortcut} : {expires_at: value.at.toISOString().replace(/\.\d{3}Z$/, "Z")};
}
