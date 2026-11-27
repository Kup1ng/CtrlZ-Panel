import {toAsciiDigits} from "@ctrlz/i18n/digits.ts";

import {stripInvisible} from "../../forms/invisible.ts";

// What an admin typed into a whole-number field, read once and the same everywhere (wp10-r2-3). Only digits are a number.
// Spaces and thousands separators (Latin "," and Persian U+066C) and invisible marks are layout, so "1,000" and "۱ ۰۰۰" are
// 1000. Everything else (a decimal point or Persian decimal separator, a minus sign, a letter) makes the text "invalid":
// the old rule dropped every non-digit, so "1.5" became 15 and "-5" became 5, a different number sent with no message.

export type ParsedInteger = {kind: "empty"} | {kind: "invalid"} | {kind: "number"; value: number};

/** Past 15 digits a number is no longer exact; the field's bound takes it anyway. */
const MAX_DIGITS = 15;
const GROUPING = /[\s,\u066c]/gu;

export function parseInteger(text: string): ParsedInteger {
  const compact = stripInvisible(toAsciiDigits(text)).replace(GROUPING, "");
  if (compact === "") return stripInvisible(text).trim() === "" ? {kind: "empty"} : {kind: "invalid"};
  if (!/^\d+$/.test(compact)) return {kind: "invalid"};
  return {kind: "number", value: Number(compact.slice(0, MAX_DIGITS))};
}
