import {toAsciiDigits} from "@ctrlz/i18n/digits.ts";

import {stripInvisible} from "../../forms/invisible.ts";

// Rial amounts the admin types (a gateway's price, the daily money cap): a decimal string with up to ten digits and four
// decimals (`money` in admin-openapi.yaml). Read once and the same in every field (wp10-r3-2). What the page shows back is
// `format.number`, which in fa writes U+066B as the decimal mark and U+066C as the thousands mark, and the Persian numeric
// keypad types the same marks, so an amount that was copied from the card or typed there has to be read as it was meant:
// the digits of every numeral system become ASCII, U+066B becomes ".", and U+066C and spaces are layout. A Latin comma is
// not touched, since it is a decimal mark in some languages and a thousands mark in others, so it stays invalid.

export const MONEY_RE = /^[0-9]{0,10}(\.[0-9]{1,4})?$/;

/** The text as the API takes it. Not a validity check: run `isMoney` on the result. */
export function normalizeMoney(text: string): string {
  return stripInvisible(toAsciiDigits(text)).replace(/[\s\u066c]/gu, "").replaceAll("\u066b", ".");
}

export const isMoney = (normalized: string): boolean => MONEY_RE.test(normalized);

/**
 * One spelling for one amount: "250000.0000", "250000.00" and "250000" are the same cap, and the server writes numeric(14,4)
 * back with four decimals (wp10-r3-3). Empty stays empty (no cap), and "0" is not empty. Not for text that failed `isMoney`.
 */
export function canonicalMoney(normalized: string): string {
  if (!normalized.includes(".")) return normalized.replace(/^0+(?=\d)/, "");
  const [whole = "", fraction = ""] = normalized.split(".");
  const trimmed = fraction.replace(/0+$/, "");
  const head = whole.replace(/^0+(?=\d)/, "") || "0";
  return trimmed === "" ? head : `${head}.${trimmed}`;
}

/** Two spellings of one amount. Text that is not an amount is never the same as anything ("1." must not pass for "1"). */
export function sameMoney(a: string, b: string): boolean {
  const x = normalizeMoney(a);
  const y = normalizeMoney(b);
  return isMoney(x) && isMoney(y) && canonicalMoney(x) === canonicalMoney(y);
}
