import {toAsciiDigits} from "@ctrlz/i18n/digits.ts";

// The same rule as the API's phone.SearchPrefix (internal/auth/phone): what an admin typed in the Users search is a prefix
// of an Iranian mobile number, or the API answers 400 validation_failed. That answer in a search box is not a failure to
// retry, it is "nothing matches", so the page asks only when the text can start a number (wp10-r2-1). The page also treats
// a 400 on the query as "not a number", so a drift between this copy and the Go one costs a request, never a Retry.

// Separators the API reads as layout: space, tab, hyphen, parentheses, no-break space, dashes and the minus sign. The
// invisible marks are already gone from the typed text (stripInvisible).
const SEPARATORS = /[\s\-()\u00a0\u2010-\u2015\u2212]/gu;

export function isPhonePrefix(text: string): boolean {
  const s = toAsciiDigits(text.normalize("NFKC"));
  const plus = s.includes("+");
  // A "+" is allowed only once and only before every digit.
  if (plus && !/^[\s\-()\u00a0\u2010-\u2015\u2212]*\+[^+]*$/u.test(s)) return false;
  const rest = s.replace("+", "").replace(SEPARATORS, "");
  if (!/^\d*$/.test(rest)) return false;
  let n = rest;
  if (plus) n = n.replace(/^98/, "");
  else if (n.startsWith("0098")) n = n.slice(4);
  else if (n.startsWith("98")) n = n.slice(2);
  n = n.replace(/^0/, "");
  return n.length <= 10 && (n === "" || n[0] === "9");
}
