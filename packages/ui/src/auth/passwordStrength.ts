import {toAsciiDigits} from "@ctrlz/i18n/digits.ts";

import {stripInvisible} from "../forms/invisible.ts";

// T-100, client side (AUTH 4.3, last paragraph). The meter is advisory: the server decides, the two
// scores can differ, and nothing here blocks a submit or sends a byte. `@zxcvbn-ts` and its three
// language packs (common, English, Persian) are loaded on the first keystroke, so a visitor who only
// signs in with a saved password never downloads them, and a build keeps them in their own chunks.
//
// Known limit, kept as the spec has it today: the list of common passwords and of Persian words is the
// owner's open question (AUTH 4.3, "Known limit", and spec 21). The server's zxcvbn-go knows English
// only; this meter also has the Persian dictionary that ships with `@zxcvbn-ts/language-fa`, so it can
// call a Persian phrase weak where the server still accepts it. That is the safe direction for an
// advisory, and the list that decides is not this one.

export type Score = 0 | 1 | 2 | 3 | 4;
export type Scorer = (password: string, userInputs: readonly string[]) => Score;

/**
 * The server scores only the first 24 runes (AUTH 4.3 item 4), so the meter reads the same 24 and no more (wp8-r16-1).
 * A longer text would let a weak head followed by random characters show a green level that the server then refuses
 * with `password_weak`. The server also lets a tail of 16 or more runes add up to one point; that bonus is not modelled,
 * so the meter can understate a long password and never overstate it, which is the safe side for an advisory.
 */
export const SCORED_RUNES = 24;

/** The score of AUTH 4.2 that a user password needs. Used only to word the hint, never to block. */
export const ENOUGH_SCORE: Score = 3;

/** The minimum length of AUTH 4.2, in code points. Used only to word the hint. */
export const MIN_LENGTH = 10;

/** What a password must reach to stop earning a hint. Only wording: the server enforces its own rule. */
export type PasswordRule = {minLength: number; enoughScore: Score};

export const USER_RULE: PasswordRule = {minLength: MIN_LENGTH, enoughScore: ENOUGH_SCORE};

/** AUTH 4.2: an admin password has 14 code points (counted like a user's) and a score of 4. */
export const ADMIN_RULE: PasswordRule = {minLength: 14, enoughScore: 4};

let loaded: Promise<Scorer> | undefined;

/** Loads the scorer once. A failed load is forgotten, so the next keystroke tries again. */
export function loadScorer(): Promise<Scorer> {
  loaded ??= (async (): Promise<Scorer> => {
    const [core, common, en, fa] = await Promise.all([
      import("@zxcvbn-ts/core"),
      import("@zxcvbn-ts/language-common"),
      import("@zxcvbn-ts/language-en"),
      import("@zxcvbn-ts/language-fa"),
    ]);
    const checker = new core.ZxcvbnFactory({
      translations: en.translations,
      graphs: common.adjacencyGraphs,
      dictionary: {...common.dictionary, ...en.dictionary, ...fa.dictionary},
    });
    // The server refuses a password that holds the last 7 digits of the phone before it scores anything (AUTH 4.3
    // item 3, reason contains_phone). zxcvbn matches user inputs as whole words, so that rule is applied here by hand
    // and shows as the lowest score (wp8-r24-2).
    return (password, userInputs) =>
      containsPhoneTail(password, userInputs) ? 0 : checker.check(prepare(password), prepareInputs(userInputs)).score;
  })().catch((error: unknown) => {
    loaded = undefined;
    throw error;
  });
  return loaded;
}

/** Persian and Arabic digits read as ASCII, like the server (AUTH 4.3 item 2), and only the first runes count. */
export function prepare(password: string): string {
  return [...toAsciiDigits(withoutHalfSpace(password))].slice(0, SCORED_RUNES).join("");
}

/**
 * The server removes U+200C before it scores and before it counts (password.Normalize, AUTH 4.2), so a password typed with
 * the half-space of the Persian keyboard is the same text as one typed without it. The meter reads that text too.
 */
const withoutHalfSpace = (password: string) => password.replace(/\u200c/gu, "");

/** Only the digits of a phone as typed ("0912 358 2641", Persian digits, a pasted "+98"). */
function phoneDigits(input: string): string {
  return toAsciiDigits(stripInvisible(input)).replace(/[^0-9]/gu, "");
}

/**
 * What the password must not resemble, as AUTH 4.3 passes it to the server's scorer: the phone digits with the
 * leading zero, without it and with the country code 98, and `ctrlz`. Spaces and hyphens typed in the number are
 * not part of it, because the server keeps digits only.
 */
export function prepareInputs(inputs: readonly string[]): string[] {
  const out = new Set<string>(["ctrlz"]);
  for (const input of inputs) {
    const digits = phoneDigits(input);
    if (digits.length < 3) continue;
    out.add(digits);
    const national = digits.startsWith("98") && digits.length > 10 ? digits.slice(2) : digits.replace(/^0/u, "");
    out.add(national);
    out.add(`0${national}`);
    out.add(`98${national}`);
  }
  return [...out];
}

/**
 * AUTH 4.3 item 3: a password that holds the last 7 digits of the phone is refused as `contains_phone`, also when
 * `-`, `_`, `.`, spaces or invisible characters sit between them. The server reads the NFKC text with Persian digits
 * as ASCII, so this does too.
 */
export function containsPhoneTail(password: string, inputs: readonly string[]): boolean {
  const text = toAsciiDigits(password.normalize("NFKC"));
  const bare = stripInvisible(text).replace(/[-_. ]/gu, "");
  for (const input of inputs) {
    const digits = phoneDigits(input);
    if (digits.length < 7) continue;
    const tail = digits.slice(-7);
    if (text.includes(tail) || bare.includes(tail)) return true;
  }
  return false;
}

export type Hint = "none" | "short" | "weak" | "advisory";

/** AUTH 4.2 counts the smaller of the typed code points and those of the NFKC form, so the hint does too (wp8-r8-2). */
export function countedLength(password: string): number {
  const text = withoutHalfSpace(password);
  return Math.min([...text].length, [...text.normalize("NFKC")].length);
}

/** Which line goes under the meter. The length rule comes first because it is the one the server always enforces. */
export function hintFor(password: string, score: Score | null, rule: PasswordRule = USER_RULE): Hint {
  if (password.length === 0) return "none";
  if (countedLength(password) < rule.minLength) return "short";
  if (score !== null && score < rule.enoughScore) return "weak";
  return "advisory";
}

/** A score as the 0..100 of the Meter, so the lowest score still shows a sliver. */
export function meterValue(score: Score): number {
  return (score + 1) * 20;
}

export type MeterColor = "danger" | "warning" | "success";

export function meterColor(score: Score): MeterColor {
  if (score <= 1) return "danger";
  return score === 2 ? "warning" : "success";
}
