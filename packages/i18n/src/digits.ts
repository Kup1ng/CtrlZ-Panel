// Persian keyboards type U+06F0..U+06F9, Arabic keyboards U+0660..U+0669.
// Servers accept only ASCII digits in codes.
const EXTENDED_ARABIC_INDIC_ZERO = 0x06f0;
const ARABIC_INDIC_ZERO = 0x0660;

/**
 * Maps Persian and Arabic-Indic digits to 0-9. Run it on every OTP, TOTP and
 * recovery value before it leaves the browser. It changes nothing else.
 */
export function toAsciiDigits(s: string): string {
  let out = "";
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (c >= EXTENDED_ARABIC_INDIC_ZERO && c <= EXTENDED_ARABIC_INDIC_ZERO + 9) {
      out += String(c - EXTENDED_ARABIC_INDIC_ZERO);
    } else if (c >= ARABIC_INDIC_ZERO && c <= ARABIC_INDIC_ZERO + 9) {
      out += String(c - ARABIC_INDIC_ZERO);
    } else {
      out += ch;
    }
  }
  return out;
}

/**
 * Folds the Arabic forms of yeh and kaf to the Persian ones, so a search typed
 * on an Arabic keyboard finds Persian text. For client-side search only. Never
 * apply it to a password: it would change what the user typed.
 */
export function normalizeFaSearch(s: string): string {
  return s.replaceAll("ي", "ی").replaceAll("ك", "ک");
}
