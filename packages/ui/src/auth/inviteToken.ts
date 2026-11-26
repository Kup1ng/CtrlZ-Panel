import {toAsciiDigits} from "@ctrlz/i18n/digits.ts";

import {stripInvisible} from "../forms/invisible.ts";

// The invite token (D67, AUTH 11.3): an Ed25519 signature over the claim, 140 characters of the base64url alphabet, case
// sensitive. It is a link's fragment, never something a person types, so nothing here uppercases it, groups it or drops its
// hyphens: any of those would turn a valid token into another string and the signature check on the server would refuse it.
// The page cleans what a paste brings along (white space and invisible marks around or inside the text) and folds it the way the
// server does before it opens the token (invite.fold: NFKC, then the Persian, Arabic and fullwidth digits as ASCII), so a link
// that a chat or editing app showed with Persian digits is the same invite on the page as it is for the server (webi-r1-4).
// Then it cuts the fragment out of a pasted link and checks the shape before a lookup is spent.

export const INVITE_TOKEN_LENGTH = 140;

const TOKEN = /^[A-Za-z0-9_-]+$/;
const WHITE_SPACE = /\s+/gu;

/** The paste with its white space and its invisible marks (LRM, RLM, ZWNJ, a line break a chat app wrapped in) dropped and its digits as ASCII, as the server folds it. */
const clean = (text: string) => toAsciiDigits(stripInvisible(text.normalize("NFKC"))).replace(WHITE_SPACE, "");

/**
 * The text with its percent escapes undone and cleaned again, or `null` when one is malformed. A browser hands `location.hash`
 * over percent-encoded for every character above U+007E (a trailing RLM is `%E2%80%8F`, a Persian digit `%DB%B1`), and a link
 * copied from the address bar stays that way. `%` is not in the token alphabet, so decoding cannot change a valid token; it lets
 * the marks and digits be cleaned the same way as in a paste (webi-r2-1, webi-r2-9).
 */
const decoded = (text: string): string | null => {
  try {
    return clean(decodeURIComponent(text));
  } catch {
    return null;
  }
};

/** Whether `text` is exactly an invite token: the alphabet and the length, nothing else. Case is not touched. */
export const isInviteToken = (text: string): boolean => text.length === INVITE_TOKEN_LENGTH && TOKEN.test(text);

/**
 * The token in what a visitor pasted: a whole link (`https://host/invite#<token>`, with or without the language prefix),
 * a bare fragment (`#<token>`) or the token alone. `null` when the text holds nothing that has the shape of a token, which
 * the page shows as the one `invite_invalid` text: a shape check says nothing about whether the invite exists or who made it.
 * A second `#` is not in the alphabet, so a paste that holds one is not a token.
 */
export function inviteTokenFromPaste(text: string): string | null {
  const flat = clean(text);
  const at = flat.indexOf("#");
  const candidate = decoded(at === -1 ? flat : flat.slice(at + 1));
  return candidate !== null && isInviteToken(candidate) ? candidate : null;
}

/**
 * The token of a page's own fragment (`#<token>`), or `null` when something is there that is not one (a link a chat app has
 * cut or mangled, `#---`): the page treats it as an invalid invite and spends no lookup on a string that cannot be signed.
 */
export function inviteTokenFromFragment(hash: string): string | null {
  const flat = decoded(clean(hash.replace(/^#/, "")));
  return flat !== null && isInviteToken(flat) ? flat : null;
}
