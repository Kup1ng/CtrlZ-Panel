import {safeInternalPath} from "./useBellData.ts";

// Question 19 (spec 8.5, 8.8): the two notices that report a change a thief could use to keep access, a passkey that was
// added and recovery codes that were replaced. The API marks them `security: true` and says in `markable` whether the
// session that asked may clear one. The page never decides that from a kind name; it reads the two flags. This file only
// holds what the page adds to such a notice: where its links go.
//
// The links depend on the kind, because what evicts the thief depends on it (webi-r1-5). A password change ends the other
// sessions and keeps every passkey, and a passkey signs in alone, so a notice about a passkey must lead to the passkeys; the
// recovery codes that were replaced stay valid as a second factor after a password change, so a notice about them must lead
// to the place where new ones are made. The password and the sessions follow in both.

const LINKS = {
  passkeys: {id: "passkeys", href: "/preferences/account#passkeys", label: "reviewPasskeys"},
  totp: {id: "totp", href: "/preferences/account#totp", label: "makeNewCodes"},
  password: {id: "password", href: "/preferences/account#password", label: "changePassword"},
  sessions: {id: "sessions", href: "/preferences/account#sessions", label: "reviewSessions"},
} as const;

export type SecurityActionId = keyof typeof LINKS;
export type SecurityActionLabel = (typeof LINKS)[SecurityActionId]["label"];

/** The links of each kind, in the order a person should take them. A kind that is not listed gets the last row. */
// A Map and not an object: a kind is a string from the API, and `constructor` must not find a member of Object.prototype.
const ACTIONS_OF_KIND = new Map<string, readonly SecurityActionId[]>([
  ["passkey_added", ["passkeys", "password", "sessions"]],
  // A passkey signs in with no code, so a thief who added one (and then made new codes to hide it) is not stopped by new codes alone (webi-r2-6).
  ["recovery_codes_regenerated", ["totp", "passkeys", "password", "sessions"]],
]);
const DEFAULT_ACTIONS: readonly SecurityActionId[] = ["passkeys", "password", "sessions"];

/** The rows of the account page that a link may name. Anything else in a fragment is ignored by the page. */
export const ACCOUNT_ROW_FRAGMENTS: readonly string[] = Object.keys(LINKS);

/**
 * The links of a security notice of `kind`, each address built here and never read from the notice, and each checked by the
 * same validator that guards every other internal link, so no external address can come out of it.
 */
export function securityActions(kind?: string): {id: SecurityActionId; href: string; label: SecurityActionLabel}[] {
  return (ACTIONS_OF_KIND.get(kind ?? "") ?? DEFAULT_ACTIONS).flatMap((id) => {
    const link = LINKS[id];
    const href = safeInternalPath(link.href);
    return href ? [{id, href, label: link.label}] : [];
  });
}

/** `#password` or `password` to a row id the account page knows, or undefined. */
export function accountRowOf(hash: string): SecurityActionId | undefined {
  const id = hash.startsWith("#") ? hash.slice(1) : hash;
  return (Object.keys(LINKS) as SecurityActionId[]).find((key) => key === id);
}

/**
 * A link of a notice to a row of the account page is pressed. A link to the page the person is already on changes nothing in
 * the address (the same fragment), or only the search parameters (the bell closes), and a same-page navigation fires no
 * `hashchange`, so the page would not move (webi-r2-2). The account page listens for this event and moves to the row the link
 * names, once the bell has closed if it was open. The detail is the row id, never read from the notice.
 */
export const ROW_LINK_EVENT = "ctrlz:row-link";

export function announceRowLink(row: SecurityActionId): void {
  window.dispatchEvent(new CustomEvent<SecurityActionId>(ROW_LINK_EVENT, {detail: row}));
}
