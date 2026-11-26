import type {AppleProfileRequest, ShareAppleParams} from "@ctrlz/api-client/hooks/setup.ts";

// The Apple profile builder's form (spec p3 7.3, Plan T-246, T-250): what it accepts before it asks the API, so a plain mistake never
// costs a request, and how the draft becomes the request. The API checks the same bounds again (`appleprofile.Validate`), so these
// are the early answer and not the rule.

export const MAX_SSIDS = 50;
export const MAX_DOMAINS = 100;
export const SSID_MAX_BYTES = 32;
export const DOMAIN_MAX_LENGTH = 253;

export type AppleDraft = {
  /** The client label, or "" for the Endpoint itself. */
  client: string;
  protocol: "doh" | "dot";
  ssids: string[];
  domains: string[];
  /** A folder of the Endpoint's profile whose domain rules are added to the list, or "". Not available on the share page. */
  folderId: string;
  excludeCommon: boolean;
  prohibitDisablement: boolean;
};

export const EMPTY_APPLE_DRAFT: AppleDraft = {client: "", protocol: "doh", ssids: [], domains: [], folderId: "", excludeCommon: false, prohibitDisablement: false};

export type EntryProblem = "empty" | "too_long" | "invalid" | "duplicate" | "full";

// Controls, the format characters (Cf) and the line and paragraph separators are refused in an SSID (spec 7.3); U+200C (the Persian
// half-space) stays allowed, as in RULES 9.
const REFUSED = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;
const ZWNJ = String.fromCharCode(0x200c);
const hasRefused = (value: string): boolean => value.split(ZWNJ).join("").search(REFUSED) !== -1;

export const utf8Length = (value: string): number => new TextEncoder().encode(value).length;

/** What a typed network name needs before it is added. The list is the tags already added. */
export function ssidProblem(value: string, list: readonly string[]): EntryProblem | null {
  if (value === "" || value.trim() === "") return "empty";
  if (utf8Length(value) > SSID_MAX_BYTES) return "too_long";
  if (hasRefused(value)) return "invalid";
  if (list.includes(value)) return "duplicate";
  if (list.length >= MAX_SSIDS) return "full";
  return null;
}

/** A host name as it is kept: trimmed, lower case, with no scheme, path, port or leading dots, which a pasted address often has. */
export function normalizeDomain(value: string): string {
  let out = value.trim().toLowerCase();
  out = out.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  out = out.replace(/[/?#].*$/, "");
  out = out.replace(/:\d+$/, "");
  out = out.replace(/^\*?\.+/, "").replace(/\.+$/, "");
  return out;
}

/** What a typed domain needs before it is added. `value` is already normalised. */
export function domainProblem(value: string, list: readonly string[]): EntryProblem | null {
  if (value === "") return "empty";
  if (value.length > DOMAIN_MAX_LENGTH) return "too_long";
  if (/[\s\p{Cc}\p{Cf}@:,;"'<>\\]/u.test(value) || value.includes("..")) return "invalid";
  if (list.includes(value)) return "duplicate";
  if (list.length >= MAX_DOMAINS) return "full";
  return null;
}

/** The request of the owner's builder (the profile's folder may be named). Empty lists and false flags are left out. */
export function requestOf(draft: AppleDraft): AppleProfileRequest {
  return {
    protocol: draft.protocol,
    ...(draft.client ? {client: draft.client} : {}),
    ...(draft.ssids.length ? {excluded_ssids: draft.ssids} : {}),
    ...(draft.domains.length ? {excluded_domains: draft.domains} : {}),
    ...(draft.folderId ? {from_folder_id: draft.folderId} : {}),
    ...(draft.excludeCommon ? {exclude_common: true} : {}),
    ...(draft.prohibitDisablement ? {prohibit_disablement: true} : {}),
  };
}

/** The params of a share link's builder: no folder (the page shows no profile data), and the link's client when it has one. */
export function shareParamsOf(draft: AppleDraft, linkClient: string | undefined): ShareAppleParams {
  const {from_folder_id: _folder, ...rest} = requestOf({...draft, folderId: "", client: linkClient ?? draft.client});
  void _folder;
  return rest;
}

/** The part of the draft that decides what the profile holds. A change to any of it makes a link already made out of date. */
export const draftKey = (draft: AppleDraft): string => JSON.stringify(draft);
