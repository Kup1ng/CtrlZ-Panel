import type {Folder, Rule, RuleFilter, RulePatch, RuleSelector, RulesBatch} from "@ctrlz/api-client/hooks/rules.ts";
import type {Target} from "@ctrlz/api-client/hooks/services.ts";

import {expiryBody, type ExpiryShortcut} from "../../calendar/dateTime.ts";
import type {Action} from "../../controls/threeState.ts";
import type {BatchTarget} from "../../controls/selection.ts";

// The rules of the Rules screens that need no DOM (spec p2 9.6, 3.7, 8.3), so each is tested alone: what the list asks for, how a rule shows,
// the tags of the rule dialog, the Geo Rule rows, the expiry choice and the bodies the writes send.

/** The most patterns one create takes (the schema's `maxItems`), and the longest comment and folder name (3.7). */
export const MAX_PATTERNS = 1000;
export const COMMENT_MAX = 64;
export const FOLDER_NAME_MAX = 31;
/** The largest file Upload Folder takes before it is encoded (spec 6.2, 8.2). */
export const UPLOAD_MAX_BYTES = 4 * 1024 * 1024;

// ---- the list ----

export const STATUS_FILTERS = ["enabled", "disabled", "expired"] as const;
export const ACTION_FILTERS = ["block", "bypass", "redirect", "inherit"] as const;
export const SORTS = ["created", "updated", "pattern"] as const;
export type RuleSort = (typeof SORTS)[number];
export type RuleView = "large" | "small";

/** What the person set on the toolbar. An empty string is "all". */
export type ListFilter = {q: string; status: "" | (typeof STATUS_FILTERS)[number]; action: "" | (typeof ACTION_FILTERS)[number]; sort: RuleSort};
export const NO_FILTER: ListFilter = {q: "", status: "", action: "", sort: "created"};

/** A search, a status or an action narrows the list; the sort does not. */
export const isFiltered = (f: ListFilter): boolean => f.q.trim() !== "" || f.status !== "" || f.action !== "";

/**
 * The query of the list. A folder page asks for its folder. The top level asks for `root` (folders come first and hold their own rules);
 * a filter asks for every folder, since a search that skipped the rules inside folders would miss most of them (the row then names its folder).
 */
export function listQuery(f: ListFilter, folderId?: string): RuleFilter {
  const q = f.q.trim().slice(0, 253);
  return {
    folder: folderId ?? (isFiltered(f) ? undefined : "root"),
    ...(q ? {q} : {}),
    ...(f.status ? {status: f.status} : {}),
    ...(f.action ? {action: f.action} : {}),
    sort: f.sort,
  };
}

/** The selector of Select All: the same filter the list shows, without the sort (a selector has none). */
export function selectorOf(query: RuleFilter): RuleSelector {
  const {sort, ...selector} = query;
  void sort;
  return selector;
}

/**
 * How many rules the filter holds, when it is known without asking for more: every page loaded (no next cursor) is the loaded count; a view
 * with no filter has the count of its folder, or the profile's rules less the folders' (the top level). Otherwise it is not known and the bar
 * says "every matching rule".
 */
export function knownTotal(input: {filtered: boolean; folder?: Folder; profileRules: number; folders: readonly Folder[]; loaded: number; hasNext: boolean}): number | undefined {
  if (!input.hasNext) return input.loaded;
  if (input.filtered) return undefined;
  if (input.folder) return input.folder.rule_count;
  return Math.max(0, input.profileRules - input.folders.reduce((sum, f) => sum + f.rule_count, 0));
}

// ---- a rule on screen ----

export type RuleState = "on" | "off" | "expired";

/** A rule past its expiry is expired whatever its switch says; the node never serves it (P4 purges it later). */
export function ruleState(rule: Pick<Rule, "enabled" | "expires_at">, now: Date): RuleState {
  if (rule.expires_at && Date.parse(rule.expires_at) <= now.getTime()) return "expired";
  return rule.enabled ? "on" : "off";
}

/** A rule that inherits takes its folder's action. The folder may be unknown (it is not loaded yet), and then the rule says only "inherit". */
export function effectiveRuleAction(rule: Pick<Rule, "action" | "folder_id">, folders: readonly Folder[]): Action {
  if (rule.action !== "inherit") return rule.action;
  return folders.find((f) => f.id === rule.folder_id)?.action ?? "inherit";
}

export const isGeoKind = (kind: Rule["match_kind"]): boolean => kind === "dest_cc" || kind === "dest_as" || kind === "src_cc";

/**
 * The record types a rule's answer covers, as the A and AAAA capsules of WF "Rules". A Redirect to an address covers the families the address
 * has; a Geo Rule is about the answer or the asker, not a record, and shows none; every other rule covers both.
 */
export function recordsOf(rule: Pick<Rule, "match_kind" | "action" | "target">): {a: boolean; aaaa: boolean} {
  if (isGeoKind(rule.match_kind)) return {a: false, aaaa: false};
  if (rule.action === "redirect" && rule.target?.kind === "ip") return {a: Boolean(rule.target.ipv4), aaaa: Boolean(rule.target.ipv6)};
  return {a: true, aaaa: true};
}

// ---- Geo Rule rows ----

export type GeoSide = "dest" | "src";
export type Geo = {side: GeoSide; negated: boolean; country: string};

const GEO = /^(!?)([@#])([A-Za-z]{2})$/;
const ASN = /^(!?)@AS([0-9]{1,10})$/i;

/** A country Geo Rule from its token (`@IR`, `!#DE`), or null for anything else (an AS number, a domain). */
export function parseGeo(pattern: string): Geo | null {
  const m = GEO.exec(pattern.trim());
  if (!m) return null;
  return {side: m[2] === "@" ? "dest" : "src", negated: m[1] === "!", country: m[3]!.toUpperCase()};
}

export const geoPattern = (g: Geo): string => `${g.negated ? "!" : ""}${g.side === "dest" ? "@" : "#"}${g.country.toUpperCase()}`;

/** The AS number of an `@AS1234` token, or null. */
export function parseAsn(pattern: string): {negated: boolean; number: string} | null {
  const m = ASN.exec(pattern.trim());
  return m ? {negated: m[1] === "!", number: m[2]!} : null;
}

// ---- domain tags ----

/** The words a pasted or typed text holds: split on spaces, commas, semicolons and line breaks (a name has none of them). */
export function splitTokens(text: string): string[] {
  return text
    .split(/[\s,;،؛]+/u)
    .map((s) => s.trim())
    .filter((s) => s !== "");
}

/**
 * Adds the tokens of `text` to the tags. A tag that is there already is left out (the API refuses a key twice in one request, so the
 * screen does not send it), and tags past `max` are counted in `over`, not added.
 */
export function addTags(tags: readonly string[], text: string, max = MAX_PATTERNS): {tags: string[]; added: number; duplicates: number; over: number} {
  const next = [...tags];
  const seen = new Set(next.map((t) => t.toLowerCase()));
  let added = 0;
  let duplicates = 0;
  let over = 0;
  for (const token of splitTokens(text)) {
    if (seen.has(token.toLowerCase())) {
      duplicates++;
    } else if (next.length >= max) {
      over++;
    } else {
      next.push(token);
      seen.add(token.toLowerCase());
      added++;
    }
  }
  return {tags: next, added, duplicates, over};
}

/** `/patterns/3` or `/patterns/3/...` gives 3; anything else is null. */
export function patternIndex(fieldName: string): number | null {
  const m = /^\/patterns\/(\d{1,5})(?:\/|$)/.exec(fieldName);
  return m ? Number(m[1]) : null;
}

// ---- the expiry choice ----

export type ExpiryChoice = {kind: "none"} | {kind: "keep"} | {kind: "shortcut"; value: ExpiryShortcut} | {kind: "at"; at: Date};

/** The members a create sends for the choice; none for "none" and "keep". */
export const createExpiry = (choice: ExpiryChoice) => expiryBody(choice.kind === "shortcut" ? {shortcut: choice.value} : choice.kind === "at" ? {at: choice.at} : null);

// ---- bodies ----

export type RuleDraft = {
  pattern: string;
  action: Action;
  target: Target | null;
  folderId: string;
  comment: string;
  expiry: ExpiryChoice;
};

/** Whether two destinations are the same place: the id of a location, or the address, host or kind. */
export function sameTarget(a: Target | undefined | null, b: Target | undefined | null): boolean {
  if (!a || !b) return !a && !b;
  return a.kind === b.kind && a.location_id === b.location_id && a.ipv4 === b.ipv4 && a.ipv6 === b.ipv6 && a.host === b.host;
}

/** The PATCH of an edit: only what the person changed, so a value equal to the stored one is not set (spec 3.7, first paragraph). */
export function rulePatch(rule: Rule, draft: RuleDraft): RulePatch {
  const patch: RulePatch = {};
  const clear: NonNullable<RulePatch["clear"]> = [];
  const pattern = draft.pattern.trim();
  if (pattern !== "" && pattern !== rule.pattern) patch.pattern = pattern;
  if (draft.action !== rule.action) patch.action = draft.action;
  if (draft.action === "redirect" && draft.target && (draft.action !== rule.action || !sameTarget(draft.target, rule.target))) patch.target = draft.target;
  if (draft.folderId !== (rule.folder_id ?? "")) {
    if (draft.folderId === "") clear.push("folder");
    else patch.folder_id = draft.folderId;
  }
  const comment = draft.comment.trim();
  if (comment !== (rule.comment ?? "")) {
    if (comment === "") clear.push("comment");
    else patch.comment = comment;
  }
  if (draft.expiry.kind === "none") {
    if (rule.expires_at) clear.push("expires");
  } else if (draft.expiry.kind !== "keep") {
    Object.assign(patch, createExpiry(draft.expiry));
  }
  if (clear.length > 0) patch.clear = clear;
  return patch;
}

export const isEmptyPatch = (patch: RulePatch): boolean => Object.keys(patch).length === 0;

// ---- Copy, Move and group Edit ----

export type TransferPlace = {kind: "root"} | {kind: "folder"; folderId: string} | {kind: "new"; name: string};
export type TransferDraft = {op: "copy" | "move"; profileId: string; place: TransferPlace};

/** The destination members of a copy or a move (spec 8.3 "Batch semantics"): the other profile when it is another, and the one place. */
export function transferMembers(draft: TransferDraft, sourceProfileId: string) {
  const place = draft.place;
  return {
    ...(draft.profileId !== sourceProfileId || draft.op === "copy" ? {dest_profile_id: draft.profileId} : {}),
    ...(place.kind === "root" ? {dest_root: true} : place.kind === "folder" ? {dest_folder_id: place.folderId} : {new_folder: {name: place.name.trim(), kind: "standard" as const}}),
  };
}

/** Whether the draft can be sent: a Copy goes to another profile, and a new folder needs a name that fits. */
export function transferProblem(draft: TransferDraft, sourceProfileId: string): "same_profile" | "name_required" | "name_too_long" | "folder_required" | null {
  if (draft.op === "copy" && draft.profileId === sourceProfileId) return "same_profile";
  if (draft.place.kind === "folder" && draft.place.folderId === "") return "folder_required";
  if (draft.place.kind === "new") {
    const name = draft.place.name.trim();
    if (name === "") return "name_required";
    if ([...name].length > FOLDER_NAME_MAX) return "name_too_long";
  }
  return null;
}

export type Change<T> = {mode: "keep"} | {mode: "set"; value: T} | {mode: "clear"};
export type EditDraft = {action: Change<Action>; target: Target | null; comment: Change<string>; expiry: Change<ExpiryChoice>; folder: Change<string>};
export const KEEP_ALL: EditDraft = {action: {mode: "keep"}, target: null, comment: {mode: "keep"}, expiry: {mode: "keep"}, folder: {mode: "keep"}};

/** The `set` and `clear` of a group Edit, or null when nothing was chosen. */
export function editMembers(draft: EditDraft): Pick<RulesBatch, "set" | "clear"> | null {
  const set: NonNullable<RulesBatch["set"]> = {};
  const clear: NonNullable<RulesBatch["clear"]> = [];
  if (draft.action.mode === "set") {
    set.action = draft.action.value;
    if (draft.action.value === "redirect" && draft.target) set.target = draft.target;
  }
  if (draft.comment.mode === "set" && draft.comment.value.trim() !== "") set.comment = draft.comment.value.trim();
  if (draft.comment.mode === "clear") clear.push("comment");
  if (draft.expiry.mode === "set") Object.assign(set, createExpiry(draft.expiry.value));
  if (draft.expiry.mode === "clear") clear.push("expires");
  if (draft.folder.mode === "set" && draft.folder.value !== "") set.folder_id = draft.folder.value;
  if (draft.folder.mode === "clear") clear.push("folder");
  if (Object.keys(set).length === 0 && clear.length === 0) return null;
  return {...(Object.keys(set).length > 0 ? {set} : {}), ...(clear.length > 0 ? {clear} : {})};
}

/** A selection as the batch route takes it: ids, or the selector of the filter. */
export function selectionMembers(target: BatchTarget, query: RuleFilter): Pick<RulesBatch, "ids" | "selector"> {
  return target.kind === "ids" ? {ids: target.ids} : {selector: selectorOf(query)};
}

// ---- Upload Folder ----

/** A file's bytes as base64, in chunks so a 4 MiB file does not overflow the argument list of `String.fromCharCode`. */
export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  const step = 0x8000;
  for (let i = 0; i < bytes.length; i += step) binary += String.fromCharCode(...bytes.subarray(i, i + step));
  return btoa(binary);
}
