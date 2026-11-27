import type {AdminState, Endpoint, Group} from "@ctrlz/api-client/hooks/endpoints.ts";
import type {Profile} from "@ctrlz/api-client/hooks/profiles.ts";

import {cleanProse, nameLength} from "../forms/invisible.ts";

// The rules of the Endpoint forms and lists that need no DOM (spec p3 3.8, 9.3, 10): names on add, the groups of the list, the profiles
// a change may need a lock password for, and the status words. Kept apart from the components so each rule has a plain test.

/** Spec p3 3.5 and 3.8: 50 names to create, 64 characters each, 255 of comment. */
export const MAX_NAMES = 50;
export const MAX_NAME_LENGTH = 64;
export const MAX_COMMENT_LENGTH = 255;
/** One batch carries at most 500 ids, and the Endpoint routes have no selector (controls/selection.ts). */
export const MAX_BATCH_IDS = 500;

const NAME_SEPARATORS = /[\n,،؛;]+/u;

/**
 * The names typed in the Add box: one per line, or separated by a comma (Latin or Persian) or a semicolon. Every name goes through
 * `cleanProse` (a half-space stays, a control character goes, the ends are trimmed) and an empty one is dropped. A name is not made
 * unique here: the server decides what a repeat means.
 */
export function parseNames(text: string): string[] {
  return text
    .split(NAME_SEPARATORS)
    .map((name) => cleanProse(name))
    .filter((name) => name !== "");
}

export type NamesProblem = "required" | "too_long" | "exceeded";

/** The first thing wrong with a list of names, in the order the form shows it, or `null`. */
export function checkNames(names: readonly string[]): NamesProblem | null {
  if (names.length === 0) return "required";
  if (names.length > MAX_NAMES) return "exceeded";
  if (names.some((name) => nameLength(name) > MAX_NAME_LENGTH)) return "too_long";
  return null;
}

/** Characters of a comment as the server counts them. */
export const commentLength = (text: string): number => nameLength(text);

/** What the list draws under one heading. `group` is `null` for the Endpoints with no group. */
export type EndpointSection = {key: string; group: Group | null; endpoints: Endpoint[]};

/**
 * The sections of the list: every group by name, then the Endpoints with no group. A group with no row in the view is kept only when
 * nothing narrows the view, so it can still be renamed or deleted, and left out when a search or a filter is on, where it would only
 * be noise. The ungrouped Endpoints have no heading when the tenant has no group at all (the `heading` is decided by the screen).
 */
export function sectionsOf(endpoints: readonly Endpoint[], groups: readonly Group[], compare: (a: string, b: string) => number, keepEmptyGroups: boolean): EndpointSection[] {
  const byGroup = new Map<string, Endpoint[]>();
  const loose: Endpoint[] = [];
  const known = new Set(groups.map((g) => g.id));
  for (const e of endpoints) {
    if (e.group_id && known.has(e.group_id)) byGroup.set(e.group_id, [...(byGroup.get(e.group_id) ?? []), e]);
    else loose.push(e);
  }
  const named = [...groups]
    .sort((a, b) => compare(a.name, b.name))
    .map((group) => ({key: group.id, group, endpoints: byGroup.get(group.id) ?? []}))
    .filter((s) => s.endpoints.length > 0 || keepEmptyGroups);
  return loose.length > 0 || named.length === 0 ? [...named, {key: "ungrouped", group: null, endpoints: loose}] : named;
}

/** The ids of the Endpoints that an administrator holds, by their place in `ids`, from an `endpoint_held` answer (`fields` named `/ids/<i>`). */
export function heldIndexes(fields: readonly {name: string}[] | undefined): number[] {
  const out: number[] = [];
  for (const f of fields ?? []) {
    const m = /^\/ids\/(\d+)$/.exec(f.name);
    if (m) out.push(Number(m[1]));
  }
  return out;
}

/**
 * The locked profiles a change to these Endpoints may need the password of: the locked ones among their two profile slots. A change
 * can also pull a locked profile out of a schedule window or a client, which the slots do not show, so when none of the slots is locked
 * the answer is every locked profile of the tenant, and the server takes the passwords it needs and ignores the others (p3 3.3).
 */
export function lockCandidates(endpoints: readonly Pick<Endpoint, "profile_id" | "profile2_id">[], profiles: readonly Profile[]): Profile[] {
  const lockedProfiles = profiles.filter((p) => p.locked);
  const ids = new Set(endpoints.flatMap((e) => [e.profile_id, e.profile2_id]));
  const inSlots = lockedProfiles.filter((p) => ids.has(p.id));
  return inSlots.length > 0 ? inSlots : lockedProfiles;
}

/** Whether a locked profile sits in a slot (each one asked for is needed), or the ask is a guess over the tenant (the person fills in what they know). */
export function slotsAreLocked(endpoints: readonly Pick<Endpoint, "profile_id" | "profile2_id">[], profiles: readonly Profile[]): boolean {
  const ids = new Set(endpoints.flatMap((e) => [e.profile_id, e.profile2_id]));
  return profiles.some((p) => p.locked && ids.has(p.id));
}

/**
 * The profiles to ask for after a second 423, when the passwords of the first ask were not enough: the ones already given first, then the
 * locked profiles never asked, then the ones asked and left empty, at most `max` (a request carries 8). Empty when there is nothing new to
 * ask, so the refusal stands.
 */
export function widenLockAsk(locked: readonly Profile[], asked: ReadonlySet<string>, given: ReadonlySet<string>, max: number): Profile[] {
  const rank = (p: Profile) => (given.has(p.id) ? 0 : asked.has(p.id) ? 2 : 1);
  const wide = [...locked].sort((x, y) => rank(x) - rank(y)).slice(0, max);
  return wide.some((p) => !asked.has(p.id)) ? wide : [];
}

/** The status shown in Edit, in one word: what an enabled Endpoint is called depends on whether it has been queried. */
export type StatusWord = "pending" | "active" | "soft_disabled" | "hard_disabled";
export const statusWord = (e: Pick<Endpoint, "admin_state" | "status">): StatusWord => (e.admin_state === "enabled" ? e.status : e.admin_state);
/** The admin state a status word is written as. `pending` and `active` are the same state: the server moves one to the other. */
export const adminStateOf = (word: StatusWord): AdminState => (word === "pending" || word === "active" ? "enabled" : word);

/**
 * Whether a change of `admin_state` empties the stack of every identity of the Endpoint, so each locked profile it holds is needed (spec
 * p3 3.3): any move to Soft or Hard Disabled from another value. Hard to Soft counts too: it turns a dead Endpoint into unfiltered DNS.
 */
export const isDisabling = (from: AdminState, to: AdminState): boolean => from !== to && to !== "enabled";

/** Turning Require Authorized IPs on turns away every address that is not listed, so it empties the stack of those identities too (p3 3.3). */
export const turnsRequireOn = (from: boolean, to: boolean): boolean => !from && to;

/** A write that empties S for every identity: each locked profile of the slots is needed, so the ask is not a guess (S5-r3-10). */
export const emptiesStack = (from: Pick<Endpoint, "admin_state" | "require_authorized_ips">, to: {admin_state: AdminState; require_authorized_ips: boolean}): boolean =>
  isDisabling(from.admin_state, to.admin_state) || turnsRequireOn(from.require_authorized_ips, to.require_authorized_ips);
