import type {Client} from "@ctrlz/api-client/hooks/clients.ts";

// The Clients page (spec p3 10, T-257 to T-259), without React. The list is grouped by `group_name`; the server pages the clients, so the
// screen groups what it has loaded. A flat list of "header" and "client" items is what the virtual window draws, one item to a row.

/** The message of each Analytics level, as the Endpoint dialog words it. */
export const ANALYTICS_KEY = {none: "analyticsNone", some: "analyticsSome", full: "analyticsFull"} as const;

export const DEFAULT_LABEL = "default";
export const MAX_LABEL = 36;
export const MAX_TEXT = 64;
export const MIN_INACTIVE_DAYS = 1;
export const MAX_INACTIVE_DAYS = 3650;
export const DEFAULT_INACTIVE_DAYS = 30;

export type ClientItem = {kind: "header"; key: string; name: string | null; count: number} | {kind: "client"; key: string; client: Client};

/** What the person calls the client: its alias, or its label. */
export const clientName = (c: Pick<Client, "alias" | "label">): string => c.alias ?? c.label;

/**
 * Groups in the order of the reader's language with the clients that have none last, and the clients of a group by name. A list with no
 * group at all has no headers, so a plain list does not carry a title that says "no group".
 */
export function itemsOf(clients: readonly Client[], compare: (a: string, b: string) => number): ClientItem[] {
  const groups = new Map<string, Client[]>();
  const loose: Client[] = [];
  for (const c of clients) {
    if (c.group_name) groups.set(c.group_name, [...(groups.get(c.group_name) ?? []), c]);
    else loose.push(c);
  }
  const byName = (a: Client, b: Client) => compare(clientName(a), clientName(b)) || compare(a.label, b.label);
  const out: ClientItem[] = [];
  const names = [...groups.keys()].sort(compare);
  for (const name of names) {
    const members = groups.get(name)!.sort(byName);
    out.push({kind: "header", key: `g:${name}`, name, count: members.length});
    for (const client of members) out.push({kind: "client", key: client.id, client});
  }
  if (names.length > 0 && loose.length > 0) out.push({kind: "header", key: "g:", name: null, count: loose.length});
  for (const client of loose.sort(byName)) out.push({kind: "client", key: client.id, client});
  return out;
}

/** A whole number of days within what the API takes (1 to 3650), or null for anything else, a half day and an empty box included. */
export function parseDays(text: string): number | null {
  const digits = text.trim().replace(/[\u06F0-\u06F9]/g, (d) => String(d.charCodeAt(0) - 0x6f0)).replace(/[\u0660-\u0669]/g, (d) => String(d.charCodeAt(0) - 0x660));
  if (!/^[0-9]{1,4}$/.test(digits)) return null;
  const n = Number(digits);
  return n >= MIN_INACTIVE_DAYS && n <= MAX_INACTIVE_DAYS ? n : null;
}

/** The fields of a client the form lets a person change, as they stand, for the diff of a PATCH. */
export type ClientFields = {alias: string; group: string; profileId: string | null; profile2Id: string | null; analytics: "none" | "some" | "full" | null};

export function fieldsOf(c: Client | null): ClientFields {
  return {alias: c?.alias ?? "", group: c?.group_name ?? "", profileId: c?.profile_id ?? null, profile2Id: c?.profile2_id ?? null, analytics: c?.analytics_level ?? null};
}

type Patch = {alias?: string; group_name?: string; profile_id?: string; profile2_id?: string; analytics_level?: "none" | "some" | "full"; clear?: ("alias" | "group_name" | "profile_id" | "profile2_id" | "analytics_level")[]};

/** The PATCH that turns `was` into `now`: what changed is set, what was emptied is in `clear`, what did not change is not sent. `null` when nothing changed. */
export function diffFields(was: ClientFields, now: ClientFields): Patch | null {
  const patch: Patch = {};
  const clear: NonNullable<Patch["clear"]> = [];
  if (now.alias !== was.alias) {
    if (now.alias) patch.alias = now.alias;
    else clear.push("alias");
  }
  if (now.group !== was.group) {
    if (now.group) patch.group_name = now.group;
    else clear.push("group_name");
  }
  if (now.profileId !== was.profileId) {
    if (now.profileId) patch.profile_id = now.profileId;
    else clear.push("profile_id");
  }
  if (now.profile2Id !== was.profile2Id) {
    if (now.profile2Id) patch.profile2_id = now.profile2Id;
    else clear.push("profile2_id");
  }
  if (now.analytics !== was.analytics) {
    if (now.analytics) patch.analytics_level = now.analytics;
    else clear.push("analytics_level");
  }
  // Profile 2 cannot stand without Profile 1 (the CHECK `clients_profiles_differ`): emptying the first empties the second.
  if (clear.includes("profile_id") && !clear.includes("profile2_id") && was.profile2Id) clear.push("profile2_id");
  if (clear.length > 0) patch.clear = clear;
  return Object.keys(patch).length === 0 ? null : patch;
}
