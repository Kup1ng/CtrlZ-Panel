import type {LocationRef} from "@ctrlz/api-client/hooks/profiles.ts";
import type {Target} from "@ctrlz/api-client/hooks/services.ts";

// The model of the Destinations dialog (spec p2 9.5, WF "Destinations"): where a Redirect goes. Kept apart from the component so that
// the grouping, the search, the checks of an address and the Target that comes out are tested without a DOM.
//
// A destination is one of: a location of the profile's set (a country, a city of it, or a location that has only a label), Auto or
// Random (only when the set has at least two locations, SC 10.2: the API reports it as `auto_random`), a custom IP (an IPv4, an IPv6, or
// both: at least one), or a host name (a CNAME). A request names a location by its id, never by its key.

export type CountryGroup = {
  /** The country code, or `label:<id>` for a location that is only a label. */
  key: string;
  country?: string;
  /** The name to show and to search: the country's name in the person's language, or the label as it is. */
  name: string;
  /** The location of the country as a whole, when the set has one. */
  whole?: LocationRef;
  cities: LocationRef[];
  /** A label-only location. */
  label?: LocationRef;
};

/** Groups the set by country, sorted by the country's name (locale collation); label-only locations come last, by label. */
export function groupLocations(locations: readonly LocationRef[], regionName: (code: string) => string, collator: {compare: (a: string, b: string) => number}): CountryGroup[] {
  const byCountry = new Map<string, CountryGroup>();
  const labels: CountryGroup[] = [];
  for (const loc of locations) {
    if (loc.country) {
      const code = loc.country.toUpperCase();
      let group = byCountry.get(code);
      if (!group) {
        group = {key: code, country: code, name: regionName(code), cities: []};
        byCountry.set(code, group);
      }
      if (loc.city) group.cities.push(loc);
      else group.whole = loc;
    } else if (loc.label) {
      labels.push({key: `label:${loc.id}`, name: loc.label, cities: [], label: loc});
    }
  }
  const groups = [...byCountry.values()].sort((a, b) => collator.compare(a.name, b.name));
  for (const g of groups) g.cities.sort((a, b) => collator.compare(a.city ?? "", b.city ?? ""));
  labels.sort((a, b) => collator.compare(a.name, b.name));
  return [...groups, ...labels];
}

/**
 * The groups that match a search. A country matches by its name or its code; a city by its name, and then only that city is kept (the
 * country stays as its container). `fold` is the app's search folding (Persian and Arabic letters and digits made equal, case dropped).
 */
export function filterGroups(groups: readonly CountryGroup[], query: string, fold: (s: string) => string): CountryGroup[] {
  const q = fold(query.trim());
  if (q === "") return [...groups];
  return groups.flatMap((g) => {
    if (fold(g.name).includes(q) || (g.country !== undefined && fold(g.country).includes(q))) return [g];
    const cities = g.cities.filter((c) => fold(c.city ?? "").includes(q));
    return cities.length > 0 ? [{...g, whole: undefined, cities}] : [];
  });
}

// ---- Addresses ----

const OCTET = /^(0|[1-9]\d{0,2})$/;

export function isIPv4(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((p) => OCTET.test(p) && Number(p) <= 255);
}

const HEX_GROUP = /^[0-9a-fA-F]{1,4}$/;

/** An IPv6 address in the forms people write: `::` once, up to eight groups, an IPv4 tail. No zone id and no brackets. */
export function isIPv6(value: string): boolean {
  if (value === "" || /[^0-9a-fA-F:.]/.test(value)) return false;
  const doubles = value.split("::").length - 1;
  if (doubles > 1 || value.includes(":::")) return false;
  let groupsNeeded = 8;
  let work = value;
  const tail = work.slice(work.lastIndexOf(":") + 1);
  if (tail.includes(".")) {
    if (!isIPv4(tail)) return false;
    work = `${work.slice(0, work.lastIndexOf(":") + 1)}0:0`;
  }
  const [head, rest] = work.split("::") as [string, string | undefined];
  const side = (s: string) => (s === "" ? [] : s.split(":"));
  const left = side(head);
  const right = rest === undefined ? [] : side(rest);
  if (![...left, ...right].every((g) => HEX_GROUP.test(g))) return false;
  const count = left.length + right.length;
  if (rest === undefined) return count === groupsNeeded;
  groupsNeeded -= 1; // `::` stands for at least one group
  return count <= groupsNeeded;
}

const LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

/** A host name for a CNAME: letters, digits and hyphens in labels of 1 to 63, at most 253 in all, at least two labels. The API checks it again. */
export function isHostName(value: string): boolean {
  const name = value.endsWith(".") ? value.slice(0, -1) : value;
  if (name.length === 0 || name.length > 253) return false;
  const labels = name.split(".");
  return labels.length >= 2 && labels.every((l) => LABEL.test(l));
}

// ---- The draft of the form, and the Target it makes ----

export type ProxyChoice = {kind: "auto"} | {kind: "random"} | {kind: "location"; id: string};

export type DestinationDraft = {
  tab: "proxies" | "ip";
  proxy: ProxyChoice | null;
  record: "a" | "cname";
  v4: string;
  v6: string;
  host: string;
};

export const EMPTY_DRAFT: DestinationDraft = {tab: "proxies", proxy: null, record: "a", v4: "", v6: "", host: ""};

export type DraftProblems = {v4?: "invalidV4"; v6?: "invalidV6"; host?: "invalidHost"; needOne?: true};

/** What is wrong with the IP or Hostname tab. Empty when it is fine, and also while nothing is typed (the Save button, not an error, says so). */
export function draftProblems(draft: DestinationDraft): DraftProblems {
  if (draft.tab !== "ip") return {};
  const out: DraftProblems = {};
  if (draft.record === "a") {
    const v4 = draft.v4.trim();
    const v6 = draft.v6.trim();
    if (v4 !== "" && !isIPv4(v4)) out.v4 = "invalidV4";
    if (v6 !== "" && !isIPv6(v6)) out.v6 = "invalidV6";
  } else if (draft.host.trim() !== "" && !isHostName(draft.host.trim())) {
    out.host = "invalidHost";
  }
  return out;
}

/** The Target a draft stands for, or `null` while it is not complete or not valid. */
export function targetOf(draft: DestinationDraft): Target | null {
  if (draft.tab === "proxies") {
    const p = draft.proxy;
    if (!p) return null;
    return p.kind === "location" ? {kind: "location", location_id: p.id} : {kind: p.kind};
  }
  if (Object.keys(draftProblems(draft)).length > 0) return null;
  if (draft.record === "cname") {
    const host = draft.host.trim();
    return host === "" ? null : {kind: "host", host};
  }
  const v4 = draft.v4.trim();
  const v6 = draft.v6.trim();
  if (v4 === "" && v6 === "") return null;
  return {kind: "ip", ...(v4 ? {ipv4: v4} : {}), ...(v6 ? {ipv6: v6} : {})};
}

/** The draft that shows an existing Target, so the dialog opens on what the row has. A location given by key is found in the set by key. */
export function draftOf(target: Target | null | undefined, locations: readonly LocationRef[]): DestinationDraft {
  if (!target) return EMPTY_DRAFT;
  switch (target.kind) {
    case "auto":
    case "random":
      return {...EMPTY_DRAFT, proxy: {kind: target.kind}};
    case "location": {
      const id =
        target.location_id ??
        locations.find((l) => (l.country ?? "") === (target.location?.country ?? "") && (l.city ?? "") === (target.location?.city ?? "") && (l.label ?? "") === (target.location?.label ?? ""))?.id;
      return {...EMPTY_DRAFT, proxy: id ? {kind: "location", id} : null};
    }
    case "ip":
      return {...EMPTY_DRAFT, tab: "ip", record: "a", v4: target.ipv4 ?? "", v6: target.ipv6 ?? ""};
    case "host":
      return {...EMPTY_DRAFT, tab: "ip", record: "cname", host: target.host ?? ""};
  }
}

/** The set of locations shared by several calls: a selection of more than 100 services is intersected on the client from several answers (spec p2 9.5). */
export function intersectLocations(sets: readonly (readonly LocationRef[])[]): LocationRef[] {
  if (sets.length === 0) return [];
  const [first, ...rest] = sets;
  return first!.filter((loc) => rest.every((s) => s.some((o) => o.id === loc.id)));
}

/** A selection of slugs cut into the calls of at most 100 that `GET /profiles/{id}/locations?services=` takes. */
export function chunkSlugs(slugs: readonly string[], size = 100): string[][] {
  const out: string[][] = [];
  for (let i = 0; i < slugs.length; i += size) out.push(slugs.slice(i, i + size));
  return out;
}

/**
 * A selection cut along a fixed partition of the catalogue (`order`: slug to its place in the catalogue), at most `size` places to a part. The
 * parts of `chunkSlugs` shift by one whenever one slug joins or leaves the sorted selection, so the cache entry of every part after it is lost and a
 * large selection is asked for again in full at each tick. Here a slug stays in its part, so a tick changes only the part that holds it. A part with
 * nothing selected is not asked for, and each part is sorted so that equal parts share a cache key.
 */
export function bucketSlugs(slugs: readonly string[], order: ReadonlyMap<string, number>, size = 100): string[][] {
  const parts = new Map<number, string[]>();
  for (const slug of slugs) {
    const part = Math.floor((order.get(slug) ?? order.size) / size);
    const list = parts.get(part);
    if (list) list.push(slug);
    else parts.set(part, [slug]);
  }
  // A slug the catalogue does not know all lands in the last part, which `chunkSlugs` then keeps within the limit of a call.
  return [...parts.entries()].sort(([a], [b]) => a - b).flatMap(([, list]) => chunkSlugs(list.sort(), size));
}

/**
 * Whether a destination is still one the set offers. A location must be in the set, Auto and Random need the set to allow them, and a custom
 * address or host name is the person's own and fits any set. A selection that changes can take a destination out of its reach (the API answers
 * `location_not_allowed` or `no_shared_destination`), so the screen asks before it writes.
 */
export function targetFits(target: Target, set: {locations: readonly LocationRef[]; autoRandom: boolean}): boolean {
  switch (target.kind) {
    case "location":
      return set.locations.some((l) => l.id === target.location_id);
    case "auto":
    case "random":
      return set.autoRandom;
    default:
      return true;
  }
}
