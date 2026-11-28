import {normalizeFaSearch} from "@ctrlz/i18n/digits.ts";
import type {Profile} from "@ctrlz/api-client/hooks/profiles.ts";

// The list of spec p2 9.1 as pure functions, so the order and the search are tested without a browser.
//
//   sort "changed"  newest change first (the default: what a person was just working on is on top)
//   sort "name"     `Intl.Collator` of the locale, passed in as `compare`, since the list is small (spec p2 9.1)
//   a new profile   first, whatever the sort, while the list is shown (T-136), but only if it passes the search
//   the search      the name, with Arabic yeh and kaf read as the Persian letters (digits.ts) and no regard to case

export type ProfileSort = "changed" | "name";
export const PROFILE_SORTS = ["changed", "name"] as const satisfies readonly ProfileSort[];

const fold = (s: string) => normalizeFaSearch(s).trim().toLocaleLowerCase();

export function matchesQuery(profile: Pick<Profile, "name">, query: string): boolean {
  const q = fold(query);
  return q === "" || fold(profile.name).includes(q);
}

const changedAt = (p: Pick<Profile, "updated_at">) => {
  const time = Date.parse(p.updated_at);
  return Number.isNaN(time) ? 0 : time;
};

export function visibleProfiles(
  profiles: readonly Profile[],
  options: {query: string; sort: ProfileSort; compare: (a: string, b: string) => number; newId?: string | null},
): Profile[] {
  const found = profiles.filter((p) => matchesQuery(p, options.query));
  const sorted =
    options.sort === "name"
      ? found.toSorted((a, b) => options.compare(a.name, b.name) || changedAt(b) - changedAt(a))
      : found.toSorted((a, b) => changedAt(b) - changedAt(a) || options.compare(a.name, b.name));
  if (!options.newId) return sorted;
  const at = sorted.findIndex((p) => p.id === options.newId);
  if (at <= 0) return sorted;
  return [sorted[at]!, ...sorted.slice(0, at), ...sorted.slice(at + 1)];
}

/** A file picked for Import may not be larger than the API takes before it is encoded (spec p2 6.2, D31). */
export const MAX_IMPORT_BYTES = 4 * 1024 * 1024;

/** Base64 of the bytes of a file, in chunks, so a 4 MiB file does not build one argument list for `String.fromCharCode`. */
export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  return btoa(binary);
}
