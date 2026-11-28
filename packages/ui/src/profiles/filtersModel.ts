import {defaultMode, type CatalogFilter, type ProfileFilter} from "@ctrlz/api-client/hooks/filters.ts";

// The rules of the Filters screens (spec p2 9.3, T-144 to T-150, T-537), kept out of the components so they are tested with no DOM.

/** The mode a filter with nothing to choose carries in the seed. It is never sent and never shown (the API refuses a `mode` on such a filter). */
export const ONE_MODE = "standard";
export const NEW_DOMAINS = "new-domains";

/** The meter of a mode: how many of three segments it fills. A mode with no level (a window of time) has none. */
export const MODE_LEVEL: Readonly<Record<string, number>> = {relaxed: 1, balanced: 2, strict: 3};
export const MODE_LEVEL_MAX = 3;

/** The name of a catalogue entry in the language of the page. */
export const catalogName = (item: {name_fa: string; name_en: string}, locale: string): string => (locale === "fa" ? item.name_fa : item.name_en);

/** The modes a person may choose between: none when the filter has one mode, or only the seed's `standard`. */
export function choosableModes(filter: Pick<CatalogFilter, "modes">): string[] {
  const modes = filter.modes.map((m) => m.mode).filter((m) => m !== ONE_MODE);
  return modes.length >= 2 ? modes : [];
}

/**
 * The mode to send when a filter is switched on (T-146): the one the profile remembers when the catalogue still offers it, else the
 * catalogue's default (Relaxed for Ads and Malware). Nothing for a filter with no choice.
 */
export function modeToSend(filter: Pick<CatalogFilter, "modes">, row: Pick<ProfileFilter, "mode"> | undefined): string | undefined {
  const modes = choosableModes(filter);
  if (modes.length === 0) return undefined;
  if (row?.mode && modes.includes(row.mode)) return row.mode;
  const fallback = defaultMode(filter);
  return fallback && modes.includes(fallback) ? fallback : modes[0];
}

export type FilterCard = {
  id: string;
  kind: CatalogFilter["kind"];
  enabled: boolean;
  /** The mode shown: only for an enabled filter that has a choice. */
  mode?: string;
  modes: string[];
  /** Words, never colour alone: Blocked while it is on, Allowed while it is off (T-144). */
  status: "blocked" | "allowed";
  deprecated: boolean;
  unavailable: boolean;
  /** The switch can be pressed: a deprecated filter can only be turned off, an unavailable one not at all. */
  canToggle: boolean;
};

export function cardOf(filter: CatalogFilter, rows: readonly ProfileFilter[] | undefined): FilterCard {
  const row = rows?.find((r) => r.filter_id === filter.id);
  const enabled = row?.enabled ?? false;
  const modes = choosableModes(filter);
  const deprecated = filter.state === "deprecated";
  const unavailable = filter.state === "unavailable";
  return {
    id: filter.id,
    kind: filter.kind,
    enabled,
    modes,
    ...(enabled && modes.length > 0 ? {mode: modeToSend(filter, row)} : {}),
    status: enabled ? "blocked" : "allowed",
    deprecated,
    unavailable,
    canToggle: unavailable ? enabled : deprecated ? enabled : true,
  };
}

export const nativeFilters = (catalog: readonly CatalogFilter[] | undefined): CatalogFilter[] => (catalog ?? []).filter((f) => f.kind === "native");
export const thirdPartyFilters = (catalog: readonly CatalogFilter[] | undefined): CatalogFilter[] => (catalog ?? []).filter((f) => f.kind === "third_party");

/** How many of the given filters the profile has on. */
export function onCount(filters: readonly CatalogFilter[], rows: readonly ProfileFilter[] | undefined): number {
  return filters.filter((f) => rows?.some((r) => r.filter_id === f.id && r.enabled)).length;
}

/** The many-lists warning (open question 4): shown while a second 3rd Party list is on. */
export const manyListsOn = (count: number): boolean => count >= 2;

/**
 * The `.ir` warning of D45 (T-537): shown when New Domains is switched on, and when its mode changes while it is on. Switching it off,
 * or any other filter, says nothing.
 */
export function needsNewDomainsWarning(change: {filterId: string; enabled: boolean; wasEnabled: boolean; mode?: string; wasMode?: string}): boolean {
  if (change.filterId !== NEW_DOMAINS || !change.enabled) return false;
  return !change.wasEnabled || (change.mode !== undefined && change.mode !== change.wasMode);
}
