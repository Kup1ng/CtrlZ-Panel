"use client";

import {profileLocationsQuery} from "@ctrlz/api-client/hooks/profiles.ts";
import {useQueries} from "@tanstack/react-query";
import {useMemo} from "react";

// Whether each of some services has a destination of its own (spec p2 4.2 `EffectiveService`, 9.4, T-166). A service limited to some regions
// (`region_limited`) can reach fewer locations than the profile, so its card must not offer Redirect when its own set is empty: pressing it would
// open Destinations with nothing to save. The call is the one the Destinations dialog of that service makes (`services=<slug>`), so the two share
// a cache entry. Only the services the page draws and that are limited are asked, so the number of calls is that of the cards on screen.
//
// A service with no answer yet, or whose call failed, is not taken away from: it reads as "has a destination", and the dialog says what is missing.

const hasAny = (results: readonly {data?: {locations: readonly unknown[]; auto_random: boolean}}[]) =>
  results.map((r) => (r.data ? r.data.locations.length > 0 || r.data.auto_random : true));

export function useServiceDestinations(profileId: string, slugs: readonly string[]): ReadonlyMap<string, boolean> {
  const has = useQueries({queries: slugs.map((slug) => profileLocationsQuery(profileId, [slug])), combine: hasAny});
  const key = slugs.join(",");
  return useMemo(() => new Map(key === "" ? [] : key.split(",").map((slug, i) => [slug, has[i] ?? true] as const)), [key, has]);
}
