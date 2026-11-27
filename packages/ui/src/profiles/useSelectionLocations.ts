"use client";

import {profileLocationsQuery, type LocationRef} from "@ctrlz/api-client/hooks/profiles.ts";
import {useQueries} from "@tanstack/react-query";
import {useEffect, useMemo, useState} from "react";

import {bucketSlugs, chunkSlugs, intersectLocations} from "../destinations/destinations.ts";

// Where a group of services may be redirected to (spec p2 9.5, T-166): the locations that every one of them can reach. The API answers for at
// most 100 services a call, so a larger selection is several calls whose answers are intersected here. The slugs settle for a moment before the
// calls go out, because each tick of a check box changes the selection and a request for each would be wasted. `order` is the catalogue's own
// order: it cuts the selection into fixed parts, so a tick that settles asks for the part it changed and not for the whole selection again.
//
// With nothing selected the set is the profile's own (the call without `services`), not an empty one: "no service" does not reach nowhere.

const SETTLE_MS = 250;
// A deployment's location sets change when a node joins or leaves, not between two ticks of a check box, so an answer is kept for a minute and a
// part that comes back (a tick and an untick) is not asked for again. The route is `user-read`: 300 a minute for the whole page.
const STALE_MS = 60_000;

export type SelectionLocations = {
  locations: LocationRef[];
  autoRandom: boolean;
  /**
   * Something can be redirected to: a location, or Auto and Random. Unknown (true) until the answer arrives, so the control does not flicker,
   * and when the answer failed: a failed call says nothing about the set, so it must not read as "no shared destination" (the screen says
   * the locations could not be read, with a retry).
   */
  hasDestination: boolean;
  isPending: boolean;
  error: unknown;
  /** Asks again for the answers that failed. */
  retry: () => void;
};

export function useSelectionLocations(profileId: string, slugs: readonly string[], enabled: boolean, order?: ReadonlyMap<string, number>): SelectionLocations {
  const joined = [...slugs].sort().join(",");
  const [settled, setSettled] = useState(joined);
  useEffect(() => {
    const timer = setTimeout(() => setSettled(joined), SETTLE_MS);
    return () => clearTimeout(timer);
  }, [joined]);

  // With the catalogue's order the parts are fixed, so a change of one service asks again for one part and not for all of them (S3-r3-2).
  const chunks = useMemo(() => (settled === "" ? [[]] : order ? bucketSlugs(settled.split(","), order) : chunkSlugs(settled.split(","))), [settled, order]);
  const results = useQueries({queries: chunks.map((chunk) => ({...profileLocationsQuery(profileId, chunk), enabled, staleTime: STALE_MS}))});

  return useMemo(() => {
    const waiting = results.some((r) => r.isPending);
    const failed = results.find((r) => r.isError);
    const locations = intersectLocations(results.map((r) => r.data?.locations ?? []));
    // One answer says it itself. Several are intersected, and the API's rule (at least two locations) is applied to the intersection: each
    // answer's own `auto_random` says nothing about what the chunks share.
    const autoRandom = results.length === 1 ? results[0]!.data?.auto_random === true : locations.length >= 2;
    const unsettled = settled !== joined;
    return {
      locations,
      autoRandom,
      hasDestination: unsettled || waiting || failed !== undefined || locations.length > 0 || autoRandom,
      isPending: unsettled || waiting,
      error: failed?.error ?? null,
      retry: () => {
        for (const r of results) if (r.isError) void r.refetch();
      },
    };
  }, [results, settled, joined]);
}
