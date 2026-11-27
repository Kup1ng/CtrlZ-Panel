"use client";

import {endpointCountQueryOptions} from "@ctrlz/api-client/hooks/endpoints.ts";
import {profileListQueryOptions, type Profile} from "@ctrlz/api-client/hooks/profiles.ts";
import {useQueries} from "@tanstack/react-query";
import {createContext, createElement, useContext, type ReactNode} from "react";

import {useShellApp} from "./shellContext.tsx";

// Counters on the sidebar (WF "Profiles" and "Endpoints", T-113). Keys are NavLink.countKey.
//
// From real data: the profile list (the same query as the Profiles page, so it costs no second request) and one row of the Endpoint list
// (`endpointCountQueryOptions`). A counter is left out until its answer has come, and while it has failed: a wrong zero would be worse than
// none. The admin console has no counters, and its shell must not even REGISTER the two queries (a disabled query is still in the cache, and
// adminShell.test.tsx holds every key of that cache to the admin's), so the list of queries is empty there. `/me` carries no counts (spec 8.3).
//
// A context can still hand the numbers over: the (lab) layout gives fixed ones (spec question 10, T-113), whose browser case reads the chips
// in both languages and at every width. When it does, the real queries are not registered either, so the lab never calls the API for them.
export type ShellCounts = Partial<Record<string, number>>;

const ShellCountsContext = createContext<ShellCounts | null>(null);

/** Fixture of the lab only: the value replaces the real counts below it. */
export function ShellCountsProvider({value, children}: {value: ShellCounts; children: ReactNode}) {
  return createElement(ShellCountsContext.Provider, {value}, children);
}

export function useShellCounts(): ShellCounts | null {
  const fixed = useContext(ShellCountsContext);
  const panel = useShellApp() === "panel" && fixed === null;
  // The two option objects have different data types and a list that is sometimes empty: TanStack's tuple typing cannot say that, so the
  // results are read as what they are, below.
  const queries = (panel ? [profileListQueryOptions(), endpointCountQueryOptions()] : []) as never[];
  const [profiles, endpoints] = useQueries({queries}) as unknown as ({data?: unknown} | undefined)[];
  if (fixed !== null) return fixed;
  if (!panel) return null;
  const counts: ShellCounts = {};
  const list = profiles?.data as Profile[] | undefined;
  const total = (endpoints?.data as {total: number} | undefined)?.total;
  if (list) counts.profiles = list.length;
  if (total !== undefined) counts.endpoints = total;
  return Object.keys(counts).length > 0 ? counts : null;
}
