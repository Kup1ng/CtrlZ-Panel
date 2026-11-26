"use client";

import {createContext, createElement, useContext, type ReactNode} from "react";

// Counters on the sidebar (WF: Profiles and Endpoints). P1 has no list route, so
// the hook returns null and the chips stay hidden. P2 and P3 fill it from their list
// queries; `/me` carries no counts (spec 8.3). Keys are NavLink.countKey.
//
// The numbers come from a context so that the one place that has numbers before P2 does can
// give them: the (lab) layout (spec question 10, T-113), whose browser case reads the chips in both
// languages and at every width. The default value is null, so no other route ever shows a chip.
export type ShellCounts = Partial<Record<string, number>>;

const ShellCountsContext = createContext<ShellCounts | null>(null);

/** Fixture of the lab only; the real counts replace the `value` when P2 and P3 land. */
export function ShellCountsProvider({value, children}: {value: ShellCounts; children: ReactNode}) {
  return createElement(ShellCountsContext.Provider, {value}, children);
}

export function useShellCounts(): ShellCounts | null {
  return useContext(ShellCountsContext);
}
