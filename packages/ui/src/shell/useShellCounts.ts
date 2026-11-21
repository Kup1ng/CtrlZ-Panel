"use client";

// Counters on the sidebar (WF: Profiles and Endpoints). P1 has no list route, so
// this returns null and the chips stay hidden. P2 and P3 fill it from their list
// queries; `/me` carries no counts (spec 8.3). Keys are NavLink.countKey.
export type ShellCounts = Partial<Record<string, number>>;

export function useShellCounts(): ShellCounts | null {
  return null;
}
