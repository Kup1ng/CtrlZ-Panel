// Fixture data of the lab pages (spec 8.10 and 6.3). Nothing here comes from an API, and nothing
// here is user text: wording lives in messages/<locale>/lab.json. What stays in this file is data
// that is the same in both languages: counts, domains, addresses, series, timestamps.
//
// The domains use reserved TLDs (`.example`), so no fixture claims anything about a real site.

export type ActivityDecision = "blocked" | "allowed" | "redirected";

// A fixed base so every screenshot shows the same times, whatever the clock says.
const BASE = Date.UTC(2026, 10, 7, 11, 2, 40);

/** The series of the sparkline on the token strip. */
export const sparkline = [41, 48, 44, 52, 61, 58, 66, 71, 64, 78, 83, 80];

export type BigRow = {id: number; at: number; domain: string; decision: ActivityDecision; client: string};

const DECISIONS: ActivityDecision[] = ["blocked", "allowed", "allowed", "redirected", "allowed"];

/**
 * The 5,000 rows of the virtualisation proof (spec 8.10). Deterministic, so a test sees the same
 * rows on every run, and reserved names only, like every other fixture here.
 */
export function bigActivity(count: number): BigRow[] {
  return Array.from({length: count}, (_, i) => ({
    id: i + 1,
    at: BASE - i * 37_000,
    domain: `host-${i + 1}.metrics.example`,
    decision: DECISIONS[i % DECISIONS.length]!,
    client: `10.20.${(i >> 8) & 255}.${i & 255}`,
  }));
}
