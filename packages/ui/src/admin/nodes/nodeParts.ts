import type {NodeHealth, NodeView} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import type {GeneralIconName} from "@ctrlz/icons/hugeicons.ts";

// Pure parts of the P4 admin pages (p4-nodes 10.1), kept out of the components so each rule has a test that names its Plan row.

/** Every outcome of `FreeOutcome` (shared contract 5.2a). A value that is not here reads as `other`, never as raw wording. */
export const FREE_OUTCOMES = [
  "answered",
  "hop",
  "off",
  "not_caught_up",
  "myip",
  "rd0",
  "rate_limited",
  "prefix_share",
  "unvalidated_share",
  "validated_share",
  "source_share",
  "over_budget",
  "isolated",
  "over_miss_cap",
] as const;
export type FreeOutcomeKey = (typeof FREE_OUTCOMES)[number];

export function outcomeKey(outcome: string): FreeOutcomeKey | "other" {
  return (FREE_OUTCOMES as readonly string[]).includes(outcome) ? (outcome as FreeOutcomeKey) : "other";
}

type ChipColor = "default" | "accent" | "success" | "warning" | "danger";

/**
 * Status is never by colour alone (the design rules): each state has a word, and an icon that differs by kind of state, beside the
 * colour. Serving is the only success; a node the hub holds or has taken out of the answer is a warning; one with no contact is danger.
 */
export const HEALTH_LOOK: Record<NodeHealth, {color: ChipColor; icon: GeneralIconName}> = {
  serving: {color: "success", icon: "check"},
  held: {color: "warning", icon: "warning"},
  withdrawn: {color: "warning", icon: "warning"},
  isolated: {color: "warning", icon: "warning"},
  out_of_touch: {color: "danger", icon: "error"},
  no_contact: {color: "default", icon: "info"},
  pending: {color: "accent", icon: "info"},
  revoked: {color: "default", icon: "close"},
};

export const HUB_HEALTH_LOOK = {
  healthy: {color: "success", icon: "check"},
  degraded: {color: "warning", icon: "warning"},
  down: {color: "danger", icon: "error"},
} as const satisfies Record<string, {color: ChipColor; icon: GeneralIconName}>;

/** How the configuration of a node reads: a pending or revoked node has no lag to speak of. */
export type LagState = {kind: "none"} | {kind: "upToDate"} | {kind: "behind"; count: number; applied: number; head: number};

export function lagState(node: Pick<NodeView, "status" | "applied_seq" | "config_head" | "applied_seq_lag">): LagState {
  if (node.status !== "active") return {kind: "none"};
  // A lag below zero (a node that reports ahead of the head the panel read a moment earlier) is up to date, not "-1 behind".
  if (node.applied_seq_lag <= 0) return {kind: "upToDate"};
  return {kind: "behind", count: node.applied_seq_lag, applied: node.applied_seq, head: node.config_head};
}

/** The nodes of the overview that serve now, and the nodes that could (the active ones): "3 of 4". */
export function servingCount(nodes: readonly NodeView[], health: (n: NodeView) => NodeHealth): {serving: number; total: number} {
  const active = nodes.filter((n) => n.status === "active");
  return {serving: active.filter((n) => health(n) === "serving").length, total: active.length};
}

/** Whether the date from which an address may go back has come. The list holds only addresses whose date had not passed when it was read. */
export const isSafeNow = (safeFrom: string, now: number = Date.now()): boolean => {
  const at = Date.parse(safeFrom);
  return !Number.isNaN(at) && at <= now;
};

export type CounterWindow = "day" | "week";
const HOUR_MS = 3_600_000;
const WINDOW_HOURS: Record<CounterWindow, number> = {day: 24, week: 168};

/**
 * The window the counters are asked for. `to` is the end of the current hour (exclusive in the API), so the hour in progress counts,
 * and both ends are whole hours: the query key stays the same across renders and the rows are the hourly rows the node sends.
 */
export function counterRange(window: CounterWindow, now: number = Date.now()): {from: string; to: string} {
  const to = (Math.floor(now / HOUR_MS) + 1) * HOUR_MS;
  return {from: new Date(to - WINDOW_HOURS[window] * HOUR_MS).toISOString(), to: new Date(to).toISOString()};
}

/** The most pages of counters the overview loads by itself (500 rows each). Past it the screen says the period is cut. */
export const COUNTER_PAGES_MAX = 10;

// ---- The node page and the enrolment (p4-nodes 4.2, 4.5, 10.1) ---------------------------------------------------------------------

/**
 * A fingerprint as it is compared: the host prints the hex SHA-256 of the key, perhaps with colons, spaces or a `SHA256:` label, in
 * either case, and none of that is part of what is compared (4.2 step 4, T-340).
 */
export function normaliseFingerprint(text: string): string {
  return text
    .replace(/[\s:\u200c\u200e\u200f]/g, "")
    .replace(/^sha-?256/i, "")
    .toLowerCase();
}

export type FingerprintCheck = "empty" | "partial" | "mismatch" | "match";

/**
 * What the admin has typed against the record's fingerprint. `partial` is a correct beginning, so the field does not call a half-typed
 * value wrong; `mismatch` is a character that differs. Only `match` lets the confirmation through. A record without a fingerprint
 * never matches: there is nothing to compare.
 */
export function checkFingerprint(typed: string, record: string | undefined): FingerprintCheck {
  const want = normaliseFingerprint(record ?? "");
  const got = normaliseFingerprint(typed);
  if (got === "") return "empty";
  if (want === "") return "mismatch";
  if (got === want) return "match";
  return want.startsWith(got) ? "partial" : "mismatch";
}

/** A 64-digit fingerprint in eight groups of eight, which is easier to compare by eye. Anything else is shown as it is. */
export function groupFingerprint(fingerprint: string): string[] {
  const plain = normaliseFingerprint(fingerprint);
  return /^[0-9a-f]{64}$/.test(plain) ? (plain.match(/.{8}/g) ?? [plain]) : [fingerprint];
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
function looksLikeIpv6(v: string): boolean {
  if (!/^[0-9a-f:.]+$/i.test(v) || !v.includes(":")) return false;
  const halves = v.split("::");
  if (halves.length > 2) return false;
  const groups = halves.flatMap((half) => (half === "" ? [] : half.split(":")));
  // An embedded IPv4 closes the address and stands for two groups.
  const last = groups[groups.length - 1];
  const tail = last !== undefined && last.includes(".");
  if (tail && !IPV4.test(last)) return false;
  const hex = tail ? groups.slice(0, -1) : groups;
  if (!hex.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return false;
  const count = hex.length + (tail ? 2 : 0);
  return halves.length === 2 ? count <= 7 : count === 8;
}

/** The shape of an address, not its class: the route judges whether it is public and whether the pair is valid (4.2 step 4). */
export function looksLikeIp(text: string): boolean {
  const v = text.trim();
  return IPV4.test(v) || looksLikeIpv6(v);
}

/** The conditions of F3 (shared contract 8a.6) the hub can name as unmet. A name this list does not know is shown by its own name. */
export const F3_CONDITIONS = ["hub_fit", "peer_view", "stable_period", "flapping", "held"] as const;
export type F3Condition = (typeof F3_CONDITIONS)[number];
export const f3ConditionKey = (name: string): F3Condition | "other" => ((F3_CONDITIONS as readonly string[]).includes(name) ? (name as F3Condition) : "other");

export const DRAIN_STATES = ["none", "draining", "done"] as const;
export type DrainKey = (typeof DRAIN_STATES)[number];
export const drainKey = (state: string): DrainKey | "other" => ((DRAIN_STATES as readonly string[]).includes(state) ? (state as DrainKey) : "other");

export type NodeAction = "approve" | "revoke" | "remove" | "hold" | "release" | "force_failback" | "addresses";

/**
 * What the page offers for a node, from what the database holds (9.2). The route decides in the end (`node_state`, `node_paired`): this
 * keeps a button off a node it cannot apply to, and `remove` stays offered for a paired node only as a disabled button with its reason.
 */
export function nodeActions(node: Pick<NodeView, "status" | "dns_hold" | "dns_withdrawn">): Record<NodeAction, boolean> {
  const active = node.status === "active";
  return {
    approve: node.status === "pending",
    revoke: active,
    remove: true,
    // A revoked node can be held and released (SC 8a.9: the hold is the remedy until the revocation reaches the nodes); a force failback
    // would return it to service, which no row but F0 does for a revoked node, so it stays active-only.
    hold: (active || node.status === "revoked") && !node.dns_hold,
    release: (active || node.status === "revoked") && node.dns_hold,
    force_failback: active && node.dns_withdrawn,
    addresses: node.status !== "revoked",
  };
}

/** `true` when the node is in a pair and so cannot be removed (`node_paired`). The table check (`node_in_table`) is the route's. */
export const removeBlockedByPair = (node: Pick<NodeView, "pair_peer_id">): boolean => node.pair_peer_id !== undefined;

/** Reports are asked for from the start of a day, so the query key stays the same across renders and polls. */
export const REPORT_WINDOWS = [7, 30, 90] as const;
export type ReportWindow = (typeof REPORT_WINDOWS)[number];
export function reportsFrom(days: ReportWindow, now: number = Date.now()): string {
  const dayMs = 86_400_000;
  return new Date((Math.floor(now / dayMs) - days) * dayMs).toISOString();
}

/** When the install command stops working: the enrolment's own time, and whether it has passed. */
export const enrollmentOpen = (state: string, expiresAt: string, now: number = Date.now()): boolean =>
  (state === "issued" || state === "pending_approval") && Date.parse(expiresAt) > now;

/** The time before which a flapping node does not return by itself, when it is still in the future. */
export const flapUntilActive = (until: string | undefined, now: number = Date.now()): string | undefined => (until && Date.parse(until) > now ? until : undefined);

/** How many enrolments are waiting for their fingerprint to be compared, counting only those whose command has not run out. */
export const waitingEnrolments = (rows: readonly {state: string; expires_at: string}[], now: number = Date.now()): number =>
  rows.filter((e) => e.state === "pending_approval" && Date.parse(e.expires_at) > now).length;

/**
 * The node that already holds the DNS address a pending host asks for. No table holds two nodes with one `dns_ip` (SC 8a.7), and the approval
 * checks the table before it commits, so the approval of such a host is refused whatever slots are free; the page says so before it sends
 * (SC 8a.9, Replacement order). A pending row is not in a table, so only active and revoked nodes count.
 */
export function addressHolder(
  node: Pick<NodeView, "id" | "dns_advertised_ip">,
  others: readonly Pick<NodeView, "id" | "name" | "status" | "dns_advertised_ip">[] | undefined,
): string | undefined {
  const wanted = node.dns_advertised_ip?.trim().toLowerCase();
  if (!wanted || !others) return undefined;
  return others.find((n) => n.id !== node.id && n.status !== "pending" && n.dns_advertised_ip?.trim().toLowerCase() === wanted)?.name;
}
