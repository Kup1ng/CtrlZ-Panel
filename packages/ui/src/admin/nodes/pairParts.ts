import {contactState, type NodeView} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import type {PairView} from "@ctrlz/api-client/admin/hooks/pairs.ts";

// p4-nodes 10.1, T-341. What the Pair page works out from the nodes and the pairs it was given, kept apart from the screens so that a
// unit test can drive every case. Nothing here asks the server: the server judges the table (`table_invalid`, `second_peer`, ...) and
// this is the part the page can say before the admin sends anything, with the reasons in words. The hub's own view of a node is not in
// NodeView yet, so "withdrawn" and "held" are the flags the database holds (`dns_withdrawn`, `dns_hold`), as the node page reads them.

export type NodeLike = Pick<NodeView, "id" | "name" | "status" | "dns_withdrawn" | "dns_hold" | "applied_seq_lag" | "dns_advertised_ip" | "proxy_advertised_ip" | "last_heartbeat_at">;

export const byIdMap = <T extends {id: string}>(rows: readonly T[]): Map<string, T> => new Map(rows.map((row) => [row.id, row]));

// ---- which node answers ----------------------------------------------------------------------------------------------------------

export type Advertised =
  | {kind: "primary"; node: NodeLike}
  | {kind: "fallback"; node: NodeLike}
  /** Both are withdrawn: nothing in the pair is advertised on purpose, and the page says so instead of naming one. */
  | {kind: "none"}
  /** A node of the pair is not in the list the page has (the list is paged, or the node was just removed). */
  | {kind: "unknown"};

/**
 * The node whose address the zone advertises for the pair: the primary, unless it is withdrawn and the fallback is not (SC 8a.1, 8a.6).
 * A held node is withdrawn too (a hold withdraws it, and the flag says so), so the held primary hands the answer to the fallback.
 */
export function advertisedNode(pair: Pick<PairView, "primary_node_id" | "fallback_node_id">, nodes: ReadonlyMap<string, NodeLike>): Advertised {
  const primary = nodes.get(pair.primary_node_id);
  const fallback = nodes.get(pair.fallback_node_id);
  if (!primary || !fallback) return {kind: "unknown"};
  if (!primary.dns_withdrawn) return {kind: "primary", node: primary};
  if (!fallback.dns_withdrawn) return {kind: "fallback", node: fallback};
  return {kind: "none"};
}

/**
 * The members of a pair that are revoked. A revocation changes only the node's status (the route does not touch the pair, SC 8a.9), so the
 * revoked node stays in the pair, and keeps being advertised when it is the primary, until the admin replaces it (PG-r2-6).
 */
export function revokedMembers(pair: Pick<PairView, "primary_node_id" | "fallback_node_id">, nodes: ReadonlyMap<string, NodeLike>): NodeLike[] {
  return [pair.primary_node_id, pair.fallback_node_id].map((id) => nodes.get(id)).filter((n): n is NodeLike => n !== undefined && n.status === "revoked");
}

/**
 * The state a node page reports for the node's own part in the answer. Only one node of a pair is advertised, so a node that is not
 * withdrawn is advertised only when the pair's rule above names it: its standby peer is "standby", not advertised. A node in no pair is
 * not part of an Endpoint's answer, and a node whose pair the page has not loaded is "unknown" rather than guessed (PG-r1-3).
 */
export type AnswerState = "held" | "withdrawn" | "advertised" | "standby" | "unpaired" | "unknown";

export function answerState(
  node: NodeLike & {pair_peer_id?: string | null | undefined},
  pairs: readonly Pick<PairView, "primary_node_id" | "fallback_node_id">[] | undefined,
  others: readonly NodeLike[] | undefined,
): AnswerState {
  if (node.dns_hold) return "held";
  if (node.dns_withdrawn) return "withdrawn";
  if (!node.pair_peer_id) return "unpaired";
  if (!pairs || !others) return "unknown";
  const pair = pairs.find((p) => p.primary_node_id === node.id || p.fallback_node_id === node.id);
  if (!pair) return "unknown";
  // The node page is fresher than the list, so the node itself replaces its own row in it.
  const byId = byIdMap([...others.filter((n) => n.id !== node.id), node]);
  const advertised = advertisedNode(pair, byId);
  if (advertised.kind === "unknown") return "unknown";
  return advertised.kind !== "none" && advertised.node.id === node.id ? "advertised" : "standby";
}

// ---- who can be chosen -----------------------------------------------------------------------------------------------------------

export type NotOffered = "pending" | "revoked" | "inPair";
export type Offer = {node: NodeLike; reason: NotOffered | null; /** The name of the peer, for `inPair`. */ peerName?: string};

/**
 * Every node with the reason it cannot be chosen, or null when it can: only an active node, and only one that no other pair holds
 * (the `node_pairs_one_peer` trigger, `second_peer`). The pair being edited does not count against its own two nodes.
 */
export function offers(nodes: readonly NodeLike[], pairs: readonly PairView[], editing?: PairView): Offer[] {
  const byId = byIdMap(nodes);
  return nodes.map((node) => {
    if (node.status === "pending") return {node, reason: "pending" as const};
    if (node.status === "revoked") return {node, reason: "revoked" as const};
    const holder = pairs.find((p) => p.id !== editing?.id && (p.primary_node_id === node.id || p.fallback_node_id === node.id));
    if (holder) {
      const peer = byId.get(holder.primary_node_id === node.id ? holder.fallback_node_id : holder.primary_node_id);
      return {node, reason: "inPair" as const, ...(peer ? {peerName: peer.name} : {})};
    }
    return {node, reason: null};
  });
}

// ---- what a change does ----------------------------------------------------------------------------------------------------------

export type Change = {primaryId: string | null; fallbackId: string | null; editing?: PairView | undefined};

export type ChangeKind =
  /** A pair that is made. */
  | "create"
  /** The same two nodes with the roles exchanged: no peer changes, so no row of F0 runs (SC 8a.9). */
  | "swap"
  /** One or both nodes are other than the pair held. */
  | "replace"
  /** Nothing differs from what the pair holds. */
  | "same";

export function changeKind({primaryId, fallbackId, editing}: Change): ChangeKind {
  if (!editing) return "create";
  if (primaryId === editing.primary_node_id && fallbackId === editing.fallback_node_id) return "same";
  if (primaryId === editing.fallback_node_id && fallbackId === editing.primary_node_id) return "swap";
  return "replace";
}

/** A node that may be behind on the log: it has not been heard from, is late, or has not applied the head. The words differ, the advice does not. */
export const maybeBehind = (node: NodeLike, now: number = Date.now()): boolean => node.applied_seq_lag > 0 || contactState(node, now) !== "recent";

export type WarningId = "primaryWithdrawn" | "primaryHeld" | "fallbackHeld" | "fallbackNew" | "bothWithdrawn" | "twoNew" | "behind" | "swap" | "heldFallbackFirst";

export type PairWarning = {id: WarningId; /** The names the sentence is about. */ names: string[]};

/**
 * Every warning of SC 8a.9 ("F0 reads no tracker") that applies to the change in front of the admin, in the order the sentences read.
 * The page also says all of them at rest (T-341); this is the part that names the nodes of this change.
 */
export function pairWarnings(change: Change, nodes: readonly NodeLike[], pairs: readonly PairView[], now: number = Date.now()): PairWarning[] {
  const byId = byIdMap(nodes);
  const primary = change.primaryId ? byId.get(change.primaryId) : undefined;
  const fallback = change.fallbackId ? byId.get(change.fallbackId) : undefined;
  if (!primary || !fallback || primary.id === fallback.id) return [];
  const kind = changeKind(change);
  if (kind === "same") return [];
  const inAnyOtherPair = (n: NodeLike) => pairs.some((p) => p.id !== change.editing?.id && (p.primary_node_id === n.id || p.fallback_node_id === n.id));
  // "New" is a node that has no peer today: in no pair, and not one of the two the pair being edited holds now.
  const wasHere = (n: NodeLike) => change.editing !== undefined && (change.editing.primary_node_id === n.id || change.editing.fallback_node_id === n.id);
  const isNew = (n: NodeLike) => !wasHere(n) && !inAnyOtherPair(n);

  const out: PairWarning[] = [];
  const add = (id: WarningId, names: string[]) => out.push({id, names});

  if (kind === "swap") add("swap", [primary.name, fallback.name]);
  // A primary with no peer today is withdrawn by the change itself (SC 8a.9, F0 step 1): it answers nothing until F3 returns it, and the
  // answer goes at once to the fallback. The database flag cannot say so yet, so the page counts it here. Two new nodes have their own
  // sentence (twoNew), which already says to pair one at a time.
  const primaryNew = isNew(primary);
  const primaryOut = primary.dns_withdrawn || primaryNew;
  if (primary.dns_hold) add("primaryHeld", [primary.name]);
  else if (primary.dns_withdrawn || (primaryNew && !isNew(fallback))) add("primaryWithdrawn", [primary.name]);
  if (primaryOut && fallback.dns_withdrawn && !fallback.dns_hold) add("bothWithdrawn", [primary.name, fallback.name]);
  // A changed pair whose primary is withdrawn gives the answer to the fallback at once: a new fallback is the case the sentence names.
  if (primary.dns_withdrawn && isNew(fallback)) add("fallbackNew", [fallback.name]);
  if (primaryOut && fallback.dns_hold) add("fallbackHeld", [fallback.name]);
  if (isNew(primary) && isNew(fallback)) add("twoNew", [primary.name, fallback.name]);
  // Release or replace a held fallback before changing the primary it stands behind.
  if (kind === "replace" && change.editing) {
    const oldFallback = byId.get(change.editing.fallback_node_id);
    if (oldFallback?.dns_hold && change.primaryId !== change.editing.primary_node_id) add("heldFallbackFirst", [oldFallback.name]);
  }
  // The node that receives the answer is looked at too: the fallback when the primary is out, new or the one that stays.
  const behind = [primary, fallback].filter((n) => (isNew(n) || kind === "swap" || (primaryOut && n === fallback)) && maybeBehind(n, now));
  if (behind.length > 0) add("behind", behind.map((n) => n.name));
  return out;
}

// ---- what the page refuses before it sends ----------------------------------------------------------------------------------------

export type RefusalId = "same" | "sameNode" | "missing" | "duplicateAddress" | "mixedFamilies";
export type Refusal = {id: RefusalId; names: string[]};

const isV6 = (ip: string | undefined) => ip !== undefined && ip.includes(":");

/**
 * A change the page does not send, with the reason, so the admin is not told "table_invalid" for what the page can read in the two nodes
 * (T-341: a repeated address, two families in a pair). The rejected address classes are the server's to judge: a lab runs on private ranges,
 * and the page cannot tell which class the owner's network allows. The other rules (`second_peer`, `node_state`) are the choices the
 * selects already leave out, and the route says them if the page was stale.
 */
export function refusals(change: Change, nodes: readonly NodeLike[], pairs: readonly PairView[]): Refusal[] {
  if (!change.primaryId || !change.fallbackId) return [{id: "missing", names: []}];
  if (change.primaryId === change.fallbackId) return [{id: "sameNode", names: []}];
  const byId = byIdMap(nodes);
  const primary = byId.get(change.primaryId);
  const fallback = byId.get(change.fallbackId);
  if (!primary || !fallback) return [{id: "missing", names: []}];
  if (changeKind(change) === "same") return [{id: "same", names: []}];
  const out: Refusal[] = [];
  // A table holds no two nodes with one address (8a.7): the two nodes, and every node of another pair.
  const others = nodes.filter((n) => n.id !== primary.id && n.id !== fallback.id && pairs.some((p) => p.id !== change.editing?.id && (p.primary_node_id === n.id || p.fallback_node_id === n.id)));
  const inTable = [primary, fallback, ...others];
  const duplicated = new Set<string>();
  // Only the DNS address: the validator (`Build`) compares dns_ip alone, and the proxy address is only parsed (SC 8a.4, PG-r3-1).
  const seen = new Map<string, NodeLike>();
  for (const node of inTable) {
    const ip = node.dns_advertised_ip?.trim().toLowerCase();
    if (!ip) continue;
    const other = seen.get(ip);
    if (other) {
      duplicated.add(other.name);
      duplicated.add(node.name);
    } else seen.set(ip, node);
  }
  if (duplicated.size > 0) out.push({id: "duplicateAddress", names: [...duplicated]});
  if (isV6(primary.dns_advertised_ip) !== isV6(fallback.dns_advertised_ip)) out.push({id: "mixedFamilies", names: [primary.name, fallback.name]});
  return out;
}

// ---- the other changes ------------------------------------------------------------------------------------------------------------

/**
 * Switching the global pair to a pair that exists changes no peer, so no row of F0 runs and the answer moves at once to a node that may
 * be behind (SC 8a.9). The names are the nodes of the pair that would become global that may be behind.
 */
export function switchWarnings(target: Pick<PairView, "primary_node_id" | "fallback_node_id">, nodes: readonly NodeLike[], now: number = Date.now()): PairWarning[] {
  const byId = byIdMap(nodes);
  const both = [byId.get(target.primary_node_id), byId.get(target.fallback_node_id)].filter((n): n is NodeLike => n !== undefined);
  const out: PairWarning[] = [{id: "swap", names: both.map((n) => n.name)}];
  const behind = both.filter((n) => maybeBehind(n, now));
  if (behind.length > 0) out.push({id: "behind", names: behind.map((n) => n.name)});
  const held = both.filter((n) => n.dns_hold);
  if (held.length > 0) out.push({id: "primaryHeld", names: held.map((n) => n.name)});
  return out;
}

/** At four nodes every slot is held, a pending row's included, and the page then states the replacement order (SC 8a.9). */
export const noSlotFree = (nodes: readonly {id: string}[], limit: number): boolean => nodes.length >= limit;
