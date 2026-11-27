import {RESOLVER_PROTOCOLS, type ResolverView} from "@ctrlz/api-client/hooks/setup.ts";

// What the Resolvers page lists, from the Resolver view alone (spec p3 8.1, T-239, T-240, T-544). Kept apart from the components so a
// plain test holds the order: the primary first everywhere a list is given, the hostname stamp before the address stamps, and exactly the
// five protocols of D24 and D51.

export type StampProtocol = "doh" | "dot" | "doq";
export const STAMP_PROTOCOLS: readonly StampProtocol[] = ["doh", "dot", "doq"];

export type StampGroup = {
  protocol: StampProtocol;
  /** The stamp with the host name and no address (`bootstrap_ipi` inside it is the primary, then the fallback). Listed first. */
  hostname: string;
  /** The stamps with one node address each, the primary's first. Listed under "for apps that take several stamps". */
  addresses: {ip: string; stamp: string}[];
};

/** The index of an address in the view's order of nodes (DNS 1, DNS 2); unknown addresses go last and keep their order. */
function rank(view: ResolverView, ip: string): number {
  const order = [view.legacy?.dns1, view.legacy?.dns2];
  const at = order.indexOf(ip);
  return at === -1 ? order.length : at;
}

/** The stamps by protocol. A protocol the view has no stamp for is left out. */
export function stampGroups(view: ResolverView): StampGroup[] {
  const out: StampGroup[] = [];
  for (const protocol of STAMP_PROTOCOLS) {
    const entry = view.stamps?.[protocol];
    if (!entry) continue;
    const addresses = (entry.address_stamps ?? [])
      .map((item, index) => ({item, index}))
      .sort((a, b) => rank(view, a.item.ip) - rank(view, b.item.ip) || a.index - b.index)
      .map(({item}) => ({ip: item.ip, stamp: item.stamp}));
    out.push({protocol, hostname: entry.hostname_stamp, addresses});
  }
  return out;
}

/** Bootstrap IPs, the primary first. */
export function bootstrapList(view: ResolverView): string[] {
  return [...(view.bootstrap ?? [])]
    .map((ip, index) => ({ip, index}))
    .sort((a, b) => rank(view, a.ip) - rank(view, b.ip) || a.index - b.index)
    .map(({ip}) => ip);
}

/** The protocols to list: the five of the contract, in its order, and only those the view carries. Never one that is not in the list. */
export function listedProtocols(view: ResolverView): (typeof RESOLVER_PROTOCOLS)[number][] {
  return RESOLVER_PROTOCOLS.filter((p) => view.protocols.includes(p));
}

/** True when the view has what a page needs to show values (not ready has no host, no address and no stamp). */
export const hasValues = (view: ResolverView): boolean => view.ready && !!view.host && !!view.legacy;
