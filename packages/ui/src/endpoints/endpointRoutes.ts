// The routes of an Endpoint (spec p3 10), in one place, so a link, a tab and the frame agree. Paths are without the locale and carry the
// Endpoint's id, never its name.

export const ENDPOINT_TABS = ["clients", "ips", "schedule"] as const;
export type EndpointTab = (typeof ENDPOINT_TABS)[number];

export const endpointsHref = "/endpoints";
export const endpointHref = (id: string, tab: EndpointTab = "clients"): string => `/endpoints/${id}/${tab}`;

/** The tab a path is in, or `null` outside any (`/endpoints/<id>` itself, which redirects to Clients). */
export function endpointTabOf(pathname: string): EndpointTab | null {
  const segment = /^\/endpoints\/[^/]+\/([^/]+)/.exec(pathname)?.[1];
  return (ENDPOINT_TABS.find((tab) => tab === segment) ?? null) as EndpointTab | null;
}

/** The id in `/endpoints/<id>/...`, or `null`. */
export function endpointIdOf(pathname: string): string | null {
  const id = /^\/endpoints\/([^/]+)/.exec(pathname)?.[1];
  return id && id !== "export" ? id : null;
}
