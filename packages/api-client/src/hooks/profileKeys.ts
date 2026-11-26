// The query keys of the profile family, in one file so that a hook of another resource can invalidate them without importing the
// hooks (which import this). A key part is a string or a number, never an object (queryKeys.test.ts), and no parameter is named like a
// secret. A list with filters carries the filters as one canonical string, `filterKey` of `./filterKey.ts`.

export const profileKeys = {
  all: ["profiles"] as const,
  list: ["profiles", "list"] as const,
  detail: (id: string) => ["profiles", "detail", id] as const,
  locations: (id: string, slugs: string) => ["profiles", "locations", id, slugs] as const,
  filters: (id: string) => ["profile-filters", id] as const,
  services: (id: string) => ["profile-services", id] as const,
  options: (id: string) => ["profile-options", id] as const,
  folders: (id: string) => ["profile-folders", id] as const,
  /** Every page of every filter of a profile's rules, the prefix an optimistic write and an invalidation use. */
  rulesOf: (id: string) => ["profile-rules", id] as const,
  rules: (id: string, filter: string) => ["profile-rules", id, filter] as const,
};

export const catalogKeys = {
  filters: ["catalog", "filters"] as const,
  services: ["catalog", "services"] as const,
  timezones: ["catalog", "timezones"] as const,
  endpointTypes: ["catalog", "endpoint-types"] as const,
};

export const jobKeys = {
  active: ["jobs", "active"] as const,
  one: (id: string) => ["jobs", "one", id] as const,
};

export const endpointKeys = {
  all: ["endpoints"] as const,
  /** The one-row read that gives the sidebar's counter and the checklist's facts (limit 1: only `by_type` and `by_status` are used). */
  count: ["endpoints", "count"] as const,
  list: (filter: string) => ["endpoints", "list", filter] as const,
  lists: ["endpoints", "list"] as const,
  detail: (id: string) => ["endpoints", "detail", id] as const,
  schedule: (id: string) => ["endpoints", "schedule", id] as const,
  groups: ["endpoint-groups"] as const,
  clients: (id: string, filter: string) => ["endpoint-clients", id, filter] as const,
  clientsOf: (id: string) => ["endpoint-clients", id] as const,
  ddns: (id: string) => ["endpoint-ddns", id] as const,
  authorized: (id: string, filter: string) => ["endpoint-authorized", id, filter] as const,
  authorizedOf: (id: string) => ["endpoint-authorized", id] as const,
  claims: (id: string) => ["endpoint-claims", id] as const,
  /** Every Resolver view of an Endpoint, or of all of them with no id: what setup shows, DoH token included. */
  resolversOf: (id?: string) => (id === undefined ? (["endpoint-resolvers"] as const) : (["endpoint-resolvers", id] as const)),
  /** The same for the generators, whose text carries the DoH token. */
  generatorsOf: (id?: string) => (id === undefined ? (["endpoint-generator"] as const) : (["endpoint-generator", id] as const)),
  resolvers: (id: string, client: string) => ["endpoint-resolvers", id, client] as const,
  generator: (id: string, generator: string, client: string) => ["endpoint-generator", id, generator, client] as const,
  shareLinks: (id: string) => ["endpoint-share-links", id] as const,
};

export const accountKeys = {
  limits: ["account", "limits"] as const,
  apiKeys: ["account", "api-keys"] as const,
};
