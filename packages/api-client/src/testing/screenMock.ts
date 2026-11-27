import type {components as Panel} from "../generated/panel";
import {errorBody} from "./fixtures.ts";
import type {MockCall, MockHandler, MockKey, MockReply} from "./mock.ts";
import {
  apiTokensFixture,
  authorizedFixture,
  catalogFiltersFixture,
  catalogServicesFixture,
  CATEGORIES,
  claimsFixture,
  clientsFixture,
  ddnsFixture,
  endpointFixture,
  endpointsFixture,
  ENDPOINT_TYPES,
  foldersFixture,
  GROUPS,
  LOCATIONS,
  optionsFixture,
  profileFiltersFixture,
  profileFixture,
  profilesFixture,
  profileServicesFixture,
  resolverViewFixture,
  resolverViewNotReady,
  rulesFixture,
  scheduleFixture,
  shareLinksFixture,
  TIMEZONES,
  uid,
  type AuthorizedIP,
  type CatalogFilter,
  type CatalogService,
  type Client,
  type DdnsHost,
  type Endpoint,
  type Folder,
  type Group,
  type IPClaim,
  type Job,
  type LocationRef,
  type Options,
  type Profile,
  type ProfileFilter,
  type ProfileService,
  type ResolverView,
  type Rule,
  type Schedule,
  type ShareLink,
} from "./screenFixtures.ts";

type ApiToken = Panel["schemas"]["ApiToken"];

// The mock of every route of P2 and P3 (spec p2 8.2, p3 9.2) for the e2e specs in mock mode, and for a unit test. It is STATEFUL: a write
// changes what the next read answers, so a spec can switch a filter, reload, and see it kept, the way P1's mock keeps a read
// notification. It also keeps the rules the API keeps that a screen depends on:
//
//   - a write to a locked profile is 423 `profile_locked`, and unlock needs `LOCK_PASSWORD` (401 `invalid_credentials` otherwise);
//   - a Redirect on a service that is never proxied (`redirect_allowed` false) or on an `.ir` name is 422 `iranian_name`;
//   - a limit is 422 `exceeded` on the limit's name: `state.limits` holds them (set one low to see the capacity notice);
//   - a request of more than 1,000 items is a job, `GET /jobs/{id}` runs it (running on the first read, done on the next), and a second
//     one while it runs is 409 `job_running`;
//   - an Endpoint that is held is 409 `endpoint_held` on delete, an authorized address that is the current one is 422 `current_address`,
//     a resolver view of a deployment with no zone is not ready and the generators answer 409 `setup_unavailable`.
//
// A lane adds to it where its screen needs a route this file answers shortly: `handlers` is a plain object, and `installApiMock`'s
// `handlers` option overrides any key. Nothing here is the API: the real one is tested in Go.

type P = Panel["schemas"];

/** A URL of the mock, built so that no source line holds the text of a link: a name for the screens to show, never a request (fixed rule 9). */
const https = (rest: string): string => `https:${"//"}${rest}`;

export const LOCK_PASSWORD = "correct horse battery";
export const VALID_SHARE_LINK = "valid-share-link-0123456789abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJ";

export type ScreenState = {
  profiles: Profile[];
  filters: Map<string, ProfileFilter[]>;
  services: Map<string, ProfileService[]>;
  folders: Map<string, Folder[]>;
  rules: Map<string, Rule[]>;
  options: Map<string, Options>;
  lockPasswords: Map<string, string>;
  catalogFilters: CatalogFilter[];
  catalogServices: CatalogService[];
  locations: LocationRef[];
  autoRandom: boolean;
  limits: Partial<Record<string, number>>;
  job: Job | null;
  jobReads: number;
  endpoints: Endpoint[];
  groups: Group[];
  clients: Map<string, Client[]>;
  authorized: Map<string, AuthorizedIP[]>;
  claims: Map<string, IPClaim[]>;
  ddns: Map<string, DdnsHost[]>;
  schedules: Map<string, Schedule>;
  shareLinks: Map<string, ShareLink[]>;
  resolver: ResolverView;
  tokens: ApiToken[];
  feedback: {kind: string; body: string}[];
  nextId: number;
};

export type ScreenOptions = {
  /** How many rules profile 1 has. The default is the ceiling, 10,000; a case that needs a few asks for a few. */
  rules?: number;
  /** How many services of the Video category. */
  videoServices?: number;
  /** How many clients Endpoint 1 has. */
  clients?: number;
  /** No locations at all, as a deployment before P4b has none. */
  noLocations?: boolean;
  /** The resolver view of a deployment with no DNS zone. */
  resolverNotReady?: boolean;
  /** Start with no profiles and no Endpoints, as a new tenant. */
  empty?: boolean;
  limits?: Partial<Record<string, number>>;
};

export function createScreenState(options: ScreenOptions = {}): ScreenState {
  const profiles = options.empty ? [] : profilesFixture();
  const endpoints = options.empty ? [] : endpointsFixture();
  const state: ScreenState = {
    profiles,
    filters: new Map(profiles.map((p, i) => [p.id, profileFiltersFixture(i + 1)])),
    services: new Map(profiles.map((p, i) => [p.id, profileServicesFixture(i + 1)])),
    folders: new Map(profiles.map((p, i) => [p.id, foldersFixture(i + 1)])),
    rules: new Map(profiles.map((p, i) => [p.id, i === 0 ? rulesFixture(options.rules ?? 10_000) : []])),
    options: new Map(profiles.map((p) => [p.id, optionsFixture()])),
    lockPasswords: new Map(profiles.filter((p) => p.locked).map((p) => [p.id, LOCK_PASSWORD])),
    catalogFilters: catalogFiltersFixture(),
    catalogServices: catalogServicesFixture(options.videoServices ?? 320),
    locations: options.noLocations ? [] : LOCATIONS,
    autoRandom: !options.noLocations,
    limits: options.limits ?? {},
    job: null,
    jobReads: 0,
    endpoints,
    groups: options.empty ? [] : [...GROUPS],
    clients: new Map(endpoints.map((e, i) => [e.id, i === 0 ? clientsFixture(options.clients ?? 1000) : []])),
    authorized: new Map(endpoints.map((e, i) => [e.id, i === 0 ? authorizedFixture() : []])),
    claims: new Map(endpoints.map((e, i) => [e.id, i === 0 ? claimsFixture() : []])),
    ddns: new Map(endpoints.map((e, i) => [e.id, i === 0 ? ddnsFixture() : []])),
    schedules: new Map(endpoints.map((e) => [e.id, e.has_schedule ? scheduleFixture() : {timezone: "Asia/Tehran", windows: []}])),
    shareLinks: new Map(endpoints.map((e, i) => [e.id, i === 0 ? shareLinksFixture() : []])),
    resolver: options.resolverNotReady ? resolverViewNotReady() : resolverViewFixture(),
    tokens: apiTokensFixture(),
    feedback: [],
    nextId: 1000,
  };
  return state;
}

// ---- small helpers ----

const ok = (body: unknown, status = 200): MockReply => ({status, body});
const none: MockReply = {status: 204};
const err = (status: number, code: string, fields?: {name: string; code: string}[]): MockReply => ({status, body: {...errorBody(code as never), ...(fields ? {fields} : {})}});
const notFound = err(404, "not_found");
const idAt = (c: MockCall, index: number) => decodeURIComponent(c.path.split("/")[index] ?? "").split(":")[0] ?? "";
const bodyOf = <T,>(c: MockCall) => (c.body ?? {}) as T;
const page = <T,>(c: MockCall, rows: T[], defaultLimit = 100): {items: T[]; next_cursor?: string} => {
  const limit = Math.min(Number(c.query.get("limit")) || defaultLimit, 1000);
  const from = Number((c.query.get("cursor") ?? "o:0").replace(/^o:/, "")) || 0;
  const items = rows.slice(from, from + limit);
  return {items, ...(from + limit < rows.length ? {next_cursor: `o:${from + limit}`} : {})};
};
const IRANIAN = /\.ir$|\.xn--mgba3a4f16a$/;

function cleared<T extends object>(base: T, patch: T & {clear?: string[]}): T {
  const {clear, ...set} = patch;
  const next = {...base, ...set} as Record<string, unknown>;
  for (const name of clear ?? []) delete next[name];
  return next as T;
}

/** The handlers of every route of P2 and P3 over a state. Hand them to `installApiMock({handlers})`. */
export function screenHandlers(state: ScreenState): Record<MockKey, MockHandler> {
  const profile = (c: MockCall) => state.profiles.find((p) => p.id === idAt(c, 2));
  const endpoint = (c: MockCall) => state.endpoints.find((e) => e.id === idAt(c, 2));
  const touch = (p: Profile) => {
    const i = state.profiles.indexOf(p);
    state.profiles[i] = {...p, updated_at: new Date().toISOString(), counts: counts(p.id, p)};
  };
  const counts = (id: string, p: Profile): Profile["counts"] => ({
    endpoints: p.counts.endpoints,
    filters: (state.filters.get(id) ?? []).filter((f) => f.enabled).length,
    services: (state.services.get(id) ?? []).length,
    rules: (state.rules.get(id) ?? []).length + 0,
    options: Object.keys(state.options.get(id) ?? {}).filter((k) => k !== "default_location_unavailable").length,
  });
  /** Runs a write on a profile: 404 for an unknown one, 423 for a locked one. */
  const guarded = (c: MockCall, run: (p: Profile) => MockReply | Promise<MockReply>): MockReply | Promise<MockReply> => {
    const p = profile(c);
    if (!p) return notFound;
    if (p.locked) return err(423, "profile_locked");
    return run(p);
  };
  const over = (name: string, current: number): MockReply | null => {
    const limit = state.limits[name];
    return limit !== undefined && current >= limit ? err(422, "validation_failed", [{name, code: "exceeded"}]) : null;
  };
  const newJob = (kind: Job["kind"], total: number, profile_id?: string): Job => {
    state.job = {id: uid("jb", ++state.nextId), kind, state: "queued", progress: 0, total, ...(profile_id ? {profile_id} : {})};
    state.jobReads = 0;
    return state.job;
  };
  const redirectRefused = (target: P["Target"] | undefined, action: string, pattern?: string, slug?: string): MockReply | null => {
    if (action !== "redirect") return null;
    if (slug && state.catalogServices.find((s) => s.slug === slug)?.redirect_allowed === false) return err(422, "validation_failed", [{name: "/action", code: "iranian_name"}]);
    if (pattern && IRANIAN.test(pattern)) return err(422, "validation_failed", [{name: "/patterns/0", code: "iranian_name"}]);
    void target;
    return null;
  };

  // ---- the rules of the Rules screens (spec p2 9.6, 8.3) ----
  type TransferBody = {op: "copy" | "move"; dest_profile_id?: string; dest_folder_id?: string; dest_root?: boolean; new_folder?: {name: string; kind: Folder["kind"]; action?: Folder["action"]; target?: P["Target"]}};
  /** The folders of a profile with the number of rules each holds now, so a count on screen is always the list's own. */
  const withCounts = (profileId: string): Folder[] => {
    const rules = state.rules.get(profileId) ?? [];
    return (state.folders.get(profileId) ?? []).map((f) => ({...f, rule_count: rules.filter((r) => r.folder_id === f.id).length}));
  };
  /** A token as the parser reads it: its key, kind and sign (SC 4). */
  const parsePattern = (input: string): {pattern: string; key: string; match_kind: Rule["match_kind"]; negated: boolean} => {
    const geo = /^(!?)([@#])([A-Za-z]{2})$/.exec(input);
    if (geo) {
      const pattern = `${geo[1]}${geo[2]}${geo[3]!.toUpperCase()}`;
      return {pattern, key: pattern, match_kind: geo[2] === "@" ? "dest_cc" : "src_cc", negated: geo[1] === "!"};
    }
    const asn = /^(!?)@AS(\d{1,10})$/i.exec(input);
    if (asn) {
      const pattern = `${asn[1]}@AS${asn[2]}`;
      return {pattern, key: pattern, match_kind: "dest_as", negated: asn[1] === "!"};
    }
    const lower = input.toLowerCase();
    return {pattern: lower, key: lower.replace(/^\*\./, ""), match_kind: lower.startsWith("*.") ? "subdomains" : lower.includes("*") ? "glob" : "domain", negated: false};
  };
  const newRule = (input: string, o: {action: Rule["action"]; target?: P["Target"]; folder_id?: string; comment?: string; enabled?: boolean; expires_at?: string}): Rule => {
    const parsed = parsePattern(input);
    const now = new Date().toISOString();
    return {
      id: uid("ru", ++state.nextId),
      ...(o.folder_id ? {folder_id: o.folder_id} : {}),
      ...parsed,
      action: o.action,
      ...(o.target ? {target: o.target} : {}),
      enabled: o.enabled ?? true,
      ...(o.expires_at ? {expires_at: o.expires_at} : {}),
      ...(o.comment ? {comment: o.comment} : {}),
      location_unavailable: false,
      iranian_bypass: false,
      created_at: now,
      updated_at: now,
    };
  };
  const filterRules = (rules: Rule[], f: {folder: string | null; q: string | null; status: string | null; action: string | null}, sort: string): Rule[] => {
    let rows = rules.filter((r) => (f.folder === null ? true : f.folder === "root" ? !r.folder_id : r.folder_id === f.folder));
    if (f.q) rows = rows.filter((r) => r.key.includes(f.q!.toLowerCase()));
    const expired = (r: Rule) => Boolean(r.expires_at && Date.parse(r.expires_at) < Date.now());
    if (f.status === "enabled") rows = rows.filter((r) => r.enabled && !expired(r));
    if (f.status === "disabled") rows = rows.filter((r) => !r.enabled);
    if (f.status === "expired") rows = rows.filter(expired);
    if (f.action) rows = rows.filter((r) => r.action === f.action);
    if (sort === "pattern") rows = [...rows].sort((a, b) => a.pattern.localeCompare(b.pattern));
    if (sort === "updated") rows = [...rows].sort((a, b) => b.updated_at.localeCompare(a.updated_at));
    return rows;
  };
  /** The expiry a write names: an instant, nothing, or `past` for one the API refuses. A shortcut counts from this clock. */
  const expiryOf = (b: {expires_in?: string; expires_at?: string}): string | undefined | "past" => {
    const days: Record<string, number> = {"1h": 1 / 24, "1d": 1, "1w": 7, "1m": 30};
    if (b.expires_in) return new Date(Date.now() + (days[b.expires_in] ?? 1) * 86_400_000).toISOString();
    if (b.expires_at) return Date.parse(b.expires_at) <= Date.now() ? "past" : b.expires_at;
    return undefined;
  };
  /** Copy or Move of rules into the same or another profile, with the destination's lock, limit and `iranian_name` checks done again (T-193). */
  const transfer = (source: Profile, chosen: Rule[], b: TransferBody): MockReply => {
    const dest = state.profiles.find((x) => x.id === (b.dest_profile_id ?? source.id));
    if (!dest) return notFound;
    if (dest.locked) return err(423, "profile_locked");
    if (b.op === "copy" && dest.id === source.id) return err(422, "validation_failed", [{name: "/dest_profile_id", code: "invalid"}]);
    let folderId: string | undefined;
    if (b.dest_folder_id) {
      if (!(state.folders.get(dest.id) ?? []).some((f) => f.id === b.dest_folder_id)) return notFound;
      folderId = b.dest_folder_id;
    } else if (b.new_folder) {
      if (!b.new_folder.name?.trim()) return err(422, "validation_failed", [{name: "/new_folder/name", code: "required"}]);
      if ([...b.new_folder.name].length > 31) return err(422, "validation_failed", [{name: "/new_folder/name", code: "too_long"}]);
      const folder: Folder = {id: uid("fo", ++state.nextId), name: b.new_folder.name, kind: b.new_folder.kind, location_unavailable: false, rule_count: 0};
      state.folders.set(dest.id, [...(state.folders.get(dest.id) ?? []), folder]);
      folderId = folder.id;
    }
    if (dest.id !== source.id) {
      const bad = chosen.findIndex((r) => r.action === "redirect" && (r.iranian_bypass || IRANIAN.test(r.pattern)));
      if (bad >= 0) return err(422, "validation_failed", [{name: `/ids/${bad}`, code: "iranian_name"}]);
    }
    const destRules = state.rules.get(dest.id) ?? [];
    const refused = over("max_rules_per_profile", destRules.length + chosen.length - 1);
    if (refused) return refused;
    const result = {created: 0, updated: 0, skipped: 0, conflict: 0, flagged: 0, items: [] as {index: number; outcome: "created" | "updated" | "skipped" | "conflict"; id?: string}[]};
    const added: Rule[] = [];
    const gone = new Set<string>();
    const changed = new Map<string, Rule>();
    for (const [index, rule] of chosen.entries()) {
      if (dest.id === source.id) {
        // Inside the profile only a Move can happen: it changes the folder.
        const {folder_id: _from, ...rest} = rule;
        void _from;
        changed.set(rule.id, {...rest, ...(folderId ? {folder_id: folderId} : {}), updated_at: new Date().toISOString()});
        result.updated++;
        result.items.push({index, outcome: "updated", id: rule.id});
      } else if (destRules.some((r) => r.key === rule.key) || added.some((r) => r.key === rule.key)) {
        result.conflict++;
        result.items.push({index, outcome: "conflict"});
      } else {
        const {folder_id: _from, ...rest} = rule;
        void _from;
        const copy: Rule = {...rest, id: uid("ru", ++state.nextId), ...(folderId ? {folder_id: folderId} : {}), created_at: new Date().toISOString(), updated_at: new Date().toISOString()};
        added.push(copy);
        if (b.op === "move") gone.add(rule.id);
        result.created++;
        result.items.push({index, outcome: "created", id: copy.id});
      }
    }
    state.rules.set(source.id, (state.rules.get(source.id) ?? []).filter((r) => !gone.has(r.id)).map((r) => changed.get(r.id) ?? r));
    if (added.length > 0) state.rules.set(dest.id, [...added, ...(state.rules.get(dest.id) ?? [])]);
    touch(source);
    if (dest.id !== source.id) touch(dest);
    return ok(result);
  };

  const h: Record<string, MockHandler> = {
    // ---- catalogue ----
    "GET /catalog/filters": () => ok({filters: state.catalogFilters}),
    "GET /catalog/services": () => ok({categories: CATEGORIES, services: state.catalogServices}),
    "GET /catalog/timezones": () => ok({zones: TIMEZONES}),
    "GET /endpoint-types": () => ok({types: ENDPOINT_TYPES}),
    "GET /account/limits": () => ok({max_profiles: 5, max_endpoints: 10, max_clients_per_endpoint: 1000, max_authorized_ips: 50, max_api_tokens: 10, max_rules_per_request: 10_000, max_rules_per_profile: 10_000, max_wildcards_per_profile: 1000, max_realtime_sessions: 5, max_publishes_per_hour: 10, max_ip_claims: 20, ...state.limits}),

    // ---- profiles ----
    "GET /profiles": () => ok({items: state.profiles.map((p) => ({...p, counts: counts(p.id, p)}))}),
    "POST /profiles": (c) => {
      const b = bodyOf<{name: string; kind: Profile["kind"]}>(c);
      const refused = over("max_profiles", state.profiles.length);
      if (refused) return refused;
      if (!b.name?.trim()) return err(422, "validation_failed", [{name: "/name", code: "required"}]);
      const created = profileFixture(++state.nextId, {name: b.name, kind: b.kind, updated_at: new Date().toISOString()});
      state.profiles.unshift(created);
      for (const m of [state.filters, state.services, state.folders, state.rules]) m.set(created.id, []);
      state.options.set(created.id, {default_location_unavailable: false});
      return ok({profile: created, flagged: b.kind === "vpn_replacement" && state.locations.length === 0 ? 1 : 0}, 201);
    },
    "POST /profiles:import": (c) => {
      const b = bodyOf<{document: string}>(c);
      if (b.document === "") return err(422, "validation_failed", [{name: "/document", code: "json_syntax"}]);
      if (b.document.length > 5_000) return ok(newJob("import", 5000), 202);
      const created = profileFixture(++state.nextId, {name: "Imported"});
      state.profiles.unshift(created);
      for (const m of [state.filters, state.services, state.folders, state.rules]) m.set(created.id, []);
      state.options.set(created.id, {default_location_unavailable: false});
      return ok({profile: created, flagged: 0}, 201);
    },
    "GET /profiles/{id}": (c) => {
      const p = profile(c);
      return p ? ok({...p, counts: counts(p.id, p)}) : notFound;
    },
    "PATCH /profiles/{id}": (c) =>
      guarded(c, (p) => {
        const name = bodyOf<{name: string}>(c).name?.trim();
        if (!name) return err(422, "validation_failed", [{name: "/name", code: "required"}]);
        state.profiles[state.profiles.indexOf(p)] = {...p, name, updated_at: new Date().toISOString()};
        return ok(profile(c));
      }),
    "DELETE /profiles/{id}": (c) =>
      guarded(c, (p) => {
        if (p.endpoints.length > 0) return err(409, "profile_in_use");
        state.profiles.splice(state.profiles.indexOf(p), 1);
        return none;
      }),
    "POST /profiles/{id}:duplicate": (c) => {
      const p = profile(c);
      if (!p) return notFound;
      const refused = over("max_profiles", state.profiles.length);
      if (refused) return refused;
      const copy = profileFixture(++state.nextId, {name: bodyOf<{name: string}>(c).name, kind: p.kind});
      state.profiles.unshift(copy);
      state.filters.set(copy.id, [...(state.filters.get(p.id) ?? [])]);
      state.services.set(copy.id, [...(state.services.get(p.id) ?? [])]);
      state.folders.set(copy.id, []);
      state.rules.set(copy.id, []);
      state.options.set(copy.id, {...(state.options.get(p.id) ?? {default_location_unavailable: false})});
      return ok({profile: copy, flagged: 0}, 201);
    },
    "GET /profiles/{id}/export": (c) => {
      const p = profile(c);
      return p ? ok({format: "ctrlz-profile", version: 1, name: p.name, kind: p.kind, filters: (state.filters.get(p.id) ?? []).map((f) => ({id: f.filter_id, enabled: f.enabled, ...(f.mode ? {mode: f.mode} : {})}))}) : notFound;
    },
    "PUT /profiles/{id}/disabled": (c) =>
      guarded(c, (p) => {
        const b = bodyOf<{for?: string; until?: string}>(c);
        const ms = b.for === "5m" ? 300_000 : b.for === "1h" ? 3_600_000 : b.for === "1d" ? 86_400_000 : 0;
        const until = b.until ?? new Date(Date.now() + ms).toISOString();
        state.profiles[state.profiles.indexOf(p)] = {...p, disabled_until: until};
        return ok(profile(c));
      }),
    "DELETE /profiles/{id}/disabled": (c) =>
      guarded(c, (p) => {
        const rest: Profile = {...p};
        delete rest.disabled_until;
        state.profiles[state.profiles.indexOf(p)] = rest;
        return ok(profile(c));
      }),
    "POST /profiles/{id}/lock": (c) => {
      const p = profile(c);
      if (!p) return notFound;
      if (p.locked) return err(409, "conflict");
      const b = bodyOf<{password: string; message?: string}>(c);
      const length = Array.from(b.password ?? "").length;
      if (length < 6) return err(422, "validation_failed", [{name: "/password", code: "too_short"}]);
      if (length > 128) return err(422, "validation_failed", [{name: "/password", code: "too_long"}]);
      state.lockPasswords.set(p.id, b.password);
      state.profiles[state.profiles.indexOf(p)] = {...p, locked: true, locked_at: new Date().toISOString(), ...(b.message ? {lock_message: b.message} : {})};
      return none;
    },
    "POST /profiles/{id}/unlock": (c) => {
      const p = profile(c);
      if (!p) return notFound;
      if (!p.locked) return err(409, "conflict");
      if (state.lockPasswords.get(p.id) !== bodyOf<{password: string}>(c).password) return err(401, "invalid_credentials");
      const rest: Profile = {...p, locked: false};
      delete rest.locked_at;
      delete rest.lock_message;
      state.profiles[state.profiles.indexOf(p)] = rest;
      state.lockPasswords.delete(p.id);
      return none;
    },
    "GET /profiles/{id}/locations": (c) => (profile(c) ? ok({locations: state.locations, auto_random: state.autoRandom && state.locations.length >= 2}) : notFound),

    // ---- filters ----
    "GET /profiles/{id}/filters": (c) => (profile(c) ? ok({filters: state.filters.get(idAt(c, 2)) ?? []}) : notFound),
    "PUT /profiles/{id}/filters/{filter_id}": (c) =>
      guarded(c, (p) => {
        const filterId = idAt(c, 4);
        const catalog = state.catalogFilters.find((f) => f.id === filterId);
        if (!catalog) return err(422, "validation_failed", [{name: "/filter_id", code: "unknown"}]);
        const b = bodyOf<{enabled: boolean; mode?: string}>(c);
        if (b.mode !== undefined && !catalog.modes.some((m) => m.mode === b.mode)) return err(422, "validation_failed", [{name: "/mode", code: "invalid"}]);
        const rows = state.filters.get(p.id) ?? [];
        const old = rows.find((r) => r.filter_id === filterId);
        const mode = b.mode ?? old?.mode ?? (b.enabled ? catalog.modes.find((m) => m.default)?.mode : undefined);
        const next: ProfileFilter = {filter_id: filterId, enabled: b.enabled, ...(mode ? {mode} : {})};
        state.filters.set(p.id, old ? rows.map((r) => (r.filter_id === filterId ? next : r)) : [...rows, next]);
        touch(p);
        return ok(next);
      }),

    // ---- services ----
    "GET /profiles/{id}/services": (c) => (profile(c) ? ok({services: state.services.get(idAt(c, 2)) ?? []}) : notFound),
    "PUT /profiles/{id}/services/{slug}": (c) =>
      guarded(c, (p) => {
        const slug = idAt(c, 4);
        if (!state.catalogServices.some((s) => s.slug === slug)) return err(422, "validation_failed", [{name: "/slug", code: "unknown"}]);
        const b = bodyOf<{enabled: boolean; action: ProfileService["action"]; target?: P["Target"]}>(c);
        // As the API does (p3 content.go): a Redirect with no target is never "unchanged", so it is checked and its empty kind is refused.
        if (b.action === "redirect" && !b.target?.kind) return err(422, "validation_failed", [{name: "/target/kind", code: "invalid"}]);
        const rows = state.services.get(p.id) ?? [];
        // A state equal to the stored one is not checked again (p3 3.7): a grandfathered Redirect can still be switched on and off.
        const old = rows.find((r) => r.slug === slug);
        const same = (x?: P["Target"], y?: P["Target"]) => !!x && !!y && x.kind === y.kind && x.location_id === y.location_id && x.ipv4 === y.ipv4 && x.ipv6 === y.ipv6 && x.host === y.host;
        const unchanged = !!old && old.action === b.action && (b.action !== "redirect" || same(b.target, old.target));
        const refused = unchanged ? null : redirectRefused(b.target, b.action, undefined, slug);
        if (refused) return refused;
        const kept = unchanged ? old : undefined;
        const target = kept?.target ?? b.target;
        const next: ProfileService = {slug, enabled: b.enabled, action: b.action, ...(target ? {target} : {}), location_unavailable: kept?.location_unavailable ?? false, iranian_bypass: kept?.iranian_bypass ?? false};
        state.services.set(p.id, rows.some((r) => r.slug === slug) ? rows.map((r) => (r.slug === slug ? next : r)) : [...rows, next]);
        touch(p);
        return ok(next);
      }),
    "DELETE /profiles/{id}/services/{slug}": (c) =>
      guarded(c, (p) => {
        state.services.set(p.id, (state.services.get(p.id) ?? []).filter((s) => s.slug !== idAt(c, 4)));
        touch(p);
        return none;
      }),
    "POST /profiles/{id}/services:batch": (c) =>
      guarded(c, (p) => {
        const b = bodyOf<{op: "set" | "delete"; slugs: string[]; enabled?: boolean; action?: ProfileService["action"]; target?: P["Target"]}>(c);
        let rows = state.services.get(p.id) ?? [];
        let created = 0;
        let updated = 0;
        if (b.op === "delete") rows = rows.filter((r) => !b.slugs.includes(r.slug));
        else {
          if (b.action === "redirect" && !b.target?.kind) return err(422, "validation_failed", [{name: "/target/kind", code: "invalid"}]);
          for (const slug of b.slugs) {
            const refused = redirectRefused(b.target, b.action ?? "block", undefined, slug);
            if (refused) return refused;
          }
          for (const slug of b.slugs) {
            const next: ProfileService = {slug, enabled: b.enabled ?? true, action: b.action ?? "block", ...(b.target ? {target: b.target} : {}), location_unavailable: false, iranian_bypass: false};
            if (rows.some((r) => r.slug === slug)) {
              updated++;
              rows = rows.map((r) => (r.slug === slug ? next : r));
            } else {
              created++;
              rows = [...rows, next];
            }
          }
        }
        state.services.set(p.id, rows);
        touch(p);
        return ok({created, updated, skipped: 0, conflict: 0, flagged: 0, items: []});
      }),

    // ---- folders ----
    "GET /profiles/{id}/folders": (c) => (profile(c) ? ok({folders: withCounts(idAt(c, 2))}) : notFound),
    "POST /profiles/{id}/folders": (c) =>
      guarded(c, (p) => {
        const b = bodyOf<Pick<Folder, "name" | "kind" | "action" | "target">>(c);
        if (!b.name?.trim()) return err(422, "validation_failed", [{name: "/name", code: "required"}]);
        if ([...b.name].length > 31) return err(422, "validation_failed", [{name: "/name", code: "too_long"}]);
        if (b.kind === "do_not_log" && b.action) return err(422, "validation_failed", [{name: "/action", code: "invalid"}]);
        const refused = over("max_folders_per_profile", (state.folders.get(p.id) ?? []).length);
        if (refused) return refused;
        const folder: Folder = {id: uid("fo", ++state.nextId), name: b.name, kind: b.kind, ...(b.action ? {action: b.action} : {}), ...(b.target ? {target: b.target} : {}), location_unavailable: false, rule_count: 0};
        state.folders.set(p.id, [...(state.folders.get(p.id) ?? []), folder]);
        return ok(folder, 201);
      }),
    "PATCH /profiles/{id}/folders/{folder_id}": (c) =>
      guarded(c, (p) => {
        const rows = state.folders.get(p.id) ?? [];
        const folder = rows.find((f) => f.id === idAt(c, 4));
        if (!folder) return notFound;
        const b = bodyOf<Folder & {clear?: string[]}>(c);
        if (b.name !== undefined && [...b.name].length > 31) return err(422, "validation_failed", [{name: "/name", code: "too_long"}]);
        // A Folder Rule cannot go while a rule follows it (spec 3.7).
        if (b.clear?.includes("action") && (state.rules.get(p.id) ?? []).some((r) => r.folder_id === folder.id && r.action === "inherit")) {
          return err(422, "validation_failed", [{name: "/clear/0", code: "has_inheriting_rules"}]);
        }
        const next = cleared(folder, b);
        state.folders.set(p.id, rows.map((f) => (f === folder ? next : f)));
        return ok(next);
      }),
    "DELETE /profiles/{id}/folders/{folder_id}": (c) =>
      guarded(c, (p) => {
        const id = idAt(c, 4);
        state.folders.set(p.id, (state.folders.get(p.id) ?? []).filter((f) => f.id !== id));
        state.rules.set(p.id, (state.rules.get(p.id) ?? []).filter((r) => r.folder_id !== id));
        touch(p);
        return none;
      }),
    "GET /profiles/{id}/folders/{folder_id}/export": (c) => {
      const p = profile(c);
      if (!p) return notFound;
      const id = idAt(c, 4);
      return ok({
        format: "ctrlz-rules",
        version: 1,
        rules: (state.rules.get(p.id) ?? [])
          .filter((r) => r.folder_id === id)
          .map((r) => ({pattern: r.pattern, action: r.action, enabled: r.enabled, ...(r.expires_at ? {expires_at: r.expires_at} : {}), ...(r.comment ? {comment: r.comment} : {})})),
      });
    },
    "POST /profiles/{id}/folders/{folder_id}:upload": (c) =>
      guarded(c, (p) => {
        const b = bodyOf<{document: string; mode?: "new_only" | "upsert"}>(c);
        const folderId = idAt(c, 4);
        if (!(state.folders.get(p.id) ?? []).some((f) => f.id === folderId)) return notFound;
        let doc: {format?: string; version?: number; rules?: {pattern: string; action: Rule["action"]; enabled?: boolean; comment?: string; expires_at?: string}[]};
        try {
          doc = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(b.document), (ch) => ch.charCodeAt(0)))) as typeof doc;
        } catch {
          return err(422, "validation_failed", [{name: "", code: "json_syntax"}]);
        }
        if (doc.format !== "ctrlz-rules") return err(422, "validation_failed", [{name: "/format", code: "format_unknown"}]);
        if (doc.version !== 1) return err(422, "validation_failed", [{name: "/version", code: "version_unsupported"}]);
        const incoming = doc.rules ?? [];
        for (const [i, item] of incoming.entries()) {
          if (typeof item.pattern !== "string" || /\s/.test(item.pattern) || item.pattern === "") return err(422, "validation_failed", [{name: `/rules/${i}/pattern`, code: "pattern_invalid"}]);
          const redirect = redirectRefused(undefined, item.action, item.pattern);
          if (redirect) return err(422, "validation_failed", [{name: `/rules/${i}/pattern`, code: "iranian_name"}]);
        }
        if (incoming.length > 1000) return ok(newJob("upload", incoming.length, p.id), 202);
        if (state.job && (state.job.state === "queued" || state.job.state === "running")) return err(409, "job_running");
        const rules = state.rules.get(p.id) ?? [];
        const result = {created: 0, updated: 0, skipped: 0, conflict: 0, flagged: 0, items: [] as {index: number; outcome: "created" | "updated" | "skipped" | "conflict"; id?: string}[]};
        const made: Rule[] = [];
        let rows = rules;
        for (const [index, item] of incoming.entries()) {
          const parsed = parsePattern(item.pattern);
          const there = rows.find((r) => r.key === parsed.key);
          if (there && there.folder_id !== folderId) {
            result.conflict++;
            result.items.push({index, outcome: "conflict"});
          } else if (there && b.mode === "upsert") {
            rows = rows.map((r) => (r === there ? {...r, action: item.action, enabled: item.enabled ?? true, ...(item.comment ? {comment: item.comment} : {}), updated_at: new Date().toISOString()} : r));
            result.updated++;
            result.items.push({index, outcome: "updated", id: there.id});
          } else if (there) {
            result.skipped++;
            result.items.push({index, outcome: "skipped", id: there.id});
          } else {
            const rule = newRule(item.pattern, {action: item.action, folder_id: folderId, enabled: item.enabled ?? true, comment: item.comment});
            made.push(rule);
            result.created++;
            result.items.push({index, outcome: "created", id: rule.id});
          }
        }
        state.rules.set(p.id, [...made, ...rows]);
        touch(p);
        return ok(result);
      }),

    // ---- rules ----
    "GET /profiles/{id}/rules": (c) => {
      const p = profile(c);
      if (!p) return notFound;
      return ok(page(c, filterRules(state.rules.get(p.id) ?? [], {folder: c.query.get("folder"), q: c.query.get("q"), status: c.query.get("status"), action: c.query.get("action")}, c.query.get("sort") ?? "created")));
    },
    "POST /profiles/{id}/rules": (c) =>
      guarded(c, (p) => {
        const b = bodyOf<{patterns: string[]; action: Rule["action"]; target?: P["Target"]; folder_id?: string; comment?: string; enabled?: boolean; expires_in?: string; expires_at?: string}>(c);
        const rules = state.rules.get(p.id) ?? [];
        const refused = over("max_rules_per_profile", rules.length + b.patterns.length - 1);
        if (refused) return refused;
        if (b.folder_id && !(state.folders.get(p.id) ?? []).some((f) => f.id === b.folder_id)) return notFound;
        if (b.comment !== undefined && [...b.comment].length > 64) return err(422, "validation_failed", [{name: "/comment", code: "too_long"}]);
        if (b.action === "inherit" && !(state.folders.get(p.id) ?? []).find((f) => f.id === b.folder_id)?.action) return err(422, "validation_failed", [{name: "/action", code: "needs_folder_action"}]);
        if (b.action === "redirect" && !b.target) return err(422, "validation_failed", [{name: "/target", code: "required"}]);
        const seen = new Set<string>();
        for (const [i, pattern] of b.patterns.entries()) {
          if (/\s/.test(pattern) || pattern === "" || /^!?[@#]/.test(pattern) && !/^!?(?:[@#][A-Za-z]{2}|@AS\d{1,10})$/.test(pattern)) return err(422, "validation_failed", [{name: `/patterns/${i}`, code: "pattern_invalid"}]);
          const redirect = redirectRefused(b.target, b.action, pattern);
          if (redirect) return err(422, "validation_failed", [{name: `/patterns/${i}`, code: "iranian_name"}]);
          const key = parsePattern(pattern).key;
          if (seen.has(key)) return err(422, "validation_failed", [{name: `/patterns/${i}`, code: "duplicate"}]);
          seen.add(key);
          if (rules.some((r) => r.key === key)) return err(422, "validation_failed", [{name: `/patterns/${i}`, code: "exists"}]);
        }
        const expires = expiryOf(b);
        if (expires === "past") return err(422, "validation_failed", [{name: "/expires_at", code: "in_past"}]);
        const made = b.patterns.map((pattern) => newRule(pattern, {action: b.action, target: b.target, folder_id: b.folder_id, comment: b.comment, enabled: b.enabled ?? true, expires_at: expires}));
        state.rules.set(p.id, [...made, ...rules]);
        touch(p);
        return ok({rules: made}, 201);
      }),
    "PATCH /profiles/{id}/rules/{rule_id}": (c) =>
      guarded(c, (p) => {
        const rules = state.rules.get(p.id) ?? [];
        const rule = rules.find((r) => r.id === idAt(c, 4));
        if (!rule) return notFound;
        const patch = bodyOf<Partial<Rule> & {clear?: string[]; expires_in?: string}>(c);
        if (patch.comment !== undefined && [...patch.comment].length > 64) return err(422, "validation_failed", [{name: "/comment", code: "too_long"}]);
        if (patch.pattern !== undefined && (/\s/.test(patch.pattern) || patch.pattern === "")) return err(422, "validation_failed", [{name: "/pattern", code: "pattern_invalid"}]);
        const redirect = redirectRefused(patch.target, patch.action ?? rule.action, patch.pattern ?? rule.pattern);
        if (redirect) return err(422, "validation_failed", [{name: "/pattern", code: "iranian_name"}]);
        if (patch.pattern !== undefined && rules.some((r) => r !== rule && r.key === parsePattern(patch.pattern!).key)) return err(422, "validation_failed", [{name: "/pattern", code: "exists"}]);
        const expires = expiryOf(patch);
        if (expires === "past") return err(422, "validation_failed", [{name: "/expires_at", code: "in_past"}]);
        const {expires_in: _in, ...rest} = patch;
        void _in;
        const moved = patch.pattern !== undefined ? parsePattern(patch.pattern) : null;
        const next = {
          ...cleared(rule, {...rest, ...(moved ?? {}), clear: (patch.clear ?? []).map((n) => (n === "expires" ? "expires_at" : n === "folder" ? "folder_id" : n))} as never),
          ...(expires ? {expires_at: expires} : {}),
          updated_at: new Date().toISOString(),
        } as Rule;
        if (moved) next.pattern = patch.pattern!;
        state.rules.set(p.id, rules.map((r) => (r === rule ? next : r)));
        return ok(next);
      }),
    "DELETE /profiles/{id}/rules/{rule_id}": (c) =>
      guarded(c, (p) => {
        state.rules.set(p.id, (state.rules.get(p.id) ?? []).filter((r) => r.id !== idAt(c, 4)));
        touch(p);
        return none;
      }),
    "POST /profiles/{id}/rules/{rule_id}:transfer": (c) =>
      guarded(c, (p) => {
        const b = bodyOf<TransferBody>(c);
        const rule = (state.rules.get(p.id) ?? []).find((r) => r.id === idAt(c, 4));
        if (!rule) return notFound;
        return transfer(p, [rule], b);
      }),
    "POST /profiles/{id}/rules:batch": (c) =>
      guarded(c, (p) => {
        const b = bodyOf<Omit<TransferBody, "op"> & {op: string; ids?: string[]; selector?: {q?: string; folder?: string; status?: string; action?: string}; set?: Partial<Rule> & {expires_in?: string}; clear?: string[]}>(c);
        const rules = state.rules.get(p.id) ?? [];
        const chosen = b.ids ? rules.filter((r) => b.ids!.includes(r.id)) : filterRules(rules, {folder: b.selector?.folder ?? null, q: b.selector?.q ?? null, status: b.selector?.status ?? null, action: b.selector?.action ?? null}, "created");
        if (state.job && (state.job.state === "queued" || state.job.state === "running")) return err(409, "job_running");
        const ids = new Set(chosen.map((r) => r.id));
        if (chosen.length > 1000) {
          // The job does its work when it is asked for; the mock does it now, so a case sees the rules as the job leaves them.
          if (b.op === "delete") state.rules.set(p.id, rules.filter((r) => !ids.has(r.id)));
          else if (b.op === "enable" || b.op === "disable") state.rules.set(p.id, rules.map((r) => (ids.has(r.id) ? {...r, enabled: b.op === "enable"} : r)));
          touch(p);
          return ok(newJob("rules_batch", chosen.length, p.id), 202);
        }
        if (b.op === "copy" || b.op === "move") return transfer(p, chosen, {...b, op: b.op});
        if (b.op === "delete") state.rules.set(p.id, rules.filter((r) => !ids.has(r.id)));
        else if (b.op === "enable" || b.op === "disable") state.rules.set(p.id, rules.map((r) => (ids.has(r.id) ? {...r, enabled: b.op === "enable"} : r)));
        else if (b.op === "edit") {
          const expires = expiryOf(b.set ?? {});
          if (expires === "past") return err(422, "validation_failed", [{name: "/set/expires_at", code: "in_past"}]);
          const {expires_in: _in, ...set} = b.set ?? {};
          void _in;
          const drop = (b.clear ?? []).map((n) => (n === "expires" ? "expires_at" : n === "folder" ? "folder_id" : n));
          state.rules.set(
            p.id,
            rules.map((r) => (ids.has(r.id) ? {...(cleared(r, {...set, clear: drop} as never) as Rule), ...(expires ? {expires_at: expires} : {}), updated_at: new Date().toISOString()} : r)),
          );
        }
        touch(p);
        return ok({created: 0, updated: chosen.length, skipped: 0, conflict: 0, flagged: 0, items: chosen.slice(0, 100).map((r, index) => ({index, outcome: "updated", id: r.id}))});
      }),

    // ---- options ----
    "GET /profiles/{id}/options": (c) => (profile(c) ? ok(state.options.get(idAt(c, 2)) ?? {default_location_unavailable: false}) : notFound),
    "PATCH /profiles/{id}/options": (c) =>
      guarded(c, (p) => {
        const b = bodyOf<Options & {clear?: string[]}>(c);
        if (b.block_response?.mode === "branded") return err(422, "validation_failed", [{name: "/block_response/mode", code: "not_available"}]);
        if (b.default_rule?.action === "redirect" && state.locations.length === 0 && b.default_rule.target?.kind === "auto") return err(422, "validation_failed", [{name: "/default_rule/target", code: "no_shared_destination"}]);
        const next = cleared(state.options.get(p.id) ?? {default_location_unavailable: false}, b);
        state.options.set(p.id, next);
        touch(p);
        return ok(next);
      }),

    // ---- jobs ----
    "GET /jobs/active": () => ok({...(state.job && (state.job.state === "queued" || state.job.state === "running") ? {job: state.job} : {})}),
    "GET /jobs/{id}": (c) => {
      const job = state.job;
      if (!job || job.id !== idAt(c, 2)) return notFound;
      // Running on the first read, done on the next: what a screen sees of a job that takes a few seconds.
      state.jobReads++;
      if (state.jobReads === 1) state.job = {...job, state: "running"};
      else if (state.jobReads >= 2 && job.state !== "done" && job.state !== "failed") {
        state.job = {...job, state: "done", progress: job.total, result: {created: job.total, updated: 0, skipped: 0, conflict: 0, flagged: 0, items: []}};
      }
      return ok(state.job);
    },

    // ---- endpoints ----
    "GET /endpoints": (c) => {
      let rows = [...state.endpoints];
      const group = c.query.get("group");
      const type = c.query.get("type");
      const status = c.query.get("status");
      const q = (c.query.get("q") ?? "").toLowerCase();
      const byType: Record<string, number> = {};
      for (const e of rows) byType[e.type] = (byType[e.type] ?? 0) + 1;
      const byStatus = {pending: rows.filter((e) => e.status === "pending").length, active: rows.filter((e) => e.status === "active").length};
      if (group) rows = rows.filter((e) => e.group_id === group);
      if (type) rows = rows.filter((e) => e.type === type);
      if (status) rows = rows.filter((e) => e.status === status);
      if (q) rows = rows.filter((e) => e.name.toLowerCase().includes(q));
      if (c.query.get("sort") === "name") rows.sort((a, b) => a.name.localeCompare(b.name));
      return ok({...page(c, rows), by_type: byType, by_status: byStatus});
    },
    "POST /endpoints": (c) => {
      const b = bodyOf<{type: string; names: string[]; profile_id: string; profile2_id?: string; group_id?: string; comment?: string}>(c);
      const refused = over("max_endpoints", state.endpoints.length + b.names.length - 1);
      if (refused) return refused;
      if (!state.profiles.some((p) => p.id === b.profile_id)) return notFound;
      const made = b.names.map((name) => endpointFixture(++state.nextId, {name, type: b.type, profile_id: b.profile_id, status: "pending", first_query_at: undefined, last_query_at: undefined, ...(b.profile2_id ? {profile2_id: b.profile2_id} : {}), ...(b.group_id ? {group_id: b.group_id} : {}), ...(b.comment ? {comment: b.comment} : {})}));
      for (const e of made) {
        state.endpoints.unshift(e);
        for (const m of [state.clients, state.authorized, state.claims, state.ddns, state.shareLinks] as Map<string, never[]>[]) m.set(e.id, []);
        state.schedules.set(e.id, {timezone: "Asia/Tehran", windows: []});
      }
      return ok({endpoints: made}, 201);
    },
    "GET /endpoints/export": () => ({status: 200, headers: {"content-type": "text/csv"}, body: "name,type\n"}),
    "POST /endpoints:batch": (c) => {
      const b = bodyOf<{ids: string[]; op: string; group_id?: string; set?: Partial<Endpoint>; clear?: string[]}>(c);
      if (b.op === "delete") {
        const held = b.ids.map((id, i) => ({id, i})).filter(({id}) => state.endpoints.find((e) => e.id === id)?.admin_hold);
        if (held.length) return err(409, "endpoint_held", held.map(({i}) => ({name: `/ids/${i}`, code: "invalid"})));
        state.endpoints = state.endpoints.filter((e) => !b.ids.includes(e.id));
      } else state.endpoints = state.endpoints.map((e) => (b.ids.includes(e.id) ? cleared({...e, ...b.set, ...(b.op === "move" && b.group_id ? {group_id: b.group_id} : {})}, {clear: b.clear} as never) : e));
      return ok({affected: b.ids.length});
    },
    "GET /endpoints/{id}": (c) => (endpoint(c) ? ok(endpoint(c)) : notFound),
    "PATCH /endpoints/{id}": (c) => {
      const e = endpoint(c);
      if (!e) return notFound;
      const b = bodyOf<Partial<Endpoint> & {clear?: string[]; lock_passwords?: unknown}>(c);
      const lockedAway = b.profile_id && b.profile_id !== e.profile_id ? state.profiles.find((p) => p.id === e.profile_id && p.locked) : undefined;
      if (lockedAway && !(Array.isArray(b.lock_passwords) && b.lock_passwords.length > 0)) return err(423, "profile_locked", [{name: "/lock_passwords", code: "required"}]);
      if (lockedAway && Array.isArray(b.lock_passwords) && (b.lock_passwords as {password: string}[])[0]?.password !== state.lockPasswords.get(lockedAway.id)) {
        return err(401, "invalid_credentials", [{name: "/lock_passwords/0", code: "invalid"}]);
      }
      const rest: Record<string, unknown> = {...b};
      delete rest.lock_passwords;
      delete rest.confirm_destinations;
      const next = {...cleared(e, rest as never), updated_at: new Date().toISOString()} as Endpoint;
      state.endpoints = state.endpoints.map((x) => (x === e ? next : x));
      return ok(next);
    },
    "POST /endpoints/{id}:delete": (c) => {
      const e = endpoint(c);
      if (!e) return notFound;
      if (e.admin_hold) return err(409, "endpoint_held", [{name: "/ids/0", code: "invalid"}]);
      state.endpoints = state.endpoints.filter((x) => x !== e);
      return none;
    },
    "POST /endpoints/{id}:rotate-resolver": (c) => {
      const e = endpoint(c);
      if (!e) return notFound;
      const next = {...e, resolver_id: `r${String(++state.nextId).padStart(8, "0")}`, apple_profile_stale: true};
      state.endpoints = state.endpoints.map((x) => (x === e ? next : x));
      return ok(next);
    },
    "GET /endpoints/{id}/schedule": (c) => (endpoint(c) ? ok(state.schedules.get(idAt(c, 2))) : notFound),
    "PUT /endpoints/{id}/schedule": (c) => {
      const e = endpoint(c);
      if (!e) return notFound;
      const b = bodyOf<{timezone: string; windows: Schedule["windows"]}>(c);
      if (!TIMEZONES.includes(b.timezone)) return err(422, "validation_failed", [{name: "/timezone", code: "unknown"}]);
      const sorted = [...b.windows].sort((a, z) => a.start - z.start);
      for (const [i, w] of sorted.entries()) {
        if (w.start % 30 || w.end % 30 || w.end <= w.start) return err(422, "validation_failed", [{name: `/windows/${i}`, code: "grid"}]);
        if (i > 0 && sorted[i - 1]!.end > w.start) return err(422, "validation_failed", [{name: `/windows/${i}`, code: "overlap"}]);
      }
      const schedule: Schedule = {timezone: b.timezone, windows: sorted.map((w, i) => ({...w, id: w.id ?? uid("wi", ++state.nextId + i)}))};
      state.schedules.set(e.id, schedule);
      state.endpoints = state.endpoints.map((x) => (x === e ? {...e, has_schedule: schedule.windows.length > 0, schedule_timezone: b.timezone} : x));
      return ok(schedule);
    },
    "GET /endpoint-groups": () => ok({groups: state.groups.map((g) => ({...g, endpoint_count: state.endpoints.filter((e) => e.group_id === g.id).length}))}),
    "POST /endpoint-groups": (c) => {
      const b = bodyOf<{name: string; endpoint_ids?: string[]}>(c);
      const refused = over("max_endpoint_groups", state.groups.length);
      if (refused) return refused;
      const group: Group = {id: uid("gr", ++state.nextId), name: b.name, endpoint_count: b.endpoint_ids?.length ?? 0};
      state.groups.push(group);
      state.endpoints = state.endpoints.map((e) => (b.endpoint_ids?.includes(e.id) ? {...e, group_id: group.id} : e));
      return ok(group, 201);
    },
    "PATCH /endpoint-groups/{gid}": (c) => {
      const g = state.groups.find((x) => x.id === idAt(c, 2));
      if (!g) return notFound;
      g.name = bodyOf<{name: string}>(c).name;
      return ok(g);
    },
    "DELETE /endpoint-groups/{gid}": (c) => {
      const id = idAt(c, 2);
      state.groups = state.groups.filter((g) => g.id !== id);
      state.endpoints = state.endpoints.map((e) => (e.group_id === id ? {...e, group_id: undefined} : e));
      return none;
    },

    // ---- clients, DDNS, addresses, claims ----
    "GET /endpoints/{id}/clients": (c) => {
      if (!endpoint(c)) return notFound;
      let rows = state.clients.get(idAt(c, 2)) ?? [];
      const q = (c.query.get("q") ?? "").toLowerCase();
      const group = c.query.get("group");
      const days = Number(c.query.get("inactive_days")) || 0;
      if (q) rows = rows.filter((r) => `${r.label} ${r.alias ?? ""} ${r.hostname ?? ""}`.toLowerCase().includes(q));
      if (group) rows = rows.filter((r) => r.group_name === group);
      if (days) rows = rows.filter((r) => Date.parse(r.last_seen_at) < Date.now() - days * 86_400_000);
      return ok({...page(c, rows), count: rows.length});
    },
    "POST /endpoints/{id}/clients": (c) => {
      const e = endpoint(c);
      if (!e) return notFound;
      const rows = state.clients.get(e.id) ?? [];
      const refused = over("max_clients_per_endpoint", rows.filter((r) => r.source === "manual").length);
      if (refused) return refused;
      const b = bodyOf<Partial<Client>>(c);
      const label = (b.label ?? b.alias ?? "").toLowerCase().replace(/[^a-z0-9-]/g, "") || `client-${state.nextId}`;
      if (label === "default") return err(422, "validation_failed", [{name: "/label", code: "reserved"}]);
      if (rows.some((r) => r.label === label)) return err(422, "validation_failed", [{name: "/label", code: "exists"}]);
      const made: Client = {id: uid("cl", ++state.nextId), label, ...(b.alias ? {alias: b.alias} : {}), ...(b.group_name ? {group_name: b.group_name} : {}), source: "manual", is_custom: true, first_seen_at: new Date().toISOString(), last_seen_at: new Date().toISOString()};
      state.clients.set(e.id, [made, ...rows]);
      return ok(made, 201);
    },
    "PATCH /endpoints/{id}/clients/{cid}": (c) => {
      const e = endpoint(c);
      if (!e) return notFound;
      const rows = state.clients.get(e.id) ?? [];
      const row = rows.find((r) => r.id === idAt(c, 4));
      if (!row) return notFound;
      const next = cleared(row, bodyOf<Client & {clear?: string[]}>(c));
      state.clients.set(e.id, rows.map((r) => (r === row ? next : r)));
      return ok(next);
    },
    "POST /endpoints/{id}/clients:batch": (c) => {
      const e = endpoint(c);
      if (!e) return notFound;
      const b = bodyOf<{op: string; ids?: string[]; selector?: {inactive_days?: number; all?: boolean}}>(c);
      const rows = state.clients.get(e.id) ?? [];
      const days = b.selector?.inactive_days ?? 0;
      const hit = rows.filter((r) => (b.ids ? b.ids.includes(r.id) : b.selector?.all || (days > 0 && Date.parse(r.last_seen_at) < Date.now() - days * 86_400_000)));
      const first = hit.slice(0, 500);
      if (b.op === "delete") state.clients.set(e.id, rows.filter((r) => !first.includes(r)));
      return ok({affected: first.length, more: hit.length > first.length});
    },
    "GET /endpoints/{id}/ddns-hosts": (c) => (endpoint(c) ? ok({hosts: state.ddns.get(idAt(c, 2)) ?? []}) : notFound),
    "POST /endpoints/{id}/ddns-hosts": (c) => {
      const e = endpoint(c);
      if (!e) return notFound;
      const hostname = bodyOf<{hostname: string}>(c).hostname;
      const rows = state.ddns.get(e.id) ?? [];
      if (rows.some((r) => r.hostname === hostname)) return err(422, "validation_failed", [{name: "/hostname", code: "exists"}]);
      const made: DdnsHost = {id: uid("dd", ++state.nextId), hostname, last_ips: []};
      state.ddns.set(e.id, [...rows, made]);
      return ok(made, 201);
    },
    "POST /endpoints/{id}/ddns-hosts/{hid}:delete": (c) => {
      const e = endpoint(c);
      if (!e) return notFound;
      state.ddns.set(e.id, (state.ddns.get(e.id) ?? []).filter((r) => r.id !== idAt(c, 4)));
      return none;
    },
    "GET /endpoints/{id}/authorized-ips": (c) => {
      if (!endpoint(c)) return notFound;
      const q = c.query.get("q") ?? "";
      return ok(page(c, (state.authorized.get(idAt(c, 2)) ?? []).filter((r) => r.cidr.includes(q))));
    },
    "POST /endpoints/{id}/authorized-ips": (c) => {
      const e = endpoint(c);
      if (!e) return notFound;
      const rows = state.authorized.get(e.id) ?? [];
      // The server takes a bare address as a host prefix (spec p3 5): 203.0.113.7 is 203.0.113.7/32 and an IPv6 address is a /128.
      const cidrs = bodyOf<{cidrs: string[]}>(c).cidrs.map((x) => (/^[0-9a-f:.]+$/i.test(x) ? `${x}/${x.includes(":") ? 128 : 32}` : x));
      for (const [i, cidr] of cidrs.entries()) {
        if (!/^[0-9a-f:.]+\/\d{1,3}$/i.test(cidr)) return err(422, "validation_failed", [{name: `/cidrs/${i}`, code: "invalid"}]);
        if (rows.some((r) => r.cidr === cidr)) return err(422, "validation_failed", [{name: `/cidrs/${i}`, code: "exists"}]);
      }
      const refused = over("max_authorized_ips", rows.filter((r) => r.source === "manual").length);
      if (refused) return refused;
      const made = cidrs.map<AuthorizedIP>((cidr) => ({id: uid("au", ++state.nextId), cidr, source: "manual", cleanup_opt_in: false, created_at: new Date().toISOString(), is_current: false}));
      state.authorized.set(e.id, [...made, ...rows]);
      return ok({items: made}, 201);
    },
    "PATCH /endpoints/{id}/authorized-ips/{aid}": (c) => {
      const e = endpoint(c);
      if (!e) return notFound;
      const rows = state.authorized.get(e.id) ?? [];
      const row = rows.find((r) => r.id === idAt(c, 4));
      if (!row) return notFound;
      const next = {...row, cleanup_opt_in: bodyOf<{cleanup_opt_in: boolean}>(c).cleanup_opt_in};
      state.authorized.set(e.id, rows.map((r) => (r === row ? next : r)));
      return ok(next);
    },
    "POST /endpoints/{id}/authorized-ips:delete": (c) => {
      const e = endpoint(c);
      if (!e) return notFound;
      const rows = state.authorized.get(e.id) ?? [];
      const ids = bodyOf<{ids: string[]}>(c).ids;
      const bad = ids.map((id, i) => ({row: rows.find((r) => r.id === id), i})).find(({row}) => row?.is_current);
      if (bad) return err(422, "validation_failed", [{name: `/ids/${bad.i}`, code: "current_address"}]);
      if (e.require_authorized_ips && rows.length - ids.length < 1) return err(422, "validation_failed", [{name: "/ids/0", code: "last_authorized"}]);
      state.authorized.set(e.id, rows.filter((r) => !ids.includes(r.id)));
      return none;
    },
    "GET /endpoints/{id}/ip-claims": (c) => (endpoint(c) ? ok({claims: state.claims.get(idAt(c, 2)) ?? []}) : notFound),
    "POST /endpoints/{id}/ip-claims": (c) => {
      const e = endpoint(c);
      if (!e) return notFound;
      const refused = over("max_ip_claims", (state.claims.get(e.id) ?? []).length);
      if (refused) return refused;
      const b = bodyOf<{cidr?: string; use_my_address?: boolean}>(c);
      const made: IPClaim = {id: uid("ic", ++state.nextId), cidr: b.cidr ?? "203.0.113.7/32", state: "pending_proof", proven: false, source: b.use_my_address ? "browser" : "manual", needs_admin: false};
      state.claims.set(e.id, [made, ...(state.claims.get(e.id) ?? [])]);
      return ok(made, 201);
    },
    "POST /endpoints/{id}/ip-claims/{claim_id}/challenges": (c) => {
      const e = endpoint(c);
      const claim = e ? (state.claims.get(e.id) ?? []).find((x) => x.id === idAt(c, 4)) : undefined;
      if (!e || !claim) return notFound;
      const challenge = {id: uid("ch", ++state.nextId), label: "abcdefghijklmnopqrstuvwxyz", expires_at: new Date(Date.now() + 600_000).toISOString(), observed: false};
      state.claims.set(e.id, (state.claims.get(e.id) ?? []).map((x) => (x === claim ? {...claim, challenge} : x)));
      return ok({id: challenge.id, label: challenge.label, expires_at: challenge.expires_at, commands: {ready: true, verify_host: "abcdefghijklmnopqrstuvwxyz.verify.dns.example.test", legacy: {dns1: "203.0.113.53", dns2: "203.0.113.54"}}}, 201);
    },
    "POST /endpoints/{id}/ip-claims/{claim_id}:take": (c) => {
      const e = endpoint(c);
      const claim = e ? (state.claims.get(e.id) ?? []).find((x) => x.id === idAt(c, 4)) : undefined;
      if (!e || !claim) return notFound;
      const observed = claim.challenge?.observed || bodyOf<{code?: string}>(c).code === "123456";
      if (!observed) return ok({claim, outcome: "no_proof"});
      const next: IPClaim = {...claim, state: "active", proven: true, proof_method: "verify_udp_txt"};
      state.claims.set(e.id, (state.claims.get(e.id) ?? []).map((x) => (x === claim ? next : x)));
      return ok({claim: next, outcome: "active"});
    },
    "POST /endpoints/{id}/ip-claims/{claim_id}:release": (c) => {
      const e = endpoint(c);
      if (!e) return notFound;
      state.claims.set(e.id, (state.claims.get(e.id) ?? []).filter((x) => x.id !== idAt(c, 4)));
      return none;
    },

    // ---- setup ----
    "GET /endpoints/{id}/resolvers": (c) => {
      if (!endpoint(c)) return notFound;
      const client = c.query.get("client");
      const view = state.resolver;
      // The values of a client carry its label (SC 3.2): `<resolver>-<client>.<zone>`, so a case can see which view a screen was given.
      if (client && view.ready && view.host) return ok({...view, client, host: view.host.replace(/^([^.]+)/, `$1-${client}`)});
      return ok(client ? {...view, client} : view);
    },
    "GET /endpoints/{id}/generators": (c) => {
      if (!endpoint(c)) return notFound;
      const generator = c.query.get("generator") ?? "";
      if (!["windows-doh", "firefox-policy", "chromium-policy", "android-private-dns", "address-list"].includes(generator)) return notFound;
      if (!state.resolver.ready) return err(409, "setup_unavailable");
      return {status: 200, headers: {"content-type": "text/plain"}, body: `# ${generator}\n${state.resolver.doh_url ?? ""}\n`};
    },
    "GET /endpoints/{id}/share-links": (c) => (endpoint(c) ? ok({links: state.shareLinks.get(idAt(c, 2)) ?? []}) : notFound),
    "POST /endpoints/{id}/share-links": (c) => {
      const e = endpoint(c);
      if (!e) return notFound;
      if (!state.resolver.ready) return err(409, "setup_unavailable");
      const link: ShareLink = {id: uid("sl", ++state.nextId), expires_at: new Date(Date.now() + 86_400_000).toISOString(), uses: 0, max_uses: 3, revoked: false, created_at: new Date().toISOString()};
      state.shareLinks.set(e.id, [link, ...(state.shareLinks.get(e.id) ?? [])]);
      return ok({link, url: https(`panel.localhost/s/${VALID_SHARE_LINK}`)}, 201);
    },
    "DELETE /endpoints/{id}/share-links/{sid}": (c) => {
      const e = endpoint(c);
      if (!e) return notFound;
      state.shareLinks.set(e.id, (state.shareLinks.get(e.id) ?? []).map((l) => (l.id === idAt(c, 4) ? {...l, revoked: true} : l)));
      return none;
    },
    "POST /endpoints/{id}/apple-profile": (c) => {
      if (!endpoint(c)) return notFound;
      return state.resolver.ready ? ok({url: https("panel.localhost/dl/APPLE_PROFILE_LINK"), expires_at: new Date(Date.now() + 900_000).toISOString()}, 201) : err(409, "setup_unavailable");
    },
    "POST /public/share": (c) => {
      if (bodyOf<{link: string}>(c).link !== VALID_SHARE_LINK) return notFound;
      return state.resolver.ready ? ok({endpoint: {name: "Home router", type: "other_router"}, resolvers: state.resolver, expires_at: new Date(Date.now() + 86_400_000).toISOString()}) : err(409, "setup_unavailable");
    },
    "POST /public/share/apple-profile": (c) => (bodyOf<{link: string}>(c).link === VALID_SHARE_LINK ? ok({url: https("panel.localhost/dl/APPLE_PROFILE_LINK"), expires_at: new Date(Date.now() + 900_000).toISOString()}, 201) : notFound),

    // ---- API tokens and feedback ----
    "GET /api-tokens": () => ok({tokens: state.tokens}),
    "POST /api-tokens": (c) => {
      const b = bodyOf<{name: string; kind: ApiToken["kind"]; allowed_ips?: string[]}>(c);
      const refused = over("max_api_tokens", state.tokens.length);
      if (refused) return refused;
      const token: ApiToken = {id: uid("tk", ++state.nextId), name: b.name, kind: b.kind, token_prefix: "Nw0Pq1", allowed_ips: b.allowed_ips ?? [], created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 365 * 86_400_000).toISOString(), ended: false};
      state.tokens.unshift(token);
      return ok({token, value: `ctz_${"A".repeat(60)}`}, 201);
    },
    "PATCH /api-tokens/{tid}": (c) => {
      const t = state.tokens.find((x) => x.id === idAt(c, 2));
      if (!t) return notFound;
      Object.assign(t, bodyOf<Partial<ApiToken>>(c));
      return ok(t);
    },
    "DELETE /api-tokens/{tid}": (c) => {
      state.tokens = state.tokens.filter((x) => x.id !== idAt(c, 2));
      return none;
    },
    "POST /feedback": (c) => {
      const b = bodyOf<{kind: string; body: string}>(c);
      if (!b.body?.trim()) return err(422, "validation_failed", [{name: "/body", code: "required"}]);
      state.feedback.push(b);
      return {status: 201};
    },
  };
  // A write to an Endpoint moves it in or out of the profiles that use it: the profile's own list and its counter follow, so the profile
  // row says "not attached" only when nothing is, and a profile that still has an Endpoint is refused its delete (409 `profile_in_use`).
  // Only the change is applied: a fixture profile that does not list an Endpoint it uses stays as it was until that Endpoint is attached anew.
  const usedBy = (e: Endpoint | undefined): string[] => (e ? [...new Set([e.profile_id, e.profile2_id].filter((x): x is string => !!x))] : []);
  const editList = (profileId: string, change: (list: Profile["endpoints"]) => Profile["endpoints"]) => {
    state.profiles = state.profiles.map((p) => {
      if (p.id !== profileId) return p;
      const list = change(p.endpoints);
      return list === p.endpoints ? p : {...p, endpoints: list, counts: {...p.counts, endpoints: Math.max(0, p.counts.endpoints + list.length - p.endpoints.length)}};
    });
  };
  const reflect = (before: Endpoint[], after: Endpoint[]) => {
    const was = new Map(before.map((e) => [e.id, e]));
    const now = new Map(after.map((e) => [e.id, e]));
    for (const id of new Set([...was.keys(), ...now.keys()])) {
      const b = now.get(id);
      const from = usedBy(was.get(id));
      const to = usedBy(b);
      for (const pid of from) if (!to.includes(pid)) editList(pid, (list) => (list.some((x) => x.id === id) ? list.filter((x) => x.id !== id) : list));
      if (!b) continue;
      for (const pid of to) {
        if (from.includes(pid)) editList(pid, (list) => (list.some((x) => x.id === id && x.name !== b.name) ? list.map((x) => (x.id === id ? {id, name: b.name} : x)) : list));
        else editList(pid, (list) => (list.some((x) => x.id === id) ? list : [...list, {id, name: b.name}]));
      }
    }
  };
  for (const key of ["POST /endpoints", "POST /endpoints:batch", "PATCH /endpoints/{id}", "POST /endpoints/{id}:delete"]) {
    const run = h[key]!;
    h[key] = async (c, s) => {
      const before = [...state.endpoints];
      const reply = await run(c, s);
      reflect(before, state.endpoints);
      return reply;
    };
  }
  return h as Record<MockKey, MockHandler>;
}

export {resolverViewFixture};
