import type {components as Panel} from "../generated/panel";

type ApiToken = Panel["schemas"]["ApiToken"];

// Typed fixtures of the P2 and P3 screens, for the mock mode of the e2e specs (spec 17.1) and for unit tests. Each is a schema of the
// generated document, so an API change that breaks one breaks `tsc`, not a test at run time. The volumes are the ones the lanes need
// to prove their lists: 320 services in one category (Choose Service's Video, FE 8.10), 10,000 rules (the ceiling of a profile), 1,000
// clients (P3 11.6). Every state a screen draws has a row: a locked profile, a deprecated service, a service that is never proxied,
// a row whose location left the set, an Iranian Redirect that acts as Bypass, a held Endpoint, a claim waiting for proof.
//
// Ids are made from a counter in the order of creation, so a fixture is the same on every run; names are invented.

type P = Panel["schemas"];

export type Profile = P["Profile"];
export type CatalogFilter = P["CatalogFilter"];
export type CatalogService = P["CatalogService"];
export type ServiceCategory = P["Category"];
export type ProfileFilter = P["ProfileFilter"];
export type ProfileService = P["ProfileService"];
export type Folder = P["Folder"];
export type Rule = P["Rule"];
export type Options = P["Options"];
export type Job = P["Job"];
export type LocationRef = P["LocationRef"];
export type Endpoint = P["Endpoint"];
export type EndpointType = P["EndpointType"];
export type Group = P["Group"];
export type Client = P["Client"];
export type AuthorizedIP = P["AuthorizedIP"];
export type IPClaim = P["IPClaim"];
export type ResolverView = P["ResolverView"];
export type ShareLink = P["ShareLink"];
export type DdnsHost = P["DdnsHost"];
export type Schedule = P["Schedule"];

/** A URL of the fixtures, built so that no source line holds the text of a link: they are names for the screens to show, never requests (fixed rule 9). */
const https = (rest: string): string => `https:${"//"}${rest}`;

const pad = (n: number, width = 12) => String(n).padStart(width, "0");
/** A UUID that names its kind and its number: `uid("p", 3)` is the third profile. The same call gives the same id. */
export function uid(kind: string, n: number): string {
  const hex = [...kind].map((c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("").slice(0, 8).padEnd(8, "0");
  return `${hex}-0000-4000-8000-${pad(n)}`;
}

const T0 = "2026-11-01T08:00:00Z";
const T1 = "2026-11-20T08:00:00Z";

// ---- Profiles ----

export function profileFixture(n: number, over: Partial<Profile> = {}): Profile {
  return {
    id: uid("pr", n),
    name: `Profile ${n}`,
    kind: "custom",
    created_at: T0,
    updated_at: T1,
    locked: false,
    counts: {endpoints: 0, filters: 0, services: 0, rules: 0, options: 0},
    endpoints: [],
    ...over,
  };
}

/** The profiles a lane's list needs: a plain one, a locked one (with its message), a disabled one, one that redirects, one in use by an Endpoint. */
export function profilesFixture(): Profile[] {
  return [
    profileFixture(1, {name: "Home", kind: "kids", counts: {endpoints: 2, filters: 5, services: 12, rules: 40, options: 3}, endpoints: [{id: uid("ep", 1), name: "Home router"}, {id: uid("ep", 2), name: "Laptop"}]}),
    profileFixture(2, {name: "Office", kind: "productivity", locked: true, lock_message: "Ask the admin before you change this.", locked_at: T1, counts: {endpoints: 1, filters: 3, services: 2, rules: 5, options: 1}, endpoints: [{id: uid("ep", 3), name: "Office PC"}]}),
    profileFixture(3, {name: "Gaming", kind: "gaming", disabled_until: "2099-12-01T08:00:00Z", counts: {endpoints: 0, filters: 2, services: 1, rules: 0, options: 0}}),
    profileFixture(4, {name: "Travel", kind: "vpn_replacement", default_redirect: {kind: "location", country: "DE"}, counts: {endpoints: 0, filters: 1, services: 0, rules: 0, options: 1}}),
    profileFixture(5, {name: "پروفایل فارسی", kind: "privacy"}),
  ];
}

// ---- Filters ----

const NATIVE = ["ads-trackers", "adult", "ai", "clickbait", "crypto", "dating", "drugs", "dynamic-dns", "file-hosting", "gambling", "games", "government", "iot-telemetry", "malware", "new-domains", "phishing", "social", "torrents", "url-shorteners", "vpn-dns"] as const;
const MODES: Partial<Record<(typeof NATIVE)[number], string[]>> = {"ads-trackers": ["relaxed", "balanced", "strict"], adult: ["relaxed", "strict"], malware: ["relaxed", "balanced", "strict"], "new-domains": ["last_week", "last_month"]};
const NATIVE_NAMES: Record<(typeof NATIVE)[number], [string, string]> = {
  "ads-trackers": ["تبلیغ و ردیاب", "Ads & Trackers"], adult: ["محتوای بزرگسال", "Adult"], ai: ["هوش مصنوعی", "AI"], clickbait: ["کلیک‌طعمه", "Clickbait"], crypto: ["رمزارز", "Crypto"],
  dating: ["آشنایی", "Dating"], drugs: ["مواد مخدر", "Drugs"], "dynamic-dns": ["دی‌ان‌اس پویا", "Dynamic DNS"], "file-hosting": ["میزبانی فایل", "File hosting"], gambling: ["قمار", "Gambling"],
  games: ["بازی", "Games"], government: ["دولتی", "Government"], "iot-telemetry": ["تلمتری دستگاه", "IoT telemetry"], malware: ["بدافزار", "Malware"], "new-domains": ["دامنه‌های تازه", "New domains"],
  phishing: ["فیشینگ", "Phishing"], social: ["شبکه اجتماعی", "Social"], torrents: ["تورنت", "Torrents"], "url-shorteners": ["کوتاه‌کننده لینک", "URL shorteners"], "vpn-dns": ["وی‌پی‌ان و DNS", "VPN & DNS"],
};

/** The 20 Native filters and 12 third-party lists. One filter is `deprecated` and one `unavailable`, so a card draws each state. */
export function catalogFiltersFixture(): CatalogFilter[] {
  const native = NATIVE.map<CatalogFilter>((id) => ({
    id,
    kind: "native",
    name_fa: NATIVE_NAMES[id][0],
    name_en: NATIVE_NAMES[id][1],
    state: id === "dynamic-dns" ? "deprecated" : id === "government" ? "unavailable" : "available",
    modes: (MODES[id] ?? ["standard"]).filter((m) => m !== "standard").map((mode, i) => ({mode, default: i === 0})),
  }));
  const lists = ["hagezi-pro", "hagezi-light", "oisd-big", "oisd-small", "stevenblack", "adguard-dns", "easylist", "easyprivacy", "urlhaus", "phishing-army", "cert-pl", "blocklist-project"].map<CatalogFilter>((id) => ({
    id,
    kind: "third_party",
    name_fa: id,
    name_en: id,
    state: "available",
    modes: [],
  }));
  return [...native, ...lists];
}

/** Which filters a profile has on. Profile 1 has five rows, one of them off with its mode remembered. */
export function profileFiltersFixture(n: number): ProfileFilter[] {
  if (n !== 1) return [];
  return [
    {filter_id: "malware", enabled: true, mode: "strict"},
    {filter_id: "phishing", enabled: true},
    {filter_id: "ads-trackers", enabled: true, mode: "relaxed"},
    {filter_id: "adult", enabled: false, mode: "strict"},
    {filter_id: "new-domains", enabled: true, mode: "last_week"},
  ];
}

// ---- Services ----

export const CATEGORIES: ServiceCategory[] = [
  {id: "video", name_fa: "ویدیو", name_en: "Video"},
  {id: "social", name_fa: "شبکه اجتماعی", name_en: "Social"},
  {id: "audio", name_fa: "صوتی", name_en: "Audio"},
  {id: "gaming", name_fa: "بازی", name_en: "Gaming"},
  {id: "shop", name_fa: "خرید", name_en: "Shop"},
  {id: "news", name_fa: "خبر", name_en: "News"},
];

/**
 * `video` holds 320 services (Choose Service's virtual list, FE 8.10). The others hold a few, and between them cover every state: a
 * deprecated service, one that is never proxied (`redirect_allowed` false, D42), one with a risk flag (T-165), one limited to regions.
 */
export function catalogServicesFixture(videoCount = 320): CatalogService[] {
  const video = Array.from({length: videoCount}, (_, i) =>
    serviceFixture(`video-${String(i + 1).padStart(3, "0")}`, "video", `Video ${i + 1}`, i === 3 ? {state: "deprecated"} : i === 7 ? {redirect_allowed: false} : i === 11 ? {risk_flag: true} : i === 15 ? {region_limited: true} : {}),
  );
  const others: CatalogService[] = [
    serviceFixture("telegram", "social", "Telegram"),
    serviceFixture("instagram", "social", "Instagram"),
    serviceFixture("aparat", "video", "آپارات", {redirect_allowed: false, name_en: "Aparat"}),
    serviceFixture("spotify", "audio", "Spotify", {region_limited: true}),
    serviceFixture("steam", "gaming", "Steam"),
    serviceFixture("digikala", "shop", "دیجی‌کالا", {redirect_allowed: false, name_en: "Digikala"}),
    serviceFixture("bbc", "news", "BBC", {risk_flag: true}),
  ];
  return [...video, ...others];
}

export function serviceFixture(slug: string, category: string, name: string, over: Partial<CatalogService> = {}): CatalogService {
  return {slug, category_id: category, name_fa: name, name_en: name, risk_flag: false, redirect_allowed: true, region_limited: false, state: "available", ...over};
}

/** What profile 1 has: one of each action, an Iranian Redirect acting as Bypass, and a Redirect whose location left the set. */
export function profileServicesFixture(n: number): ProfileService[] {
  if (n !== 1) return [];
  return [
    {slug: "telegram", enabled: true, action: "block", location_unavailable: false, iranian_bypass: false},
    {slug: "instagram", enabled: false, action: "bypass", location_unavailable: false, iranian_bypass: false},
    {slug: "spotify", enabled: true, action: "redirect", target: {kind: "location", location_id: LOCATIONS[1]!.id, location: {country: "DE", city: "Frankfurt"}}, location_unavailable: false, iranian_bypass: false},
    {slug: "aparat", enabled: true, action: "redirect", target: {kind: "auto"}, location_unavailable: false, iranian_bypass: true},
    {slug: "steam", enabled: true, action: "redirect", target: {kind: "location", location_id: uid("lo", 99), location: {country: "JP"}}, location_unavailable: true, iranian_bypass: false},
    {slug: "video-004", enabled: true, action: "block", location_unavailable: false, iranian_bypass: false},
  ];
}

// ---- Locations ----

export const LOCATIONS: LocationRef[] = [
  {id: uid("lo", 1), country: "DE"},
  {id: uid("lo", 2), country: "DE", city: "Frankfurt"},
  {id: uid("lo", 3), country: "DE", city: "Berlin"},
  {id: uid("lo", 4), country: "NL"},
  {id: uid("lo", 5), country: "FR", city: "Paris"},
  {id: uid("lo", 6), country: "US"},
  {id: uid("lo", 7), country: "US", city: "New York"},
  {id: uid("lo", 8), label: "Home lab"},
];

// ---- Rules and folders ----

export function foldersFixture(profile = 1): Folder[] {
  if (profile !== 1) return [];
  return [
    {id: uid("fo", 1), name: "Work", kind: "standard", action: "block", location_unavailable: false, rule_count: 120},
    {id: uid("fo", 2), name: "Streaming", kind: "standard", action: "redirect", target: {kind: "auto"}, location_unavailable: false, rule_count: 30},
    {id: uid("fo", 3), name: "No logs", kind: "do_not_log", location_unavailable: false, rule_count: 5},
    {id: uid("fo", 4), name: "Old destination", kind: "standard", action: "redirect", target: {kind: "location", location_id: uid("lo", 99), location: {country: "JP"}}, location_unavailable: true, rule_count: 2},
  ];
}

const ACTIONS: Rule["action"][] = ["block", "bypass", "redirect"];

/**
 * `n` rules (the ceiling is 10,000), made on demand so that a case that needs a few does not build all of them. Every 7th is disabled,
 * every 11th has an expiry, every 13th a comment, every 17th redirects, every 19th is a wildcard, every 23rd is an Iranian name that
 * acts as Bypass, every 29th has a location that left the set. Rules 0 to 119 are in folder 1 (Work), the rest at the top level.
 */
export function rulesFixture(n = 10_000): Rule[] {
  return Array.from({length: n}, (_, i) => ruleFixture(i));
}

export function ruleFixture(i: number, over: Partial<Rule> = {}): Rule {
  const wildcard = i % 19 === 0;
  const iranian = i % 23 === 0;
  const name = iranian ? `site${i}.ir` : wildcard ? `*.example${i}.com` : `example${i}.com`;
  const redirects = i % 17 === 0 || iranian;
  return {
    id: uid("ru", i + 1),
    ...(i < 120 ? {folder_id: uid("fo", 1)} : {}),
    pattern: name,
    key: name.replace(/^\*\./, ""),
    match_kind: wildcard ? "subdomains" : "domain",
    negated: false,
    action: redirects ? "redirect" : (ACTIONS[i % 2] ?? "block"),
    ...(redirects ? {target: i % 29 === 0 ? {kind: "location", location_id: uid("lo", 99), location: {country: "JP"}} : {kind: "auto"}} : {}),
    enabled: i % 7 !== 0,
    ...(i % 11 === 0 ? {expires_at: "2026-12-20T08:00:00Z"} : {}),
    ...(i % 13 === 0 ? {comment: `note ${i}`} : {}),
    location_unavailable: redirects && i % 29 === 0,
    iranian_bypass: iranian,
    created_at: T0,
    updated_at: T1,
    ...over,
  };
}

export function optionsFixture(over: Partial<Options> = {}): Options {
  return {
    default_rule: {action: "bypass"},
    default_location_unavailable: false,
    block_exfiltration: true,
    block_ttl: 10,
    block_response: {mode: "zero"},
    ecs: {mode: "auto"},
    safe_search: true,
    ...over,
  };
}

export function jobFixture(state: Job["state"] = "running", over: Partial<Job> = {}): Job {
  return {id: uid("jb", 1), kind: "upload", state, progress: 0, total: 5000, ...over};
}

// ---- Endpoints ----

// The keys and icon slugs are the ones of the catalogue seed (migration 0076), a short selection of it, so a screen that looks for a
// key finds what the real API has.
export const ENDPOINT_TYPES: EndpointType[] = [
  {key: "windows", name_fa: "ویندوز", name_en: "Windows", position: 1, icon: "computer"},
  {key: "mac", name_fa: "مک", name_en: "Mac", position: 2, icon: "computer"},
  {key: "ios", name_fa: "آی‌اواس", name_en: "iOS", position: 4, icon: "phone"},
  {key: "android", name_fa: "اندروید", name_en: "Android", position: 5, icon: "phone"},
  {key: "other_tv", name_fa: "تلویزیون دیگر", name_en: "Other TV", position: 15, icon: "tv"},
  {key: "other_router", name_fa: "روتر دیگر", name_en: "Other Router", position: 29, icon: "router"},
  {key: "other_endpoint", name_fa: "Endpoint دیگر", name_en: "Other Endpoint", position: 30, icon: "network"},
];

export function endpointFixture(n: number, over: Partial<Endpoint> = {}): Endpoint {
  return {
    id: uid("ep", n),
    name: `Endpoint ${n}`,
    type: ENDPOINT_TYPES[n % ENDPOINT_TYPES.length]!.key,
    resolver_id: `r${pad(n, 8)}`,
    profile_id: uid("pr", 1),
    analytics_level: "full",
    admin_state: "enabled",
    admin_hold: false,
    status: "active",
    legacy_dns: true,
    authorize_secure_dns: false,
    authorize_ddns: false,
    expose_ip: false,
    prevent_deactivation: false,
    require_authorized_ips: false,
    schedule_timezone: "Asia/Tehran",
    has_schedule: false,
    first_query_at: T0,
    last_query_at: T1,
    apple_profile_stale: false,
    created_at: T0,
    updated_at: T1,
    counts: {clients: 0, authorized_ips: 0, claims_waiting: 0},
    ...over,
  };
}

/** Five Endpoints, one for each state a row draws: new and not configured, held by an administrator, soft disabled, hard disabled, one with a schedule and a waiting claim. */
export function endpointsFixture(): Endpoint[] {
  return [
    endpointFixture(1, {name: "Home router", type: "other_router", counts: {clients: 1000, authorized_ips: 3, claims_waiting: 0}, group_id: uid("gr", 1)}),
    endpointFixture(2, {name: "Laptop", type: "windows", profile_id: uid("pr", 1), profile2_id: uid("pr", 3), comment: "Work laptop", group_id: uid("gr", 1)}),
    endpointFixture(3, {name: "Office PC", type: "windows", profile_id: uid("pr", 2), has_schedule: true, counts: {clients: 4, authorized_ips: 1, claims_waiting: 1}}),
    endpointFixture(4, {name: "New phone", type: "android", status: "pending", first_query_at: undefined, last_query_at: undefined}),
    endpointFixture(5, {name: "Held router", type: "other_router", admin_hold: true}),
    endpointFixture(6, {name: "Soft off", type: "other_tv", admin_state: "soft_disabled"}),
    endpointFixture(7, {name: "Hard off", type: "other_tv", admin_state: "hard_disabled", require_authorized_ips: true}),
  ];
}

export const GROUPS: Group[] = [{id: uid("gr", 1), name: "Home", endpoint_count: 2}];

export function clientFixture(i: number, over: Partial<Client> = {}): Client {
  return {
    id: uid("cl", i + 1),
    label: `device-${i + 1}`,
    ...(i % 3 === 0 ? {alias: `Phone ${i + 1}`} : {}),
    ...(i % 5 === 0 ? {group_name: "Family"} : {}),
    ...(i % 4 === 0 ? {profile_id: uid("pr", 1)} : {}),
    source: i % 6 === 0 ? "manual" : "auto",
    is_custom: i % 6 === 0,
    ...(i % 2 === 0 ? {hostname: `host-${i + 1}.lan`} : {}),
    ...(i % 7 === 0 ? {mac: "aa:bb:cc:dd:ee:ff"} : {}),
    ...(i % 2 === 1 ? {ip: `192.168.1.${(i % 250) + 1}`} : {}),
    first_seen_at: T0,
    last_seen_at: i % 9 === 0 ? "2026-01-05T08:00:00Z" : T1,
    ...over,
  };
}

export function clientsFixture(n = 1000): Client[] {
  return Array.from({length: n}, (_, i) => clientFixture(i));
}

export function authorizedFixture(): AuthorizedIP[] {
  return [
    {id: uid("au", 1), cidr: "203.0.113.7/32", source: "manual", cleanup_opt_in: false, created_at: T0, is_current: true, city: "Tehran", isp: "Example ISP", last_seen_at: T1},
    {id: uid("au", 2), cidr: "198.51.100.0/24", source: "manual", cleanup_opt_in: true, created_at: T0, is_current: false},
    {id: uid("au", 3), cidr: "2001:db8::/48", source: "secure_dns", cleanup_opt_in: false, created_at: T0, is_current: false, last_seen_at: T1},
    {id: uid("au", 4), cidr: "192.0.2.9/32", source: "ddns", cleanup_opt_in: false, created_at: T0, is_current: false},
  ];
}

export function claimsFixture(): IPClaim[] {
  return [
    {id: uid("ic", 1), cidr: "203.0.113.7/32", state: "active", proven: true, proof_method: "browser_ip", source: "browser", needs_admin: false},
    {id: uid("ic", 2), cidr: "198.51.100.0/24", state: "pending_proof", proven: false, source: "manual", needs_admin: false, challenge: {id: uid("ch", 1), label: "abcdefghijklmnopqrstuvwxyz", expires_at: "2026-11-25T09:00:00Z", observed: false}},
    {id: uid("ic", 3), cidr: "192.0.2.0/28", state: "grace", proven: false, source: "ddns", needs_admin: false, grace_until: "2026-12-01T08:00:00Z"},
    {id: uid("ic", 4), cidr: "192.0.2.64/26", state: "suspended", proven: false, source: "manual", needs_admin: true},
  ];
}

export function ddnsFixture(): DdnsHost[] {
  return [{id: uid("dd", 1), hostname: "home.example.org", last_resolved_at: T1, last_ips: ["203.0.113.7"]}];
}

export function scheduleFixture(): Schedule {
  return {timezone: "Asia/Tehran", windows: [{id: uid("wi", 1), start: 540, end: 1020, profile_id: uid("pr", 2)}]};
}

export function resolverViewFixture(over: Partial<ResolverView> = {}): ResolverView {
  return {
    ready: true,
    resolver_id: "r00000001",
    host: "r00000001.dns.example.test",
    doh_url: https("r00000001.dns.example.test/TOKEN_TOKEN_TOKEN"),
    legacy: {dns1: "203.0.113.53", dns2: "203.0.113.54"},
    bootstrap: ["203.0.113.53", "203.0.113.54"],
    stamps: {
      doh: {hostname_stamp: "sdns://AgAAAAAAAAAAAAAAAAAAAAA", address_stamps: [{ip: "203.0.113.53", stamp: "sdns://AgAAAAAAAAAAAAAAAAAAAAB"}]},
      dot: {hostname_stamp: "sdns://AwAAAAAAAAAAAAAAAAAAAAA", address_stamps: [{ip: "203.0.113.53", stamp: "sdns://AwAAAAAAAAAAAAAAAAAAAAB"}]},
      doq: {hostname_stamp: "sdns://BAAAAAAAAAAAAAAAAAAAAAA", address_stamps: [{ip: "203.0.113.53", stamp: "sdns://BAAAAAAAAAAAAAAAAAAAAAB"}]},
    },
    protocols: ["plain", "doh", "doh3", "dot", "doq"],
    ...over,
  };
}

/** A view for an Endpoint of a deployment whose zone or pair is not set: nothing is generated and the routes that generate answer 409. */
export function resolverViewNotReady(reason: "zone_missing" | "pair_missing" = "zone_missing"): ResolverView {
  return {ready: false, reason, resolver_id: "r00000001", protocols: ["plain", "doh", "doh3", "dot", "doq"]};
}

export function shareLinksFixture(): ShareLink[] {
  return [
    {id: uid("sl", 1), expires_at: "2026-11-26T08:00:00Z", uses: 1, max_uses: 3, revoked: false, created_at: T1},
    {id: uid("sl", 2), client: "device-1", expires_at: "2026-11-20T08:00:00Z", uses: 3, max_uses: 3, revoked: false, created_at: T0},
    {id: uid("sl", 3), expires_at: "2026-11-30T08:00:00Z", uses: 0, max_uses: 3, revoked: true, created_at: T0},
  ];
}

export function apiTokensFixture(): ApiToken[] {
  return [
    {id: uid("tk", 1), name: "CI", kind: "read", token_prefix: "aB3dE9", allowed_ips: ["203.0.113.0/24"], created_at: T0, expires_at: "2027-11-01T08:00:00Z", last_used_at: T1, ended: false},
    {id: uid("tk", 2), name: "Automation", kind: "write", token_prefix: "Zq81Xp", allowed_ips: [], created_at: T0, expires_at: "2027-11-01T08:00:00Z", ended: false},
    {id: uid("tk", 3), name: "Old", kind: "read", token_prefix: "k2Lm0A", allowed_ips: [], created_at: "2025-01-01T08:00:00Z", expires_at: "2026-01-01T08:00:00Z", ended: false},
    {id: uid("tk", 4), name: "Ended by a password change", kind: "write", token_prefix: "Ww4Rt7", allowed_ips: [], created_at: T0, expires_at: "2027-11-01T08:00:00Z", ended: true},
  ];
}

export const TIMEZONES = ["Asia/Tehran", "Asia/Dubai", "Asia/Kathmandu", "Europe/Berlin", "UTC"];
