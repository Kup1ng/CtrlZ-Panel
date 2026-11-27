// p4-nodes 4.3, 9.2 and 10.4, T-344. What the Domain page checks before it sends: the grammar of the three names, the rules between them,
// and the shape of the PEM text of a certificate upload. The server judges every one of these again (`domain_invalid`, `cert_invalid`,
// `cert_key_mismatch`, `cert_not_public`, `cert_expiring`) and knows the public suffix list, which the page does not carry; this is the part
// the page can say at once, in the field, with the reason in words.

// ---- names ------------------------------------------------------------------------------------------------------------------------

const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
/** A panel or admin host becomes the file name `<host>.caddy`, so it may not pass 249 bytes (p4-nodes 9.2). */
export const HOST_MAX = 249;
export const ZONE_MAX = 253;

/** What every zone starts with, and an example of the whole shape: the placeholders of the three fields and the words of the problems. Not translated: they are values. */
export const ZONE_PREFIX = "dns.";
export const PLACEHOLDER = {dns_zone: "dns.example.ir", panel_host: "panel.example.ir", admin_host: "admin.example.ir"} as const;

/** A value inside a sentence of the other direction keeps its own order: a left-to-right isolate (U+2066 .. U+2069). */
export const ltr = (value: string): string => `⁦${value}⁩`;

export type NameKind = "zone" | "panel" | "admin";
export type NameProblem = "grammar" | "tooLong" | "zonePrefix" | "zoneShort" | "underZone" | "same";

/** What is sent: trimmed and in lower case, as the route reads it. */
export const normaliseName = (text: string): string => text.trim().toLowerCase();

/** Whether `name` is `zone` or a name below it. */
export const isUnder = (name: string, zone: string): boolean => name === zone || name.endsWith(`.${zone}`);

function grammarOk(name: string): boolean {
  const labels = name.split(".");
  return labels.length >= 2 && labels.every((label) => LABEL.test(label));
}

/** The first thing wrong with one name, or null. An empty host is not a problem (it asks for no change); an empty zone is the caller's. */
export function nameProblem(kind: NameKind, text: string): NameProblem | null {
  const name = normaliseName(text);
  if (name === "") return null;
  if (name.length > (kind === "zone" ? ZONE_MAX : HOST_MAX)) return "tooLong";
  if (!grammarOk(name)) return "grammar";
  if (kind === "zone") {
    if (!name.startsWith("dns.")) return "zonePrefix";
    // `dns.` and a remainder of two labels at least: `dns.example.ir`, not `dns.ir` (the public suffix itself is the server's to judge).
    if (name.slice("dns.".length).split(".").length < 2) return "zoneShort";
  }
  return null;
}

export type DomainValues = {dns_zone: string; panel_host: string; admin_host: string};

/**
 * Whether two drafts of the form are one value. The length of the transition is not part of it: it is shown only while the zone differs from
 * the server's, and then the draft is a change whatever the length is. Counted, a length left over from a zone typed and put back would
 * keep Save lit and send a write that changes nothing (PG-r2-3).
 */
export function sameDomainDraft(a: DomainValues, b: DomainValues): boolean {
  return normaliseName(a.dns_zone) === normaliseName(b.dns_zone) && normaliseName(a.panel_host) === normaliseName(b.panel_host) && normaliseName(a.admin_host) === normaliseName(b.admin_host);
}

/**
 * The problem of each field, keyed by field, for the whole form: the grammar of each, and then the rules between them. A host may not be
 * the zone or below it, whichever zone is live (the new one, the one being replaced during a transition, the one now), and the two hosts
 * differ, since Caddy would serve two services from one name.
 */
export function formProblems(values: DomainValues, liveZones: readonly string[]): Partial<Record<keyof DomainValues, NameProblem>> {
  const out: Partial<Record<keyof DomainValues, NameProblem>> = {};
  const zone = normaliseName(values.dns_zone);
  const panel = normaliseName(values.panel_host);
  const admin = normaliseName(values.admin_host);
  const zoneProblem = nameProblem("zone", values.dns_zone);
  if (zoneProblem) out.dns_zone = zoneProblem;
  const panelProblem = nameProblem("panel", values.panel_host);
  if (panelProblem) out.panel_host = panelProblem;
  const adminProblem = nameProblem("admin", values.admin_host);
  if (adminProblem) out.admin_host = adminProblem;
  const zones = [...new Set([zone, ...liveZones.map(normaliseName)].filter((z) => z !== ""))];
  if (!out.panel_host && panel !== "" && zones.some((z) => isUnder(panel, z))) out.panel_host = "underZone";
  if (!out.admin_host && admin !== "" && zones.some((z) => isUnder(admin, z))) out.admin_host = "underZone";
  if (!out.admin_host && !out.panel_host && panel !== "" && panel === admin) out.admin_host = "same";
  return out;
}

/** The zones that serve now: the one set, and the one being replaced while its transition runs. */
export function liveZones(settings: {dns_zone?: string | undefined; prev_dns_zone?: string | undefined; transition_until?: string | undefined}, now: number = Date.now()): string[] {
  const zones: string[] = [];
  if (settings.dns_zone) zones.push(settings.dns_zone);
  if (settings.prev_dns_zone && settings.transition_until && Date.parse(settings.transition_until) > now) zones.push(settings.prev_dns_zone);
  return zones;
}

/** A transition is running: the zone cannot change again until it ends (`transition_active`). */
export const transitionRunning = (settings: {prev_dns_zone?: string | undefined; transition_until?: string | undefined}, now: number = Date.now()): boolean =>
  settings.prev_dns_zone !== undefined && settings.transition_until !== undefined && Date.parse(settings.transition_until) > now;

/**
 * A change from one zone to another starts a transition; a first set, and a change of a host only, do not (p4-nodes 10.4). The impact is
 * asked only for the first kind, because only then do the Endpoints' setup values and the Apple profiles point at a zone that goes.
 */
export const startsTransition = (current: string | undefined, next: string): boolean => current !== undefined && current !== "" && normaliseName(next) !== normaliseName(current);

// ---- certificates -----------------------------------------------------------------------------------------------------------------

export const CHAIN_MAX = 32768;
export const KEY_MAX = 8192;
export const PEM_MIN = 64;
/** The pattern of the API's `chain_pem` and `key_pem`: it begins with a BEGIN line and holds base64, spaces, line ends and dashes. */
const PEM_SHAPE = /^-----BEGIN [A-Z ]+-----[A-Za-z0-9+/=\r\n -]*$/;

export type PemProblem = "empty" | "tooShort" | "tooLong" | "shape" | "notCertificate" | "isKey" | "notKey" | "isCertificate";

const bytes = (text: string) => new TextEncoder().encode(text).length;

/** The first thing wrong with the text of a chain or a key, or null. The key is never printed back: only its problem is named. */
export function pemProblem(part: "chain" | "key", text: string): PemProblem | null {
  const body = text.trim();
  if (body === "") return "empty";
  if (body.length < PEM_MIN) return "tooShort";
  if (bytes(body) > (part === "chain" ? CHAIN_MAX : KEY_MAX)) return "tooLong";
  const hasKey = /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(body);
  const hasCertificate = /-----BEGIN CERTIFICATE-----/.test(body);
  // The mistakes people make: the key pasted in the chain box, and the other way round. Said before the shape, since it is the clearer reason.
  if (part === "chain" && hasKey) return "isKey";
  if (part === "key" && !hasKey && hasCertificate) return "isCertificate";
  if (!PEM_SHAPE.test(body)) return "shape";
  if (part === "chain" && !hasCertificate) return "notCertificate";
  if (part === "key" && !hasKey) return "notKey";
  return null;
}

const KEY_BLOCK = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g;

/**
 * The text of the chain box without any private key block in it, and whether there was one. A combined fullchain and key file, or a paste
 * of both, puts the key where it must not be held; the box drops the block at once, so the key is not kept in the state of the chain (PG-r3-4).
 * A block with no END line is dropped to the end of the text: a half-pasted key is still a key.
 */
export function withoutPrivateKey(text: string): {text: string; removed: boolean} {
  if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text)) return {text, removed: false};
  // The blank lines the block leaves are trimmed with it, so the box holds the certificates and nothing else.
  return {text: text.replace(KEY_BLOCK, "").trim(), removed: true};
}

export const CERTIFICATE_KINDS = ["wildcard", "panel", "admin"] as const;
export type UploadKind = (typeof CERTIFICATE_KINDS)[number];

/** A certificate an admin can retire: an uploaded row that is active (the route answers `not_found` for any other, p4-nodes 9.2). */
export const canRetire = (row: {source: string; state: string; kind: string}): boolean =>
  row.source === "uploaded" && row.state === "active" && (CERTIFICATE_KINDS as readonly string[]).includes(row.kind);

/** Days left, rounded down; negative once it has passed. */
export const daysLeft = (notAfter: string, now: number = Date.now()): number => Math.floor((Date.parse(notAfter) - now) / 86_400_000);

/** The page warns when an active certificate has this many days or fewer left. */
export const EXPIRY_WARN_DAYS = 30;
