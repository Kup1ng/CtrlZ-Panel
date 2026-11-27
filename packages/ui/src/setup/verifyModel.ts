// The setup verification of spec p3 8.4 and Plan "تایید راه‌اندازی از مرورگر", without React so a plain test holds the rules.
//
// The page draws a fresh 26-character label per attempt and asks `https://<label>.verify.<zone>/v`. To fetch that name the browser has to
// resolve it, and it does so through whatever DNS the device uses: if that is this Endpoint, a node answers the name and remembers the
// label with the identity it came from. The answer is `{seen, n, rid_tag, client_tag, proto_tag}`: `n` is 16 random bytes per answer, and
// each tag is the first 16 bytes (hex) of HMAC-SHA256 with the key `label || n` over a message the page can build for the Endpoint it
// expects. So the answer never names the Endpoint, the client or the protocol, and the page proves a match by computing the tags itself.
//
//   pending: the probe failed, or `seen` is false (the name did not come through this service)
//   partial: `seen` is true but `rid_tag` is not the expected Endpoint's (the query was not identified, or was another Endpoint's)
//   success: two probes in a row had `seen` true and the expected `rid_tag` (a second probe, so one lucky answer does not count)

export const LABEL_LENGTH = 26;
export const POLL_MS = 3000;
/** How long one probe may take. A fresh host needs its own DNS lookup, TCP and TLS, so a slow mobile link needs more than the poll interval; the next label starts on time anyway. */
export const PROBE_TIMEOUT_MS = 10_000;
export const MAX_MS = 120_000;
export const SUCCESS_STREAK = 2;
// RFC 4648 base32 without padding: 32 letters, so 5 random bits make one letter and nothing is biased.
const ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

/** A label drawn from a CSPRNG, `[a-z2-7]{26}`. */
export function newLabel(random: (bytes: Uint8Array) => Uint8Array = (b) => crypto.getRandomValues(b)): string {
  const bytes = random(new Uint8Array(LABEL_LENGTH));
  let out = "";
  for (let i = 0; i < LABEL_LENGTH; i++) out += ALPHABET[bytes[i]! & 31];
  return out;
}

/** The protocols of the `proto_tag`, in the order the page tries them (the Plan says six: Plain DNS over UDP and TCP, DoH, DoH3, DoT, DoQ). */
export const VERIFY_PROTOCOLS = ["udp", "tcp", "doh", "doh3", "dot", "doq"] as const;
export type VerifyProtocol = (typeof VERIFY_PROTOCOLS)[number];

/** The protocol byte of the `proto_tag` message: the number of `common.v1.Protocol` (spec p4-nodes 7.6). One table, so a drift shows in one place. */
export const PROTOCOL_NUMBER: Record<VerifyProtocol, number> = {udp: 1, tcp: 2, doh: 3, dot: 4, doq: 5, doh3: 6};

export type VerifyAnswer = {seen: boolean; n: string; rid_tag: string; client_tag: string; proto_tag: string};

/** The shape of `/v`, or `null`. Any other body (an error page, a captive portal's HTML) is no answer. */
export function parseAnswer(value: unknown): VerifyAnswer | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;
  const hex = (x: unknown, length: number): x is string => typeof x === "string" && new RegExp(`^[0-9a-f]{${length}}$`).test(x);
  if (typeof v.seen !== "boolean") return null;
  if (!hex(v.n, 32) || !hex(v.rid_tag, 32) || !hex(v.client_tag, 32) || !hex(v.proto_tag, 32)) return null;
  return {seen: v.seen, n: v.n, rid_tag: v.rid_tag, client_tag: v.client_tag, proto_tag: v.proto_tag};
}

const encoder = new TextEncoder();
const fromHex = (hex: string): Uint8Array<ArrayBuffer> => Uint8Array.from(hex.match(/../g) ?? [], (h) => parseInt(h, 16));
const toHex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/** First 16 bytes of HMAC-SHA256(key = label || n, message), as hex. */
export async function tagOf(label: string, n: string, message: Uint8Array<ArrayBuffer>): Promise<string> {
  const labelBytes = encoder.encode(label);
  const nBytes = fromHex(n);
  const keyBytes = new Uint8Array(labelBytes.length + nBytes.length);
  keyBytes.set(labelBytes, 0);
  keyBytes.set(nBytes, labelBytes.length);
  const key = await crypto.subtle.importKey("raw", keyBytes, {name: "HMAC", hash: "SHA-256"}, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  return toHex(mac.slice(0, 16));
}

function join(parts: (Uint8Array | number)[]): Uint8Array<ArrayBuffer> {
  const chunks = parts.map((p) => (typeof p === "number" ? Uint8Array.of(p) : p));
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
}

/**
 * The three messages of an Endpoint (and a client): `rid`, `rid || 0x00 || client`, and `rid || 0x01 || protocol byte` for each protocol.
 * The client label of an unnamed client is empty here: the node's activity says `default`, but its `client_tag` does not (spec p4-nodes 7.6).
 */
export function messagesOf(resolverId: string, client: string) {
  const rid = encoder.encode(resolverId);
  return {
    rid,
    client: join([rid, 0, encoder.encode(client)]),
    proto: (protocol: VerifyProtocol) => join([rid, 1, PROTOCOL_NUMBER[protocol]]),
  };
}

export type Judgement = {
  state: "pending" | "partial" | "match";
  /** The protocol the query came over, when the Endpoint matched. */
  protocol?: VerifyProtocol;
  /** The client matched too (the Endpoint's own unnamed client or the one in the view). */
  clientMatched?: boolean;
};

/** Compares an answer with what is expected. Equal-length hex strings, and nothing secret: a plain comparison is enough. */
export async function judge(label: string, answer: VerifyAnswer | null, expected: {resolverId: string; client?: string}): Promise<Judgement> {
  if (!answer || !answer.seen) return {state: "pending"};
  const messages = messagesOf(expected.resolverId, expected.client ?? "");
  if ((await tagOf(label, answer.n, messages.rid)) !== answer.rid_tag) return {state: "partial"};
  const clientMatched = (await tagOf(label, answer.n, messages.client)) === answer.client_tag;
  for (const protocol of VERIFY_PROTOCOLS) {
    if ((await tagOf(label, answer.n, messages.proto(protocol))) === answer.proto_tag) return {state: "match", protocol, clientMatched};
  }
  return {state: "match", clientMatched};
}

/** `confirming` is the one probe between the first match and Success: the second probe has not answered yet. */
export type VerifyState = "idle" | "pending" | "partial" | "confirming" | "success" | "timeout";

/** The state the person sees after each probe. `streak` counts matches in a row; a probe that is not a match ends it. */
export function nextState(previous: {streak: number}, judgement: Judgement): {state: Exclude<VerifyState, "idle" | "timeout">; streak: number} {
  if (judgement.state === "match") {
    const streak = previous.streak + 1;
    return {state: streak >= SUCCESS_STREAK ? "success" : "confirming", streak};
  }
  return {state: judgement.state, streak: 0};
}

/** The host a probe asks: `<label>.verify.<zone>`, where the zone is what follows the first label of the Resolver view's host. */
export function probeHost(label: string, viewHost: string | undefined): string | null {
  if (!viewHost) return null;
  const dot = viewHost.indexOf(".");
  if (dot < 1) return null;
  return `${label}.verify.${viewHost.slice(dot + 1)}`;
}

/** The name of the manual check: `myip.<zone>`, which only an identified Endpoint is answered (shared contract 8a.3). */
export function myipHost(viewHost: string | undefined): string | null {
  if (!viewHost) return null;
  const dot = viewHost.indexOf(".");
  if (dot < 1) return null;
  return `myip.${viewHost.slice(dot + 1)}`;
}

/**
 * Whether a probe host is inside what the page's policy allows: `CTRLZ_VERIFY_ORIGIN` is up to two `https://*.verify.dns.<domain>` (the second is the previous zone during a domain transition), and a host that is
 * not under that suffix would be refused by `connect-src` anyway, so the verification is not offered for it.
 */
export function inVerifyOrigin(host: string, verifyOrigin: string | readonly string[] | null): boolean {
  const origins = typeof verifyOrigin === "string" ? [verifyOrigin] : (verifyOrigin ?? []);
  return origins.some((origin) => {
    const suffix = origin.replace(/^https:\/\/\*/, "");
    return suffix.startsWith(".verify.") && host.endsWith(suffix) && host.length > suffix.length && !host.slice(0, -suffix.length).includes(".");
  });
}
