import {api} from "./client.ts";
import {required} from "./core.ts";
import type {createApiClient} from "./core.ts";
import type {components, paths} from "./generated/panel";

// Spec 14.2. The WebAuthn routes carry the browser's credential JSON as the body
// and the ticket in the `X-Ctrlz-Ticket` header. No WebAuthn library: the browser
// has `parse*OptionsFromJSON` and `toJSON()` (Chrome 129, Safari 18.4, Firefox 119),
// and the fallbacks below are the same conversion by hand for the rest.

type Schemas = components["schemas"];
export type WebAuthnResponse = Schemas["WebAuthnResponse"];
export type PasskeyCeremony = Schemas["PasskeyCeremony"];
/** What go-webauthn sends: the options nested under `publicKey`. */
export type CeremonyOptions = PasskeyCeremony["options"];

// ---- base64url -----------------------------------------------------------

const B64_URL = /^[A-Za-z0-9_-]*$/;

export function base64urlToBytes(text: string): Uint8Array<ArrayBuffer> {
  if (!B64_URL.test(text)) throw new TypeError("not base64url");
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function bytesToBase64url(input: ArrayBuffer | ArrayBufferView): string {
  const bytes = input instanceof ArrayBuffer ? new Uint8Array(input) : new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---- support and errors ---------------------------------------------------

export function isWebAuthnSupported(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential === "function" && !!navigator.credentials;
}

/**
 * The user closed or refused the prompt (`NotAllowedError`), or this ceremony was
 * replaced by another (`AbortError`). The login screen stays silent for it (spec 10.2).
 */
export function isWebAuthnCancel(error: unknown): boolean {
  return error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError");
}

// ---- options --------------------------------------------------------------

type Json = Record<string, unknown>;

/** go-webauthn nests the options under `publicKey`. A bare options object is accepted too. */
export function unwrapOptions(options: unknown): Json {
  if (typeof options !== "object" || options === null) throw new TypeError("no options");
  const nested = (options as Json).publicKey;
  return typeof nested === "object" && nested !== null ? (nested as Json) : (options as Json);
}

function descriptors(list: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) return undefined;
  return list.map((d: Json) => ({
    type: "public-key" as const,
    id: base64urlToBytes(String(d.id)),
    ...(Array.isArray(d.transports) ? {transports: d.transports as AuthenticatorTransport[]} : {}),
  }));
}

type StaticParser = {
  parseCreationOptionsFromJSON?: (json: unknown) => PublicKeyCredentialCreationOptions;
  parseRequestOptionsFromJSON?: (json: unknown) => PublicKeyCredentialRequestOptions;
};

const parser = (): StaticParser =>
  typeof PublicKeyCredential === "undefined" ? {} : (PublicKeyCredential as unknown as StaticParser);

export function creationOptions(serverOptions: unknown): PublicKeyCredentialCreationOptions {
  const json = unwrapOptions(serverOptions);
  const parse = parser().parseCreationOptionsFromJSON;
  if (parse) return parse.call(PublicKeyCredential, json);
  const user = json.user as Json;
  return {
    ...(json as object),
    challenge: base64urlToBytes(String(json.challenge)),
    user: {...(user as object), id: base64urlToBytes(String(user.id))} as unknown as PublicKeyCredentialUserEntity,
    excludeCredentials: descriptors(json.excludeCredentials),
  } as unknown as PublicKeyCredentialCreationOptions;
}

export function requestOptions(serverOptions: unknown): PublicKeyCredentialRequestOptions {
  const json = unwrapOptions(serverOptions);
  const parse = parser().parseRequestOptionsFromJSON;
  if (parse) return parse.call(PublicKeyCredential, json);
  return {
    ...(json as object),
    challenge: base64urlToBytes(String(json.challenge)),
    allowCredentials: descriptors(json.allowCredentials),
  } as PublicKeyCredentialRequestOptions;
}

// ---- credential to JSON ---------------------------------------------------

type ToJson = {toJSON?: () => unknown};

/**
 * The body of a finish route. `toJSON()` where the browser has it; otherwise the
 * same shape by hand. Either way only the members the schema names are kept, so a
 * member a newer browser adds cannot turn a valid ceremony into a 400.
 */
export function credentialToJSON(credential: PublicKeyCredential): WebAuthnResponse {
  const raw: Json =
    typeof (credential as ToJson).toJSON === "function"
      ? ((credential as ToJson).toJSON!() as Json)
      : fallbackJson(credential);
  return pickSchemaMembers(raw);
}

function fallbackJson(credential: PublicKeyCredential): Json {
  const response = credential.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse;
  const out: Json = {
    id: credential.id,
    rawId: bytesToBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? null,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {clientDataJSON: bytesToBase64url(response.clientDataJSON)},
  };
  const r = out.response as Json;
  if ("attestationObject" in response && response.attestationObject) {
    r.attestationObject = bytesToBase64url(response.attestationObject);
    if (typeof response.getTransports === "function") r.transports = response.getTransports();
    if (typeof response.getAuthenticatorData === "function") r.authenticatorData = bytesToBase64url(response.getAuthenticatorData());
    const key = typeof response.getPublicKey === "function" ? response.getPublicKey() : null;
    r.publicKey = key ? bytesToBase64url(key) : null;
    if (typeof response.getPublicKeyAlgorithm === "function") r.publicKeyAlgorithm = response.getPublicKeyAlgorithm();
  } else {
    r.authenticatorData = bytesToBase64url(response.authenticatorData);
    r.signature = bytesToBase64url(response.signature);
    r.userHandle = response.userHandle ? bytesToBase64url(response.userHandle) : null;
  }
  return out;
}

const TOP = ["id", "rawId", "type", "authenticatorAttachment", "response", "clientExtensionResults"] as const;
const INNER = [
  "clientDataJSON",
  "attestationObject",
  "authenticatorData",
  "publicKey",
  "publicKeyAlgorithm",
  "signature",
  "userHandle",
  "transports",
] as const;

/** Exported for the test: keeps only the members of the `WebAuthnResponse` schema. */
export function pickSchemaMembers(raw: Json): WebAuthnResponse {
  const out: Json = {};
  for (const key of TOP) if (raw[key] !== undefined) out[key] = raw[key];
  const inner: Json = {};
  const response = (raw.response ?? {}) as Json;
  for (const key of INNER) if (response[key] !== undefined) inner[key] = response[key];
  out.response = inner;
  return out as WebAuthnResponse;
}

// ---- ceremonies -----------------------------------------------------------

export async function createCredential(serverOptions: unknown, signal?: AbortSignal): Promise<WebAuthnResponse> {
  const credential = await navigator.credentials.create({publicKey: creationOptions(serverOptions), signal});
  if (!(credential instanceof PublicKeyCredential)) throw new TypeError("no credential");
  return credentialToJSON(credential);
}

export async function getAssertion(serverOptions: unknown, signal?: AbortSignal): Promise<WebAuthnResponse> {
  const credential = await navigator.credentials.get({publicKey: requestOptions(serverOptions), signal});
  if (!(credential instanceof PublicKeyCredential)) throw new TypeError("no credential");
  return credentialToJSON(credential);
}

// ---- the routes -----------------------------------------------------------
// Each is begin, the browser prompt, finish. The ticket goes in the header and
// lives only in this function: it is never returned or stored (spec 14.4).
// A factory over the client, so the tests can run the real sequence on a fake
// `fetch`; the exports below are bound to the app's client.

type Ceremony = {signal?: AbortSignal};
type Client = ReturnType<typeof createApiClient<paths>>;

export function webauthnRoutes(client: Client) {
  return {
    /** `POST /auth/passkey/login/begin` and `finish`. Resolves to the `LoginResult`. */
    async passkeyLogin({rememberMe, signal}: Ceremony & {rememberMe?: boolean} = {}) {
      const begin = required(await client.POST("/auth/passkey/login/begin", {body: {remember_me: rememberMe}, signal}));
      const assertion = await getAssertion(begin.options, signal);
      // Nothing has happened on the server yet, so leaving here costs nothing.
      signal?.throwIfAborted();
      // `finish` opens the session and sends its cookies. The abort reaches only the prompt and `begin`: a
      // `finish` cancelled in flight may already have opened the session while the caller never sees the
      // answer, and then nothing could end it (wp8-r8-3). The caller checks its own signal once this returns
      // and ends a session it no longer wants.
      return required(await client.POST("/auth/passkey/login/finish", {params: {header: {"X-Ctrlz-Ticket": begin.ticket}}, body: assertion}));
    },

    /** Reauth with a passkey, `POST /auth/reauth/passkey/begin` and `finish` (AUTH 3.5, 7.6). */
    async passkeyReauth({signal}: Ceremony = {}) {
      const begin = required(await client.POST("/auth/reauth/passkey/begin", {signal}));
      const assertion = await getAssertion(begin.options, signal);
      // A `finish` that was sent is not cancelled, for every ceremony (gate-r16-9, see passkeyLogin): this one opens a reauth window that
      // the page would never learn of.
      signal?.throwIfAborted();
      await client.POST("/auth/reauth/passkey/finish", {params: {header: {"X-Ctrlz-Ticket": begin.ticket}}, body: assertion});
    },

    /** Add a passkey, `POST /account/passkeys/begin` and `finish`. Needs a live reauth. */
    async passkeyAdd({signal}: Ceremony = {}) {
      const begin = required(await client.POST("/account/passkeys/begin", {body: {}, signal}));
      const attestation = await createCredential(begin.options, signal);
      // `finish` registers the passkey and ends the account's other sessions. A row that closes while it is on the wire must not cancel it:
      // the server may already have committed, and the page would keep a stale list and say nothing of the sessions (gate-r16-9). The caller
      // sees the answer, and the mutation's onSuccess drops the caches whether or not the row is still there.
      signal?.throwIfAborted();
      return required(await client.POST("/account/passkeys/finish", {params: {header: {"X-Ctrlz-Ticket": begin.ticket}}, body: attestation}));
    },

    /**
     * Forgot Password, second factor by passkey: the `reset` ticket goes to begin in the
     * body, the browser answers, and finish returns the ticket for `/password/reset/complete`.
     * Returns the new ticket, which the caller keeps in component state only.
     */
    async passkeyResetProof(resetTicket: string, {signal}: Ceremony = {}): Promise<string> {
      const begin = required(await client.POST("/auth/password/reset/passkey/begin", {body: {ticket: resetTicket}, signal}));
      const assertion = await getAssertion(begin.options, signal);
      // Not cancelled once sent, like the other two (gate-r16-9): the new ticket is the answer, and a cancelled call loses it.
      signal?.throwIfAborted();
      const done = required(
        await client.POST("/auth/password/reset/passkey/finish", {
          params: {header: {"X-Ctrlz-Ticket": begin.ticket}},
          body: assertion,
        }),
      );
      return done.ticket;
    },
  };
}

export const {passkeyLogin, passkeyReauth, passkeyAdd, passkeyResetProof} = webauthnRoutes(api);
