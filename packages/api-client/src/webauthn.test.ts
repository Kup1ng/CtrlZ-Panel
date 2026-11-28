import {afterEach, describe, expect, it, vi} from "vitest";

import {createApiClient} from "./core.ts";
import type {paths} from "./generated/panel";
import {
  base64urlToBytes,
  bytesToBase64url,
  createCredential,
  creationOptions,
  credentialToJSON,
  getAssertion,
  isWebAuthnCancel,
  pickSchemaMembers,
  requestOptions,
  unwrapOptions,
  webauthnRoutes,
} from "./webauthn.ts";

afterEach(() => vi.unstubAllGlobals());

const bytes = (...n: number[]) => new Uint8Array(n);

// What go-webauthn sends: base64url members, nested under `publicKey`.
const CHALLENGE = bytesToBase64url(bytes(1, 2, 3, 250, 251, 252));
const serverCreation = {
  publicKey: {
    challenge: CHALLENGE,
    rp: {id: "panel.example", name: "Ctrl Z"},
    user: {id: bytesToBase64url(bytes(9, 8, 7)), name: "u", displayName: "u"},
    pubKeyCredParams: [{type: "public-key", alg: -7}],
    excludeCredentials: [{type: "public-key", id: bytesToBase64url(bytes(5, 5)), transports: ["internal"]}],
    authenticatorSelection: {residentKey: "preferred", userVerification: "preferred"},
  },
};
const serverRequest = {
  publicKey: {challenge: CHALLENGE, rpId: "panel.example", allowCredentials: [{type: "public-key", id: bytesToBase64url(bytes(4, 4, 4))}]},
};

describe("base64url", () => {
  it("round-trips, with no padding and the URL alphabet", () => {
    const data = bytes(251, 255, 254, 0, 1, 62, 63);
    const text = bytesToBase64url(data);
    expect(text).toMatch(/^[A-Za-z0-9_-]+$/);
    expect([...base64urlToBytes(text)]).toEqual([...data]);
    expect(bytesToBase64url(bytes())).toBe("");
    expect([...base64urlToBytes("")]).toEqual([]);
  });

  it("refuses a character outside the alphabet", () => {
    for (const bad of ["a+b", "a/b", "a=b", "a b", "é"]) expect(() => base64urlToBytes(bad), bad).toThrow(TypeError);
  });

  it("encodes a view of a larger buffer by its own window", () => {
    const whole = bytes(0, 1, 2, 3, 4);
    expect(bytesToBase64url(whole.subarray(1, 3))).toBe(bytesToBase64url(bytes(1, 2)));
    expect(bytesToBase64url(whole.buffer)).toBe(bytesToBase64url(whole));
  });
});

describe("unwrapOptions", () => {
  it("unwraps what go-webauthn nests under publicKey, and takes a bare object as is", () => {
    expect(unwrapOptions(serverRequest)).toBe(serverRequest.publicKey);
    expect(unwrapOptions({challenge: "x"})).toEqual({challenge: "x"});
  });

  it("refuses what is not an object", () => {
    for (const bad of [null, undefined, "x", 3]) expect(() => unwrapOptions(bad)).toThrow(TypeError);
  });
});

describe("options without the browser's parsers (the fallback)", () => {
  it("decodes the creation options", () => {
    const o = creationOptions(serverCreation);
    expect([...new Uint8Array(o.challenge as ArrayBuffer)]).toEqual([1, 2, 3, 250, 251, 252]);
    expect([...new Uint8Array(o.user.id as ArrayBuffer)]).toEqual([9, 8, 7]);
    expect(o.user.name).toBe("u");
    expect([...new Uint8Array(o.excludeCredentials![0]!.id as ArrayBuffer)]).toEqual([5, 5]);
    expect(o.excludeCredentials![0]).toMatchObject({type: "public-key", transports: ["internal"]});
    expect(o.rp).toEqual({id: "panel.example", name: "Ctrl Z"});
    expect(o.pubKeyCredParams).toEqual([{type: "public-key", alg: -7}]);
  });

  it("decodes the request options, and leaves allowCredentials undefined when the server sent none", () => {
    const o = requestOptions(serverRequest);
    expect([...new Uint8Array(o.challenge as ArrayBuffer)]).toEqual([1, 2, 3, 250, 251, 252]);
    expect([...new Uint8Array(o.allowCredentials![0]!.id as ArrayBuffer)]).toEqual([4, 4, 4]);
    expect(o.rpId).toBe("panel.example");
    expect(requestOptions({publicKey: {challenge: CHALLENGE}}).allowCredentials).toBeUndefined();
  });

  it("refuses a challenge that is not base64url", () => {
    expect(() => requestOptions({publicKey: {challenge: "not base64!"}})).toThrow(TypeError);
  });
});

describe("options with the browser's parsers", () => {
  it("hands the unwrapped JSON to parseCreationOptionsFromJSON and parseRequestOptionsFromJSON", () => {
    const parsedCreation = {parsed: "creation"};
    const parsedRequest = {parsed: "request"};
    const parseCreationOptionsFromJSON = vi.fn(() => parsedCreation);
    const parseRequestOptionsFromJSON = vi.fn(() => parsedRequest);
    vi.stubGlobal("PublicKeyCredential", Object.assign(function PublicKeyCredential() {}, {parseCreationOptionsFromJSON, parseRequestOptionsFromJSON}));
    expect(creationOptions(serverCreation)).toBe(parsedCreation);
    expect(requestOptions(serverRequest)).toBe(parsedRequest);
    expect(parseCreationOptionsFromJSON).toHaveBeenCalledWith(serverCreation.publicKey);
    expect(parseRequestOptionsFromJSON).toHaveBeenCalledWith(serverRequest.publicKey);
  });
});

// Chrome's toJSON for an attestation has more than the schema holds.
const attestationJson = {
  id: "cred-id",
  rawId: "cred-id",
  type: "public-key",
  authenticatorAttachment: "platform",
  clientExtensionResults: {credProps: {rk: true}},
  response: {
    clientDataJSON: "cdj",
    attestationObject: "att",
    authenticatorData: "ad",
    publicKey: "pk",
    publicKeyAlgorithm: -7,
    transports: ["internal", "hybrid"],
    somethingNew: "not in the schema",
  },
  somethingElse: 1,
};

function fakeCredential(extra: Record<string, unknown>): PublicKeyCredential {
  return extra as unknown as PublicKeyCredential;
}

describe("credentialToJSON", () => {
  it("uses toJSON() and keeps only the members of the WebAuthnResponse schema", () => {
    const json = credentialToJSON(fakeCredential({toJSON: () => attestationJson}));
    expect(json).toEqual({
      id: "cred-id",
      rawId: "cred-id",
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {credProps: {rk: true}},
      response: {
        clientDataJSON: "cdj",
        attestationObject: "att",
        authenticatorData: "ad",
        publicKey: "pk",
        publicKeyAlgorithm: -7,
        transports: ["internal", "hybrid"],
      },
    });
  });

  it("builds an attestation by hand when the browser has no toJSON", () => {
    const buf = (...n: number[]) => bytes(...n).buffer;
    const json = credentialToJSON(
      fakeCredential({
        id: "abc",
        rawId: buf(1, 2),
        type: "public-key",
        authenticatorAttachment: null,
        getClientExtensionResults: () => ({}),
        response: {
          clientDataJSON: buf(3),
          attestationObject: buf(4, 5),
          getTransports: () => ["usb"],
          getAuthenticatorData: () => buf(6),
          getPublicKey: () => buf(7),
          getPublicKeyAlgorithm: () => -257,
        },
      }),
    );
    expect(json).toEqual({
      id: "abc",
      rawId: bytesToBase64url(bytes(1, 2)),
      type: "public-key",
      authenticatorAttachment: null,
      clientExtensionResults: {},
      response: {
        clientDataJSON: bytesToBase64url(bytes(3)),
        attestationObject: bytesToBase64url(bytes(4, 5)),
        authenticatorData: bytesToBase64url(bytes(6)),
        publicKey: bytesToBase64url(bytes(7)),
        publicKeyAlgorithm: -257,
        transports: ["usb"],
      },
    });
  });

  it("builds an assertion by hand, with a null userHandle when there is none", () => {
    const buf = (...n: number[]) => bytes(...n).buffer;
    const json = credentialToJSON(
      fakeCredential({
        id: "abc",
        rawId: buf(1),
        type: "public-key",
        getClientExtensionResults: () => ({}),
        response: {clientDataJSON: buf(3), authenticatorData: buf(8), signature: buf(9), userHandle: null},
      }),
    );
    expect(json.response).toEqual({
      clientDataJSON: bytesToBase64url(bytes(3)),
      authenticatorData: bytesToBase64url(bytes(8)),
      signature: bytesToBase64url(bytes(9)),
      userHandle: null,
    });
    expect(json.authenticatorAttachment).toBeNull();
  });

  it("drops members that are undefined and ones the schema does not name", () => {
    const out = pickSchemaMembers({id: "a", rawId: "a", type: "public-key", extra: 1, response: {clientDataJSON: "c", x: 1, signature: undefined}});
    expect(out).toEqual({id: "a", rawId: "a", type: "public-key", response: {clientDataJSON: "c"}});
  });
});

describe("cancel", () => {
  it("is NotAllowedError and AbortError, and nothing else", () => {
    expect(isWebAuthnCancel(new DOMException("x", "NotAllowedError"))).toBe(true);
    expect(isWebAuthnCancel(new DOMException("x", "AbortError"))).toBe(true);
    expect(isWebAuthnCancel(new DOMException("x", "SecurityError"))).toBe(false);
    expect(isWebAuthnCancel(new DOMException("x", "InvalidStateError"))).toBe(false);
    expect(isWebAuthnCancel(new Error("NotAllowedError"))).toBe(false);
  });
});

// A stand-in for the browser's credential container and class.
class FakePublicKeyCredential {
  constructor(private readonly json: unknown) {}
  toJSON() {
    return this.json;
  }
}

function stubBrowser(json: unknown) {
  const credential = new FakePublicKeyCredential(json);
  const create = vi.fn(async () => credential);
  const get = vi.fn(async () => credential);
  vi.stubGlobal("PublicKeyCredential", FakePublicKeyCredential);
  vi.stubGlobal("navigator", {credentials: {create, get}});
  return {create, get};
}

describe("ceremonies", () => {
  it("createCredential and getAssertion call the browser with decoded options and return schema JSON", async () => {
    const browser = stubBrowser(attestationJson);
    const made = await createCredential(serverCreation);
    expect(made.response.attestationObject).toBe("att");
    const calls = browser.create.mock.calls as unknown as {publicKey: {user: {name: string}}}[][];
    expect(calls[0]![0]!.publicKey.user.name).toBe("u");
    await getAssertion(serverRequest);
    expect(browser.get).toHaveBeenCalledOnce();
  });

  it("refuses a browser answer that is not a PublicKeyCredential", async () => {
    vi.stubGlobal("PublicKeyCredential", FakePublicKeyCredential);
    vi.stubGlobal("navigator", {credentials: {get: async () => null}});
    await expect(getAssertion(serverRequest)).rejects.toThrow(TypeError);
  });
});

describe("routes: the ticket is a header, the body is the credential", () => {
  const BASE = "http://panel.test/api/v1";

  function setup(finishBody: unknown) {
    const seen: {path: string; ticket: string | null; body: unknown}[] = [];
    const fetch = async (request: Request) => {
      const path = new URL(request.url).pathname.replace("/api/v1", "");
      const text = request.body ? await request.clone().text() : "";
      seen.push({path, ticket: request.headers.get("X-Ctrlz-Ticket"), body: text ? JSON.parse(text) : undefined});
      const begin = {ticket: "T-1", options: serverRequest};
      const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), {status, headers: {"content-type": "application/json"}});
      return path.endsWith("/begin") ? json(path.includes("/account/") ? {ticket: "T-1", options: serverCreation} : begin) : json(finishBody);
    };
    stubBrowser(attestationJson);
    return {seen, routes: webauthnRoutes(createApiClient<paths>({baseUrl: BASE, fetch}))};
  }

  it("login: begin with remember_me, finish with the ticket in X-Ctrlz-Ticket only", async () => {
    const {seen, routes} = setup({status: "authenticated"});
    await expect(routes.passkeyLogin({rememberMe: true})).resolves.toEqual({status: "authenticated"});
    expect(seen[0]).toMatchObject({path: "/auth/passkey/login/begin", ticket: null, body: {remember_me: true}});
    expect(seen[1]!.path).toBe("/auth/passkey/login/finish");
    expect(seen[1]!.ticket).toBe("T-1");
    expect(JSON.stringify(seen[1]!.body)).not.toContain("T-1");
    expect((seen[1]!.body as {response: Record<string, unknown>}).response).not.toHaveProperty("somethingNew");
  });

  it("reauth: the same, with no body on begin", async () => {
    const {seen, routes} = setup(undefined);
    await routes.passkeyReauth();
    expect(seen.map((s) => s.path)).toEqual(["/auth/reauth/passkey/begin", "/auth/reauth/passkey/finish"]);
    expect(seen[1]!.ticket).toBe("T-1");
  });

  it("add: begin, create, finish, and the PasskeyAdded comes back", async () => {
    const added = {passkey: {id: "p"}, ended_sessions: 2};
    const {seen, routes} = setup(added);
    await expect(routes.passkeyAdd()).resolves.toEqual(added);
    expect(seen[1]).toMatchObject({path: "/account/passkeys/finish", ticket: "T-1"});
  });

  it("reset proof: the reset ticket goes in the begin body, and the new ticket comes back", async () => {
    const {seen, routes} = setup({ticket: "T-2"});
    await expect(routes.passkeyResetProof("RESET-1")).resolves.toBe("T-2");
    expect(seen[0]).toMatchObject({path: "/auth/password/reset/passkey/begin", body: {ticket: "RESET-1"}});
    expect(seen[0]!.ticket).toBeNull();
    expect(seen[1]!.ticket).toBe("T-1");
  });

  // wp8-r8-3: `finish` opens the session, so an abort that arrives while it is in flight must not cancel it.
  it("login: an abort during finish does not cancel the request, and the answer still comes back", async () => {
    const controller = new AbortController();
    let finishSignal: AbortSignal | undefined;
    let releaseFinish!: () => void;
    const finishHeld = new Promise<void>((resolve) => {
      releaseFinish = resolve;
    });
    const json = (b: unknown) => new Response(JSON.stringify(b), {status: 200, headers: {"content-type": "application/json"}});
    const fetch = async (request: Request) => {
      if (new URL(request.url).pathname.endsWith("/begin")) return json({ticket: "T-1", options: serverRequest});
      finishSignal = request.signal;
      await finishHeld;
      return json({status: "authenticated"});
    };
    stubBrowser(attestationJson);
    const routes = webauthnRoutes(createApiClient<paths>({baseUrl: BASE, fetch}));
    const done = routes.passkeyLogin({signal: controller.signal});
    await vi.waitFor(() => expect(finishSignal).toBeDefined());
    controller.abort();
    expect(finishSignal!.aborted).toBe(false);
    releaseFinish();
    await expect(done).resolves.toEqual({status: "authenticated"});
  });

  it("login: an abort after the assertion, before finish, sends no finish at all", async () => {
    const {seen, routes} = setup({status: "authenticated"});
    const controller = new AbortController();
    vi.stubGlobal("navigator", {
      credentials: {
        get: async () => {
          controller.abort();
          return new FakePublicKeyCredential(attestationJson);
        },
      },
    });
    const failure = await routes.passkeyLogin({signal: controller.signal}).catch((e: unknown) => e);
    expect(isWebAuthnCancel(failure)).toBe(true);
    expect(seen.map((s) => s.path)).toEqual(["/auth/passkey/login/begin"]);
  });

  // gate-r16-9: the rule of wp8-r8-3 holds for every ceremony, the add of a passkey above all (finish registers it and ends other sessions).
  const everyCeremony = [
    ["add", "/account/passkeys/", {passkey: {id: "p"}, ended_sessions: 1}, (r: ReturnType<typeof webauthnRoutes>, signal: AbortSignal) => r.passkeyAdd({signal}), true],
    ["reauth", "/auth/reauth/passkey/", undefined, (r: ReturnType<typeof webauthnRoutes>, signal: AbortSignal) => r.passkeyReauth({signal}), true],
    ["reset proof", "/auth/password/reset/passkey/", {ticket: "T-2"}, (r: ReturnType<typeof webauthnRoutes>, signal: AbortSignal) => r.passkeyResetProof("RESET-1", {signal}), false],
  ] as const;

  it.each(everyCeremony)("%s: an abort during finish does not cancel the request, and the answer still comes back", async (_name, prefix, answer, run, create) => {
    const controller = new AbortController();
    let finishSignal: AbortSignal | undefined;
    let releaseFinish!: () => void;
    const finishHeld = new Promise<void>((resolve) => {
      releaseFinish = resolve;
    });
    const json = (b: unknown) => new Response(JSON.stringify(b), {status: 200, headers: {"content-type": "application/json"}});
    const fetch = async (request: Request) => {
      if (new URL(request.url).pathname.endsWith("/begin")) return json({ticket: "T-1", options: create ? serverCreation : serverRequest});
      finishSignal = request.signal;
      await finishHeld;
      return answer === undefined ? new Response(null, {status: 204}) : json(answer);
    };
    stubBrowser(attestationJson);
    const routes = webauthnRoutes(createApiClient<paths>({baseUrl: BASE, fetch}));
    const done = run(routes, controller.signal);
    await vi.waitFor(() => expect(finishSignal).toBeDefined());
    controller.abort();
    expect(finishSignal!.aborted, prefix).toBe(false);
    releaseFinish();
    await expect(done).resolves.toEqual(answer === undefined ? undefined : "ticket" in answer ? answer.ticket : answer);
  });

  it.each(everyCeremony)("%s: an abort after the prompt, before finish, sends no finish at all", async (_name, prefix, answer, run, create) => {
    const {seen, routes} = setup(answer);
    const controller = new AbortController();
    const abortThen = async () => {
      controller.abort();
      return new FakePublicKeyCredential(attestationJson);
    };
    vi.stubGlobal("navigator", {credentials: {get: abortThen, create: abortThen}});
    const failure = await run(routes, controller.signal).catch((e: unknown) => e);
    expect(isWebAuthnCancel(failure)).toBe(true);
    expect(seen.map((x) => x.path).filter((path) => path.startsWith(prefix) && path.endsWith("/finish"))).toEqual([]);
    void create;
  });

  it("stops before finish when the user cancels the prompt", async () => {
    const {seen, routes} = setup({status: "authenticated"});
    vi.stubGlobal("navigator", {credentials: {get: async () => Promise.reject(new DOMException("closed", "NotAllowedError"))}});
    const failure = await routes.passkeyLogin().catch((e: unknown) => e);
    expect(isWebAuthnCancel(failure)).toBe(true);
    expect(seen.map((s) => s.path)).toEqual(["/auth/passkey/login/begin"]);
  });
});
