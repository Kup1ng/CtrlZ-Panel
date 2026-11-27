import {createHmac} from "node:crypto";

import {describe, expect, it} from "vitest";

import {
  LABEL_LENGTH,
  PROTOCOL_NUMBER,
  inVerifyOrigin,
  judge,
  messagesOf,
  newLabel,
  nextState,
  parseAnswer,
  probeHost,
  tagOf,
  type VerifyAnswer,
} from "./verifyModel.ts";

// T-236: the three states of the verification, and the tags the page computes for itself.

const hmac = (label: string, n: string, message: Uint8Array) =>
  createHmac("sha256", Buffer.concat([Buffer.from(label), Buffer.from(n, "hex")])).update(message).digest("hex").slice(0, 32);

const LABEL = "abcdefghijklmnopqrstuvwxyz".slice(0, LABEL_LENGTH);
const N = "00112233445566778899aabbccddeeff";

// The messages of spec p4-nodes 7.6 written out as bytes here, not through `messagesOf`, so the page is not checked against itself:
// `rid`, `rid || 0x00 || client` (empty for an unnamed client), `rid || 0x01 || protocol byte` (udp 1, tcp 2, doh 3, dot 4, doq 5, doh3 6).
const PROTOCOL_BYTE = {udp: 1, tcp: 2, doh: 3, dot: 4, doq: 5, doh3: 6} as const;
function answerFor(resolverId: string, client: string, protocol: keyof typeof PROTOCOL_BYTE, seen = true): VerifyAnswer {
  const rid = Buffer.from(resolverId);
  return {
    seen,
    n: N,
    rid_tag: hmac(LABEL, N, rid),
    client_tag: hmac(LABEL, N, Buffer.concat([rid, Buffer.from([0]), Buffer.from(client)])),
    proto_tag: hmac(LABEL, N, Buffer.concat([rid, Buffer.from([1, PROTOCOL_BYTE[protocol]])])),
  };
}

describe("newLabel", () => {
  it("is 26 characters of a-z and 2-7", () => {
    for (let i = 0; i < 50; i++) expect(newLabel()).toMatch(/^[a-z2-7]{26}$/);
  });
  it("is drawn fresh each time", () => {
    expect(new Set(Array.from({length: 20}, () => newLabel())).size).toBe(20);
  });
  it("maps 5 bits to one letter with no bias", () => {
    const label = newLabel((bytes) => bytes.map((_, i) => i));
    expect(label.startsWith("abcdef")).toBe(true);
    expect(newLabel((bytes) => bytes.fill(255))).toBe("7".repeat(26));
  });
});

describe("tagOf", () => {
  it("is the first 16 bytes of HMAC-SHA256 with the key label || n", async () => {
    const m = messagesOf("r00000001", "");
    expect(await tagOf(LABEL, N, m.rid)).toBe(hmac(LABEL, N, m.rid));
    expect(await tagOf(LABEL, N, m.proto("doq"))).toBe(hmac(LABEL, N, m.proto("doq")));
  });
});

describe("the messages of spec p4-nodes 7.6", () => {
  // Golden values for LABEL, N and the Endpoint r00000001, computed once from the literal bytes of the spec.
  const GOLDEN = {
    rid: "4eac506f28ce3353dd93bdb661034533",
    clientEmpty: "0c62f899648277036f257ba1f323a77a",
    clientDevice1: "9d79efae50779b7da3cf372f997d3980",
    proto: {
      udp: "d35cdb86a63113cdd7dea8bd0caf3523",
      tcp: "520550a95cb3999f6dcb324c13f2b103",
      doh: "f85e8624b06775a5c5c9026ef4f7300c",
      dot: "b54ddb64c4020049ab1a2c7634ed227f",
      doq: "c1c065896d371dd8d863cbea2245e26d",
      doh3: "e879efe3b9e6da32191048160146a090",
    },
  };
  it("numbers the protocols as common.v1.Protocol does", () => {
    expect(PROTOCOL_NUMBER).toEqual({udp: 1, tcp: 2, doh: 3, dot: 4, doq: 5, doh3: 6});
  });
  it("computes the tags of the golden vectors", async () => {
    const m = messagesOf("r00000001", "");
    expect(await tagOf(LABEL, N, m.rid)).toBe(GOLDEN.rid);
    expect(await tagOf(LABEL, N, m.client)).toBe(GOLDEN.clientEmpty);
    expect(await tagOf(LABEL, N, messagesOf("r00000001", "device-1").client)).toBe(GOLDEN.clientDevice1);
    for (const [name, tag] of Object.entries(GOLDEN.proto)) expect(await tagOf(LABEL, N, m.proto(name as keyof typeof PROTOCOL_NUMBER))).toBe(tag);
  });
  it("names every one of the six protocols from an answer built with the spec bytes", async () => {
    for (const protocol of Object.keys(PROTOCOL_BYTE) as (keyof typeof PROTOCOL_BYTE)[]) {
      expect(await judge(LABEL, answerFor("r00000001", "", protocol), {resolverId: "r00000001"})).toEqual({state: "match", protocol, clientMatched: true});
    }
  });
  it("matches the unnamed client with an empty label", async () => {
    const answer = {...answerFor("r00000001", "", "doh"), client_tag: GOLDEN.clientEmpty};
    expect((await judge(LABEL, answer, {resolverId: "r00000001"})).clientMatched).toBe(true);
  });
});

describe("parseAnswer", () => {
  it("takes the shape of /v and nothing else", () => {
    expect(parseAnswer(answerFor("r1", "", "doh"))).not.toBeNull();
    expect(parseAnswer({seen: true})).toBeNull();
    expect(parseAnswer({...answerFor("r1", "", "doh"), n: "zz"})).toBeNull();
    expect(parseAnswer("<html>")).toBeNull();
    expect(parseAnswer(null)).toBeNull();
  });
});

describe("judge", () => {
  const expected = {resolverId: "r00000001", client: "device-1"};
  it("is pending when the probe failed or the label was not seen", async () => {
    expect((await judge(LABEL, null, expected)).state).toBe("pending");
    expect((await judge(LABEL, answerFor("r00000001", "device-1", "doh", false), expected)).state).toBe("pending");
  });
  it("is partial when the label was seen under another Endpoint", async () => {
    expect((await judge(LABEL, answerFor("r00000002", "device-1", "doh"), expected)).state).toBe("partial");
  });
  it("is a match for the expected Endpoint, with its client and protocol", async () => {
    expect(await judge(LABEL, answerFor("r00000001", "device-1", "dot"), expected)).toEqual({state: "match", protocol: "dot", clientMatched: true});
  });
  it("matches the Endpoint with another client, and says so", async () => {
    expect(await judge(LABEL, answerFor("r00000001", "other", "doh"), expected)).toEqual({state: "match", protocol: "doh", clientMatched: false});
  });
});

describe("nextState", () => {
  it("needs two matches in a row for Success", () => {
    const one = nextState({streak: 0}, {state: "match"});
    expect(one).toEqual({state: "confirming", streak: 1});
    expect(nextState(one, {state: "match"})).toEqual({state: "success", streak: 2});
  });
  it("starts the count over when a probe is not a match", () => {
    expect(nextState({streak: 1}, {state: "pending"})).toEqual({state: "pending", streak: 0});
    expect(nextState({streak: 1}, {state: "partial"})).toEqual({state: "partial", streak: 0});
  });
});

describe("probeHost and inVerifyOrigin", () => {
  it("asks a name under verify.<zone>", () => {
    expect(probeHost("lab", "r1.dns.example.test")).toBe("lab.verify.dns.example.test");
    expect(probeHost("lab", "nodot")).toBeNull();
    expect(probeHost("lab", undefined)).toBeNull();
  });
  it("is offered only inside the allowed origin", () => {
    const origin = "https://*.verify.dns.example.test";
    expect(inVerifyOrigin("lab.verify.dns.example.test", origin)).toBe(true);
    expect(inVerifyOrigin("lab.verify.dns.other.test", origin)).toBe(false);
    expect(inVerifyOrigin("a.b.verify.dns.example.test", origin)).toBe(false);
    expect(inVerifyOrigin("lab.verify.dns.example.test", null)).toBe(false);
  });
  it("accepts either zone while a domain transition runs (p4-nodes 10.3) and none when the list is empty", () => {
    const origins = ["https://*.verify.dns.example.test", "https://*.verify.dns.old.example.test"];
    expect(inVerifyOrigin("lab.verify.dns.example.test", origins)).toBe(true);
    expect(inVerifyOrigin("lab.verify.dns.old.example.test", origins)).toBe(true);
    expect(inVerifyOrigin("lab.verify.dns.third.test", origins)).toBe(false);
    expect(inVerifyOrigin("lab.verify.dns.example.test", [])).toBe(false);
  });
});
