/// <reference types="node" />
import {readFileSync} from "node:fs";
import path from "node:path";

import {describe, expect, it} from "vitest";

import {freeCounterFixture, hexFingerprint, nodeFixture, pairFixture} from "./adminFixtures.ts";
import type {MockCall} from "./mock.ts";
import {createNodeMock} from "./nodeMock.ts";

// The mock of the P4 admin routes (p4-nodes 9.2) has to answer every operation of the document, and the rules a screen shows (T-339, T-546,
// T-556). The first test reads the operations from api/admin-openapi.yaml, so an operation added to the document without a handler fails here.

const repo = path.resolve(import.meta.dirname, "../../../..");

function operationsOfTag(tag: string): string[] {
  const out: string[] = [];
  let route = "";
  let method = "";
  for (const line of readFileSync(path.join(repo, "api/admin-openapi.yaml"), "utf8").split("\n")) {
    const p = /^ {2}(\/\S*):$/.exec(line);
    if (p) route = p[1]!;
    const m = /^ {4}(get|put|post|patch|delete):$/.exec(line);
    if (m) method = m[1]!.toUpperCase();
    if (line.trim() === `tags: [${tag}]` && route && method) out.push(`${method} ${route}`);
  }
  return out;
}

const call = (method: string, pathname: string, body?: unknown, query = ""): MockCall => ({
  method,
  path: pathname,
  query: new URLSearchParams(query),
  body,
  headers: {},
  pageUrl: "https://admin.example.ir/fa/nodes",
});

describe("the P4 admin mock", () => {
  it("has a handler for every operation tagged nodes in api/admin-openapi.yaml", () => {
    const {handlers} = createNodeMock();
    const operations = operationsOfTag("nodes");
    expect(operations.length).toBeGreaterThanOrEqual(29);
    expect(operations.filter((o) => !(o in handlers))).toEqual([]);
  });

  it("answers the overview with the node-wide figures only, summed over the nodes that reported one", () => {
    const a = nodeFixture({slot: 1, qps: 100});
    const b = nodeFixture({slot: 2, qps: 250});
    const c = nodeFixture({slot: 3});
    const {handlers} = createNodeMock({nodes: [a, b, c]});
    const body = handlers["GET /overview"]!(call("GET", "/overview"), undefined as never) as {body: {qps?: number; nodes: unknown[]}};
    expect(body.body.qps).toBe(350);
    expect(body.body.nodes).toHaveLength(3);
    const none = createNodeMock({nodes: [c]}).handlers["GET /overview"]!(call("GET", "/overview"), undefined as never) as {body: Record<string, unknown>};
    expect("qps" in none.body).toBe(false);
  });

  it("keeps the counters to the window and the node, with no name and no address in a row (T-339)", () => {
    const a = nodeFixture({slot: 1});
    const b = nodeFixture({slot: 2});
    const {handlers} = createNodeMock({
      nodes: [a, b],
      counters: [
        freeCounterFixture(a, {bucket_start: "2026-11-24T09:00:00Z"}),
        freeCounterFixture(a, {bucket_start: "2026-11-01T09:00:00Z"}),
        freeCounterFixture(b, {bucket_start: "2026-11-24T09:00:00Z"}),
      ],
    });
    const reply = handlers["GET /free-dns/counters"]!(call("GET", "/free-dns/counters", undefined, `from=2026-11-24T00:00:00Z&to=2026-11-25T00:00:00Z&node_id=${a.id}`), undefined as never) as {body: {items: Record<string, unknown>[]}};
    expect(reply.body.items).toHaveLength(1);
    expect(Object.keys(reply.body.items[0]!).sort()).toEqual(["bucket_start", "count", "node_id", "outcome", "rcode", "transport"]);
    const refused = handlers["GET /free-dns/counters"]!(call("GET", "/free-dns/counters", undefined, "from=2026-11-25T00:00:00Z&to=2026-11-24T00:00:00Z"), undefined as never) as {status: number};
    expect(refused.status).toBe(422);
  });

  it("refuses a qps outside 1 to 2000 with qps_out_of_range and changes nothing (T-556)", () => {
    const {handlers, state} = createNodeMock();
    const put = (qps: number, enabled = true) => handlers["PUT /settings/free-dns"]!(call("PUT", "/settings/free-dns", {enabled, qps}), undefined as never) as {status?: number; body: {code?: string}};
    expect(put(0).body.code).toBe("qps_out_of_range");
    expect(put(2001).body.code).toBe("qps_out_of_range");
    expect(state.freeDns.qps).toBe(1000);
    expect(state.writes).toEqual([]);
    const version = state.freeDns.version;
    put(1000);
    expect(state.freeDns.version).toBe(version);
    put(500, false);
    expect(state.freeDns).toMatchObject({enabled: false, qps: 500, version: version + 1});
  });

  it("answers totp_fresh_required until the window is opened, when the spec asks for it", () => {
    const {handlers, state} = createNodeMock({freshRequired: true});
    const put = () => handlers["PUT /settings/free-dns"]!(call("PUT", "/settings/free-dns", {enabled: true, qps: 10}), undefined as never) as {status?: number; body: {code?: string}};
    expect(put()).toMatchObject({status: 403, body: {code: "totp_fresh_required"}});
    handlers["POST /auth/totp/fresh"]!(call("POST", "/auth/totp/fresh", {code: "123456"}), undefined as never);
    expect(put().body).toMatchObject({qps: 10});
    expect(state.writes).toEqual(["PUT /settings/free-dns"]);
  });

  it("gives the old address up with a safe date 30 days on, on an address edit and on a removal (T-546)", () => {
    const a = nodeFixture({slot: 1});
    const b = nodeFixture({slot: 2});
    const {handlers, state} = createNodeMock({nodes: [a, b]});
    handlers["PUT /nodes/{id}/addresses"]!(call("PUT", `/nodes/${a.id}/addresses`, {dns_advertised_ip: "203.0.113.99", proxy_advertised_ip: a.proxy_advertised_ip}), undefined as never);
    expect(state.givenUp).toHaveLength(1);
    expect(state.givenUp[0]).toMatchObject({address: "203.0.113.11", kind: "dns", node_name: "node-1"});
    const days = (Date.parse(state.givenUp[0]!.safe_from) - Date.parse(state.givenUp[0]!.given_up_at)) / 86_400_000;
    expect(Math.round(days)).toBe(30);
    handlers["DELETE /nodes/{id}"]!(call("DELETE", `/nodes/${b.id}`), undefined as never);
    expect(state.givenUp.map((g) => g.kind).sort()).toEqual(["dns", "dns", "proxy"]);
  });

  it("refuses to remove a node that a pair holds, and a pair of two nodes already paired", () => {
    const a = nodeFixture({slot: 1});
    const b = nodeFixture({slot: 2});
    const c = nodeFixture({slot: 3});
    const {handlers} = createNodeMock({nodes: [a, b, c], pairs: [pairFixture(a, b)]});
    const del = handlers["DELETE /nodes/{id}"]!(call("DELETE", `/nodes/${a.id}`), undefined as never) as {status: number; body: {code: string}};
    expect(del).toMatchObject({status: 409, body: {code: "node_paired"}});
    const make = handlers["POST /pairs"]!(call("POST", "/pairs", {primary_node_id: c.id, fallback_node_id: a.id}), undefined as never) as {body: {code: string}};
    expect(make.body.code).toBe("second_peer");
  });

  it("answers the enrolment with the install command once, and a wrong fingerprint with fingerprint_mismatch", () => {
    const {handlers, state} = createNodeMock();
    const made = handlers["POST /node-enrollments"]!(call("POST", "/node-enrollments", {dns_bind_ip: "203.0.113.20", dns_advertised_ip: "203.0.113.20", proxy_bind_ip: "198.51.100.20", proxy_advertised_ip: "198.51.100.20"}), undefined as never) as {status: number; body: {install_command: string}};
    expect(made.status).toBe(201);
    expect(made.body.install_command).toContain("sudo sh");
    // The list holds no command: it is shown once.
    const list = handlers["GET /node-enrollments"]!(call("GET", "/node-enrollments"), undefined as never) as {body: {items: Record<string, unknown>[]}};
    expect(JSON.stringify(list.body)).not.toContain("install_command");
    state.enrollments[0]!.state = "pending_approval";
    state.enrollments[0]!.key_fingerprint = hexFingerprint(1);
    const bad = handlers["POST /node-enrollments/{id}:confirm"]!(call("POST", `/node-enrollments/${state.enrollments[0]!.id}:confirm`, {fingerprint: hexFingerprint(2), name: "n1"}), undefined as never) as {body: {code: string}};
    expect(bad.body.code).toBe("fingerprint_mismatch");
    // A text that is no hex is refused by the contract's pattern before any comparison (PG-r1-11), and the grouped upper-case form of the right one passes it.
    const label = handlers["POST /node-enrollments/{id}:confirm"]!(call("POST", `/node-enrollments/${state.enrollments[0]!.id}:confirm`, {fingerprint: "SHA256:right", name: "n1"}), undefined as never) as {body: {code: string}};
    expect(label.body.code).toBe("validation_failed");
    const grouped = hexFingerprint(1).toUpperCase().replace(/(.{8})/g, "$1:").slice(0, -1);
    const ok = handlers["POST /node-enrollments/{id}:confirm"]!(call("POST", `/node-enrollments/${state.enrollments[0]!.id}:confirm`, {fingerprint: grouped, name: "n1"}), undefined as never) as {status: number};
    expect(ok.status).toBe(201);
  });
});
