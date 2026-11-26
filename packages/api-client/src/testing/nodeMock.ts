import {
  certificateFixture,
  domainFixture,
  freeDnsFixture,
  givenUpFixture,
  nodeFixture,
  overviewFixture,
  type AddressGivenUp,
  type CertificateView,
  type DomainSettings,
  type FreeCounterRow,
  type FreeDnsSettings,
  type KeptRow,
  type NodeEnrollmentRow,
  type NodeView,
  type PairView,
  type TakenClaim,
} from "./adminFixtures.ts";
import {errorBody} from "./fixtures.ts";
import type {MockCall, MockHandler, MockKey, MockReply} from "./mock.ts";

// The mock of every P4 admin operation (p4-nodes 9.2), for the e2e specs in mock mode (spec 17.1). It is a small model of the routes, not
// a copy of them: it keeps nodes, pairs, enrolments, the free DNS switch, the counters, the domain and the certificates in memory and
// answers each route from them, with the refusals the document names, so a screen can be driven through its whole flow. A spec that wants
// one odd answer overrides the key afterwards. The rules it keeps are the ones a screen shows:
//   - a write needs the fresh TOTP window only when `state.freshRequired` is set (the window opens on `POST /auth/totp/fresh`);
//   - a node in a pair is not removed (`node_paired`), a revoke only touches an active node, and a pair needs two different active nodes;
//   - `qps` of free DNS is 1 to 2000 (`qps_out_of_range`);
//   - an edit of an advertised address makes the old one an address given up, with the date 30 days on.

export type NodeMockState = {
  nodes: NodeView[];
  pairs: PairView[];
  enrollments: NodeEnrollmentRow[];
  givenUp: AddressGivenUp[];
  freeDns: FreeDnsSettings;
  counters: FreeCounterRow[];
  domain: DomainSettings;
  certificates: CertificateView[];
  /** What a revoked node's reports hold, for `GET /nodes/{id}/reports` (the same for every node): claims newest first, and the rows the job kept. */
  reports: {claims: TakenClaim[]; kept_rows: KeptRow[]};
  /** When true, a write answers `totp_fresh_required` until `POST /auth/totp/fresh` has been called. */
  freshRequired: boolean;
  fresh: boolean;
  /** The install command `POST /node-enrollments` answers with, shown once. A made-up one: it carries no real token. */
  installCommand: string;
  /** The writes the mock took, in order, as `"METHOD /path"`: a spec asserts what was sent and what was not. */
  writes: string[];
};

const DAY_MS = 86_400_000;
const GIVE_BACK_WAIT_MS = 30 * DAY_MS;

export const MOCK_INSTALL_COMMAND = " curl -k --pinnedpubkey sha256//AAAAFIXTURE -o /tmp/ctrlz-node.sh hub.example.ir:9443/install/node.sh && printf %s 'FIXTURETOKEN' | sudo sh /tmp/ctrlz-node.sh --hub hub.example.ir";

export function nodeMockState(over: Partial<NodeMockState> = {}): NodeMockState {
  return {
    nodes: [],
    pairs: [],
    enrollments: [],
    givenUp: [],
    freeDns: freeDnsFixture(),
    counters: [],
    domain: domainFixture(),
    certificates: [certificateFixture()],
    reports: {claims: [], kept_rows: []},
    freshRequired: false,
    fresh: false,
    installCommand: MOCK_INSTALL_COMMAND,
    writes: [],
    ...over,
  };
}

const fail = (status: number, code: string): MockReply => ({status, body: errorBody(code)});
const ok = (body: unknown, status = 200): MockReply => ({status, body});
const idOf = (call: MockCall, index = 2): string => call.path.split("/")[index]!.split(":")[0]!;
const page = <T,>(items: T[]) => ({items});

let made = 0;
const newId = () => `00000000-0000-4000-8000-${String(900_000 + ++made).padStart(12, "0")}`;

/** A model of the node routes: the handlers to give `openAdmin({handlers})`, and the state a spec reads and changes. */
export function createNodeMock(initial: Partial<NodeMockState> = {}): {state: NodeMockState; handlers: Record<MockKey, MockHandler>} {
  const state = nodeMockState(initial);

  /** Every write goes through here: the fresh window, then the record of the write. */
  const write =
    (key: string, run: (call: MockCall) => MockReply): MockHandler =>
    (call) => {
      if (state.freshRequired && !state.fresh) return fail(403, "totp_fresh_required");
      const reply = run(call);
      if ((reply.status ?? 200) < 400) state.writes.push(key);
      return reply;
    };

  const node = (id: string) => state.nodes.find((n) => n.id === id);
  const paired = (id: string) => state.pairs.some((p) => p.primary_node_id === id || p.fallback_node_id === id);
  const withPeers = (n: NodeView): NodeView => {
    const pair = state.pairs.find((p) => p.primary_node_id === n.id || p.fallback_node_id === n.id);
    const peer = pair ? (pair.primary_node_id === n.id ? pair.fallback_node_id : pair.primary_node_id) : undefined;
    return peer ? {...n, pair_peer_id: peer} : n;
  };
  const views = () => state.nodes.map(withPeers);

  const handlers: Record<string, MockHandler> = {
    "POST /auth/totp/fresh": () => {
      state.fresh = true;
      return ok({fresh_until: "2099-01-01T00:00:00Z"});
    },

    "GET /overview": () => {
      const nodes = views();
      const active = nodes.filter((n) => n.status === "active" && n.qps !== undefined);
      const qps = active.length ? active.reduce((sum, n) => sum + (n.qps ?? 0), 0) : undefined;
      const body = overviewFixture(nodes, {config_head: Math.max(0, ...nodes.map((n) => n.config_head)), free_dns: state.freeDns});
      // The figure is absent until a Heartbeat carries one, not zero.
      if (qps === undefined) delete body.qps;
      else body.qps = qps;
      return ok(body);
    },
    "GET /free-dns/counters": (call) => {
      const from = Date.parse(call.query.get("from") ?? "");
      const to = Date.parse(call.query.get("to") ?? "");
      if (!Number.isNaN(from) && !Number.isNaN(to) && from >= to) return fail(422, "validation_failed");
      const only = call.query.get("node_id");
      const rows = state.counters.filter((r) => {
        const at = Date.parse(r.bucket_start);
        return (Number.isNaN(from) || at >= from) && (Number.isNaN(to) || at < to) && (!only || r.node_id === only);
      });
      return ok(page(rows));
    },

    "GET /nodes": () => ok(page(views())),
    "GET /nodes/addresses-given-up": () => ok(page(state.givenUp)),
    "GET /nodes/{id}": (call) => {
      const n = node(idOf(call));
      return n ? ok(withPeers(n)) : fail(404, "not_found");
    },
    "PATCH /nodes/{id}": write("PATCH /nodes/{id}", (call) => {
      const n = node(idOf(call));
      if (!n) return fail(404, "not_found");
      const body = call.body as {name?: string; proxy_blocked?: boolean};
      if (body.name !== undefined) n.name = body.name;
      if (body.proxy_blocked !== undefined) n.proxy_blocked = body.proxy_blocked;
      return ok(withPeers(n));
    }),
    "DELETE /nodes/{id}": write("DELETE /nodes/{id}", (call) => {
      const n = node(idOf(call));
      if (!n) return fail(404, "not_found");
      if (paired(n.id)) return fail(409, "node_paired");
      state.nodes = state.nodes.filter((x) => x.id !== n.id);
      for (const [address, kind] of [[n.dns_advertised_ip, "dns"], [n.proxy_advertised_ip, "proxy"]] as const) {
        if (address) state.givenUp.push(givenUpFixture({address, kind, node_name: n.name, node_id: n.id, given_up_at: new Date().toISOString(), safe_from: new Date(Date.now() + GIVE_BACK_WAIT_MS).toISOString()}));
      }
      return {status: 204};
    }),
    "POST /nodes/{id}:approve": write("POST /nodes/{id}:approve", (call) => {
      const n = node(idOf(call));
      if (!n) return fail(404, "not_found");
      if (n.status !== "pending") return fail(409, "node_state");
      n.status = "active";
      return ok(withPeers(n));
    }),
    "POST /nodes/{id}:revoke": write("POST /nodes/{id}:revoke", (call) => {
      const n = node(idOf(call));
      if (!n) return fail(404, "not_found");
      if (n.status !== "active") return fail(409, "node_state");
      n.status = "revoked";
      return ok(withPeers(n));
    }),
    "PUT /nodes/{id}/addresses": write("PUT /nodes/{id}/addresses", (call) => {
      const n = node(idOf(call));
      if (!n) return fail(404, "not_found");
      if (n.status === "revoked") return fail(409, "node_state");
      const body = call.body as {dns_advertised_ip: string; proxy_advertised_ip: string};
      if (state.nodes.some((x) => x.id !== n.id && (x.dns_advertised_ip === body.dns_advertised_ip || x.proxy_advertised_ip === body.proxy_advertised_ip))) return fail(422, "address_refused");
      const gone = (address: string | undefined, kind: "dns" | "proxy", next: string) => {
        if (address && address !== next) {
          state.givenUp.push(givenUpFixture({address, kind, node_name: n.name, node_id: n.id, given_up_at: new Date().toISOString(), safe_from: new Date(Date.now() + GIVE_BACK_WAIT_MS).toISOString()}));
        }
      };
      gone(n.dns_advertised_ip, "dns", body.dns_advertised_ip);
      gone(n.proxy_advertised_ip, "proxy", body.proxy_advertised_ip);
      n.dns_advertised_ip = body.dns_advertised_ip;
      n.proxy_advertised_ip = body.proxy_advertised_ip;
      return ok(withPeers(n));
    }),
    "POST /nodes/{id}/dns-requests": write("POST /nodes/{id}/dns-requests", (call) => {
      const n = node(idOf(call));
      if (!n) return fail(404, "not_found");
      if (n.status !== "active") return fail(409, "node_state");
      const kind = (call.body as {kind: "hold" | "release" | "force_failback"}).kind;
      if (kind === "hold") n.dns_hold = true;
      if (kind === "release") n.dns_hold = false;
      return ok({request_id: newId()}, 202);
    }),
    "GET /nodes/{id}/reports": (call) => {
      if (!node(idOf(call))) return fail(404, "not_found");
      // The route's own rule: from and to bound the time, newest first, 200 at most, and the instant of `to` is read again.
      const from = Date.parse(call.query.get("from") ?? "") || 0;
      const to = Date.parse(call.query.get("to") ?? "") || Infinity;
      const inRange = state.reports.claims.filter((c) => Date.parse(c.consumed_at) >= from && Date.parse(c.consumed_at) <= to);
      const claims = inRange.slice(0, 200);
      return ok({claims, claims_truncated: inRange.length > claims.length, kept_rows: state.reports.kept_rows, kept_truncated: false});
    },

    "GET /node-enrollments": () => ok(page(state.enrollments)),
    "POST /node-enrollments": write("POST /node-enrollments", (call) => {
      const body = call.body as {dns_advertised_ip: string; proxy_advertised_ip: string};
      if (!body?.dns_advertised_ip) return fail(422, "validation_failed");
      const row: NodeEnrollmentRow = {id: newId(), state: "issued", created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 15 * 60_000).toISOString(), ...(body as object)} as NodeEnrollmentRow;
      state.enrollments.unshift(row);
      return ok({id: row.id, expires_at: row.expires_at, install_command: state.installCommand}, 201);
    }),
    "POST /node-enrollments/{id}:confirm": write("POST /node-enrollments/{id}:confirm", (call) => {
      const row = state.enrollments.find((e) => e.id === idOf(call));
      if (!row) return fail(404, "not_found");
      if (row.state !== "pending_approval") return fail(409, "enrollment_state");
      const body = call.body as {fingerprint: string; name: string};
      // The route's own order: the pattern of the contract first, then the comparison after case and the grouping marks are folded away.
      if (typeof body.fingerprint !== "string" || !/^[0-9A-Fa-f][0-9A-Fa-f :-]*$/.test(body.fingerprint)) return fail(422, "validation_failed");
      if (body.fingerprint.toLowerCase().replace(/[ :-]/g, "") !== row.key_fingerprint) return fail(422, "fingerprint_mismatch");
      if (state.nodes.length >= 4) return fail(409, "node_limit_reached");
      const slot = [1, 2, 3, 4].find((s) => !state.nodes.some((n) => n.slot === s))!;
      const created = nodeFixture({
        slot,
        name: body.name,
        status: "pending",
        ...(row.dns_advertised_ip ? {dns_advertised_ip: row.dns_advertised_ip} : {}),
        ...(row.proxy_advertised_ip ? {proxy_advertised_ip: row.proxy_advertised_ip} : {}),
        ...(row.key_fingerprint ? {key_fingerprint: row.key_fingerprint} : {}),
      });
      state.nodes.push(created);
      row.state = "approved";
      row.node_id = created.id;
      return ok({node_id: created.id, slot}, 201);
    }),
    "POST /node-enrollments/{id}:reject": write("POST /node-enrollments/{id}:reject", (call) => {
      const row = state.enrollments.find((e) => e.id === idOf(call));
      if (!row) return fail(404, "not_found");
      if (row.state !== "pending_approval" && row.state !== "issued") return fail(409, "enrollment_state");
      row.state = "rejected";
      return {status: 204};
    }),

    "GET /pairs": () => ok(page(state.pairs)),
    "POST /pairs": write("POST /pairs", (call) => {
      const body = call.body as {primary_node_id: string; fallback_node_id: string; make_global?: boolean};
      const a = node(body.primary_node_id);
      const b = node(body.fallback_node_id);
      if (!a || !b || a.id === b.id) return fail(422, "validation_failed");
      if (a.status !== "active" || b.status !== "active") return fail(409, "node_state");
      if (paired(a.id) || paired(b.id)) return fail(409, "second_peer");
      const first = state.pairs.length === 0;
      if (first && !body.make_global) return fail(409, "global_pair_required");
      const pair: PairView = {id: newId(), primary_node_id: a.id, fallback_node_id: b.id, is_global: first || body.make_global === true, created_at: new Date().toISOString()};
      if (pair.is_global) state.pairs = state.pairs.map((p) => ({...p, is_global: false}));
      state.pairs.push(pair);
      return ok(pair, 201);
    }),
    "PUT /pairs/{id}": write("PUT /pairs/{id}", (call) => {
      const pair = state.pairs.find((p) => p.id === idOf(call));
      if (!pair) return fail(404, "not_found");
      const body = call.body as {primary_node_id: string; fallback_node_id: string};
      const a = node(body.primary_node_id);
      const b = node(body.fallback_node_id);
      if (!a || !b || a.id === b.id) return fail(422, "validation_failed");
      if (a.status !== "active" || b.status !== "active") return fail(409, "node_state");
      // A node of another pair cannot be taken (one peer, the `node_pairs_one_peer` trigger).
      const heldElsewhere = (id: string) => state.pairs.some((p) => p.id !== pair.id && (p.primary_node_id === id || p.fallback_node_id === id));
      if (heldElsewhere(a.id) || heldElsewhere(b.id)) return fail(409, "second_peer");
      pair.primary_node_id = body.primary_node_id;
      pair.fallback_node_id = body.fallback_node_id;
      return ok(pair);
    }),
    "DELETE /pairs/{id}": write("DELETE /pairs/{id}", (call) => {
      const pair = state.pairs.find((p) => p.id === idOf(call));
      if (!pair) return fail(404, "not_found");
      if (pair.is_global) return fail(409, "pair_in_use");
      state.pairs = state.pairs.filter((p) => p.id !== pair.id);
      return {status: 204};
    }),
    "PUT /settings/global-pair": write("PUT /settings/global-pair", (call) => {
      const id = (call.body as {pair_id: string}).pair_id;
      if (!state.pairs.some((p) => p.id === id)) return fail(404, "not_found");
      state.pairs = state.pairs.map((p) => ({...p, is_global: p.id === id}));
      return ok({pair_id: id});
    }),

    "GET /settings/free-dns": () => ok(state.freeDns),
    "PUT /settings/free-dns": write("PUT /settings/free-dns", (call) => {
      const body = call.body as {enabled: boolean; qps: number};
      if (!Number.isInteger(body.qps) || body.qps < 1 || body.qps > 2000) return fail(422, "qps_out_of_range");
      // A request that changes nothing moves no version (p4-nodes 9.2).
      if (body.enabled !== state.freeDns.enabled || body.qps !== state.freeDns.qps) state.freeDns = {enabled: body.enabled, qps: body.qps, version: state.freeDns.version + 1};
      return ok(state.freeDns);
    }),

    "GET /settings/domain": () => ok(state.domain),
    "GET /settings/domain/impact": () => ok({endpoints: 12, apple_profiles: 3}),
    "PUT /settings/domain": write("PUT /settings/domain", (call) => {
      const body = call.body as {dns_zone: string; panel_host?: string; admin_host?: string; transition_days: number};
      if (!body.dns_zone?.startsWith("dns.")) return fail(422, "domain_invalid");
      // A host equal to or below a zone, and two equal hosts, are refused as the route refuses them.
      const hosts = [body.panel_host, body.admin_host].filter((h): h is string => !!h);
      if (hosts.some((h) => h === body.dns_zone || h.endsWith(`.${body.dns_zone}`)) || (hosts.length === 2 && hosts[0] === hosts[1])) return fail(422, "domain_invalid");
      const running = state.domain.transition_until !== undefined && Date.parse(state.domain.transition_until) > Date.now();
      if (running && body.dns_zone !== state.domain.dns_zone) return fail(409, "transition_active");
      // A change from one zone to another starts the transition; a first set and a change of a host alone do not (p4-nodes 10.4).
      const zoneChanged = state.domain.dns_zone !== undefined && body.dns_zone !== state.domain.dns_zone;
      const transition = zoneChanged ? {prev_dns_zone: state.domain.dns_zone as string, transition_until: new Date(Date.now() + (body.transition_days ?? 30) * DAY_MS).toISOString()} : {};
      state.domain = {
        ...state.domain,
        ...transition,
        dns_zone: body.dns_zone,
        ...(body.panel_host ? {panel_host: body.panel_host} : {}),
        ...(body.admin_host ? {admin_host: body.admin_host} : {}),
        apply_pending: true,
      };
      return ok(state.domain);
    }),

    "GET /certificates": () => ok(page(state.certificates)),
    "POST /certificates": write("POST /certificates", (call) => {
      const body = call.body as {kind: CertificateView["kind"]; chain_pem: string; key_pem: string};
      if (!body.chain_pem?.includes("BEGIN CERTIFICATE") || !body.key_pem?.includes("PRIVATE KEY")) return fail(422, "cert_invalid");
      // A spec drives the server's other refusals with a word inside the PEM text (letters are valid base64).
      if (body.key_pem.includes("MISMATCH")) return fail(422, "cert_key_mismatch");
      if (body.chain_pem.includes("PRIVATECA")) return fail(422, "cert_not_public");
      if (body.chain_pem.includes("EXPIRING")) return fail(422, "cert_expiring");
      const row = certificateFixture({kind: body.kind, id: newId()});
      state.certificates.unshift(row);
      return ok({id: row.id, names: row.names, not_after: row.not_after}, 201);
    }),
    "POST /certificates/{id}:retire": write("POST /certificates/{id}:retire", (call) => {
      const row = state.certificates.find((c) => c.id === idOf(call));
      if (!row || row.state !== "active") return fail(404, "not_found");
      row.state = "retired";
      return {status: 204};
    }),
  };

  return {state, handlers: handlers as Record<MockKey, MockHandler>};
}
