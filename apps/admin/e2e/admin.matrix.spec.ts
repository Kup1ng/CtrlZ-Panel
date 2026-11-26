import {createNodeMock} from "@ctrlz/api-client/testing/nodeMock.ts";
import {
  adminUserFixture,
  alertFixture,
  auditFixture,
  certificateFixture,
  claimFixture,
  domainFixture,
  enrollmentFixture,
  gatewayFixture,
  freeCounterFixture,
  givenUpFixture,
  inviteFixture,
  limitsFixture,
  nodeFixture,
  pairFixture,
  statsFixture,
  templateFixture,
} from "@ctrlz/api-client/testing/adminFixtures.ts";
import type {adminMeFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import type {Locator, Page} from "@playwright/test";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import {LIVE_ANNOUNCER} from "@ctrlz/ui/testing/axeLogic.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectMatrixPage} from "@ctrlz/ui/testing/matrixAssert.ts";

import {adm, allowAdminErrors, err, type Handlers, type Lang, nodesText, openAdmin, shellText, TOTP_URI} from "./admin-support.ts";

// The smoke case of every admin screen (spec 17.1, 19.2) on all 12 projects (three widths, two languages, two themes): the
// page renders in the project's language, direction and theme, has no sideways scroll, carries dark text on the accent, and
// has no serious or critical axe violation (17.5). Each state that draws something else is its own screen: the dialogs, the
// one-time result, the setup steps, the SMS tabs, the impact before a confirm and the banner stack.

test.beforeEach(({guard}) => allowAdminErrors(guard));


const users = Array.from({length: 6}, (_, i) => adminUserFixture({phone_e164: `+98912000${1001 + i}`, tenant_status: i === 3 ? "suspended" : "active", one_time_password_expires_at: i === 1 ? "2026-11-20T00:00:00Z" : undefined}));
const gateways = [
  gatewayFixture(),
  gatewayFixture({provider: "melipayamak", role: "fallback", hint: "…77c1", last_error_at: "2026-11-16T05:00:00Z", last_error_code: "timeout", breaker_open_until: "2099-01-01T00:00:00Z"}),
  gatewayFixture({provider: "noop", role: "disabled", configured: false, hint: undefined, cost_per_message: undefined, last_ok_at: undefined}),
];

// P4: four nodes in every state a row can be in, the first two the global pair, a few counters and two addresses given up. One model of the
// routes answers every P4 call (the mock of api-client/testing/nodeMock.ts), so a page is drawn from the same answers in all 12 projects.
const nodeA = nodeFixture({slot: 1, name: "tehran-1", qps: 200, cache_hit_permille: 900});
const nodeB = nodeFixture({slot: 2, name: "tehran-2", qps: 140, dns_hold: true, applied_seq: 118, applied_seq_lag: 2});
const nodeC = nodeFixture({slot: 3, name: "shiraz-1", last_heartbeat_at: "2026-11-24T08:00:00Z"});
const nodeD = nodeFixture({slot: 4, name: "tabriz-1", status: "pending"});
const FP = "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12";
const enrolWaiting = enrollmentFixture({
  state: "pending_approval",
  key_fingerprint: FP,
  hostname: "host-1",
  os_release: "Ubuntu 24.04.2 LTS",
  enrolled_at: "2026-11-24T09:55:00Z",
  enrolled_from: "192.0.2.9",
  expires_at: "2099-01-01T00:00:00Z",
});
const enrolments = [
  enrolWaiting,
  enrollmentFixture({state: "issued", key_fingerprint: undefined, hostname: undefined, os_release: undefined, node_version: undefined, expires_at: "2099-01-01T00:00:00Z"}),
  enrollmentFixture({state: "approved", hostname: "host-0", node_id: nodeA.id}),
  enrollmentFixture({state: "expired", hostname: "host-x"}),
];
const hourAgo = new Date(Math.floor(Date.now() / 3_600_000) * 3_600_000 - 3_600_000).toISOString();
const nodeMock = createNodeMock({
  nodes: [nodeA, nodeB, nodeC, nodeD],
  pairs: [pairFixture(nodeA, nodeB)],
  counters: [
    freeCounterFixture(nodeA, {bucket_start: hourAgo, count: 12000}),
    freeCounterFixture(nodeA, {bucket_start: hourAgo, outcome: "rd0", rcode: 5, count: 310}),
    freeCounterFixture(nodeB, {bucket_start: hourAgo, transport: "tcp", outcome: "rate_limited", rcode: 2, count: 24}),
  ],
  enrollments: enrolments,
  givenUp: [givenUpFixture(), givenUpFixture({address: "198.51.100.50", kind: "proxy", node_name: undefined})],
});

const handlers: Handlers = {
  ...nodeMock.handlers,
  "GET /users": {body: {items: users}},
  "GET /invites": {body: {items: [inviteFixture(), inviteFixture({state: "used"}), inviteFixture({state: "expired"}), inviteFixture({state: "revoked"})]}},
  "GET /audit": {
    body: {
      items: [
        auditFixture({action: "sms.gateway_put", target: "sms_ir", params: {fields: ["credentials"]}, admin_id: "00000000-0000-4000-8000-0000000000aa", admin_name: "root"}),
        auditFixture({admin_id: "00000000-0000-4000-8000-0000000000dd"}),
      ],
    },
  },
  "GET /sms/gateways": {body: {items: gateways}},
  "GET /sms/templates": {body: {items: [templateFixture({mappings: [{provider: "sms_ir", provider_template_id: "123456", param_names: ["code"]}]}), templateFixture({key: "notice_passkey", locale: "en", body: "Ctrl Z: a passkey was added to your account. If this was not you, use the forgot password page."})]}},
  "GET /sms/limits": {body: limitsFixture()},
  "GET /sms/stats": {body: statsFixture()},
  "GET /settings/registration": {body: {mode: "invite", open_grace_days: 0, takeover_idle_days: 30}},
  "GET /settings/webauthn": {body: {rp_id: "panel.example.ir", allowed_origins: ["https://panel.example.ir"], enabled: false}},
  "GET /settings/registration/impact": {body: {graced: 12, suspended_at_once: 3}},
  "GET /settings/webauthn/impact": {body: {credentials: 4, users: 3, enforced_users: 1}},
  "POST /users": {status: 201, body: {tenant_id: "00000000-0000-4000-8000-0000000000aa", user_id: "00000000-0000-4000-8000-0000000000bb", one_time_password: "fixture-otp-value"}},
  "POST /me/totp/setup": {body: {secret: "JBSWY3DPEHPK3PXP", otpauth_uri: TOTP_URI}},
};

// What "the server holds now" is, for the two conflict screens below: one test at a time sets it before the edit it is about to race.
const conflictServer: {limits: ReturnType<typeof limitsFixture>; gateways: ReturnType<typeof gatewayFixture>[]} = {limits: limitsFixture(), gateways};

/** Every answer of a conflict note is inside the note's padding (12px), not on its edge: the Limits cell is about 176px wide at 768 and a one-line button was not. */
async function expectNoteFits(note: Locator) {
  const fit = await note.evaluate((el) => {
    const box = el.getBoundingClientRect();
    return {
      overflows: el.scrollWidth > el.clientWidth,
      edges: [...el.querySelectorAll("button")].map((b) => {
        const r = b.getBoundingClientRect();
        return {name: b.textContent, start: Math.min(r.left - box.left, box.right - r.right), height: Math.round(r.height)};
      }),
    };
  });
  expect(fit.overflows, "the note has no sideways scroll").toBe(false);
  expect(fit.edges).toHaveLength(2);
  for (const edge of fit.edges) expect(edge.start, `the answer "${edge.name}" keeps the note's padding`).toBeGreaterThanOrEqual(11);
}

const pem = (label: string, body: string) => `-----BEGIN ${label}-----
${body}
-----END ${label}-----`;

type Screen = {
  name: string;
  /** The path after the language. */
  path: string;
  /** Something to wait for, so the page does not move under the checks. */
  ready: (page: Page, lang: Lang) => Promise<void>;
  me?: Partial<ReturnType<typeof adminMeFixture>>;
  signedIn?: boolean;
  alerts?: boolean;
  handlers?: Handlers;
  /** The answer the screen is meant to give; 200 unless it says so (the Not found screens answer 404, and the browser logs that as a console error). */
  status?: number;
  /** A fake clock from the start, for a screen that has to move time (a refetch after the stale time). */
  clock?: boolean;
  after?: (page: Page, lang: Lang) => Promise<void>;
};

const nodesHeading = (key: string) => async (page: Page, lang: Lang) => {
  await expect(page.getByRole("heading", {level: 1, name: nodesText(lang, key)})).toBeVisible();
};

const heading = (key: string) => async (page: Page, lang: Lang) => {
  await expect(page.getByRole("heading", {level: 1, name: adm(lang, key)})).toBeVisible();
};

const SCREENS: Screen[] = [
  {name: "login", path: "/login", signedIn: false, ready: heading("login.title")},
  // T-468, T-478: the Not found screen, inside the shell for a visitor who has an admin session cookie and alone for one who has none (spec 8.7).
  {name: "not-found-in-shell", path: "/no/such/page", status: 404, ready: async (page) => expect(page.locator(".not-found .empty-state__title")).toBeVisible()},
  {
    name: "not-found-alone",
    path: "/no/such/page",
    signedIn: false,
    status: 404,
    ready: async (page) => {
      await expect(page.locator(".not-found--standalone .empty-state__title")).toBeVisible();
      await expect(page.locator("aside.sidebar")).toHaveCount(0);
    },
  },
  {name: "login-ended", path: "/login?ended=1", signedIn: false, ready: heading("login.title"), after: async (page) => expect(page.getByTestId("session-ended")).toBeVisible()},
  {
    name: "setup-password",
    path: "/setup",
    me: {must_change_password: true, totp_enrolled: false},
    ready: heading("setup.password.title"),
  },
  {
    name: "setup-totp",
    path: "/setup",
    me: {must_change_password: false, totp_enrolled: false},
    ready: heading("setup.totp.title"),
    // A page opened straight on this step makes no secret until it is asked for (gate-r33-2).
    after: async (page) => {
      await page.getByTestId("totp-show").click();
      await expect(page.getByTestId("totp-qr")).toBeVisible();
    },
  },
  // p4-nodes 10.1, T-339: the Overview with its totals, the health of four nodes in four states and the free DNS counters.
  {
    name: "overview",
    path: "/overview",
    ready: nodesHeading("pages.overview.title"),
    after: async (page, lang) => {
      await expect(page.getByRole("grid", {name: nodesText(lang, "overview.nodes.gridLabel")}).getByRole("row")).toHaveCount(5);
      await expect(page.getByRole("grid", {name: nodesText(lang, "overview.counters.gridLabel")}).getByRole("row")).toHaveCount(4);
    },
  },
  {
    name: "overview-empty",
    path: "/overview",
    handlers: {"GET /overview": {body: {nodes: [], config_head: 0, free_dns: {enabled: false, qps: 1000, version: 1}}}, "GET /free-dns/counters": {body: {items: []}}},
    ready: nodesHeading("pages.overview.title"),
    after: async (page) => expect(page.getByTestId("counters-empty")).toBeVisible(),
  },
  // T-556, T-546, T-561: the Nodes page with the addresses of free DNS, its switch, the warning and the addresses given up.
  {
    name: "nodes",
    path: "/nodes",
    ready: nodesHeading("pages.nodes.title"),
    after: async (page, lang) => {
      await expect(page.getByRole("grid", {name: nodesText(lang, "givenUp.gridLabel")}).getByRole("row")).toHaveCount(3);
      await expect(page.getByTestId("free-dns-addresses").getByRole("listitem")).toHaveCount(2);
    },
  },
  {
    name: "nodes-empty",
    path: "/nodes",
    handlers: {"GET /nodes": {body: {items: []}}, "GET /pairs": {body: {items: []}}, "GET /nodes/addresses-given-up": {body: {items: []}}},
    ready: nodesHeading("pages.nodes.title"),
    after: async (page) => expect(page.getByTestId("free-dns-no-address")).toBeVisible(),
  },
  {
    name: "nodes-fresh-dialog",
    path: "/nodes",
    handlers: {"PUT /settings/free-dns": err(403, "totp_fresh_required")},
    ready: nodesHeading("pages.nodes.title"),
    after: async (page, lang) => {
      const card = page.getByTestId("free-dns");
      await card.getByRole("switch", {name: nodesText(lang, "freeDns.enabled")}).locator("xpath=ancestor::label").click();
      await card.getByRole("button", {name: nodesText(lang, "freeDns.submit")}).click();
      await expect(page.getByRole("dialog", {name: adm(lang, "fresh.title")})).toBeVisible();
    },
  },
  {name: "runbook", path: "/runbook", ready: nodesHeading("pages.runbook.title"), after: async (page) => expect(page.getByTestId("runbook")).toBeVisible()},
  // T-542, T-340 (package PN): the page of a node in each state it can be in, its confirmations, and the enrolment.
  {name: "node-detail", path: `/nodes/${nodeA.id}`, ready: async (page) => expect(page.getByRole("heading", {level: 1, name: "tehran-1"})).toBeVisible(), after: async (page) => expect(page.getByTestId("node-failover")).toBeVisible()},
  {
    name: "node-detail-hub",
    path: `/nodes/${nodeB.id}`,
    handlers: {"GET /nodes/{id}": {body: {...nodeB, dns_withdrawn: true, f3_unmet: ["peer_view", "stable_period"], drain_state: "draining", health: "degraded", revocation_pending: true}}},
    ready: async (page) => expect(page.getByRole("heading", {level: 1, name: "tehran-2"})).toBeVisible(),
    after: async (page) => expect(page.getByTestId("f3-unmet")).toBeVisible(),
  },
  {name: "node-detail-pending", path: `/nodes/${nodeD.id}`, ready: async (page) => expect(page.getByRole("heading", {level: 1, name: "tabriz-1"})).toBeVisible(), after: async (page) => expect(page.getByTestId("node-approve")).toBeVisible()},
  {
    name: "node-detail-revoked",
    path: `/nodes/${nodeC.id}`,
    handlers: {
      "GET /nodes/{id}": {body: {...nodeC, status: "revoked"}},
      "GET /nodes/{id}/reports": {
        body: {
          claims: [claimFixture(1), claimFixture(2), claimFixture(3)],
          claims_truncated: true,
          kept_rows: [{tenant_id: "0000000a-0000-4000-8000-000000000001", endpoint_id: "0000000b-0000-4000-8000-0000000000aa"}],
          kept_truncated: false,
        },
      },
    },
    ready: async (page) => expect(page.getByRole("heading", {level: 1, name: "shiraz-1"})).toBeVisible(),
    after: async (page, lang) => {
      await expect(page.getByRole("grid", {name: nodesText(lang, "node.reports.gridLabel")}).getByRole("row")).toHaveCount(4);
      await expect(page.getByTestId("reports-kept")).toBeVisible();
    },
  },
  {
    name: "node-detail-hold-dialog",
    path: `/nodes/${nodeA.id}`,
    ready: async (page) => expect(page.getByRole("heading", {level: 1, name: "tehran-1"})).toBeVisible(),
    after: async (page) => {
      await page.getByTestId("request-hold").click();
      await expect(page.getByRole("alertdialog")).toBeVisible();
    },
  },
  {
    name: "node-detail-revoke-dialog",
    path: `/nodes/${nodeA.id}`,
    ready: async (page) => expect(page.getByRole("heading", {level: 1, name: "tehran-1"})).toBeVisible(),
    after: async (page) => {
      await page.getByTestId("node-revoke").click();
      await expect(page.getByRole("alertdialog")).toBeVisible();
    },
  },
  {
    name: "enrol",
    path: "/nodes/enrol",
    ready: nodesHeading("pages.enrol.title"),
    after: async (page, lang) => expect(page.getByRole("grid", {name: nodesText(lang, "enrol.list.gridLabel")}).getByRole("row")).toHaveCount(5),
  },
  {
    name: "enrol-confirm",
    path: `/nodes/enrol?dialog=confirmNode&enrollmentId=${enrolWaiting.id}`,
    ready: nodesHeading("pages.enrol.title"),
    after: async (page, lang) => {
      const dialog = page.getByRole("dialog", {name: nodesText(lang, "enrol.confirm.title")});
      await expect(dialog).toBeVisible();
      await dialog.locator('input[name="typed_fingerprint"]').fill(FP.slice(0, 24));
      await expect(dialog.getByTestId("fingerprint-check")).toHaveAttribute("data-check", "partial");
    },
  },
  {
    name: "enrol-result",
    path: "/nodes/enrol",
    ready: nodesHeading("pages.enrol.title"),
    after: async (page) => {
      await page.locator('input[name="dns_bind_ip"]').fill("203.0.113.31");
      await page.locator('input[name="proxy_bind_ip"]').fill("198.51.100.31");
      await page.getByTestId("enrol-submit").click();
      await expect(page.getByTestId("one-time-result")).toBeVisible();
    },
  },
  // T-341 (package PD): the Pair page with its pairs, the notes of SC 8a.9, an empty list, the edit with its sentences, and a dialog with too few nodes.
  {
    name: "pair",
    path: "/pair",
    ready: nodesHeading("pages.pair.title"),
    after: async (page, lang) => {
      await expect(page.getByRole("grid", {name: nodesText(lang, "pair.grid.label")}).getByRole("row")).toHaveCount(2);
      await expect(page.getByTestId("pair-notes")).toBeVisible();
    },
  },
  {
    name: "pair-empty",
    path: "/pair",
    handlers: {"GET /pairs": {body: {items: []}}},
    ready: nodesHeading("pages.pair.title"),
    after: async (page) => expect(page.getByTestId("pair-global-none")).toBeVisible(),
  },
  {
    name: "pair-edit",
    path: `/pair?dialog=editPair&pairId=${nodeMock.state.pairs[0]!.id}`,
    ready: nodesHeading("pages.pair.title"),
    after: async (page, lang) => {
      const dialog = page.getByRole("dialog", {name: nodesText(lang, "pair.form.editTitle")});
      await expect(dialog).toBeVisible();
      await dialog.getByTestId("pair-swap").click();
      await expect(dialog.getByTestId("pair-form-warnings")).toBeVisible();
    },
  },
  {
    name: "pair-new",
    path: "/pair?dialog=newPair",
    ready: nodesHeading("pages.pair.title"),
    after: async (page, lang) => {
      await expect(page.getByRole("dialog", {name: nodesText(lang, "pair.form.createTitle")})).toBeVisible();
      await expect(page.getByTestId("pair-not-enough")).toBeVisible();
    },
  },
  // T-344 (package PD): the Domain page, an apply that is pending in a transition, what a change of zone touches, the certificates and the upload.
  {name: "domain", path: "/domain", ready: nodesHeading("pages.domain.title"), after: async (page) => expect(page.getByTestId("certificates")).toBeVisible()},
  {
    name: "domain-pending",
    path: "/domain",
    handlers: {
      "GET /settings/domain": {body: domainFixture({apply_pending: true, prev_dns_zone: "dns.old.example.ir", transition_until: "2099-01-01T00:00:00Z", applied_panel_host: "panel-old.example.ir"})},
      "GET /certificates": {
        body: {
          items: [
            certificateFixture({kind: "wildcard", names: ["*.dns.example.ir", "dns.example.ir"], not_after: new Date(Date.now() + 12 * 86_400_000).toISOString()}),
            certificateFixture({kind: "panel", names: ["panel.example.ir"], not_after: new Date(Date.now() + 200 * 86_400_000).toISOString()}),
            certificateFixture({kind: "admin", names: ["admin.example.ir"], state: "retired"}),
            certificateFixture({kind: "node_ca", source: "issued", names: ["ctrlz-node-ca"], not_after: "2030-01-01T00:00:00Z"}),
          ],
        },
      },
    },
    ready: nodesHeading("pages.domain.title"),
    after: async (page) => {
      await expect(page.getByTestId("domain-apply-pending")).toBeVisible();
      await expect(page.getByTestId("domain-transition")).toBeVisible();
    },
  },
  {
    name: "domain-impact",
    path: "/domain",
    ready: nodesHeading("pages.domain.title"),
    after: async (page) => {
      await page.getByTestId("domain-form").locator('input[name="dns_zone"]').fill("dns.example.com");
      await expect(page.getByTestId("domain-impact")).toContainText(/12|۱۲/);
    },
  },
  {
    name: "domain-empty",
    path: "/domain",
    handlers: {"GET /settings/domain": {body: {apply_pending: false}}, "GET /certificates": {body: {items: []}}},
    ready: nodesHeading("pages.domain.title"),
    after: async (page) => expect(page.getByTestId("certificates").getByTestId("grid-empty")).toBeVisible(),
  },
  {
    name: "domain-upload",
    path: "/domain",
    ready: nodesHeading("pages.domain.title"),
    after: async (page, lang) => {
      await page.getByTestId("cert-upload-open").click();
      const dialog = page.getByRole("dialog", {name: nodesText(lang, "domain.certs.upload.title")});
      await expect(dialog).toBeVisible();
      await dialog.getByTestId("cert-chain").fill(pem("CERTIFICATE", "A".repeat(80)));
      await dialog.getByTestId("cert-key").fill(pem("PRIVATE KEY", "B".repeat(80)));
    },
  },
  {name: "users", path: "/users", ready: heading("pages.users.title"), after: async (page, lang) => expect(page.getByRole("grid", {name: adm(lang, "users.gridLabel")}).getByRole("row")).toHaveCount(users.length + 1)},
  {
    name: "users-banners",
    path: "/users",
    me: {fresh_until: new Date(Date.now() + 4 * 60_000).toISOString(), notices: [{kind: "password_reset", at: "2026-11-16T08:00:00Z"}]},
    alerts: true,
    ready: heading("pages.users.title"),
    after: async (page, lang) => expect(page.getByText(adm(lang, "notices.password_reset.title"))).toBeVisible(),
  },
  {name: "users-empty", path: "/users", handlers: {"GET /users": {body: {items: []}}}, ready: heading("pages.users.title"), after: async (page) => expect(page.getByTestId("grid-empty")).toBeVisible()},
  {name: "users-failed", path: "/users", handlers: {"GET /users": err(503, "service_unavailable")}, ready: heading("pages.users.title"), after: async (page) => expect(page.getByRole("alert")).toBeVisible()},
  {name: "users-create", path: "/users?dialog=createUser", ready: heading("pages.users.title"), after: async (page, lang) => expect(page.getByRole("dialog", {name: adm(lang, "users.create.title")})).toBeVisible()},
  {
    name: "users-result",
    path: "/users",
    ready: heading("pages.users.title"),
    after: async (page, lang) => {
      await page.getByRole("button", {name: adm(lang, "users.create.open")}).click();
      await page.locator('input[name="phone"]').fill("09121234567");
      await page.getByRole("button", {name: adm(lang, "users.create.submit"), exact: true}).click();
      await expect(page.getByTestId("one-time-result")).toBeVisible();
    },
  },
  {name: "invites", path: "/invites", ready: heading("pages.invites.title"), after: async (page, lang) => expect(page.getByRole("grid", {name: adm(lang, "invites.gridLabel")}).getByRole("row")).toHaveCount(5)},
  {name: "invites-create", path: "/invites?dialog=createInvite", ready: heading("pages.invites.title"), after: async (page, lang) => expect(page.getByRole("dialog", {name: adm(lang, "invites.create.title")})).toBeVisible()},
  {name: "sms-gateways", path: "/sms", alerts: true, ready: heading("pages.sms.title"), after: async (page) => expect(page.getByTestId("gateway-sms_ir")).toBeVisible()},
  {
    name: "sms-edit",
    path: "/sms",
    ready: heading("pages.sms.title"),
    after: async (page, lang) => {
      await page.getByTestId("gateway-melipayamak").getByRole("button", {name: adm(lang, "sms.gateways.edit")}).click();
      await expect(page.getByRole("dialog").locator('input[name="gw_melipayamak_password"]')).toBeVisible();
    },
  },
  {
    name: "sms-test",
    path: "/sms",
    ready: heading("pages.sms.title"),
    after: async (page, lang) => {
      await page.getByTestId("gateway-sms_ir").getByRole("button", {name: adm(lang, "sms.gateways.test")}).click();
      await expect(page.getByRole("dialog").locator('input[name="phone"]')).toBeVisible();
    },
  },
  {
    name: "sms-routing",
    path: "/sms",
    ready: heading("pages.sms.title"),
    after: async (page, lang) => {
      await page.getByRole("tab", {name: adm(lang, "sms.tabs.routing")}).click();
      await expect(page.getByTestId("sms-routing")).toBeVisible();
    },
  },
  {
    name: "sms-templates",
    path: "/sms",
    ready: heading("pages.sms.title"),
    after: async (page, lang) => {
      await page.getByRole("tab", {name: adm(lang, "sms.tabs.templates")}).click();
      await expect(page.getByTestId("template-otp-fa")).toBeVisible();
      await page.getByTestId("template-otp-fa").locator("textarea").fill("ک".repeat(70));
      await expect(page.getByTestId("otp-refused")).toBeVisible();
    },
  },
  {
    name: "sms-limits",
    path: "/sms",
    ready: heading("pages.sms.title"),
    after: async (page, lang) => {
      await page.getByRole("tab", {name: adm(lang, "sms.tabs.limits")}).click();
      await expect(page.getByTestId("sms-limits")).toBeVisible();
    },
  },
  // P1 gate: the conflict note (wp10-r5-3) had been read as DOM and axe only. It sits under a field of a tab and under one of a dialog, which are
  // two different widths at 375, and it holds a number (digits follow the language) and two buttons. The server moves under the admin's edit.
  {
    name: "sms-limits-conflict",
    path: "/sms",
    clock: true,
    handlers: {"GET /sms/limits": () => ({body: conflictServer.limits})},
    ready: heading("pages.sms.title"),
    after: async (page, lang) => {
      conflictServer.limits = limitsFixture();
      await page.getByRole("tab", {name: adm(lang, "sms.tabs.limits")}).click();
      const form = page.getByTestId("sms-limits");
      const ip = form.locator('input[name="otp_cap_ip"]');
      await ip.fill("60");
      await ip.blur();
      conflictServer.limits = limitsFixture({otp_cap_ip: 10});
      // The stale time of a query is 30 s: past it, coming back online refetches, and the value the server holds now is a conflict.
      await page.clock.fastForward(31_000);
      await page.evaluate(() => {
        window.dispatchEvent(new Event("offline"));
        window.dispatchEvent(new Event("online"));
      });
      await expect(form.getByTestId("conflict-otp_cap_ip")).toBeVisible();
      await expectNoteFits(form.getByTestId("conflict-otp_cap_ip"));
    },
  },
  {
    name: "sms-edit-conflict",
    path: "/sms",
    handlers: {"GET /sms/gateways": () => ({body: {items: conflictServer.gateways}}), "PUT /sms/gateways/{provider}": {body: gateways[0]}},
    ready: heading("pages.sms.title"),
    after: async (page, lang) => {
      conflictServer.gateways = gateways;
      await page.getByTestId("gateway-sms_ir").getByRole("button", {name: adm(lang, "sms.gateways.edit")}).click();
      const dialog = page.getByRole("dialog");
      const price = dialog.locator('input[name="cost_per_message"]');
      await price.fill("600");
      await price.focus();
      conflictServer.gateways = [{...gateways[0]!, cost_per_message: "1500.0000"}, ...gateways.slice(1)];
      await page.keyboard.press("Enter");
      await expect(dialog.getByTestId("conflict-cost_per_message")).toBeVisible();
      await expectNoteFits(dialog.getByTestId("conflict-cost_per_message"));
    },
  },
  {
    name: "sms-stats",
    path: "/sms",
    ready: heading("pages.sms.title"),
    after: async (page, lang) => {
      await page.getByRole("tab", {name: adm(lang, "sms.tabs.stats")}).click();
      await expect(page.getByTestId("sms-stats")).toBeVisible();
    },
  },
  {name: "settings", path: "/settings", ready: heading("pages.settings.title"), after: async (page) => expect(page.getByTestId("webauthn-origins")).toBeVisible()},
  {
    name: "settings-impact",
    path: "/settings",
    ready: heading("pages.settings.title"),
    after: async (page, lang) => {
      await page.getByRole("radio", {name: adm(lang, "settings.registration.mode.open")}).click();
      await expect(page.getByTestId("impact-graced")).toBeVisible();
      await page.getByTestId("settings-webauthn").locator('input[name="rp_id"]').fill("example.ir");
      await expect(page.getByTestId("impact-credentials")).toBeVisible();
    },
  },
  {name: "audit", path: "/audit", ready: heading("pages.audit.title"), after: async (page, lang) => expect(page.getByRole("grid", {name: adm(lang, "audit.gridLabel")}).getByRole("row")).toHaveCount(3)},
  {
    name: "account-dialog",
    path: "/users",
    ready: heading("pages.users.title"),
    after: async (page, lang) => {
      // Below md the sidebar is a panel behind the hamburger, and the user menu is at its foot.
      const hamburger = page.getByRole("button", {name: shellText(lang, "sidebar.openMenu")});
      if (await hamburger.isVisible()) await hamburger.click();
      await page.getByRole("button", {name: adm(lang, "userMenu.label", {name: "admin"})}).first().click();
      await page.getByRole("menuitem", {name: adm(lang, "userMenu.account")}).click();
      await expect(page.getByRole("dialog", {name: adm(lang, "account.title")})).toBeVisible();
      // The panel that held the menu has finished closing: it is a dialog too, and a half-faded one makes the contrast undecidable.
      await expect(page.getByRole("dialog")).toHaveCount(1);
      // At 375 the Account item sat where the dialog's Cancel button appears, and a hovered tertiary button is 4.22:1 (#66696c on
      // #e1e1e2). That is the theme's hover state, not this screen's, so the pointer leaves before the check (reported in the WP10 notes).
      await page.mouse.move(0, 0);
    },
  },
  {
    name: "fresh-dialog",
    path: "/settings",
    handlers: {"PUT /settings/webauthn": err(403, "totp_fresh_required")},
    ready: heading("pages.settings.title"),
    after: async (page, lang) => {
      const card = page.getByTestId("settings-webauthn");
      await card.getByRole("switch", {name: adm(lang, "settings.webauthn.enabled")}).locator("xpath=ancestor::label").click();
      await card.getByRole("button", {name: adm(lang, "settings.webauthn.submit")}).click();
      await expect(page.getByRole("dialog", {name: adm(lang, "fresh.title")})).toBeVisible();
    },
  },
];

for (const screen of SCREENS) {
  test(`${screen.name}: language, direction, theme, no overflow, accessible`, async ({page, context, baseURL, matrix, guard}) => {
    expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
    const lang = matrix!.lang;
    if (screen.status === 404) guard.allowConsole(/status of 404/);
    await openAdmin(context, baseURL, {
      cookie: screen.signedIn !== false,
      me: screen.me,
      alerts: screen.alerts ? [alertFixture({severity: "critical", params: {provider: "sms_ir", class: "credit", code: "no_credit"}})] : [],
      handlers: {...handlers, ...screen.handlers},
    });
    if (screen.clock) await page.clock.install();
    const response = await page.goto(`/${lang}${screen.path}`);
    await screen.ready(page, lang);
    await screen.after?.(page, lang);
    await expectMatrixPage({page, context, response, baseURL, matrix: matrix!, status: screen.status});
    await expectAccessible(page, {screen: `admin-${screen.name}`, libraryDefects: [LIVE_ANNOUNCER]});
  });
}
