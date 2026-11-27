package adminapi

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/isolation"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// admIso is the fixture of rule isolation-success-coverage for the admin API. The admin acts on
// the console and, through three routes, on tenants: POST /users makes one, the re-issue of a
// one-time password changes one user. Every other route writes rows no tenant owns, so the case
// for it is that it SUCCEEDS, leaves both tenants' digests as they were, and the write it claims
// is there. A route that quietly touched a tenant would move a digest, and a call that was
// refused would fail on its status: either way the label cannot hide it.
type admIso struct {
	r    *rig
	db   *isolation.Tenants
	b    *browser // the admin signed in by the last Arrange
	seed secret.Bytes
	base int // the count Arrange took, for Proof
	id   string
	body map[string]any
}

func (e *admIso) t() *testing.T { return e.r.t }

// prepare puts the console account in a known state and clears what a login would trip on.
func (e *admIso) prepare(ready bool) secret.Bytes {
	t := e.t()
	e.r.env.Exec(t, `DELETE FROM ctrlz.admin_sessions; DELETE FROM ctrlz.auth_throttle;`)
	return e.r.setupAdmin(t, ready)
}

// login signs the ready admin in; the login opens the fresh window, so the admin-fresh routes work.
func (e *admIso) login() {
	e.seed = e.prepare(true)
	e.b = e.r.browser()
	e.b.mustLogin(e.seed)
}

func (e *admIso) count(sql string) int { return e.r.count(e.t(), sql) }

func aresult(r *aresp) isolation.Result {
	return isolation.Result{Status: r.Code, Body: r.Body, Cookies: strings.Join(r.H.Values("Set-Cookie"), "; ")}
}

const (
	auditRows = `SELECT count(*) FROM ctrlz.audit_log`
)

// elsewhere builds the fixture of a write that no tenant owns. arrange runs once, for B (the
// console has one admin, not two), and countSQL is read after it and after the call: the number
// must have grown, or be exactly want when want is given.
func (e *admIso) elsewhere(status int, reason, countSQL string, arrange func(), call func() *aresp) isolation.Fixture {
	return isolation.Fixture{
		Effect: isolation.Elsewhere, Status: status, Reason: reason,
		Arrange: func(w isolation.Who) {
			if w == isolation.B {
				arrange()
				e.base = e.count(countSQL)
			}
		},
		Call: func() isolation.Result { return aresult(call()) },
		Proof: func() error {
			if n := e.count(countSQL); n <= e.base {
				return fmt.Errorf("%s: %d before the call, %d after", countSQL, e.base, n)
			}
			return nil
		},
	}
}

// reads is the fixture of a GET.
func (e *admIso) reads(arrange func(), path string, sees func() []string) isolation.Fixture {
	return isolation.Fixture{
		Effect: isolation.Shows, Status: 200, Sees: sees,
		Arrange: func(w isolation.Who) {
			if w == isolation.B {
				arrange()
			}
		},
		Call: func() isolation.Result { return aresult(e.b.get(strings.ReplaceAll(path, "{id}", e.id))) },
	}
}

func (e *admIso) fixtures() map[string]isolation.Fixture {
	r := e.r
	t := r.t
	login := func() { e.login() }
	const console = "writes console state that no tenant owns"
	// gateways gives both SMS providers credentials, the state routing and templates need.
	gateways := func() {
		e.login()
		// An earlier case (putSmsGateway) leaves its credentials pending, and a PUT refuses while a pair waits
		// (db-r19-2): the console frees the gateway, as `sms discard` does.
		r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET credentials_pending_ct = NULL, pending_hint = NULL`)
		e.b.put("/sms/gateways/sms_ir", map[string]any{"credentials": map[string]string{"api_key": "key-sms-ir-123456"}, "cost_per_message": "120.5"}).want(200, "")
		e.b.put("/sms/gateways/melipayamak", map[string]any{"credentials": map[string]string{"username": "userABCD", "password": "hunter2-secret"}}).want(200, "")
		// What routing and a test send need is ACTIVE credentials, which only the console makes (admin-r18-1).
		confirmAtConsole(t, r, "sms_ir")
		confirmAtConsole(t, r, "melipayamak")
	}
	tenantB := func() string { return r.env.B.Tenant.String() }

	return map[string]isolation.Fixture{
		"adminLogin": e.elsewhere(200, "opens a console session, which no tenant owns", `SELECT count(*) FROM ctrlz.admin_sessions`,
			func() { e.seed = e.prepare(true); e.b = r.browser(); r.freeStep(t) },
			func() *aresp { return e.b.login(adminPW, totpNow(e.seed)) }),
		"adminLogout": e.elsewhere(204, "ends a console session", `SELECT count(*) FROM ctrlz.admin_sessions WHERE revoked_at IS NOT NULL`, login,
			func() *aresp { return e.b.post("/auth/logout", nil) }),
		"adminTotpFresh": e.elsewhere(200, "opens the fresh window of a console session", `SELECT count(*) FROM ctrlz.admin_sessions WHERE totp_verified_at > now() - interval '1 minute'`,
			func() {
				e.login()
				r.env.Exec(t, `UPDATE ctrlz.admin_sessions SET totp_verified_at = now() - interval '10 minutes'`)
				r.freeStep(t)
			},
			func() *aresp { return e.b.post("/auth/totp/fresh", map[string]any{"code": totpNow(e.seed)}) }),
		"getAdminMe": e.reads(login, "/me", func() []string { return []string{adminName} }),
		"ackAdminNotices": func() isolation.Fixture {
			f := e.elsewhere(204, "dismisses a banner of the console account", `SELECT count(*) FROM ctrlz.admin_users WHERE pending_notice IS NULL`,
				func() {
					e.seed = e.prepare(true)
					r.env.Exec(t, `UPDATE ctrlz.admin_users SET pending_notice = '[{"kind":"password_reset","at":"2020-01-01T00:00:00Z"}]'::jsonb`)
					e.b = r.browser()
					e.b.mustLogin(e.seed)
				},
				func() *aresp { return e.b.post("/me/notices/ack", map[string]any{}) })
			return f
		}(),
		"changeAdminPassword": e.elsewhere(204, "changes the console account's password", auditRows, login,
			func() *aresp {
				r.freeStep(t)
				return e.b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW, "totp_code": totpNow(e.seed)})
			}),
		"adminTotpSetup": e.elsewhere(200, "starts the console account's authenticator enrolment", `SELECT count(*) FROM ctrlz.admin_users WHERE totp_secret_ct IS NOT NULL`,
			func() {
				e.prepare(false)
				e.b = r.browser()
				e.b.login(adminPW, "").want(200, "")
				e.b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW}).want(204, "")
			},
			func() *aresp { return e.b.post("/me/totp/setup", map[string]any{}) }),
		"adminTotpConfirm": e.elsewhere(204, "completes the console account's authenticator enrolment", `SELECT count(*) FROM ctrlz.admin_users WHERE totp_enabled_at IS NOT NULL`,
			func() {
				e.prepare(false)
				e.b = r.browser()
				e.b.login(adminPW, "").want(200, "")
				e.b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW}).want(204, "")
				var setup struct {
					Secret string `json:"secret"`
				}
				e.b.post("/me/totp/setup", map[string]any{}).want(200, "").json(&setup)
				e.seed = seedFromBase32(t, setup.Secret)
			},
			func() *aresp { return e.b.post("/me/totp/confirm", map[string]any{"code": totpNow(e.seed)}) }),

		"listUsers": e.reads(login, "/users", nil),
		"createUser": e.elsewhere(201, "makes a new tenant", `SELECT count(*) FROM ctrlz.tenants`, login,
			func() *aresp { return e.b.post("/users", map[string]any{"phone": nextPhone()}) }),
		"reissueOneTimePassword": {
			Effect: isolation.Changes, Status: 200,
			Arrange: func(w isolation.Who) {
				// The state a re-issue acts on: an admin-issued one-time password, no second factor.
				id := r.env.A
				if w == isolation.B {
					id = r.env.B
				}
				r.env.Exec(t, `UPDATE ctrlz.users SET must_reset = true, password_expires_at = now() + interval '72 hours' WHERE id = $1`, id.User)
				if w == isolation.B {
					e.login()
				}
			},
			Call: func() isolation.Result {
				return aresult(e.b.post("/tenants/"+tenantB()+"/users/"+r.env.B.User.String()+"/one-time-password", map[string]any{}))
			}},

		"listInvites": e.reads(login, "/invites", nil),
		"createInvite": e.elsewhere(201, "makes an invite, which belongs to a phone and no tenant", `SELECT count(*) FROM ctrlz.invites`, login,
			func() *aresp { return e.b.post("/invites", map[string]any{"phone": "09125559901"}) }),
		"revokeInvite": e.elsewhere(204, "revokes an invite", `SELECT count(*) FROM ctrlz.invites WHERE revoked_at IS NOT NULL`,
			func() {
				e.login()
				var inv struct {
					ID string `json:"id"`
				}
				e.b.post("/invites", map[string]any{"phone": "09125559902"}).want(201, "").json(&inv)
				e.id = inv.ID
			},
			func() *aresp { return e.b.call("DELETE", "/invites/"+e.id, nil) }),

		"getRegistration":       e.reads(login, "/settings/registration", nil),
		"getRegistrationImpact": e.reads(login, "/settings/registration/impact?to=open", nil),
		"putRegistration": e.elsewhere(200, console+" (the registration mode)", `SELECT count(*) FROM ctrlz.system_settings WHERE registration_mode = 'open'`,
			// A registration transition job is seeded by the catalog fixture, and while one is in flight the
			// route answers 409 conflict; a refusal proves nothing, so the case starts without it.
			func() {
				e.login()
				r.env.Exec(t, `UPDATE ctrlz.system_settings SET registration_mode = 'closed'; DELETE FROM ctrlz.admin_jobs;`)
			},
			func() *aresp {
				return e.b.put("/settings/registration", map[string]any{"mode": "open", "open_grace_days": 21})
			}),
		"getWebauthn":       e.reads(login, "/settings/webauthn", nil),
		"getWebauthnImpact": e.reads(login, "/settings/webauthn/impact?rp_id=other.example.test", nil),
		"putWebauthn": e.elsewhere(200, console+" (the passkey RP ID)", `SELECT count(*) FROM ctrlz.webauthn_config WHERE rp_id = 'panel.example.test'`, login,
			func() *aresp {
				return e.b.put("/settings/webauthn", map[string]any{"rp_id": "panel.example.test", "enabled": true})
			}),

		"listSmsGateways": e.reads(login, "/sms/gateways", nil),
		"putSmsGateway": e.elsewhere(200, console+" (a gateway's credentials)", auditRows, login,
			func() *aresp {
				return e.b.put("/sms/gateways/sms_ir", map[string]any{"credentials": map[string]string{"api_key": "key-sms-ir-123456"}, "cost_per_message": "120.5"})
			}),
		"putSmsRouting": e.elsewhere(200, console+" (which gateway sends)", auditRows, gateways,
			func() *aresp {
				return e.b.put("/sms/routing", map[string]any{"primary": "sms_ir", "fallback": "melipayamak"})
			}),
		"testSmsGateway": e.elsewhere(202, "queues a test message in the SMS outbox", `SELECT count(*) FROM ctrlz.sms_outbox`, gateways,
			func() *aresp {
				return e.b.post("/sms/gateways/melipayamak/test", map[string]any{"phone": "09125550006", "template": "otp", "locale": "en"})
			}),
		"getSmsOutbox": e.reads(func() {
			e.login()
			r.env.Scan(t, `SELECT id::text FROM ctrlz.sms_outbox ORDER BY created_at LIMIT 1`, nil, &e.id)
		}, "/sms/outbox/{id}", nil),
		"listSmsTemplates": e.reads(login, "/sms/templates", nil),
		"putSmsTemplate": e.elsewhere(200, console+" (a message template)", auditRows, login,
			func() *aresp {
				return e.b.put("/sms/templates/otp/en", map[string]any{"body": "Your Ctrl Z code is {code}."})
			}),
		"putSmsProviderTemplate": e.elsewhere(200, console+" (a provider's template id)", auditRows, gateways,
			func() *aresp {
				return e.b.put("/sms/gateways/melipayamak/templates/otp/fa", map[string]any{"provider_template_id": "5001", "param_names": []string{"code"}})
			}),
		"getSmsLimits": e.reads(login, "/sms/limits", nil),
		"putSmsLimits": e.elsewhere(200, console+" (the SMS caps)", auditRows,
			func() {
				e.login()
				e.body = map[string]any{}
				e.b.get("/sms/limits").want(200, "").json(&e.body)
			},
			func() *aresp { return e.b.put("/sms/limits", e.body) }),
		"getSmsStats": e.reads(login, "/sms/stats?days=3", nil),
		"listAudit":   e.reads(login, "/audit?limit=5", nil),
		"listAlerts":  e.reads(func() { e.login(); e.alert() }, "/alerts", nil),
		// The node routes (P4). A node is no tenant's: every case succeeds, leaves both tenants' digests as they were
		// and the write it claims is there. The reports route reads claims of both tenants, which is its purpose.
		"listNodeEnrollments": e.reads(login, "/node-enrollments", nil),
		"createNodeEnrollment": e.elsewhere(201, "makes an enrolment token, which belongs to no tenant", `SELECT count(*) FROM ctrlz.node_enrollments`,
			func() { e.login(); r.withInstall(t) },
			func() *aresp { return e.b.post("/node-enrollments", enrollBody) }),
		"confirmNodeEnrollment": e.elsewhere(201, "makes a pending node", `SELECT count(*) FROM ctrlz.nodes`,
			func() {
				e.login()
				r.seedRealNodes(t)
				var fp string
				e.id, fp = r.goodRecord(t, "isolation-confirm", 40)
				e.body = map[string]any{"fingerprint": fp, "name": "isolation"}
			},
			func() *aresp { return e.b.post("/node-enrollments/"+e.id+":confirm", e.body) }),
		"rejectNodeEnrollment": e.elsewhere(204, "rejects an enrolment record", `SELECT count(*) FROM ctrlz.node_enrollments WHERE state = 'rejected'`,
			func() {
				e.login()
				e.id, _ = r.goodRecord(t, "isolation-reject", 41)
			},
			func() *aresp { return e.b.post("/node-enrollments/"+e.id+":reject", nil) }),
		"listNodes":            e.reads(login, "/nodes", nil),
		"getNode":              e.reads(func() { e.login(); e.id = seedNode1 }, "/nodes/{id}", nil),
		"listAddressesGivenUp": e.reads(login, "/nodes/addresses-given-up", nil),
		"getNodeReports":       e.reads(func() { e.login(); e.id = seedNode1 }, "/nodes/{id}/reports", nil),
		// The routes that change membership (P4 R2). Each makes its own nodes with isoNode, which clears the ones an
		// earlier case left, so the four slots are never the reason a case fails.
		"approveNode": e.elsewhere(200, "moves a pending node to active, which no tenant owns", `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'node.approve'`,
			func() { e.login(); r.seedRealNodes(t); e.id = r.isoNode(t, "pending") },
			func() *aresp { return e.b.post("/nodes/"+e.id+":approve", nil) }),
		"revokeNode": e.elsewhere(200, "revokes a node and queues the node_revoked job, which cleans rows by the nodes' own ids", `SELECT count(*) FROM ctrlz.admin_jobs WHERE kind = 'node_revoked'`,
			func() { e.login(); r.seedRealNodes(t); e.id = r.isoNode(t, "active") },
			func() *aresp { return e.b.post("/nodes/"+e.id+":revoke", nil) }),
		"removeNode": e.elsewhere(204, "removes a node row", `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'node.remove'`,
			func() { e.login(); r.seedRealNodes(t); e.id = r.isoNode(t, "active") },
			func() *aresp { return e.b.call("DELETE", "/nodes/"+e.id, nil) }),
		"patchNode": e.elsewhere(200, "renames a node", `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'node.update'`,
			func() { e.login(); r.seedRealNodes(t); e.id = r.isoNode(t, "active") },
			func() *aresp {
				return e.b.call("PATCH", "/nodes/"+e.id, map[string]any{"name": "iso-renamed", "proxy_blocked": true})
			}),
		"putNodeAddresses": e.elsewhere(200, "moves a node's advertised addresses", `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'node.addresses_change'`,
			func() { e.login(); r.seedRealNodes(t); e.id = r.isoNode(t, "active") },
			func() *aresp {
				return e.b.put("/nodes/"+e.id+"/addresses", map[string]any{"dns_advertised_ip": "93.184.231.77", "proxy_advertised_ip": "93.184.231.78"})
			}),
		"createNodeDnsRequest": e.elsewhere(202, "asks the hub to hold a node", `SELECT count(*) FROM ctrlz.node_dns_requests`,
			func() { e.login(); r.seedRealNodes(t); e.id = r.isoNode(t, "active") },
			func() *aresp { return e.b.post("/nodes/"+e.id+"/dns-requests", map[string]any{"kind": "hold"}) }),
		"listPairs": e.reads(login, "/pairs", nil),
		"createPair": e.elsewhere(201, "makes a pair of two nodes", `SELECT count(*) FROM ctrlz.node_pairs`,
			func() {
				e.login()
				r.seedRealNodes(t)
				a, b := r.isoNodes(t)
				e.body = map[string]any{"primary_node_id": a, "fallback_node_id": b}
			},
			func() *aresp { return e.b.post("/pairs", e.body) }),
		"updatePair": e.elsewhere(200, "swaps the roles of a pair", `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'pair.update'`,
			func() {
				e.login()
				r.seedRealNodes(t)
				a, b := r.isoNodes(t)
				r.env.Scan(t, `INSERT INTO ctrlz.node_pairs (primary_node_id, fallback_node_id) VALUES ($1, $2) RETURNING id::text`, []any{a, b}, &e.id)
				e.body = map[string]any{"primary_node_id": b, "fallback_node_id": a}
			},
			func() *aresp { return e.b.put("/pairs/"+e.id, e.body) }),
		"deletePair": e.elsewhere(204, "dissolves a pair no Endpoint uses", `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'pair.delete'`,
			func() {
				e.login()
				r.seedRealNodes(t)
				a, b := r.isoNodes(t)
				r.env.Scan(t, `INSERT INTO ctrlz.node_pairs (primary_node_id, fallback_node_id) VALUES ($1, $2) RETURNING id::text`, []any{a, b}, &e.id)
			},
			func() *aresp { return e.b.call("DELETE", "/pairs/"+e.id, nil) }),
		"putGlobalPair": e.elsewhere(200, "switches the global pair", `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'settings.global_pair'`,
			func() {
				e.login()
				r.seedRealNodes(t)
				a, b := r.isoNodes(t)
				r.env.Scan(t, `INSERT INTO ctrlz.node_pairs (primary_node_id, fallback_node_id) VALUES ($1, $2) RETURNING id::text`, []any{a, b}, &e.id)
			},
			func() *aresp { return e.b.put("/settings/global-pair", map[string]any{"pair_id": e.id}) }),
		// The overview, settings and certificate routes (P4 R3). None of them reads or writes a tenant's rows: the one read that
		// crosses tenants is the impact count, which is a number.
		"getOverview":         e.reads(login, "/overview", nil),
		"listFreeDnsCounters": e.reads(login, "/free-dns/counters", nil),
		"getFreeDnsSettings":  e.reads(login, "/settings/free-dns", nil),
		"getDomainSettings":   e.reads(login, "/settings/domain", nil),
		"getDomainImpact":     e.reads(login, "/settings/domain/impact", nil),
		"listCertificates":    e.reads(login, "/certificates", nil),
		"putFreeDnsSettings": e.elsewhere(200, "changes the free DNS switch", `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'settings.free_dns'`,
			e.login,
			func() *aresp { return e.b.put("/settings/free-dns", map[string]any{"enabled": false, "qps": 500}) }),
		"putDomainSettings": e.elsewhere(200, "sets the zone of the service", `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'settings.domain'`,
			e.login,
			func() *aresp { return e.b.put("/settings/domain", map[string]any{"dns_zone": "dns.isolation.example"}) }),
		"uploadCertificate": e.elsewhere(201, "stores an uploaded certificate, which belongs to no tenant", `SELECT count(*) FROM ctrlz.certificates WHERE source = 'uploaded'`,
			func() {
				e.login()
				ca, _, _ := r.withIntake(t)
				chain, key := ca.leaf(t, 60*24*time.Hour, panelHost)
				e.body = map[string]any{"kind": "panel", "chain_pem": chain, "key_pem": key}
			},
			func() *aresp { return e.b.post("/certificates", e.body) }),
		"retireCertificate": e.elsewhere(204, "retires an uploaded certificate", `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'certificate.retire'`,
			func() {
				e.login()
				r.env.Scan(t, `INSERT INTO ctrlz.certificates (kind, chain_pem, not_before, not_after, state, source) VALUES ('panel', 'x', now(), now() + interval '30 days', 'active', 'uploaded') RETURNING id::text`, nil, &e.id)
			},
			func() *aresp { return e.b.post("/certificates/"+e.id+":retire", nil) }),
		"ackAlert": e.elsewhere(204, "acknowledges an alert", auditRows,
			func() { e.login(); e.alert() },
			func() *aresp { return e.b.post("/alerts/"+e.id+"/ack", nil) }),
	}
}

// alert plants an open alert and remembers its id.
func (e *admIso) alert() {
	t := e.t()
	e.r.env.Exec(t, `DELETE FROM ctrlz.alerts`)
	e.r.env.Scan(t, `INSERT INTO ctrlz.alerts (severity, kind, params) VALUES ('warning', 'test_open', '{}') RETURNING id::text`, nil, &e.id)
}
