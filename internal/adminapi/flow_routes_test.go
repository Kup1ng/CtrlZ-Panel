package adminapi

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/invite"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/senders"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/smssend"
)

// TestCreateUserAndList covers POST /users and GET /users (10.6, T-327).
func TestCreateUserAndList(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)

	var created struct {
		TenantID string `json:"tenant_id"`
		UserID   string `json:"user_id"`
		Password string `json:"one_time_password"`
	}
	b.post("/users", map[string]any{"phone": "0912 123 4567", "locale": "fa"}).want(201, "").json(&created)
	if created.Password != r.once.issued()[0] || created.TenantID == "" || created.UserID == "" {
		t.Fatalf("created = %+v", created)
	}
	// 72 hours to the microsecond of the transaction (D31, 10.6), and must_reset.
	var lifeOK, mustReset bool
	r.env.Scan(t, `SELECT password_expires_at - created_at = interval '72 hours', must_reset FROM ctrlz.users WHERE id = $1`,
		[]any{created.UserID}, &lifeOK, &mustReset)
	if !lifeOK || !mustReset {
		t.Fatalf("expiry equals created+72h: %v, must_reset: %v", lifeOK, mustReset)
	}
	b.post("/users", map[string]any{"phone": "+989121234567"}).want(409, "phone_unavailable")
	b.post("/users", map[string]any{"phone": "12345"}).want(422, "invalid_phone")
	b.post("/users", map[string]any{"phone": "09121234568", "locale": "de"}).want(400, "bad_request") // an enum of the schema: refused before the handler (rule boundary-input)

	// The list: filtered by prefix, paged, and never a hash.
	var page struct {
		Items []struct {
			Phone    string  `json:"phone_e164"`
			UserID   string  `json:"user_id"`
			OTPUntil *string `json:"one_time_password_expires_at"`
		} `json:"items"`
		Next *string `json:"next_cursor"`
	}
	b.get("/users?q=09121234").want(200, "").json(&page)
	if len(page.Items) != 1 || page.Items[0].Phone != "+989121234567" || page.Items[0].OTPUntil == nil {
		t.Fatalf("filtered list = %+v", page)
	}
	// A filter pasted from a chat or a note carries the marks the phone parser drops: a right-to-left
	// mark, a pop-directional mark, a no-break space inside, a line feed. The schema used to refuse
	// them before the handler ran (round 15, primitives-r15-1), so the paste fold of SearchPrefix was
	// reached by a unit test and by no request.
	for _, q := range []string{"\u200f09121234\u200f", "\u202a+98 912 123\u202c 4", "0912\t1234\n", "\u2066\u06f0\u06f9\u06f1\u06f2\u06f1\u06f2\u06f3\u06f4\u2069"} {
		var got struct {
			Items []struct {
				Phone string `json:"phone_e164"`
			} `json:"items"`
		}
		b.get("/users?q="+url.QueryEscape(q)).want(200, "").json(&got)
		if len(got.Items) != 1 || got.Items[0].Phone != "+989121234567" {
			t.Errorf("a filter %q pasted with marks listed %+v, want the one user", q, got.Items)
		}
	}
	all := b.get("/users").want(200, "")
	for _, leak := range []string{"password_hash", "argon2", "totp_secret", "token_hash", "secret"} {
		if strings.Contains(strings.ToLower(string(all.Body)), leak) {
			t.Errorf("GET /users mentions %q: %s", leak, all.Body)
		}
	}
	seen := map[string]bool{}
	cursor := ""
	for pages := 0; pages < 10; pages++ {
		path := "/users?limit=1"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		var p struct {
			Items []struct {
				UserID string `json:"user_id"`
			} `json:"items"`
			Next *string `json:"next_cursor"`
		}
		b.get(path).want(200, "").json(&p)
		for _, it := range p.Items {
			seen[it.UserID] = true
		}
		if p.Next == nil {
			break
		}
		cursor = *p.Next
	}
	if len(seen) != 3 { // tenants A and B and the new one
		t.Fatalf("paging saw %d users", len(seen))
	}
	b.get("/users?cursor=%21%21").want(400, "bad_request")
	b.get("/users?q=abc").want(422, "validation_failed")
	if r.count(t, `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'user.create' AND target = $1`, "tenant:"+created.TenantID) != 1 {
		t.Fatal("no user.create audit row")
	}
}

// TestInvites covers 11.3 and the admin side of T-330.
func TestInvites(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.env.ResetSMS(t)

	var inv struct {
		ID   string `json:"id"`
		Code string `json:"code"`
		Link string `json:"link"`
	}
	b.post("/invites", map[string]any{"phone": "09125550001", "send_sms": false}).want(201, "").json(&inv)
	if len(strings.ReplaceAll(inv.Code, "-", "")) != 20 || inv.Link != "https://"+panelHost+"/invite#"+inv.Code {
		t.Fatalf("invite = %+v", inv)
	}
	want, err := invite.Hash(inv.Code)
	if err != nil {
		t.Fatal(err)
	}
	var stored []byte
	r.env.Scan(t, `SELECT token_hash FROM ctrlz.invites WHERE id = $1`, []any{inv.ID}, &stored)
	if string(stored) != string(want) {
		t.Fatal("the stored hash is not the hash of the canonical code")
	}
	if r.count(t, `SELECT count(*) FROM ctrlz.sms_outbox`) != 0 {
		t.Fatal("an invite without send_sms queued a message")
	}
	// The list holds no code.
	list := b.get("/invites").want(200, "")
	if strings.Contains(string(list.Body), inv.Code) || strings.Contains(string(list.Body), "code") {
		t.Fatalf("the list shows a code: %s", list.Body)
	}
	b.post("/invites", map[string]any{"phone": r.env.A.Phone, "send_sms": false}).want(409, "phone_unavailable")
	b.post("/invites", map[string]any{"phone": "x", "send_sms": false}).want(422, "invalid_phone")
	b.post("/invites", map[string]any{"phone": "09125550002", "send_sms": false, "ttl_hours": 0}).want(400, "bad_request")
	b.post("/invites", map[string]any{"phone": "09125550002", "send_sms": false, "ttl_hours": 721}).want(400, "bad_request")

	// send_sms: one outbox row whose value opens only under the sms_cred key.
	var inv2 struct {
		ID   string `json:"id"`
		Code string `json:"code"`
	}
	b.post("/invites", map[string]any{"phone": "09125550003", "send_sms": true, "locale": "en", "ttl_hours": 24}).want(201, "").json(&inv2)
	var oid uuid.UUID
	var ct []byte
	var kind, tmpl string
	r.env.Scan(t, `SELECT id, kind, template_key, params_ct FROM ctrlz.sms_outbox`, nil, &oid, &kind, &tmpl, &ct)
	if kind != "invite" || tmpl != "invite" || len(ct) == 0 {
		t.Fatalf("outbox row: %s %s %d bytes", kind, tmpl, len(ct))
	}
	got, err := sms.OpenOutbox(r.keys, oid, "+989125550003", ct)
	if err != nil || got.Reveal() != inv2.Code {
		t.Fatalf("the sealed value does not open to the code: %v", err)
	}
	if _, err := sms.OpenOutbox(authtest.AdminKeys(t), oid, "+989125550003", ct); err == nil {
		t.Fatal("the sealed value opened under another key")
	}
	if _, err := sms.OpenOutbox(r.keys, oid, "+989125550999", ct); err == nil {
		t.Fatal("the sealed value opened for another phone (the AAD holds the phone)")
	}

	// Revoke.
	b.call("DELETE", "/invites/"+inv.ID, nil).want(204, "")
	b.call("DELETE", "/invites/"+inv.ID, nil).want(404, "not_found")
	var state string
	var rows struct {
		Items []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"items"`
	}
	b.get("/invites").want(200, "").json(&rows)
	for _, it := range rows.Items {
		if it.ID == inv.ID {
			state = it.State
		}
	}
	if state != "revoked" {
		t.Fatalf("state = %q", state)
	}
	acts := r.auditActions(t)
	if has(acts, "invite.create") != 2 || has(acts, "invite.revoke") != 1 {
		t.Fatalf("audit: %v", acts)
	}
	// The audit row records the ttl and send_sms, never the code or the phone.
	if r.count(t, `SELECT count(*) FROM ctrlz.audit_log WHERE params::text LIKE '%' || $1 || '%' OR params::text LIKE '%0912555%' OR target LIKE '%0912555%'`, inv.Code) != 0 {
		t.Fatal("the audit log holds a code or a phone")
	}
}

// TestInviteSMSThroughTheWorker runs the real worker loop with the noop gateway:
// the admin seals the code under sms_cred, the worker opens it with its own copy
// of the key, sends, and clears the ciphertext (T-330, 18.2 "Invite SMS").
func TestInviteSMSThroughTheWorker(t *testing.T) {
	adminKeys, workerKeys := authtest.SharedRings(t)
	r := newRigKeys(t, adminKeys)
	b, _ := r.admin(t)
	r.env.ResetSMS(t)
	r.env.AddGateway(t, workerKeys, authtest.Gateway{Provider: "noop", Role: "primary"})

	file := filepath.Join(t.TempDir(), "noop.jsonl")
	log := r.deps.Log
	src := smssend.NewSource(r.env.Worker(t), workerKeys, senders.Env{Name: "test", NoopFile: file}, log)
	w, err := smssend.New(smssend.Config{Store: r.env.Worker(t), Router: sms.NewRouter(src, classify.Routing{}), Keys: workerKeys, Log: log, Poll: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = w.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	var inv struct {
		ID   string `json:"id"`
		Code string `json:"code"`
	}
	b.post("/invites", map[string]any{"phone": "09125550004", "send_sms": true, "locale": "en"}).want(201, "").json(&inv)
	waitFor(t, 20*time.Second, "the outbox row to be sent", func() bool {
		return r.count(t, `SELECT count(*) FROM ctrlz.sms_outbox WHERE state = 'sent' AND params_ct IS NULL`) == 1
	})
	line, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(line), `"template":"invite"`) || !strings.Contains(string(line), inv.Code) || !strings.Contains(string(line), "+989125550004") {
		t.Fatalf("noop received %q", line)
	}
	// The delivery log holds neither the phone nor the text.
	if r.count(t, `SELECT count(*) FROM ctrlz.sms_deliveries WHERE row_to_json(sms_deliveries)::text LIKE '%0912555%' OR row_to_json(sms_deliveries)::text LIKE '%' || $1 || '%'`, inv.Code) != 0 {
		t.Fatal("sms_deliveries holds a phone or a code")
	}

	// A test send through the same path (T-330): pinned to the gateway.
	var q struct {
		OutboxID string `json:"outbox_id"`
	}
	b.post("/sms/gateways/noop/test", map[string]any{"phone": "09125550005", "template": "otp"}).want(202, "").json(&q)
	waitFor(t, 20*time.Second, "the test message", func() bool {
		var st struct {
			State string `json:"state"`
		}
		b.get("/sms/outbox/" + q.OutboxID).json(&st)
		return st.State == "sent"
	})

	// The template with no placeholder takes no value; its test send is sent and
	// raises no payload alert (review sms-r1-17).
	b.post("/sms/gateways/noop/test", map[string]any{"phone": "09125550005", "template": "account_exists"}).want(202, "").json(&q)
	waitFor(t, 20*time.Second, "the account_exists test message", func() bool {
		var st struct {
			State     string `json:"state"`
			LastError string `json:"last_error"`
		}
		b.get("/sms/outbox/" + q.OutboxID).json(&st)
		if st.State == "failed" {
			t.Fatalf("the account_exists test send failed: %s", st.LastError)
		}
		return st.State == "sent"
	})
	if r.count(t, `SELECT count(*) FROM ctrlz.alerts WHERE kind = 'sms_payload'`) != 0 {
		t.Error("a test send of account_exists raised a payload alert")
	}
}

func waitFor(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	testwait.UntilEvery(t, d, 100*time.Millisecond, what, ok)
}

// TestRegistrationSettings covers 11.4.
func TestRegistrationSettings(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.env.Exec(t, `DELETE FROM ctrlz.admin_jobs`)

	var cur struct {
		Mode  string `json:"mode"`
		Grace int    `json:"open_grace_days"`
	}
	b.get("/settings/registration").want(200, "").json(&cur)
	if cur.Mode != "closed" {
		t.Fatalf("default mode = %q", cur.Mode)
	}
	b.put("/settings/registration", map[string]any{"mode": "bogus"}).want(400, "bad_request")
	b.put("/settings/registration", map[string]any{"mode": "open", "open_grace_days": 0}).want(400, "bad_request")
	b.get("/settings/registration/impact?to=bogus").want(400, "bad_request")

	// The seed holds one unproven active claim per tenant, none graced before.
	var im struct{ Graced, SuspendedAtOnce int }
	b.get("/settings/registration/impact?to=open").want(200, "").json(&struct {
		Graced          *int `json:"graced"`
		SuspendedAtOnce *int `json:"suspended_at_once"`
	}{&im.Graced, &im.SuspendedAtOnce})
	if want := r.count(t, `SELECT count(*) FROM ctrlz.ip_claims WHERE state = 'active' AND proven_at IS NULL AND first_grace_at IS NULL`); im.Graced != want || want == 0 {
		t.Fatalf("impact graced = %d, want %d", im.Graced, want)
	}

	b.put("/settings/registration", map[string]any{"mode": "open", "open_grace_days": 21}).want(200, "").json(&cur)
	if cur.Mode != "open" || cur.Grace != 21 {
		t.Fatalf("after change: %+v", cur)
	}
	var kind, params string
	r.env.Scan(t, `SELECT kind, params::text FROM ctrlz.admin_jobs WHERE state = 'queued'`, nil, &kind, &params)
	if kind != "registration_transition" || !strings.Contains(params, `"to": "open"`) || !strings.Contains(params, `"from": "closed"`) {
		t.Fatalf("job %s %s", kind, params)
	}
	// A second change while the first is still queued (the worker has not run it) is not refused:
	// it ends the first as superseded and queues its own (round 5, admin-r5-2; the worker-down
	// tests are TestRegistrationChangeWithTheWorkerDown).
	b.put("/settings/registration", map[string]any{"mode": "invite"}).want(200, "")
	if got := b.get("/settings/registration").want(200, ""); !strings.Contains(string(got.Body), `"mode":"invite"`) {
		t.Fatalf("the change did not apply: %s", got.Body)
	}
	b.put("/settings/registration", map[string]any{"mode": "open", "open_grace_days": 21}).want(200, "")
	// Same mode, new grace: no job and no supersede, one audit row.
	jobs := r.count(t, `SELECT count(*) FROM ctrlz.admin_jobs`)
	b.put("/settings/registration", map[string]any{"mode": "open", "open_grace_days": 30}).want(200, "").json(&cur)
	if cur.Grace != 30 || r.count(t, `SELECT count(*) FROM ctrlz.admin_jobs`) != jobs {
		t.Fatalf("grace change: %+v", cur)
	}
	if has(r.auditActions(t), "registration.mode_change") != 4 {
		t.Fatalf("audit: %v", r.auditActions(t))
	}
	var graced int
	r.env.Scan(t, `SELECT (params->>'graced')::int FROM ctrlz.audit_log WHERE action = 'registration.mode_change' ORDER BY id LIMIT 1`, nil, &graced)
	if graced != im.Graced {
		t.Fatalf("the audit row's graced = %d", graced)
	}
}

// TestWebauthnSettings covers 7.2 and 7.4.
func TestWebauthnSettings(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.env.Exec(t, `DELETE FROM ctrlz.admin_jobs`)

	// A public suffix, the wrong host, and junk are refused (7.2).
	b.put("/settings/webauthn", map[string]any{"rp_id": "test", "enabled": false}).want(422, "validation_failed")
	b.put("/settings/webauthn", map[string]any{"rp_id": "evil.test", "enabled": false}).want(422, "validation_failed")
	b.put("/settings/webauthn", map[string]any{"rp_id": "https://panel.example.test", "enabled": false}).want(422, "validation_failed")
	b.put("/settings/webauthn", map[string]any{"rp_id": "", "enabled": false}).want(400, "bad_request") // the schema refuses an empty RP ID (round 5, admin-r5-1)

	// The impact: the seeded credentials are on example.test.
	var im struct {
		Credentials, Users int
	}
	b.get("/settings/webauthn/impact?rp_id=other.example.test").want(200, "").json(&struct {
		Credentials *int `json:"credentials"`
		Users       *int `json:"users"`
	}{&im.Credentials, &im.Users})
	if im.Credentials != 2 || im.Users != 2 {
		t.Fatalf("impact = %+v", im)
	}

	// Allowed origins are not the client's to send: the server writes the panel host, and since
	// round 5 (tenant-r5-7) a body that names a member the document does not declare is refused
	// instead of having it ignored, so there is no second spelling of it that a decoder could bind.
	b.put("/settings/webauthn", `{"rp_id":"Example.Test","enabled":true,"allowed_origins":["https://evil.test"]}`).want(400, "bad_request")
	var cfg struct {
		RPID    string   `json:"rp_id"`
		Origins []string `json:"allowed_origins"`
		Enabled bool     `json:"enabled"`
	}
	b.put("/settings/webauthn", `{"rp_id":"Example.Test","enabled":true}`).want(200, "").json(&cfg)
	if cfg.RPID != "example.test" || len(cfg.Origins) != 1 || cfg.Origins[0] != "https://"+panelHost || !cfg.Enabled {
		t.Fatalf("config = %+v", cfg)
	}
	// The first RP ID queued a job; the next change queues the one this test reads.
	r.env.Exec(t, `DELETE FROM ctrlz.admin_jobs`)
	var kind, params string
	b.put("/settings/webauthn", map[string]any{"rp_id": "panel.example.test", "enabled": true}).want(200, "")
	r.env.Scan(t, `SELECT kind, params::text FROM ctrlz.admin_jobs WHERE state = 'queued' AND kind = 'webauthn_rp_change'`, nil, &kind, &params)
	if kind != "webauthn_rp_change" || !strings.Contains(params, "panel.example.test") {
		t.Fatalf("job %s %s", kind, params)
	}
	if r.count(t, `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'webauthn.config_change' AND params->>'to_rp' = 'panel.example.test' AND params->>'from_rp' = 'example.test'`) != 1 {
		t.Fatal("no webauthn.config_change audit row with the old and new RP ID")
	}
	b.get("/settings/webauthn").want(200, "")

	// In production enabling is refused until the real-domain acceptance (P4).
	prod := r.handler(t, func(d *Deps) { d.Env = EnvProduction })
	b.callOn(prod, adminHost, "PUT", "/settings/webauthn", map[string]any{"rp_id": "panel.example.test", "enabled": true}).want(422, "validation_failed")
	b.callOn(prod, adminHost, "PUT", "/settings/webauthn", map[string]any{"rp_id": "panel.example.test", "enabled": false}).want(200, "")
}

func TestCheckRPID(t *testing.T) {
	for _, c := range []struct {
		rp, host, want string
	}{
		{"panel.localhost", "panel.localhost", ""},
		{"localhost", "panel.localhost", "public_suffix"},
		{"co.ir", "panel.example.co.ir", "public_suffix"},
		{"ir", "panel.example.ir", "public_suffix"},
		{"example.co.ir", "panel.example.co.ir", ""},
		{"example.test", "panel.example.test", ""},
		{"evil.test", "panel.example.test", "not_panel_host"},
		{"anel.example.test", "panel.example.test", "not_panel_host"}, // dot boundary
		{"https://panel.example.test", "panel.example.test", "invalid"},
		{"panel.example.test:443", "panel.example.test", "invalid"},
		{"panel.example.test.", "panel.example.test", "invalid"},
		{"", "panel.example.test", "invalid"},
	} {
		e := checkRPID(c.rp, c.host)
		got := ""
		if e != nil {
			got = e.Fields[0].Code
		}
		if got != c.want {
			t.Errorf("checkRPID(%q, %q) = %q, want %q", c.rp, c.host, got, c.want)
		}
	}
}

// TestSMSPage covers the SMS routes of 15.2.
func TestSMSPage(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.env.ResetSMS(t)
	const key = "TESTKEY-abcdef-1234567"

	type row struct {
		Provider   string  `json:"provider"`
		Role       string  `json:"role"`
		Configured bool    `json:"configured"`
		Pending    *bool   `json:"pending_confirmation"`
		Hint       *string `json:"hint"`
		Cost       *string `json:"cost_per_message"`
	}
	list := func() map[string]row {
		var out struct {
			Items []row `json:"items"`
		}
		res := b.get("/sms/gateways").want(200, "")
		res.json(&out)
		if strings.Contains(string(res.Body), key) || strings.Contains(string(res.Body), "credential") {
			t.Fatalf("the gateway list mentions credentials: %s", res.Body)
		}
		m := map[string]row{}
		for _, x := range out.Items {
			m[x.Provider] = x
		}
		return m
	}
	if g := list(); g["sms_ir"].Configured || g["melipayamak"].Configured || g["sms_ir"].Role != "disabled" {
		t.Fatalf("fresh gateways: %+v", g)
	}

	// Credentials: shape only, sealed, never returned.
	b.put("/sms/gateways/sms_ir", map[string]any{"credentials": map[string]string{"nope": "x"}}).want(422, "validation_failed")
	b.put("/sms/gateways/sms_ir", map[string]any{}).want(422, "validation_failed")
	b.put("/sms/gateways/sms_ir", map[string]any{"cost_per_message": "abc"}).want(400, "bad_request")
	b.put("/sms/gateways/sms_ir", map[string]any{"cost_per_message": "12345678901"}).want(400, "bad_request") // numeric(14, 4) holds ten digits, and so does the pattern
	res := b.put("/sms/gateways/sms_ir", map[string]any{"credentials": map[string]string{"api_key": key}, "cost_per_message": "120.5"}).want(200, "")
	if strings.Contains(string(res.Body), key) {
		t.Fatal("the PUT response echoes the key")
	}
	// The credentials are PENDING: nothing configured, no hint of an active pair, and the row says
	// what waits (admin-r18-1). The price is not a credential and is live at once.
	g := list()["sms_ir"]
	if g.Configured || g.Hint != nil || g.Pending == nil || !*g.Pending || g.Cost == nil || !strings.HasPrefix(*g.Cost, "120.5") {
		t.Fatalf("sms_ir before the console confirms = %+v", g)
	}
	var id uuid.UUID
	var ct []byte
	r.env.Scan(t, `SELECT id, credentials_pending_ct FROM ctrlz.sms_gateways WHERE provider = 'sms_ir'`, nil, &id, &ct)
	plain, err := sms.OpenCredentials(r.keys, id, "sms_ir", ct)
	if err != nil || !strings.Contains(string(plain.Reveal()), key) {
		t.Fatalf("the sealed credentials do not open: %v", err)
	}
	if _, err := sms.OpenCredentials(r.keys, id, "melipayamak", ct); err == nil {
		t.Fatal("credentials opened for another provider (the AAD holds it)")
	}
	confirmAtConsole(t, r, "sms_ir")
	if g := list()["sms_ir"]; !g.Configured || g.Hint == nil || *g.Hint != "4567" || (g.Pending != nil && *g.Pending) {
		t.Fatalf("sms_ir after the console confirmed = %+v", g)
	}
	// Melipayamak: the hint comes from the username, never the password.
	b.put("/sms/gateways/melipayamak", map[string]any{"credentials": map[string]string{"username": "userABCD", "password": "hunter2-secret"}}).want(200, "")
	confirmAtConsole(t, r, "melipayamak")
	if h := list()["melipayamak"].Hint; h == nil || *h != "ABCD" {
		t.Fatalf("melipayamak hint = %v", h)
	}
	// Rewriting the credentials keeps the row, and so its id and the AAD.
	b.put("/sms/gateways/sms_ir", map[string]any{"credentials": map[string]string{"api_key": key + "X"}}).want(200, "")
	confirmAtConsole(t, r, "sms_ir")
	var id2 uuid.UUID
	r.env.Scan(t, `SELECT id FROM ctrlz.sms_gateways WHERE provider = 'sms_ir'`, nil, &id2)
	if id2 != id {
		t.Fatal("rewriting credentials made a new gateway row")
	}

	// Routing: swap, a gateway with no credentials, the same twice, noop.
	b.put("/sms/routing", map[string]any{"primary": "sms_ir", "fallback": "melipayamak"}).want(200, "")
	if g := list(); g["sms_ir"].Role != "primary" || g["melipayamak"].Role != "fallback" {
		t.Fatalf("routing: %+v", g)
	}
	b.put("/sms/routing", map[string]any{"primary": "melipayamak", "fallback": "sms_ir"}).want(200, "")
	if g := list(); g["sms_ir"].Role != "fallback" || g["melipayamak"].Role != "primary" {
		t.Fatalf("swap: %+v", g)
	}
	b.put("/sms/routing", map[string]any{"primary": "sms_ir", "fallback": "sms_ir"}).want(422, "validation_failed")
	b.put("/sms/routing", map[string]any{}).want(422, "validation_failed")
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET credentials_ct = NULL WHERE provider = 'sms_ir'`)
	b.put("/sms/routing", map[string]any{"primary": "sms_ir"}).want(422, "validation_failed")
	if g := list(); g["melipayamak"].Role != "primary" {
		t.Fatalf("a refused routing change moved a role: %+v", g)
	}
	prod := r.handler(t, func(d *Deps) { d.Env = EnvProduction })
	b.callOn(prod, adminHost, "PUT", "/sms/routing", map[string]any{"primary": "noop"}).want(422, "validation_failed")
	b.callOn(prod, adminHost, "PUT", "/sms/gateways/noop", map[string]any{"cost_per_message": "1"}).want(422, "validation_failed")
	b.put("/sms/gateways/bogus", map[string]any{"cost_per_message": "1"}).want(400, "bad_request") // the provider is an enum of the schema

	// Templates and the provider mapping.
	var tl struct {
		Items []struct {
			Key, Locale, Body string
			Mappings          []struct {
				Provider string `json:"provider"`
			} `json:"mappings"`
		} `json:"items"`
	}
	b.get("/sms/templates").want(200, "").json(&tl)
	if len(tl.Items) != 10 {
		t.Fatalf("templates: %d", len(tl.Items))
	}
	b.put("/sms/templates/otp/en", map[string]any{"body": "Your Ctrl Z code is {code}."}).want(200, "")
	b.put("/sms/templates/otp/en", map[string]any{"body": "no placeholder"}).want(422, "validation_failed")
	b.put("/sms/templates/otp/en", map[string]any{"body": "{code} and {code}"}).want(422, "validation_failed")
	b.put("/sms/templates/otp/en", map[string]any{"body": "open https://x.example {code}"}).want(422, "validation_failed")
	b.put("/sms/templates/account_exists/en", map[string]any{"body": "has {code}"}).want(422, "validation_failed")
	// sms-r13-3: the one-part bound of D58 holds for an edit, not only for the seeds. A 150 letter
	// body passes CheckBody and would be billed as three parts at the one price of the message.
	b.put("/sms/templates/otp/en", map[string]any{"body": strings.Repeat("a", 200) + " {code}"}).want(422, "validation_failed")
	b.put("/sms/templates/otp/fa", map[string]any{"body": strings.Repeat("ا", 150) + " {code}"}).want(422, "validation_failed")
	b.put("/sms/templates/otp_reset/fa", map[string]any{"body": strings.Repeat("ا", 1000) + " {code}"}).want(422, "validation_failed")
	b.put("/sms/templates/nope/en", map[string]any{"body": "{code}"}).want(404, "not_found")
	var body string
	r.env.Scan(t, `SELECT body FROM ctrlz.sms_templates WHERE key = 'otp' AND locale = 'en'`, nil, &body)
	if body != "Your Ctrl Z code is {code}." {
		t.Fatalf("body = %q", body)
	}
	b.put("/sms/gateways/melipayamak/templates/otp/fa", map[string]any{"provider_template_id": "5001", "param_names": []string{"code"}}).want(200, "")
	b.put("/sms/gateways/melipayamak/templates/otp/fa", map[string]any{"provider_template_id": "5001", "param_names": []string{"a", "b"}}).want(422, "validation_failed")
	b.put("/sms/gateways/melipayamak/templates/account_exists/fa", map[string]any{"provider_template_id": "5002", "param_names": []string{}}).want(200, "")
	b.put("/sms/gateways/melipayamak/templates/account_exists/fa", map[string]any{"provider_template_id": " ", "param_names": []string{}}).want(400, "bad_request")
	// An id one provider cannot send is refused at the PUT, whatever the document allows for the
	// others (sms-r9-2): sms.ir types templateId as an int32, so 3000000000 would go out and come
	// back as a binding 400 that counts toward the breaker. Nothing is stored for it.
	b.put("/sms/gateways/sms_ir/templates/otp/fa", map[string]any{"provider_template_id": "3000000000", "param_names": []string{"code"}}).want(422, "validation_failed")
	b.put("/sms/gateways/sms_ir/templates/otp/fa", map[string]any{"provider_template_id": "2147483648", "param_names": []string{"code"}}).want(422, "validation_failed")
	var smsirRows int
	r.env.Scan(t, `SELECT count(*) FROM ctrlz.sms_provider_templates p JOIN ctrlz.sms_gateways g ON g.id = p.gateway_id WHERE g.provider = 'sms_ir'`, nil, &smsirRows)
	if smsirRows != 0 {
		t.Fatalf("a refused sms.ir template id left %d mapping rows", smsirRows)
	}
	// A name or an id pasted with padding is refused by the schema (sms-r4-2, rule
	// boundary-input): the alphabet has no white space, so there is no padded mapping to
	// key one way and look up another, and nothing is stored.
	b.put("/sms/gateways/melipayamak/templates/otp/fa", map[string]any{"provider_template_id": " 5003 ", "param_names": []string{"code"}}).want(400, "bad_request")
	b.put("/sms/gateways/melipayamak/templates/otp/fa", map[string]any{"provider_template_id": "5003", "param_names": []string{" CODE \n"}}).want(400, "bad_request")
	var stored string
	r.env.Scan(t, `SELECT array_to_string(param_names, '|') || '#' || provider_template_id FROM ctrlz.sms_provider_templates WHERE key = 'otp' AND locale = 'fa'`, nil, &stored)
	if stored != "code#5001" {
		t.Fatalf("a refused padded mapping changed the stored one to %q", stored)
	}
	b.put("/sms/gateways/melipayamak/templates/otp/fa", map[string]any{"provider_template_id": "5003", "param_names": []string{" \t"}}).want(400, "bad_request")
	b.get("/sms/templates").want(200, "").json(&tl)
	mapped := 0
	for _, it := range tl.Items {
		if it.Key == "otp" && it.Locale == "fa" {
			mapped = len(it.Mappings)
		}
	}
	if mapped != 1 {
		t.Fatalf("otp/fa has %d mappings", mapped)
	}

	// Limits: round trip, a value the CHECK refuses, and the audit names fields only.
	var lim map[string]any
	b.get("/sms/limits").want(200, "").json(&lim)
	lim["otp_cap_phone"] = 7
	// A money cap needs a price on every route the router can choose, or it never
	// refuses a message (sms-r5-6). melipayamak is the primary and has no price here.
	lim["sms_cost_cap_daily"] = "250000"
	b.put("/sms/limits", lim).want(422, "validation_failed")
	if n := r.count(t, `SELECT count(*) FROM ctrlz.system_settings WHERE sms_cost_cap_daily IS NOT NULL`); n != 0 {
		t.Fatal("a refused cap was stored")
	}
	b.put("/sms/gateways/melipayamak", map[string]any{"cost_per_message": "95"}).want(200, "")
	lim["sms_cost_cap_daily"] = "250000"
	b.put("/sms/limits", lim).want(200, "")
	// With the cap set, removing the price (or zeroing it) of a routed gateway is refused,
	// and the price stays.
	b.put("/sms/gateways/melipayamak", map[string]any{"cost_per_message": ""}).want(422, "validation_failed")
	b.put("/sms/gateways/melipayamak", map[string]any{"cost_per_message": "0.0000"}).want(422, "validation_failed")
	if n := r.count(t, `SELECT count(*) FROM ctrlz.sms_gateways WHERE provider = 'melipayamak' AND cost_per_message = 95`); n != 1 {
		t.Fatal("a refused price change was stored")
	}
	// Routing to a configured gateway that has no price is refused as well.
	b.put("/sms/gateways/sms_ir", map[string]any{"credentials": map[string]string{"api_key": key}}).want(200, "")
	confirmAtConsole(t, r, "sms_ir")
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET role = 'disabled', cost_per_message = NULL WHERE provider = 'sms_ir'`)
	b.put("/sms/routing", map[string]any{"primary": "melipayamak", "fallback": "sms_ir"}).want(422, "validation_failed")
	if g := list(); g["sms_ir"].Role != "disabled" {
		t.Fatalf("a refused routing change moved a role: %+v", g)
	}
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET credentials_ct = NULL WHERE provider = 'sms_ir'`) // as before this block
	lim["otp_cap_phone"] = -5
	b.put("/sms/limits", lim).want(400, "bad_request")
	lim["otp_cap_phone"] = 7
	lim["sms_cost_cap_daily"] = "1e9"
	b.put("/sms/limits", lim).want(400, "bad_request")
	var capPhone int
	r.env.Scan(t, `SELECT otp_cap_phone FROM ctrlz.system_settings`, nil, &capPhone)
	if capPhone != 7 {
		t.Fatalf("otp_cap_phone = %d", capPhone)
	}
	var fields string
	r.env.Scan(t, `SELECT params->'fields'::text FROM ctrlz.audit_log WHERE action = 'sms.limits_change' ORDER BY id LIMIT 1`, nil, &fields)
	if !strings.Contains(fields, "otp_cap_phone") || strings.Contains(fields, "250000") {
		t.Fatalf("limits audit fields = %s", fields)
	}

	// Stats, with no phone or text in them.
	st := b.get("/sms/stats?days=3").want(200, "")
	if strings.Contains(string(st.Body), "+98") {
		t.Fatal("stats hold a phone")
	}
	b.get("/sms/stats?days=0").want(400, "bad_request")

	// The test send: the gateway must exist and have credentials; the phone is checked.
	b.post("/sms/gateways/sms_ir/test", map[string]any{"phone": "09125550006", "template": "otp"}).want(422, "validation_failed") // credentials were cleared above
	b.post("/sms/gateways/melipayamak/test", map[string]any{"phone": "nope", "template": "otp"}).want(422, "invalid_phone")
	b.post("/sms/gateways/melipayamak/test", map[string]any{"phone": "09125550006", "template": "bogus"}).want(422, "validation_failed")
	var q struct {
		OutboxID string `json:"outbox_id"`
	}
	b.post("/sms/gateways/melipayamak/test", map[string]any{"phone": "09125550006", "template": "otp", "locale": "en"}).want(202, "").json(&q)
	var kind string
	var pinned uuid.UUID
	var mid uuid.UUID
	r.env.Scan(t, `SELECT kind, gateway_id FROM ctrlz.sms_outbox WHERE id = $1`, []any{q.OutboxID}, &kind, &pinned)
	r.env.Scan(t, `SELECT id FROM ctrlz.sms_gateways WHERE provider = 'melipayamak'`, nil, &mid)
	if kind != "test" || pinned != mid {
		t.Fatalf("the test message: %s pinned to %s, want %s", kind, pinned, mid)
	}
	var out struct {
		State string `json:"state"`
	}
	b.get("/sms/outbox/"+q.OutboxID).want(200, "").json(&out)
	if out.State != "pending" {
		t.Fatalf("state = %q", out.State)
	}
	b.get("/sms/outbox/"+uuid.NewString()).want(404, "not_found")
	r.assertQuiet(t, key, "hunter2-secret")
	// Every change was audited by field names, never values.
	if r.count(t, `SELECT count(*) FROM ctrlz.audit_log WHERE action LIKE 'sms.%' AND (params::text LIKE '%' || $1 || '%' OR params::text LIKE '%hunter2%' OR params::text LIKE '%0912555%')`, key) != 0 {
		t.Fatal("an sms audit row holds a credential or a phone")
	}
}

// TestAuditAndAlerts covers GET /audit, GET /alerts and the ack.
func TestAuditAndAlerts(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.env.Exec(t, `DELETE FROM ctrlz.alerts`)
	// Three open and two resolved alerts, so a page boundary falls between the groups.
	for i := 0; i < 3; i++ {
		r.env.Exec(t, `INSERT INTO ctrlz.alerts (severity, kind, params) VALUES ('warning', 'test_open', jsonb_build_object('key', $1::text))`, uuid.NewString())
	}
	for i := 0; i < 2; i++ {
		r.env.Exec(t, `INSERT INTO ctrlz.alerts (severity, kind, params, resolved_at) VALUES ('info', 'test_done', '{}', now())`)
	}
	var order []string
	cursor := ""
	for pages := 0; pages < 6; pages++ {
		path := "/alerts?limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		var p struct {
			Items []struct {
				ID         string  `json:"id"`
				Kind       string  `json:"kind"`
				ResolvedAt *string `json:"resolved_at"`
			} `json:"items"`
			Next *string `json:"next_cursor"`
		}
		b.get(path).want(200, "").json(&p)
		for _, it := range p.Items {
			order = append(order, it.Kind)
		}
		if p.Next == nil {
			break
		}
		cursor = *p.Next
	}
	if strings.Join(order, ",") != "test_open,test_open,test_open,test_done,test_done" {
		t.Fatalf("alerts paged in the order %v", order)
	}
	var first struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	b.get("/alerts?limit=1").want(200, "").json(&first)
	b.post("/alerts/"+first.Items[0].ID+"/ack", nil).want(204, "")
	b.post("/alerts/"+first.Items[0].ID+"/ack", nil).want(404, "not_found")
	if has(r.auditActions(t), "alert.ack") != 1 {
		t.Fatalf("audit: %v", r.auditActions(t))
	}

	var ap struct {
		Items []struct {
			Action string `json:"action"`
			Target string `json:"target"`
		} `json:"items"`
	}
	b.get("/audit?action=alert.ack&limit=5").want(200, "").json(&ap)
	if len(ap.Items) != 1 || ap.Items[0].Action != "alert.ack" || !strings.HasPrefix(ap.Items[0].Target, "alert:") {
		t.Fatalf("audit page = %+v", ap)
	}
	res := b.get("/audit?limit=1").want(200, "")
	for _, leak := range []string{"entry_hash", "prev_hash"} {
		if strings.Contains(string(res.Body), leak) {
			t.Fatalf("GET /audit shows %s", leak)
		}
	}
	b.get("/audit?cursor=zzz").want(400, "bad_request")
}

// TestChainSurvivesTheRoutes verifies the hash chain after a mix of routes: the
// writer and the reader agree on the canonical form.
func TestChainSurvivesTheRoutes(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	b.post("/users", map[string]any{"phone": "09125550010"}).want(201, "")
	b.post("/invites", map[string]any{"phone": "09125550011", "send_sms": false}).want(201, "")
	b.put("/sms/limits", func() map[string]any {
		var l map[string]any
		b.get("/sms/limits").json(&l)
		return l
	}()).want(200, "")
	var prev []byte
	if err := r.adm.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		rows, err := g.AuditChain(0, 1000)
		if err != nil {
			return err
		}
		if len(rows) < 4 {
			t.Fatalf("only %d audit rows", len(rows))
		}
		prev, err = audit.VerifyChain(nil, rows)
		return err
	}); err != nil || prev == nil {
		t.Fatalf("chain: %v", err)
	}
	_ = secret.String{}
}

// TestGatewayChangeReachesEveryAdmin covers review round 2 (admin-r2-8). A
// session with one fresh code can point all OTP delivery at a gateway account it
// controls, and the provider's dashboard then shows every code. The change must
// reach the owner inside the product: every enabled admin gets the banner of 10.7,
// whoever made the change, for new credentials and for a routing change, and a
// cost-only change is not one.
func TestGatewayChangeReachesEveryAdmin(t *testing.T) {
	r := newRig(t)
	b, seed := r.admin(t)
	r.syncClock()
	// A second admin, who made no change and holds no session.
	other := uuid.MustParse("00000000-0000-7000-8000-0000000000e2")
	r.env.Exec(t, `INSERT INTO ctrlz.admin_users (id, username, password_hash) VALUES ($1, 'second-admin', 'x')`, other)
	notices := func(id uuid.UUID) string {
		var s *string
		r.env.Scan(t, `SELECT pending_notice::text FROM ctrlz.admin_users WHERE id = $1`, []any{id}, &s)
		if s == nil {
			return ""
		}
		return *s
	}
	var me struct {
		Notices []struct {
			Kind string `json:"kind"`
		} `json:"notices"`
	}
	kinds := func() []string {
		b.get("/me").want(200, "").json(&me)
		var out []string
		for _, n := range me.Notices {
			out = append(out, n.Kind)
		}
		return out
	}
	if n := notices(seedAdmin) + notices(other); n != "" {
		t.Fatalf("notices before any change: %s", n)
	}

	// Only a cost: not a credential event.
	b.put("/sms/gateways/sms_ir", map[string]any{"cost_per_message": "10"}).want(200, "")
	if n := notices(seedAdmin) + notices(other); n != "" {
		t.Fatalf("a cost change raised a notice: %s", n)
	}
	b.put("/sms/gateways/sms_ir", map[string]any{"credentials": map[string]string{"api_key": "attacker-account-key-123456"}}).want(200, "")
	for name, id := range map[string]uuid.UUID{"acting admin": seedAdmin, "other admin": other} {
		if !strings.Contains(notices(id), "sms_gateway_changed") {
			t.Errorf("%s has no notice after new credentials: %q", name, notices(id))
		}
	}
	if k := kinds(); len(k) != 1 || k[0] != "sms_gateway_changed" {
		t.Fatalf("GET /me notices = %v", k)
	}
	// The key is in no notice.
	if strings.Contains(notices(seedAdmin)+notices(other), "attacker-account-key") {
		t.Fatal("a notice holds the credentials")
	}
	// The session that made the change cannot dismiss it (admin-r3-1, admin-r3-8):
	// the banner is for whoever signs in next. The owner's later login can.
	b.post("/me/notices/ack", map[string]any{}).want(204, "")
	if !strings.Contains(notices(seedAdmin), "sms_gateway_changed") || !strings.Contains(notices(other), "sms_gateway_changed") {
		t.Fatal("the session that made the change dismissed its banner")
	}
	// Time passes before the owner signs in: a session is dated with the same
	// clock as a notice, and a notice made in the millisecond of the session
	// counts as made during it.
	r.ck.add(time.Second)
	owner := r.browser()
	owner.mustLogin(seed)
	owner.post("/me/notices/ack", map[string]any{}).want(204, "")
	if strings.Contains(notices(seedAdmin), "sms_gateway_changed") || !strings.Contains(notices(other), "sms_gateway_changed") {
		t.Fatal("an ack must clear only the acting admin's own banner, and only what predates its session")
	}

	r.ck.add(time.Second)
	// A routing change is one too. Routing names only a gateway with ACTIVE credentials, which only the console
	// makes (admin-r18-1).
	confirmAtConsole(t, r, "sms_ir")
	b.put("/sms/routing", map[string]any{"primary": "sms_ir"}).want(200, "")
	if k := kinds(); len(k) != 1 || k[0] != "sms_gateway_changed" {
		t.Fatalf("notices after routing = %v", k)
	}
	if strings.Count(notices(other), "sms_gateway_changed") != 2 {
		t.Fatalf("the other admin's notices: %s", notices(other))
	}
}

// TestPanelHostSpellingsReachTheOriginAndTheLink pins admin-r13-1: the Host gate serves a
// configured panel host in any case, with a trailing dot, with a port. The Passkey origin and the
// invite link are built from that host, so they must carry the spelling a browser sends
// (lower case, no trailing dot) and the RP ID check must compare the name without its port.
func TestPanelHostSpellingsReachTheOriginAndTheLink(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.env.ResetSMS(t)
	for _, c := range []struct{ configured, origin, rp string }{
		{"Panel.Example.Test", "https://panel.example.test", "example.test"},
		{"panel.example.test.", "https://panel.example.test", "panel.example.test"},
		{"PANEL.Example.Test.:8443", "https://panel.example.test:8443", "example.test"},
	} {
		h := r.handler(t, func(d *Deps) { d.PanelHost = c.configured })
		var cfg struct {
			Origins []string `json:"allowed_origins"`
		}
		b.callOn(h, adminHost, "PUT", "/settings/webauthn", map[string]any{"rp_id": c.rp, "enabled": true}).want(200, "").json(&cfg)
		if len(cfg.Origins) != 1 || cfg.Origins[0] != c.origin {
			t.Errorf("%q: origins = %v, want %s", c.configured, cfg.Origins, c.origin)
		}
		var inv struct {
			Code string `json:"code"`
			Link string `json:"link"`
		}
		b.callOn(h, adminHost, "POST", "/invites", map[string]any{"phone": "09125550077", "send_sms": false}).want(201, "").json(&inv)
		if want := c.origin + "/invite#" + inv.Code; inv.Link != want {
			t.Errorf("%q: link = %q, want %q", c.configured, inv.Link, want)
		}
		r.env.Exec(t, `DELETE FROM ctrlz.invites`)
	}
}

// confirmAtConsole is what `ctrlz-admin sms confirm` does to the row (store.SMSGatewayConfirmCredentials,
// run for real in internal/admincli), for a flow test that needs a gateway whose credentials are active.
// No route does it.
func confirmAtConsole(t *testing.T, r *rig, provider string) {
	t.Helper()
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET credentials_ct = credentials_pending_ct, hint = pending_hint,
  credentials_pending_ct = NULL, pending_hint = NULL WHERE provider = $1 AND credentials_pending_ct IS NOT NULL`, provider)
}
