package adminapi

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/oracle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// The known-or-unknown oracle of the admin API (P1 auth review round 5, rule
// known-unknown-oracle, spec 10.2, 18.5). Admin login is the one route of
// api/admin-openapi.yaml that needs no session. A username with an account may not
// change the status, body, headers, cookies, throttle movement, Argon2 runs or
// gate acquisitions of the answer to a login that fails.
//
// The known side has three shapes, because the rule is also what keeps a right
// password from showing: a wrong password, a right password with a wrong code,
// and a right password with no code. All three must look like an unknown name.
// (A login that succeeds ends in a session and a marker cookie. That is the final
// session the rule allows to differ, and is not compared.)

// adminOracleExceptions is the declared list; each entry names the section of
// p1-auth.md that accepts it.
func adminOracleExceptions() oracle.Exceptions {
	return oracle.Exceptions{
		// admin_totp is charged only once a password is right (10.2 step 4), so the
		// counter moves for a right password and not for a wrong one. It is not an
		// oracle for a stranger: the answer is the same 401 whether the scope is
		// spent or not, and the row is reachable only by somebody who already holds
		// the password. Charging it on every attempt instead would let a stranger who
		// knows the username spend it and keep the owner out.
		{Op: "adminLogin", State: "*", Subject: "known_right_password_wrong_code", Dim: "throttle.admin_totp", Spec: "10.2 step 4, 4.5: admin_totp counts after a right password"},
		// The console one-time password: its hash is cheap and takes no Argon2 slot, so
		// the owner's first login does not depend on a gate strangers can fill. With
		// the gate held, an unknown name waits and gets 503 while this account is
		// answered at once. Recorded and accepted in 10.2 step 2 (admin-r4-6); the one
		// method that does it, Hasher.VerifyGateFree, is called from the admin service
		// only (internal/lint TestGateFreeVerifyOnlyInTheAdminService).
		{Op: "adminLogin", State: "*", Subject: "known_onetime", Dim: "gates", Spec: "10.2 step 2: a one-time hash takes no slot"},
		{Op: "adminLogin", State: oracle.StateGateHeld, Subject: "known_onetime", Dim: "status", Spec: "10.2 step 2 (admin-r4-6)"},
		{Op: "adminLogin", State: oracle.StateGateHeld, Subject: "known_onetime", Dim: "body", Spec: "10.2 step 2 (admin-r4-6)"},
		{Op: "adminLogin", State: oracle.StateGateHeld, Subject: "known_onetime", Dim: "header", Spec: "10.2 step 2 (admin-r4-6)"},
		{Op: "adminLogin", State: oracle.StateGateHeld, Subject: "known_onetime", Dim: "argon2", Spec: "10.2 step 2 (admin-r4-6)"},
		// The attempt of a busy login is given back (primitives-r6-9), and the one-time password is
		// answered with the gate held, so there is nothing to give back for it: its three counters
		// stay where the unknown name's go back to zero. The status, body and headers already differ
		// in this state (the line above), so this adds no dimension an observer has not got.
		{Op: "adminLogin", State: oracle.StateGateHeld, Subject: "known_onetime", Dim: "throttle.admin_login", Spec: "10.2 step 2, 4.5 (admin-r4-6, primitives-r6-9)"},
		{Op: "adminLogin", State: oracle.StateGateHeld, Subject: "known_onetime", Dim: "throttle.admin_login_user", Spec: "10.2 step 2, 4.5 (admin-r4-6, primitives-r6-9)"},
		{Op: "adminLogin", State: oracle.StateGateHeld, Subject: "known_onetime", Dim: "throttle.admin_login_net", Spec: "10.2 step 2, 4.5 (admin-r4-6, primitives-r6-9)"},
		// A spent throttle scope (the username scope since round 2, the two network scopes since
		// round 5, admin-r5-11) refuses everybody but the right console one-time password, so the
		// account that holds one is read and its gate-free hash is checked before the same 429 is
		// answered for a wrong password: one cheap run an unknown name does not make. Status, body
		// and headers are the same 429. Recorded in 10.2 step 1.
		{Op: "adminLogin", State: oracle.StateScopeSpent, Subject: "known_onetime", Dim: "argon2", Spec: "10.2 step 1 (admin-r2-7, admin-r5-11): a spent scope reads the one-time account first"},
	}
}

type adminSubject struct {
	name     string
	username string
	password string
	code     func() string // nil for none
	known    bool
}

func adminSubjects(wrongCode string) []adminSubject {
	return []adminSubject{
		{name: "unknown", username: "ghost-admin", password: "Wrong-Guess-Heron-4412-x"},
		{name: "known_wrong_password", username: adminName, password: "Wrong-Guess-Heron-4412-x", known: true},
		{name: "known_right_password_wrong_code", username: adminName, password: adminPW, code: func() string { return wrongCode }, known: true},
		{name: "known_right_password_no_code", username: adminName, password: adminPW, known: true},
		{name: "known_onetime", username: adminName, password: "Wrong-Guess-Heron-4412-x", known: true},
	}
}

type adminWorld struct {
	r      *rig
	h      http.Handler
	gate   *password.Gate
	hasher *password.Hasher
	held   []func()
}

func newAdminWorld(t *testing.T) *adminWorld {
	t.Helper()
	r := newRig(t)
	w := &adminWorld{r: r}
	w.gate = password.NewGate(1, 100*time.Millisecond)
	var err error
	w.hasher, err = password.NewHasher(password.Params{MemoryKiB: 64, Time: 1, Threads: 1}, w.gate)
	if err != nil {
		t.Fatal(err)
	}
	w.h = r.handler(t, func(d *Deps) { d.Hasher = w.hasher })
	r.setupAdmin(t, true)
	return w
}

func (w *adminWorld) reset() {
	for _, rel := range w.held {
		rel()
	}
	w.held = nil
	w.r.env.Exec(w.r.t, `DELETE FROM ctrlz.auth_throttle`)
	w.r.setupAdmin(w.r.t, true) // the ready account of the other subjects
}

func (w *adminWorld) meters() oracle.Meters {
	return oracle.Meters{Argon2: w.hasher.Runs(), Gates: w.gate.Attempts()}
}

func (w *adminWorld) request(s adminSubject) oracle.Request {
	body := map[string]any{"username": s.username, "password": s.password}
	if s.code != nil {
		body["totp_code"] = s.code()
	}
	return oracle.Request{Method: "POST", Path: "/auth/login", Body: body}
}

// adminState changes the world for one registered state. spendOnly names the
// throttle scopes the saturation reaches ("" is all of them). The SMS states have
// nothing to act on: the admin service sends no SMS, so the action is a no-op by
// design, and the table says so.
type adminState struct {
	spend []string // scope_spent: the sub-runs, each a list of scopes; nil entry is all
	apply func(w *adminWorld, req oracle.Request, ip string, scopes string)
}

func adminStates() map[string]adminState {
	noSMS := adminState{apply: func(*adminWorld, oracle.Request, string, string) {}}
	return map[string]adminState{
		oracle.StateNone: noSMS,
		oracle.StateGateHeld: {apply: func(w *adminWorld, _ oracle.Request, _ string, _ string) {
			rel, err := w.gate.Acquire(context.Background())
			if err != nil {
				w.r.t.Fatal(err)
			}
			w.held = append(w.held, rel)
		}},
		oracle.StateScopeSpent: {spend: []string{"", "admin_totp"}, apply: func(w *adminWorld, req oracle.Request, ip string, scopes string) {
			// Once, so the scopes the request touches have rows; then they are pushed
			// past their limits. "" spends every scope; a name spends that one only,
			// which is how the late scope (admin_totp, after a right password) is
			// reached at all: with every scope spent the request stops at the first.
			if _, err := oracle.Fire(w.h, adminHost, ip, req); err != nil {
				w.r.t.Fatal(err)
			}
			// The window starts at the application clock, which is the one that decides it.
			q := `UPDATE ctrlz.auth_throttle SET count = 100000, window_start = $1 WHERE ($2 = '' OR scope = $2)`
			w.r.env.Exec(w.r.t, q, w.r.ck.now(), scopes)
		}},
		// No SMS is sent by the admin service; these states have no effect on it.
		oracle.StateTemplateUnmapped: noSMS,
		oracle.StateProvider404:      noSMS,
		oracle.StateProviderFlapping: noSMS,
		oracle.StateWorkerFailing:    noSMS,
		// The admin login sends no SMS, so no row ends in these four states (they are about
		// the tenant OTP queue and its refunds).
		oracle.StateRecipientRefused:     noSMS,
		oracle.StateBlacklisted:          noSMS,
		oracle.StateProviderRefusedLogin: noSMS,
		oracle.StateBreakerOpensMidRow:   noSMS,
		oracle.StateWorkerDown:           noSMS,
		// The admin login takes no row of the global SMS counter.
		oracle.StateGlobalCounterHeld: noSMS,
		oracle.StateDatabaseDown:      {}, // TestAdminOracleDatabaseDown
	}
}

func (w *adminWorld) observe(s adminSubject, state, scopes string, seedCode string) oracle.Obs {
	w.reset()
	req := w.request(s)
	if s.name == "known_onetime" {
		// A console-issued password in its first day, no authenticator yet.
		h, err := w.hasher.HashOneTime(secret.New("ABCDEFGHIJKLMNOPQRSTUVWX"))
		if err != nil {
			w.r.t.Fatal(err)
		}
		w.r.env.Exec(w.r.t, `UPDATE ctrlz.admin_users SET password_hash = $2, must_change_password = true, password_expires_at = now() + interval '1 hour',
		  totp_secret_ct = NULL, totp_enabled_at = NULL WHERE id = $1`, seedAdmin, h.Reveal())
	}
	ip := freshIP()
	adminStates()[state].apply(w, req, ip, scopes)
	before, m0 := oracle.Take(w.r.t, w.r.env), w.meters()
	raw, err := oracle.Fire(w.h, adminHost, ip, req)
	if err != nil {
		w.r.t.Fatal(err)
	}
	after, m1 := oracle.Take(w.r.t, w.r.env), w.meters()
	o := oracle.Observe(raw)
	o.SMS, o.Throttle, o.Gateways = after.Since(before)
	o.Meters = m1.Sub(m0)
	return o
}

func TestAdminOracleKnownUnknown(t *testing.T) {
	w := newAdminWorld(t)
	ex := adminOracleExceptions()
	// The code is wrong whatever it is; the 000000 of a made-up TOTP.
	subjects := adminSubjects("000000")
	for _, state := range oracle.AllStates() {
		st, ok := adminStates()[state]
		if !ok {
			t.Fatalf("state %s has no entry in adminStates", state)
		}
		if state == oracle.StateDatabaseDown {
			continue
		}
		runs := st.spend
		if runs == nil {
			runs = []string{""}
		}
		for _, scopes := range runs {
			name := state
			if scopes != "" {
				name += "/" + scopes
			}
			t.Run(name, func(t *testing.T) {
				w.r.t = t
				unknown := w.observe(subjects[0], state, scopes, "")
				if unknown.Dur < floorLogin-20*time.Millisecond {
					t.Errorf("an unknown name was answered in %v, under the floor", unknown.Dur)
				}
				for _, s := range subjects[1:] {
					known := w.observe(s, state, scopes, "")
					if known.Dur < floorLogin-20*time.Millisecond {
						t.Errorf("%s: answered in %v, under the floor", s.name, known.Dur)
					}
					for _, d := range ex.Unexplained("adminLogin", state, s.name, oracle.Compare(known, unknown)) {
						t.Errorf("%s: %s differs from an unknown username: %s", s.name, d.Dim, d.Detail)
					}
				}
			})
		}
	}
	for _, s := range ex.Stale() {
		t.Errorf("declared exception used by no run: %s", s)
	}
}

// TestAdminOracleDatabaseDown asks the same questions with Postgres stopped.
func TestAdminOracleDatabaseDown(t *testing.T) {
	w := newAdminWorld(t)
	w.reset()
	subjects := adminSubjects("000000")
	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := cluster.StopPostgres(stopCtx); err != nil {
		t.Fatalf("stop postgres: %v", err)
	}
	restarted := false
	restart := func() {
		if !restarted {
			restarted = true
			if err := cluster.StartPostgres(context.Background()); err != nil {
				t.Errorf("restart postgres: %v", err)
			}
		}
	}
	t.Cleanup(restart)
	obs := map[string]oracle.Obs{}
	for _, s := range subjects {
		m0 := w.meters()
		raw, _ := oracle.Fire(w.h, adminHost, freshIP(), w.request(s))
		o := oracle.Observe(raw)
		o.Meters = w.meters().Sub(m0)
		obs[s.name] = o
	}
	restart()
	ex := adminOracleExceptions()
	for _, s := range subjects[1:] {
		if obs[s.name].Dur < floorLogin-20*time.Millisecond {
			t.Errorf("%s: answered in %v with the database down, under the floor", s.name, obs[s.name].Dur)
		}
		for _, d := range ex.Unexplained("adminLogin", oracle.StateDatabaseDown, s.name, oracle.Compare(obs[s.name], obs["unknown"])) {
			t.Errorf("%s: %s differs from an unknown username, database down: %s", s.name, d.Dim, d.Detail)
		}
	}
}

// TestAdminOracleCoversEveryNoneOperation fails for an operation of
// api/admin-openapi.yaml that needs no session and is not walked here.
func TestAdminOracleCoversEveryNoneOperation(t *testing.T) {
	walked := map[string]bool{"adminLogin": true}
	for _, op := range oracle.NoneOperations(t, ratelimit.Admin) {
		if !walked[op.ID] {
			t.Errorf("operation %s (%s) needs no session and the admin oracle does not walk it", op.ID, op.Key())
		}
	}
}
