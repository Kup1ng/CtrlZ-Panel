package api

import (
	"encoding/base32"
	"net/http"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// Rule credential-generation (P1 auth review round 5, topic 5), the behaviour half.
//
// users carries one credential_gen counter that a trigger moves when any credential
// column of migrations/catalog/guarded.yaml changes, whoever writes. This test changes
// each of those columns AS THE OWNER, which no route does, and shows that every
// artefact derived from a first-factor check before the change is refused after it:
//
//   - a password login that verified the old credentials and is waiting for the row
//     lock (really waiting: the owner's transaction holds the row until the login is
//     blocked on it);
//   - an mfa ticket;
//   - a device marker.
//
// Because the change is made behind the application's back, a new column added to the
// list and a new route that writes it are both covered: nothing here knows which route
// would write the column. Tenant B is the control: its credential_gen and its marker
// do not move.

// credSnapshot is every credential column of the user, to put back after a case.
type credSnapshot struct {
	phone        string
	hash         *string
	changed      *time.Time
	expires      *time.Time
	mustReset    bool
	seed         []byte
	totpEnabled  *time.Time
	enforce      bool
	enforceUntil *time.Time
}

func (f *frig) snapshotCredentials(user any) credSnapshot {
	f.t.Helper()
	var s credSnapshot
	f.env.Scan(f.t, `SELECT phone_e164, password_hash, password_changed_at, password_expires_at, must_reset, totp_secret_ct,
  totp_enabled_at, enforce_passkey, enforce_lift_at FROM ctrlz.users WHERE id = $1`, []any{user},
		&s.phone, &s.hash, &s.changed, &s.expires, &s.mustReset, &s.seed, &s.totpEnabled, &s.enforce, &s.enforceUntil)
	return s
}

func (f *frig) restoreCredentials(user any, s credSnapshot) {
	f.t.Helper()
	// One statement, so the CHECK on the one-time password sees both columns at once.
	f.env.Exec(f.t, `UPDATE ctrlz.users SET phone_e164 = $2, password_hash = $3, password_changed_at = $4, password_expires_at = $5,
  must_reset = $6, totp_secret_ct = $7, totp_enabled_at = $8, enforce_passkey = $9, enforce_lift_at = $10 WHERE id = $1`,
		user, s.phone, s.hash, s.changed, s.expires, s.mustReset, s.seed, s.totpEnabled, s.enforce, s.enforceUntil)
}

// enrollTOTP gives the user of tenant A an authenticator and returns its seed.
func (f *frig) enrollTOTP() secret.Bytes {
	f.t.Helper()
	A := f.env.A
	c := f.client()
	c.mustLogin(A.Phone, pwA)
	c.reauthPassword(pwA).want(204, "")
	var setup struct {
		Secret string `json:"secret"`
	}
	c.post("/account/totp/setup", nil).want(200, "").json(&setup)
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if err != nil {
		f.t.Fatal(err)
	}
	seed := secret.NewBytes(raw)
	c.post("/account/totp/confirm", map[string]any{"code": codeAt(seed, time.Now()), "saved": true}).want(200, "")
	return seed
}

// holdUpdate runs an UPDATE as the owner in a transaction that stays open, so the row
// is locked. release commits it.
func (f *frig) holdUpdate(sql string, args ...any) (release func()) {
	f.t.Helper()
	conn, err := f.env.DB.Super(f.env.Ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	tx, err := conn.Begin(f.env.Ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := tx.Exec(f.env.Ctx, sql, args...); err != nil {
		f.t.Fatalf("held change: %v", err)
	}
	return func() {
		if err := tx.Commit(f.env.Ctx); err != nil {
			f.t.Errorf("commit held change: %v", err)
		}
		_ = conn.Close(f.env.Ctx)
	}
}

// waitBlocked waits until a statement of this database waits for a row lock.
func (f *frig) waitBlocked() {
	f.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if f.count(`SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`) > 0 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	f.t.Fatal("the login never waited for the row lock: the test proves nothing")
}

func TestCredentialGenerationRefusesEveryArtefact(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	seed := f.enrollTOTP()
	orig := f.snapshotCredentials(A.User)

	// Tenant B signs in and keeps a marker, the control of every case below.
	bob := f.client()
	bob.mustLogin(B.Phone, pwB)
	bobMarker := bob.jar[session.CookieDevice].Value
	bobGen := f.count(`SELECT credential_gen FROM ctrlz.users WHERE id = $1`, B.User)

	trusted := func(phone string) int {
		return f.count(`SELECT coalesce(sum(count), 0) FROM ctrlz.sms_counters WHERE scope = 'phone' AND key = $1`, phone+"|trusted")
	}
	const newPhone = "+989129990001"
	cases := []struct {
		column  string
		arrange string // runs before the artefacts are made, so the case starts from this state
		change  string // the one column the owner changes
	}{
		{"phone_e164", ``, `phone_e164 = '` + newPhone + `'`},
		{"password_hash", ``, `password_hash = 'not-the-old-hash'`},
		{"password_changed_at", ``, `password_changed_at = now()`},
		{"password_expires_at", `must_reset = true, password_expires_at = now() + interval '72 hours'`, `password_expires_at = now() + interval '96 hours'`},
		{"must_reset", ``, `must_reset = true`},
		// totp_secret_ct is not here on purpose (db-r6-4): with totp_enabled_at set and unchanged a
		// different ciphertext is a re-seal of the same second factor and must keep every artefact
		// (TestResealOfTheSeedKeepsTheDeviceMarker). The factor changing is totp_enabled_at, below,
		// and the catalog trigger test still changes the seed while the factor is not in force.
		{"totp_enabled_at", ``, `totp_enabled_at = now() - interval '1 day'`},
		{"enforce_passkey", ``, `enforce_passkey = true`},
		{"enforce_lift_at", ``, `enforce_lift_at = now() + interval '72 hours'`},
	}
	for _, tc := range cases {
		t.Run(tc.column, func(t *testing.T) {
			reset := func() {
				f.restoreCredentials(A.User, orig)
				if tc.arrange != "" {
					f.env.Exec(t, `UPDATE ctrlz.users SET `+tc.arrange+` WHERE id = $1`, A.User)
				}
				f.clearThrottle()
				f.freeStep(A.Tenant)
			}
			code := func() string {
				f.freeStep(A.Tenant)
				return codeAt(seed, time.Now())
			}
			reqPhone := A.Phone
			if tc.column == "phone_e164" {
				reqPhone = newPhone
			}

			// 1. The artefacts, made under the credentials as they are.
			reset()
			signedIn := f.client()
			signedIn.mfaLoginComplete(A.Phone, pwA, code())
			marker := signedIn.jar[session.CookieDevice]
			if marker == nil {
				t.Fatal("a password and code login left no device marker")
			}
			holder := f.client()
			holder.jar[session.CookieDevice] = &http.Cookie{Name: session.CookieDevice, Value: marker.Value}
			if tc.column != "phone_e164" {
				holder.requestOTP(reqPhone, "login", nil).want(202, "")
				if trusted(reqPhone) != 1 {
					t.Fatalf("control: the marker was not known before the change (%d)", trusted(reqPhone))
				}
			}
			ticket := f.client().mfaLogin(A.Phone, pwA)

			// 2. The owner changes the column.
			f.env.Exec(t, `UPDATE ctrlz.users SET `+tc.change+` WHERE id = $1`, A.User)

			// 3. Each artefact is refused. The ticket first: the code is right (the
			// seed case aside, where the ticket must be refused before the code is read).
			f.clearThrottle()
			if r := f.client().post("/auth/login/totp", map[string]any{"ticket": ticket, "totp_code": code()}); r.Code != http.StatusUnauthorized || r.code() != "ticket_invalid" {
				t.Errorf("an mfa ticket made before the change of %s: %d %s, want 401 ticket_invalid", tc.column, r.Code, r.Body)
			}

			holder = f.client()
			holder.jar[session.CookieDevice] = &http.Cookie{Name: session.CookieDevice, Value: marker.Value}
			holder.requestOTP(reqPhone, "login", nil).want(202, "")
			if trusted(reqPhone) != 0 {
				t.Errorf("a marker issued before the change of %s is still a known device (%d)", tc.column, trusted(reqPhone))
			}

			// 4. A login that verified the old credentials and waits for the lock.
			reset()
			release := f.holdUpdate(`UPDATE ctrlz.users SET `+tc.change+` WHERE id = $1`, A.User)
			done := make(chan *resp, 1)
			go func() { done <- f.client().loginPassword(A.Phone, pwA, false) }()
			f.waitBlocked()
			release()
			r := <-done
			if r.Code != http.StatusUnauthorized || r.code() != "invalid_credentials" {
				t.Errorf("a login that verified the credentials before the change of %s: %d %s, want 401 invalid_credentials", tc.column, r.Code, r.Body)
			}
		})
	}
	f.restoreCredentials(A.User, orig)

	// The control: tenant B did not move and its marker still counts.
	if got := f.count(`SELECT credential_gen FROM ctrlz.users WHERE id = $1`, B.User); got != bobGen {
		t.Errorf("tenant B's credential_gen moved from %d to %d while tenant A's columns changed", bobGen, got)
	}
	other := f.client()
	other.jar[session.CookieDevice] = &http.Cookie{Name: session.CookieDevice, Value: bobMarker}
	other.requestOTP(B.Phone, "login", nil).want(202, "")
	if trusted(B.Phone) != 1 {
		t.Errorf("tenant B's marker stopped counting (%d)", trusted(B.Phone))
	}
}
