package api

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
)

// P1 auth review round 6, area database (db-r6-4, db-r6-5, db-r6-7).

// TestOTPLoginAndResetTicketDieWithAPhoneChange is the OTP half of rule credential-generation.
// A first factor derived from a code for phone P1 is worth nothing once the account's phone is
// P2, and neither the session an OTP login opens nor the password a reset ticket sets may
// outlive a change that has committed, wherever in the flow the change lands. The password
// factor was stamped with credential_gen under the row lock; an OTP login and a reset ticket
// carried no stamp, and the function that was meant to bind them to the phone answered ok for
// a verified phone before it looked at the code. The phone change here is made by the owner,
// behind the application's back, as in TestCredentialGenerationRefusesEveryArtefact, so every
// route that moves phone_e164 is covered.
func TestOTPLoginAndResetTicketDieWithAPhoneChange(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	const newPhone = "+989129990042"
	orig := f.snapshotCredentials(A.User)
	defer f.restoreCredentials(A.User, orig)
	sessions := func() int { return f.count(`SELECT count(*) FROM ctrlz.sessions WHERE user_id = $1`, A.User) }

	t.Run("an OTP login that was running when the phone moved", func(t *testing.T) {
		f.restoreCredentials(A.User, orig)
		f.clearThrottle()
		c := f.client()
		var iss issued
		c.requestOTP(A.Phone, "login", nil).want(202, "").json(&iss)
		code := f.codes.Last()
		before := sessions()

		// The owner's transaction holds the row, so the login passes the code and the lookup
		// of the phone it names and then waits for the lock; the change commits first.
		release := f.holdUpdate(`UPDATE ctrlz.users SET phone_e164 = $2 WHERE id = $1`, A.User, newPhone)
		done := make(chan *resp, 1)
		go func() {
			done <- f.client().post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": iss.ID, "code": code})
		}()
		f.waitBlocked()
		release()
		r := <-done
		if r.Code == http.StatusOK || r.cookie(session.CookieSession) != nil {
			t.Fatalf("an OTP login that proved the number the user had just left opened a session: %d %s", r.Code, r.Body)
		}
		if got := sessions(); got != before {
			t.Errorf("sessions of the user went from %d to %d", before, got)
		}
	})

	t.Run("a reset ticket made for the number the user has left", func(t *testing.T) {
		f.restoreCredentials(A.User, orig)
		f.clearThrottle()
		c := f.client()
		v := c.verifyReset(A.Phone)
		// The change commits after the verify ran (a ticket revoke cannot reach a ticket
		// that is made after it).
		f.env.Exec(t, `UPDATE ctrlz.users SET phone_e164 = $2 WHERE id = $1`, A.User, newPhone)
		c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": "Cobalt-meadow-Falcon-4417"}).want(401, "ticket_invalid")
		// The password is still the old one, on the new number.
		f.clearThrottle()
		f.client().loginPassword(newPhone, pwA, false).want(200, "")
	})

	t.Run("control: the same flows on the unchanged phone, and tenant B untouched", func(t *testing.T) {
		f.restoreCredentials(A.User, orig)
		f.clearThrottle()
		c := f.client()
		var iss issued
		c.requestOTP(A.Phone, "login", nil).want(202, "").json(&iss)
		c.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": iss.ID, "code": f.codes.Last()}).want(200, "")
		f.clearThrottle()
		v := f.client().verifyReset(B.Phone)
		if v.Ticket == "" {
			t.Fatal("tenant B got no reset ticket")
		}
	})
}

// TestResealOfTheSeedKeepsTheDeviceMarker is db-r6-4: re-sealing the seed under a new key
// (`ctrlz rekey user_totp`) changes the ciphertext and not the second factor, so it must not
// end the markers and tickets of every TOTP account. The column that says which second factor is
// in force, totp_enabled_at, is still watched.
func TestResealOfTheSeedKeepsTheDeviceMarker(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	seed := f.enrollTOTP()
	orig := f.snapshotCredentials(A.User)
	defer f.restoreCredentials(A.User, orig)

	f.freeStep(A.Tenant)
	signedIn := f.client()
	signedIn.mfaLoginComplete(A.Phone, pwA, codeAt(seed, time.Now()))
	marker := signedIn.jar[session.CookieDevice]
	if marker == nil {
		t.Fatal("a password and code login left no device marker")
	}
	gen := func() int { return f.count(`SELECT credential_gen FROM ctrlz.users WHERE id = $1`, A.User) }
	before := gen()

	// The re-seal runs the way `ctrlz rekey` runs it: the definer function of ctrlz_auth, under
	// the tenant setting WithTenant makes. db-r7-4 bound the exemption to the writer, so the plain
	// UPDATE this test used in round 6 is now (correctly) a change of the generation.
	f.env.Exec(t, fmt.Sprintf(`DO $$ BEGIN
		PERFORM pg_catalog.set_config('ctrlz.tenant_id', '%s', true);
		IF NOT ctrlz_fn.keytool_totp_replace('%s'::uuid,
			(SELECT totp_secret_ct FROM ctrlz.users WHERE id = '%s'::uuid),
			(SELECT totp_secret_ct || '\x00'::bytea FROM ctrlz.users WHERE id = '%s'::uuid)) THEN
			RAISE EXCEPTION 'the re-seal swapped nothing';
		END IF;
	END $$`, A.Tenant, A.User, A.User, A.User))
	if got := gen(); got != before {
		t.Fatalf("a re-seal of the seed moved credential_gen from %d to %d", before, got)
	}
	f.clearOTP()
	holder := f.client()
	holder.jar[session.CookieDevice] = &http.Cookie{Name: session.CookieDevice, Value: marker.Value}
	holder.requestOTP(A.Phone, "login", nil).want(202, "")
	if n := f.count(`SELECT coalesce(sum(count), 0) FROM ctrlz.sms_counters WHERE scope = 'phone' AND key = $1`, A.Phone+"|trusted"); n != 1 {
		t.Errorf("the marker stopped counting after a re-seal (%d)", n)
	}

	// A plain UPDATE of the live seed is no re-seal, whoever runs it (db-r7-4).
	f.env.Exec(t, `UPDATE ctrlz.users SET totp_secret_ct = totp_secret_ct || '\x00'::bytea WHERE id = $1`, A.User)
	if got := gen(); got != before+1 {
		t.Fatalf("a plain UPDATE of the seed moved credential_gen to %d, want %d", got, before+1)
	}
	before++

	// The factor itself changing still ends it.
	f.env.Exec(t, `UPDATE ctrlz.users SET totp_enabled_at = totp_enabled_at - interval '1 hour' WHERE id = $1`, A.User)
	if got := gen(); got != before+1 {
		t.Errorf("a change of totp_enabled_at moved credential_gen to %d, want %d", got, before+1)
	}
}
