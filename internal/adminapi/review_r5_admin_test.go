package adminapi

import (
	"context"
	"errors"
	"fmt"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/adminapi/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/marker"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// TestAdminLoginAnswersAnEmptyOrBlankUsernameWithoutAServerFault is admin-r5-1. A username that
// is empty once trimmed has no throttle key (Who.part refuses it), and that refusal came back
// from the Charge step as a 500 before the fix. Two lines now hold it: the schema (pattern
// `content`, a 400 before any handler) and the handler (the 401 of a wrong password with no
// throttle row and no Argon2 run, for a request that did not come through the pipeline).
func TestAdminLoginAnswersAnEmptyOrBlankUsernameWithoutAServerFault(t *testing.T) {
	r := newRig(t)
	r.setupAdmin(t, true)
	r.env.Exec(t, `DELETE FROM ctrlz.auth_throttle`)

	t.Run("the schema refuses it", func(t *testing.T) {
		for _, name := range []string{"", " ", "   ", " ", "　"} {
			res := r.browser().post("/auth/login", map[string]any{"username": name, "password": "x"})
			if res.Code != http.StatusBadRequest {
				t.Errorf("username %q: %d %s, want 400", name, res.Code, res.Body)
			}
		}
	})

	t.Run("the handler answers it as a wrong password", func(t *testing.T) {
		s := &Server{
			d: r.deps, hasher: r.hasher, strength: pwstrength.New(),
			throttle: throttle.NewAdmin(r.deps.Store.Admin(), r.deps.Keys),
			markers:  marker.New(r.deps.Keys, r.deps.Sessions.Now),
		}
		for _, name := range []string{"", "   ", "\t"} {
			_, err := s.login(context.Background(), gen.AdminLoginRequest{Username: name, Password: "x"})
			var he *httpx.Error
			if !errors.As(err, &he) || he.Status != http.StatusUnauthorized {
				t.Errorf("username %q: %v, want the 401 of a wrong password", name, err)
			}
		}
	})

	if n := r.count(t, `SELECT count(*)::int FROM ctrlz.auth_throttle`); n != 0 {
		t.Errorf("%d throttle rows for a request with no username: it names nothing to count", n)
	}
	if lines := r.logs.String(); len(lines) > 0 {
		for _, l := range []string{`"level":"ERROR"`, `"level":"WARN"`} {
			if strings.Contains(lines, l) {
				t.Errorf("the log holds %s for a client's input", l)
			}
		}
	}
}

// TestRegistrationChangeWithTheWorkerDown is admin-r5-2: the worker is stopped, so the job that
// the last mode change queued stays queued (or sits in 'running' for a worker that died), and the
// owner must still be able to close registration. Before the fix the second change was a bare 409
// for as long as the first job lived. The kinds are judged the same way: a Passkey RP ID change
// replaces a stale RP job. A request that only repeats the mode ends nothing.
func TestRegistrationChangeWithTheWorkerDown(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.env.Exec(t, `DELETE FROM ctrlz.admin_jobs`)

	b.put("/settings/registration", map[string]any{"mode": "open", "open_grace_days": 14}).want(200, "")
	if n := r.count(t, `SELECT count(*) FROM ctrlz.admin_jobs WHERE state = 'queued'`); n != 1 {
		t.Fatalf("%d queued jobs after opening", n)
	}

	// Repeating the mode (and changing only the grace) leaves the queued job as it is.
	b.put("/settings/registration", map[string]any{"mode": "open", "open_grace_days": 30}).want(200, "")
	if n := r.count(t, `SELECT count(*) FROM ctrlz.admin_jobs WHERE state = 'queued'`); n != 1 {
		t.Fatalf("a request that repeats the mode ended the job: %d queued", n)
	}

	// The worker is down: close registration. 200, one queued job (the new one), the old one ended.
	b.put("/settings/registration", map[string]any{"mode": "closed"}).want(200, "")
	if got := b.get("/settings/registration").want(200, ""); !strings.Contains(string(got.Body), `"mode":"closed"`) {
		t.Fatalf("registration is not closed: %s", got.Body)
	}
	var queued, failed, marked int
	r.env.Scan(t, `SELECT count(*) FILTER (WHERE state = 'queued'), count(*) FILTER (WHERE state = 'failed'),
		count(*) FILTER (WHERE progress ? 'superseded') FROM ctrlz.admin_jobs WHERE kind = 'registration_transition'`, nil, &queued, &failed, &marked)
	if queued != 1 || failed != 1 || marked != 1 {
		t.Fatalf("queued %d, failed %d, superseded %d: want 1, 1, 1", queued, failed, marked)
	}
	var to string
	r.env.Scan(t, `SELECT params->>'to' FROM ctrlz.admin_jobs WHERE state = 'queued' AND kind = 'registration_transition'`, nil, &to)
	if to != "closed" {
		t.Errorf("the queued job moves to %q, want closed", to)
	}

	// A job that a dead worker left in 'running' is replaced the same way.
	r.env.Exec(t, `UPDATE ctrlz.admin_jobs SET state = 'running', started_at = now() WHERE state = 'queued' AND kind = 'registration_transition'`)
	b.put("/settings/registration", map[string]any{"mode": "invite"}).want(200, "")
	if n := r.count(t, `SELECT count(*) FROM ctrlz.admin_jobs WHERE kind = 'registration_transition' AND state IN ('queued', 'running')`); n != 1 {
		t.Fatalf("%d active transition jobs after the change", n)
	}

	// The Passkey RP ID job is replaced too.
	b.put("/settings/webauthn", map[string]any{"rp_id": "example.test", "enabled": false}).want(200, "")
	b.put("/settings/webauthn", map[string]any{"rp_id": "panel.example.test", "enabled": false}).want(200, "")
	r.env.Scan(t, `SELECT count(*) FILTER (WHERE state = 'queued'), count(*) FILTER (WHERE state = 'failed')
		FROM ctrlz.admin_jobs WHERE kind = 'webauthn_rp_change'`, nil, &queued, &failed)
	if queued != 1 || failed != 1 {
		t.Fatalf("RP jobs: queued %d, failed %d: want 1, 1", queued, failed)
	}
}

// TestNeighbourOnTheOwnersNetworkCannotKeepTheFirstLoginOut is admin-r5-11, the network half of
// admin-r2-7. The first login after bootstrap or a console reset has no device marker, so the
// network scopes (admin_login on the username and the network, admin_login_net on the network
// alone) count it like a stranger's. Someone on the owner's carrier address group who knows the
// username spends both by sending wrong logins, refills them faster than `unlock` clears them, and
// the owner's right console password got a 429. The scopes still count and still refuse everyone
// else; only the right console-issued one-time password (120 bits) is let through them.
func TestNeighbourOnTheOwnersNetworkCannotKeepTheFirstLoginOut(t *testing.T) {
	r := newRig(t)
	r.setupAdmin(t, false)
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_expires_at = now() + interval '24 hours' WHERE id = $1`, seedAdmin)

	owner, neighbour := r.browser(), r.browser()
	// Both are in one /24: the neighbour is the owner's address with another last octet.
	ip := netip.MustParseAddr(owner.ip).As4()
	ip[3] ^= 0x55
	neighbour.ip = netip.AddrFrom4(ip).String()
	svc := throttle.NewAdmin(r.adm.Admin(), r.keys)
	spend := func(sc throttle.Scope) {
		t.Helper()
		w := throttle.Who{Username: adminName, IP: netip.MustParseAddr(neighbour.ip)}
		for i := 0; i < 100; i++ {
			if err := svc.Charge(r.env.Ctx, sc, w); err != nil {
				return
			}
		}
		t.Fatalf("%s never refused", sc)
	}
	spend(throttle.AdminLogin)
	spend(throttle.AdminLoginNet)

	// A stranger on that network is refused by the scopes, before Argon2.
	neighbour.login("wrong-wrong-wrong-1", "").want(429, "too_many_attempts")
	// The owner with the console password gets in although both network scopes are spent.
	owner.login(adminPW, "").want(200, "")
	owner.get("/me").want(200, "")
	// The success clears the pair keyed on the username and keeps the network scope, which a
	// success never clears: the next stranger on that network is still refused.
	neighbour.login("wrong-wrong-wrong-1", "").want(429, "too_many_attempts")

	// The exception is for the console password alone. A password the admin chose is refused
	// like a wrong one while the network scope stays spent.
	owner.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW}).want(204, "")
	r.browser().callOn(r.h, adminHost, "POST", "/auth/login", map[string]any{"username": adminName, "password": adminNewPW}).want(200, "") // another network is untouched
	owner2 := r.browser()
	owner2.ip = neighbour.ip
	owner2.login(adminNewPW, "").want(429, "too_many_attempts")
	// A console one-time password past its expiry is not let through either.
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET must_change_password = true, password_expires_at = now() - interval '1 minute' WHERE id = $1`, seedAdmin)
	owner2.login(adminPW, "").want(429, "too_many_attempts")
}

// TestStrangersCannotKeepTheOwnerOutOfTheArgon2Gate is admin-r5-9. The admin service has one Argon2
// slot, and every unproved login runs a hash in it (an unknown username runs the dummy hash), so a
// few unknown-username logins a second from a few networks keep the slot busy for ever. The device
// marker exempts the owner from the throttle scopes and did nothing for the gate: the owner's
// login with the right password, code and marker, a password change and a new account all waited
// two seconds and got 503. A request that carries a proof (a device marker that holds for the
// account, a signed-in session) is now served before any stranger.
//
// The strangers here are real: sixteen clients, each sending unknown-username logins from its own
// network as fast as the 500 ms floor lets it, against a hash of 48 MiB. How long one hash takes
// depends on the host, though, and on a fast runner sixteen of them never made a waiter outlast the
// two seconds of the gate (admin-r16-2: the first GitHub run failed with "the gate was not under
// pressure"). So the pressure does not come from the hash alone: sixteen holders take the slot the way
// a stranger does (no proof) and keep it for a time the test sets, 300 ms, so the queue is longer than
// the wait on any host, and the test waits until the gate has refused one of them before it starts
// (a condition, not a sleep). It then requires every proved request to succeed. The guard stays: a run in
// which the gate refused nobody still fails.
func TestStrangersCannotKeepTheOwnerOutOfTheArgon2Gate(t *testing.T) {
	if testing.Short() {
		t.Skip("a saturated one-slot gate and sixteen clients behind the 500 ms floor")
	}
	r := newRig(t)
	seed := r.setupAdmin(t, true)
	gate := password.NewGate(1, 2*time.Second)
	slow, err := password.NewHasher(password.Params{MemoryKiB: 48 * 1024, Time: 3, Threads: 1}, gate)
	if err != nil {
		t.Fatal(err)
	}
	// The stored hash is the slow one, so a login does not rehash (which would move the credential
	// generation and end the marker this test is about).
	hash, err := slow.Hash(r.env.Ctx, secretOf(adminPW))
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_hash = $2 WHERE id = $1`, seedAdmin, hash.Reveal())
	h := r.handler(t, func(d *Deps) { d.Hasher = slow })

	login := func(b *browser) *aresp {
		r.freeStep(t)
		return b.callOn(h, adminHost, "POST", "/auth/login", map[string]any{"username": adminName, "password": adminPW, "totp_code": totpNow(seed)})
	}
	owner := r.browser()
	login(owner).want(200, "")
	marker := owner.jar[session.CookieAdminDevice]
	if marker == nil {
		t.Fatal("no device marker after the owner's login")
	}

	stop := make(chan struct{})
	holdCtx, stopHolders := context.WithCancel(r.env.Ctx)
	var wg sync.WaitGroup
	var busy, total, heldBusy atomic.Int64
	// Pressure the host cannot change: the holders. Acquire without a proof is what a stranger does.
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for holdCtx.Err() == nil {
				rel, err := gate.Acquire(holdCtx)
				if err != nil {
					if errors.Is(err, password.ErrBusy) {
						heldBusy.Add(1)
					}
					continue
				}
				// Hold the slot for 300 ms, or until the pressure is lifted.
				testwait.Bound(holdCtx.Done(), 300*time.Millisecond)
				rel()
			}
		}()
	}
	var seq atomic.Int64
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s := r.browser() // a new network every request: the throttle scopes are not what this is about
				res := s.callOn(h, adminHost, "POST", "/auth/login", map[string]any{"username": fmt.Sprintf("nobody-%d", seq.Add(1)), "password": "wrong-wrong-wrong-1"})
				total.Add(1)
				if res.Code == http.StatusServiceUnavailable {
					busy.Add(1)
				}
			}
		}()
	}
	defer func() { close(stop); stopHolders(); wg.Wait() }()
	// Start when the gate has refused a waiter: that is the pressure, whatever the host's speed.
	testwait.UntilEvery(t, 30*time.Second, 20*time.Millisecond, "the gate to refuse a waiter (the test could not put it under pressure)", func() bool { return heldBusy.Load() != 0 })

	// 1. The owner's login, from a browser that holds the marker.
	for i := 0; i < 4; i++ {
		b := r.browser()
		b.jar[session.CookieAdminDevice] = marker
		login(b).want(200, "")
	}
	// 2. The signed-in owner's hashes: a new account (its one-time password is hashed) five times.
	for i := 0; i < 5; i++ {
		owner.callOn(h, adminHost, "POST", "/users", map[string]any{"phone": fmt.Sprintf("+98912555%04d", i)}).want(201, "")
	}

	if total.Load() < 20 || heldBusy.Load() == 0 {
		t.Fatalf("the strangers sent %d logins (%d refused as busy) and the holders were refused %d times: the gate was not under pressure, so the test proves nothing", total.Load(), busy.Load(), heldBusy.Load())
	}
	// 3. A stranger with no proof still gets the 503.
	if res := r.browser().callOn(h, adminHost, "POST", "/auth/login", map[string]any{"username": "nobody-last", "password": "wrong-wrong-wrong-1"}); res.Code != 503 && res.Code != 401 {
		t.Errorf("a stranger got %d", res.Code)
	}
}
