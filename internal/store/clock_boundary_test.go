package store_test

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/credstate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/clockrule"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The boundary test of the clock rule (P1 auth review, round 5, topic
// clock-source; migrations/catalog/clocks.yaml, spec 3.3, 3.5, 4.5, 10.2, 10.5).
//
// Every app and db column of the registry is covered by a case below, and a
// registry column without a case fails, so a window added tomorrow gets a boundary
// test on the day it is made. Each case runs twice, with the application clock
// three hours ahead of and three hours behind Postgres:
//
//   - an app column is written with the application time and must hold exactly
//     that time (a database now() would be off by three hours), and a window that SQL
//     decides against a parameter must open and close on the application clock:
//     one second inside, the answer is "live", one second outside, it is not;
//   - a db column takes no application time at all. It is written by the database
//     and must hold the database's time (plus the window's length), and the
//     decision is SQL's: one minute inside is live, one minute outside is not,
//     whatever the application clock says.
//
// What the windows decide beyond the store (the session manager's lookup, the
// reauth gate, the admin fresh window) is covered by the tests named in
// clockWindowTests, which move the same clock.

// seedAdmin is the admin the global seed makes.
var seedAdmin = uuid.MustParse("00000000-0000-7000-8000-0000000000e1")

// skews are the two sides of the rule.
var skews = map[string]time.Duration{"application ahead": 3 * time.Hour, "application behind": -3 * time.Hour}

type windowEnv struct {
	f  *fixture
	t  *testing.T
	db time.Time // Postgres's time at the start of the case, truncated to microseconds
	// app returns the application clock d after the start of the case: Postgres's
	// time plus the skew.
	app   func(d time.Duration) time.Time
	super *pgx.Conn
}

func (e *windowEnv) at(table, column, where string, args ...any) time.Time {
	e.t.Helper()
	var at time.Time
	if err := e.super.QueryRow(e.f.ctx, "SELECT "+column+" FROM ctrlz."+table+" WHERE "+where, args...).Scan(&at); err != nil {
		e.t.Fatalf("read %s.%s: %v", table, column, err)
	}
	return at
}

// sameInstant fails unless got is want to the microsecond (Postgres's resolution).
func (e *windowEnv) sameInstant(what string, got, want time.Time) {
	e.t.Helper()
	if !got.Equal(want.Truncate(time.Microsecond)) {
		e.t.Errorf("%s = %v, want exactly the application time %v (off by %v)", what, got.UTC(), want.UTC(), got.Sub(want))
	}
}

// nearDB fails unless got is the database's time plus offset, within a minute: a
// column stamped by the application clock would be three hours away.
func (e *windowEnv) nearDB(what string, got time.Time, offset time.Duration) {
	e.t.Helper()
	var now time.Time
	if err := e.super.QueryRow(e.f.ctx, "SELECT pg_catalog.now()").Scan(&now); err != nil {
		e.t.Fatal(err)
	}
	if d := got.Sub(now.Add(offset)); d < -time.Minute || d > time.Minute {
		e.t.Errorf("%s = %v, want the database time %v plus %v (off by %v): it was stamped by another clock", what, got.UTC(), now.UTC(), offset, d)
	}
}

func (e *windowEnv) exec(sql string, args ...any) {
	e.t.Helper()
	if _, err := e.super.Exec(e.f.ctx, sql, args...); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
}

type windowCase struct {
	covers []string
	run    func(e *windowEnv)
}

// clockWindowTests names the tests that carry a window past the store, with the
// registry columns each one moves the clock for. The list is checked: a test that
// does not exist, or a column that is not a window, fails.
var clockWindowTests = map[string][]string{
	"internal/auth/session/session_test.go:TestReauthWindowUsesTheApplicationClock":  {"sessions.reauth_at"},
	"internal/adminapi/review4_test.go:TestAdminSessionClocksUseTheApplicationClock": {"admin_sessions.created_at", "admin_sessions.totp_verified_at"},
	"internal/adminapi/review4_test.go:TestNoticeAckCutoffUsesTheApplicationClock":   {"admin_sessions.created_at"},
	"internal/adminapi/review4_test.go:TestAdminPasswordExpiryUsesTheDatabaseClock":  {"admin_users.password_expires_at"},
}

func windowCases() []windowCase {
	return []windowCase{
		{[]string{"sessions.idle_expires_at", "sessions.absolute_expires_at", "sessions.reauth_at", "sessions.last_seen_at"}, func(e *windowEnv) {
			f, s := e.f, e.f.db.Store(e.f.ctx, e.t, store.RoleTenant)
			var idle, abs uuid.UUID
			f.inTenant(e.t, s, f.A.Tenant, func(tx store.Tx) {
				var err error
				// idle: 1 h, absolute: 8 h. second: absolute 8 h, idle 20 h.
				if idle, err = tx.SessionCreate(store.NewSession{UserID: f.A.User, TokenHash: hash("w-idle"), IdleExpiresAt: e.app(time.Hour),
					AbsoluteExpiresAt: e.app(20 * time.Hour), AuthMethod: "password", At: e.app(0)}); err != nil {
					e.t.Fatal(err)
				}
				if abs, err = tx.SessionCreate(store.NewSession{UserID: f.A.User, TokenHash: hash("w-abs"), IdleExpiresAt: e.app(20 * time.Hour),
					AbsoluteExpiresAt: e.app(8 * time.Hour), AuthMethod: "password", At: e.app(0)}); err != nil {
					e.t.Fatal(err)
				}
			})
			e.sameInstant("sessions.last_seen_at at creation", e.at("sessions", "last_seen_at", "id = $1", idle), e.app(0))
			live := func(now time.Time) map[uuid.UUID]bool {
				out := map[uuid.UUID]bool{}
				f.inTenant(e.t, s, f.A.Tenant, func(tx store.Tx) {
					rows, err := tx.SessionsList(f.A.User, now)
					if err != nil {
						e.t.Fatal(err)
					}
					for _, r := range rows {
						out[r.ID] = true
					}
				})
				return out
			}
			if l := live(e.app(time.Hour - time.Second)); !l[idle] {
				e.t.Error("the idle window closed a second early")
			}
			if l := live(e.app(time.Hour + time.Second)); l[idle] {
				e.t.Error("the idle window stayed open a second late")
			}
			if l := live(e.app(8*time.Hour - time.Second)); !l[abs] {
				e.t.Error("the absolute window closed a second early")
			}
			if l := live(e.app(8*time.Hour + time.Second)); l[abs] {
				e.t.Error("the absolute window stayed open a second late")
			}
			f.inTenant(e.t, s, f.A.Tenant, func(tx store.Tx) {
				if ok, err := tx.SessionRefreshToken(abs, hash("w-abs2"), e.app(20*time.Hour), e.app(8*time.Hour-time.Second)); err != nil || !ok {
					e.t.Errorf("a refresh a second before the absolute limit: %v %v", ok, err)
				}
				if ok, err := tx.SessionRefreshToken(abs, hash("w-abs3"), e.app(20*time.Hour), e.app(8*time.Hour+time.Second)); err != nil || ok {
					e.t.Errorf("a refresh a second after the absolute limit: %v %v", ok, err)
				}
				if ok, err := tx.SessionRotate(idle, hash("w-idle2"), e.app(2*time.Hour), store.ReauthSet, e.app(5*time.Minute), false); err != nil || !ok {
					e.t.Fatal(ok, err)
				}
			})
			e.sameInstant("sessions.reauth_at", e.at("sessions", "reauth_at", "id = $1", idle), e.app(5*time.Minute))
			e.sameInstant("sessions.last_seen_at after a rotation", e.at("sessions", "last_seen_at", "id = $1", idle), e.app(5*time.Minute))
			f.inTenant(e.t, s, f.A.Tenant, func(tx store.Tx) {
				if err := tx.SessionTouch(idle, e.app(3*time.Hour), e.app(10*time.Minute)); err != nil {
					e.t.Fatal(err)
				}
			})
			e.sameInstant("sessions.last_seen_at after a touch", e.at("sessions", "last_seen_at", "id = $1", idle), e.app(10*time.Minute))
			e.sameInstant("sessions.idle_expires_at after a touch", e.at("sessions", "idle_expires_at", "id = $1", idle), e.app(3*time.Hour))
		}},

		{[]string{"refresh_tokens.rotated_at", "refresh_tokens.reuse_grace_until", "refresh_tokens.expires_at"}, func(e *windowEnv) {
			f, s := e.f, e.f.db.Store(e.f.ctx, e.t, store.RoleTenant)
			sess := f.seededSession(e.t, e.super, f.A.Tenant)
			var rid uuid.UUID
			f.inTenant(e.t, s, f.A.Tenant, func(tx store.Tx) {
				var err error
				if rid, err = tx.RefreshCreate(store.NewRefresh{SessionID: sess, UserID: f.A.User, FamilyID: uuid.New(), TokenHash: hash("w-ref"), ExpiresAt: e.app(30 * 24 * time.Hour)}); err != nil {
					e.t.Fatal(err)
				}
				if ok, err := tx.RefreshRotate(rid, e.app(10*time.Second), e.app(time.Second)); err != nil || !ok {
					e.t.Fatal(ok, err)
				}
			})
			e.sameInstant("refresh_tokens.expires_at", e.at("refresh_tokens", "expires_at", "id = $1", rid), e.app(30*24*time.Hour))
			e.sameInstant("refresh_tokens.rotated_at", e.at("refresh_tokens", "rotated_at", "id = $1", rid), e.app(time.Second))
			e.sameInstant("refresh_tokens.reuse_grace_until", e.at("refresh_tokens", "reuse_grace_until", "id = $1", rid), e.app(10*time.Second))
		}},

		{[]string{"users.enforce_lift_at"}, func(e *windowEnv) {
			f, s := e.f, e.f.db.Store(e.f.ctx, e.t, store.RoleTenant)
			f.inTenant(e.t, s, f.A.Tenant, func(tx store.Tx) {
				if err := tx.SetEnforce(f.A.User, true); err != nil {
					e.t.Fatal(err)
				}
				at, ok, err := tx.DeferEnforceLift(f.A.User, 72*time.Hour, e.app(0))
				if err != nil || !ok {
					e.t.Fatal(ok, err)
				}
				e.sameInstant("the lift time returned", at, e.app(72*time.Hour))
				again, _, _ := tx.DeferEnforceLift(f.A.User, time.Hour, e.app(time.Hour))
				e.sameInstant("the lift time after a repeat", again, e.app(72*time.Hour))
			})
			e.sameInstant("users.enforce_lift_at", e.at("users", "enforce_lift_at", "id = $1", f.A.User), e.app(72*time.Hour))
		}},

		{[]string{"admin_sessions.idle_expires_at", "admin_sessions.absolute_expires_at", "admin_sessions.totp_verified_at", "admin_sessions.created_at"}, func(e *windowEnv) {
			f, s := e.f, e.f.db.Store(e.f.ctx, e.t, store.RoleAdmin)
			var sid, old, fresh uuid.UUID
			f.global(e.t, s, func(g store.GlobalTx) {
				id := seedAdmin
				mk := func(tag string, abs time.Time, verified bool) uuid.UUID {
					sid, err := g.AdminSessionCreate(store.NewAdminSession{AdminID: id, TokenHash: hash(tag), IdleExpiresAt: e.app(time.Hour), AbsoluteExpiresAt: abs,
						TOTPVerified: verified, At: e.app(0), IP: netip.MustParseAddr("203.0.113.5")})
					if err != nil {
						e.t.Fatal(err)
					}
					return sid
				}
				sid = mk("wa-1", e.app(8*time.Hour), true)
				old = mk("wa-2", e.app(-24*time.Hour-time.Second), false)   // a day and a second past its limit
				fresh = mk("wa-3", e.app(-24*time.Hour+time.Second), false) // a second short of the day
				at, ok, err := g.AdminSessionFresh(sid, e.app(2*time.Minute))
				if err != nil || !ok {
					e.t.Fatal(ok, err)
				}
				e.sameInstant("the fresh time returned", at, e.app(2*time.Minute))
				if err := g.AdminSessionTouch(sid, e.app(3*time.Hour)); err != nil {
					e.t.Fatal(err)
				}
			})
			e.sameInstant("admin_sessions.created_at", e.at("admin_sessions", "created_at", "id = $1", sid), e.app(0))
			e.sameInstant("admin_sessions.totp_verified_at", e.at("admin_sessions", "totp_verified_at", "id = $1", sid), e.app(2*time.Minute))
			e.sameInstant("admin_sessions.absolute_expires_at", e.at("admin_sessions", "absolute_expires_at", "id = $1", sid), e.app(8*time.Hour))
			e.sameInstant("admin_sessions.idle_expires_at", e.at("admin_sessions", "idle_expires_at", "id = $1", sid), e.app(3*time.Hour))
			f.global(e.t, s, func(g store.GlobalTx) {
				if _, err := g.AdminSessionsDeleteExpiredBatch(e.app(0), 1000); err != nil {
					e.t.Fatal(err)
				}
			})
			var gone, kept int
			if err := e.super.QueryRow(f.ctx, "SELECT count(*) FILTER (WHERE id = $1), count(*) FILTER (WHERE id = $2) FROM ctrlz.admin_sessions", old, fresh).Scan(&gone, &kept); err != nil {
				e.t.Fatal(err)
			}
			if gone != 0 || kept != 1 {
				e.t.Errorf("the sweep a day after the limit kept %d of the session a second past it and %d of the one a second short of it", gone, kept)
			}
		}},

		// The admin's one-time state moved to the database clock with the rule one-time-state:
		// a definer function stamps it, and ctrlz.credential_state decides on it. The two
		// stamps beside it (password_changed_at, totp_enabled_at) are records.
		{[]string{"admin_users.password_expires_at"}, func(e *windowEnv) {
			f, s := e.f, e.f.db.Store(e.f.ctx, e.t, store.RoleAdmin)
			id := seedAdmin
			state := func() (st credstate.State) {
				f.global(e.t, s, func(g store.GlobalTx) {
					u, _, err := g.AdminUserByID(id)
					if err != nil {
						e.t.Fatal(err)
					}
					st = u.State
				})
				return
			}
			f.global(e.t, s, func(g store.GlobalTx) {
				if ok, err := g.AdminReset(id, secret.New("one-time"), true); err != nil || !ok {
					e.t.Fatal(ok, err)
				}
			})
			e.nearDB("admin_users.password_expires_at after a console reset", e.at("admin_users", "password_expires_at", "id = $1", id), 24*time.Hour)
			e.exec("UPDATE ctrlz.admin_users SET password_expires_at = now() + interval '1 minute' WHERE id = $1", id)
			if st := state(); st != credstate.OneTimeLive {
				e.t.Errorf("a minute before the expiry: %v", st)
			}
			e.exec("UPDATE ctrlz.admin_users SET password_expires_at = now() - interval '1 minute' WHERE id = $1", id)
			if st := state(); st != credstate.OneTimeExpired {
				e.t.Errorf("a minute after the expiry: %v", st)
			}
			// A fresh reset revives it; a chosen password lives an hour.
			f.global(e.t, s, func(g store.GlobalTx) {
				if ok, err := g.AdminReset(id, secret.New("one-time-2"), true); err != nil || !ok {
					e.t.Fatal(ok, err)
				}
				if st, ok, err := g.AdminSetPassword(id, secret.New("mine")); err != nil || !ok || st != credstate.ChosenNoSecondFactor {
					e.t.Fatal(st, ok, err)
				}
			})
			e.nearDB("admin_users.password_expires_at after a chosen password", e.at("admin_users", "password_expires_at", "id = $1", id), time.Hour)
			e.exec("UPDATE ctrlz.admin_users SET password_expires_at = now() - interval '1 minute' WHERE id = $1", id)
			if st := state(); st != credstate.OneTimeExpired {
				e.t.Errorf("a chosen password a minute past its hour: %v", st)
			}
		}},

		// audit_log.at is a `stamp` column since migration 0059 (admin-r18-6): the key tool's definer function stamps it
		// with the database clock, and the admin writers' time is covered by the chain itself, which hashes it (the
		// verifier of internal/auth/audit and `audit verify` fail for a row whose time differs from the hashed text).

		// ---- database clock -------------------------------------------------

		{[]string{"users.totp_pending_at", "users.password_expires_at"}, func(e *windowEnv) {
			f, s := e.f, e.f.db.Store(e.f.ctx, e.t, store.RoleTenant)
			f.inTenant(e.t, s, f.A.Tenant, func(tx store.Tx) {
				if ok, err := tx.TOTPSetPending(f.A.User, []byte("ct")); err != nil || !ok {
					e.t.Fatal(ok, err)
				}
			})
			e.nearDB("users.totp_pending_at", e.at("users", "totp_pending_at", "id = $1", f.A.User), 0)
			stale := func() (pending, stale bool) {
				f.inTenant(e.t, s, f.A.Tenant, func(tx store.Tx) {
					u, _, err := tx.User(f.A.User)
					if err != nil {
						e.t.Fatal(err)
					}
					pending, stale = u.TOTPPending, u.TOTPPendingStale
				})
				return
			}
			if p, st := stale(); !p || st {
				e.t.Errorf("a setup just made: pending %v stale %v", p, st)
			}
			e.exec("UPDATE ctrlz.users SET totp_pending_at = now() - interval '14 minutes' WHERE id = $1", f.A.User)
			if _, st := stale(); st {
				e.t.Error("a setup of 14 minutes is stale")
			}
			e.exec("UPDATE ctrlz.users SET totp_pending_at = now() - interval '16 minutes' WHERE id = $1", f.A.User)
			if _, st := stale(); !st {
				e.t.Error("a setup of 16 minutes is not stale")
			}

			// The three reads of the state (the row, the locked row, the login lookup) must give
			// the same answer on the database clock.
			one := func() (live, expired bool) {
				var fromRow credstate.State
				f.inTenant(e.t, s, f.A.Tenant, func(tx store.Tx) {
					u, _, err := tx.User(f.A.User)
					if err != nil {
						e.t.Fatal(err)
					}
					l, _, err := tx.UserLock(f.A.User)
					if err != nil {
						e.t.Fatal(err)
					}
					if u.State != l.State {
						e.t.Errorf("User and UserLock disagree: %v %v", u.State, l.State)
					}
					fromRow = u.State
				})
				login, _, err := s.Auth().UserByPhone(f.ctx, f.A.Phone)
				if err != nil {
					e.t.Fatal(err)
				}
				if login.State != fromRow {
					e.t.Errorf("User and UserByPhone disagree: %v %v", fromRow, login.State)
				}
				return fromRow == credstate.OneTimeLive, login.State == credstate.OneTimeExpired
			}
			e.exec("UPDATE ctrlz.users SET must_reset = true, password_expires_at = now() + interval '1 minute' WHERE id = $1", f.A.User)
			if l, x := one(); !l || x {
				e.t.Errorf("a minute before the expiry: live %v expired %v", l, x)
			}
			e.exec("UPDATE ctrlz.users SET password_expires_at = now() - interval '1 minute' WHERE id = $1", f.A.User)
			if l, x := one(); l || !x {
				e.t.Errorf("a minute after the expiry: live %v expired %v", l, x)
			}
		}},

		{[]string{"invites.expires_at"}, func(e *windowEnv) {
			f, s := e.f, e.f.db.Store(e.f.ctx, e.t, store.RoleAdmin)
			mk := func(tag string, ttl time.Duration) []byte {
				f.global(e.t, s, func(g store.GlobalTx) {
					if _, err := g.InviteCreate(store.NewInvite{TokenHash: hash(tag), Phone: "+989121110" + tag[len(tag)-3:], Locale: "fa", TTL: ttl}); err != nil {
						e.t.Fatal(err)
					}
				})
				return hash(tag)
			}
			open, closed := mk("inv-w-001", time.Hour), mk("inv-w-002", -time.Hour)
			tenant := f.db.Store(f.ctx, e.t, store.RoleTenant).Auth()
			for h, wantExpired := range map[string]bool{string(open): false, string(closed): true} {
				got, ok, err := tenant.InviteByHash(f.ctx, []byte(h))
				if err != nil || !ok || got.Expired != wantExpired {
					e.t.Errorf("invite %s: expired %v (found %v, %v), want %v", h, got.Expired, ok, err, wantExpired)
				}
			}
			e.nearDB("invites.expires_at", e.at("invites", "expires_at", "token_hash = $1", open), time.Hour)
		}},

		{[]string{"phone_change_requests.expires_at", "phone_change_requests.created_at"}, func(e *windowEnv) {
			f, s := e.f, e.f.db.Store(e.f.ctx, e.t, store.RoleTenant)
			var id uuid.UUID
			f.inTenant(e.t, s, f.A.Tenant, func(tx store.Tx) {
				var err error
				if id, err = tx.PhoneChangeCreate(f.A.User, "+989135550999", uuid.New(), uuid.New(), 5*time.Minute); err != nil {
					e.t.Fatal(err)
				}
			})
			e.nearDB("phone_change_requests.expires_at", e.at("phone_change_requests", "expires_at", "id = $1", id), 5*time.Minute)
			e.nearDB("phone_change_requests.created_at", e.at("phone_change_requests", "created_at", "id = $1", id), 0)
		}},

		{[]string{"otp_challenges.expires_at", "otp_challenges.created_at", "otp_challenges.consumed_at", "otp_challenges.delivery_claimed_until", "sms_counters.day"}, func(e *windowEnv) {
			f := e.f
			a := f.db.Store(f.ctx, e.t, store.RoleTenant).Auth()
			phone := "+989121234599"
			iss, err := a.OTPIssue(f.ctx, phone, "login", []byte{1, 2}, []byte("sealed"), netip.MustParseAddr("198.51.100.9"), true)
			if err != nil || !iss.Allowed {
				e.t.Fatalf("OTPIssue: %+v %v", iss, err)
			}
			e.nearDB("otp_challenges.expires_at", e.at("otp_challenges", "expires_at", "id = $1", iss.ID), 5*time.Minute)
			e.nearDB("otp_challenges.created_at", e.at("otp_challenges", "created_at", "id = $1", iss.ID), 0)
			var sameDay bool
			if err := e.super.QueryRow(f.ctx, "SELECT bool_and(day = (pg_catalog.now() AT TIME ZONE 'Asia/Tehran')::date) FROM ctrlz.sms_counters WHERE scope <> 'global' OR key = 'all'").Scan(&sameDay); err != nil || !sameDay {
				e.t.Errorf("sms_counters.day is not the Tehran day of the database clock: %v %v", sameDay, err)
			}
			w := f.db.Store(f.ctx, e.t, store.RoleWorker)
			f.global(e.t, w, func(g store.GlobalTx) {
				got, err := g.OTPClaim(10, 3)
				if err != nil || len(got) == 0 {
					e.t.Fatalf("OTPClaim: %v %v", got, err)
				}
			})
			e.nearDB("otp_challenges.delivery_claimed_until", e.at("otp_challenges", "delivery_claimed_until", "id = $1", iss.ID), 20*time.Second)
			if out, err := a.OTPConsume(f.ctx, iss.ID, phone, "login", []byte{1, 2}); err != nil || out != "ok" {
				e.t.Fatalf("OTPConsume: %q %v", out, err)
			}
			e.nearDB("otp_challenges.consumed_at", e.at("otp_challenges", "consumed_at", "id = $1", iss.ID), 0)
		}},

		{[]string{"auth_tickets.expires_at", "auth_throttle.window_start"}, func(e *windowEnv) {
			f := e.f
			a := f.db.Store(f.ctx, e.t, store.RoleTenant).Auth()
			h := sha32(77)
			if _, ok, err := a.TicketPut(f.ctx, store.NewTicket{TokenHash: h, Kind: store.TicketMFA, Tenant: f.A.Tenant, User: f.A.User,
				FirstFactor: "password", Payload: []byte("p"), TTL: 5 * time.Minute}); err != nil || !ok {
				e.t.Fatal(ok, err)
			}
			e.nearDB("auth_tickets.expires_at", e.at("auth_tickets", "expires_at", "token_hash = $1", h), 5*time.Minute)
			key := sha32(78)
			if _, err := a.ThrottleHit(f.ctx, "login_net", key, 5, time.Minute); err != nil {
				e.t.Fatal(err)
			}
			e.nearDB("auth_throttle.window_start", e.at("auth_throttle", "window_start", "scope = 'login_net' AND key = $1", key), 0)
		}},

		{[]string{"sms_outbox.created_at", "sms_outbox.claimed_until", "sms_gateways.breaker_open_until", "sms_deliveries.created_at"}, func(e *windowEnv) {
			f := e.f
			gw := uuid.MustParse("00000000-0000-7000-8000-0000000000f1")
			oid := uuid.New()
			f.global(e.t, f.db.Store(f.ctx, e.t, store.RoleAdmin), func(g store.GlobalTx) {
				if err := g.SMSOutboxInsert(store.NewOutbox{ID: oid, Kind: "test", GatewayID: gw, Phone: "+989121110009", TemplateKey: "otp", Locale: "fa", ParamsCT: []byte("ct")}); err != nil {
					e.t.Fatal(err)
				}
			})
			w := f.db.Store(f.ctx, e.t, store.RoleWorker)
			f.global(e.t, w, func(g store.GlobalTx) {
				got, err := g.OutboxClaim(5)
				if err != nil || len(got) == 0 {
					e.t.Fatalf("OutboxClaim: %v %v", got, err)
				}
				for i := 0; i < 3; i++ {
					if _, err := g.GatewayFailed(gw, word("transient"), true); err != nil {
						e.t.Fatal(err)
					}
				}
				if err := g.DeliveryRecord(store.SMSDelivery{Source: "outbox", SourceID: oid, GatewayID: gw, Provider: "noop", TemplateKey: "otp", Outcome: "accepted"}); err != nil {
					e.t.Fatal(err)
				}
				open, err := g.WorkerGateways()
				if err != nil {
					e.t.Fatal(err)
				}
				for _, o := range open {
					if o.ID == gw && (o.BreakerOpenFor <= 0 || o.BreakerOpenFor > time.Minute+time.Second) {
						e.t.Errorf("the breaker stays open for %v, want up to a minute measured by the database", o.BreakerOpenFor)
					}
				}
			})
			e.nearDB("sms_outbox.created_at", e.at("sms_outbox", "created_at", "id = $1", oid), 0)
			e.nearDB("sms_outbox.claimed_until", e.at("sms_outbox", "claimed_until", "id = $1", oid), 20*time.Second)
			e.nearDB("sms_gateways.breaker_open_until", e.at("sms_gateways", "breaker_open_until", "id = $1", gw), time.Minute)
			e.nearDB("sms_deliveries.created_at", e.at("sms_deliveries", "created_at", "source_id = $1", oid), 0)
		}},

		// A Disable ends at the time Go stamps, which is the application clock; the node compares it with its own.
		{[]string{"profiles.disabled_until"}, func(e *windowEnv) {
			f, s := e.f, e.f.db.Store(e.f.ctx, e.t, store.RoleTenant)
			until := e.app(time.Hour)
			f.inTenant(e.t, s, f.A.Tenant, func(tx store.Tx) {
				pw, w, err := tx.ProfileGuard(f.A.Profile)
				if err != nil || !w.Yes() {
					e.t.Fatal(w.Yes(), err)
				}
				if err := tx.ProfileDisable(pw, &until); err != nil {
					e.t.Fatal(err)
				}
			})
			e.sameInstant("profiles.disabled_until", e.at("profiles", "disabled_until", "id = $1", f.A.Profile), until)
		}},

		{[]string{"tenant_audit_log.at"}, func(e *windowEnv) {
			f, s := e.f, e.f.db.Store(e.f.ctx, e.t, store.RoleTenant)
			f.inTenant(e.t, s, f.A.Tenant, func(tx store.Tx) {
				if err := tx.AuditAdd(store.TenantAudit{UserID: f.A.User, Action: "clock.test"}); err != nil {
					e.t.Fatal(err)
				}
			})
			e.nearDB("tenant_audit_log.at", e.at("tenant_audit_log", "at", "action = 'clock.test' AND tenant_id = $1", f.A.Tenant), 0)
		}},

		// The expiry of the two kinds of link is written by Go from the application clock and decided by the consume statements of
		// P3 7.1 against an application time passed as a parameter. Here it goes through the writers of the store and back through
		// the consume, one second either side of the expiry; a database now() would be three hours off.
		{[]string{"profile_download_tokens.expires_at", "setup_share_tokens.expires_at"}, func(e *windowEnv) {
			f, s := e.f, e.f.db.Store(e.f.ctx, e.t, store.RoleTenant)
			until := e.app(time.Hour)
			shareID, downID := uuid.New(), uuid.New()
			f.inTenant(e.t, s, f.A.Tenant, func(tx store.Tx) {
				if _, err := tx.EndpointsLock([]uuid.UUID{f.A.Endpoint}); err != nil {
					e.t.Fatal(err)
				}
				if w, err := tx.ShareLinkInsert(store.ShareLinkNew{ID: shareID, Endpoint: f.A.Endpoint, Hash: []byte("clock-share"), Expires: until, Now: e.app(0)}); err != nil || !w.Yes() {
					e.t.Fatalf("share link insert: %v", err)
				}
				if err := tx.DownloadLinkInsertVia(store.DownloadLinkNew{ID: downID, Endpoint: f.A.Endpoint, Params: []byte(`{}`), ParamsHash: []byte{1},
					Hash: []byte("clock-down"), Expires: until, Via: shareID}); err != nil {
					e.t.Fatal(err)
				}
			})
			e.sameInstant("setup_share_tokens.expires_at", e.at("setup_share_tokens", "expires_at", "id = $1", shareID), until)
			e.sameInstant("profile_download_tokens.expires_at", e.at("profile_download_tokens", "expires_at", "id = $1", downID), until)
			for d, live := range map[time.Duration]bool{time.Hour - time.Second: true, time.Hour + time.Second: false} {
				var shareWon, downWon bool
				f.inTenant(e.t, s, f.A.Tenant, func(tx store.Tx) {
					if _, err := tx.EndpointsLock([]uuid.UUID{f.A.Endpoint}); err != nil {
						e.t.Fatal(err)
					}
					_, w, err := tx.ShareLinkConsume(shareID, f.A.Endpoint, e.app(d))
					if err != nil {
						e.t.Fatal(err)
					}
					shareWon = w.Yes()
					_, w2, err := tx.DownloadLinkConsume(downID, f.A.Endpoint, e.app(d))
					if err != nil {
						e.t.Fatal(err)
					}
					downWon = w2.Yes()
				})
				if shareWon != live || downWon != live {
					e.t.Errorf("a use at %v: share %v, download %v, want %v", d, shareWon, downWon, live)
				}
			}
		}},

		// The expiry of an API token is written by Go from the application clock too (P3 2.2 item 12, 6.2), and so is the time of its
		// last use (6.3 step 7). The row is written here with an application time and read back, and the comparison of 6.3 is run with
		// a parameter one second either side of it; the touch of a request made with the token is run through the store at three
		// application times, one at the start, one inside ten minutes of it and one after.
		{[]string{"api_tokens.expires_at", "api_tokens.last_used_at"}, func(e *windowEnv) {
			f := e.f
			until := e.app(time.Hour)
			var token uuid.UUID
			if err := e.super.QueryRow(f.ctx, `INSERT INTO ctrlz.api_tokens (tenant_id, user_id, name, kind, token_hash, token_prefix, expires_at)
				VALUES ($1, $2, 'clock', 'read', '\x7a03'::bytea, 'czt_c', $3) RETURNING id`, f.A.Tenant, f.A.User, until).Scan(&token); err != nil {
				e.t.Fatal(err)
			}
			e.sameInstant("api_tokens.expires_at", e.at("api_tokens", "expires_at", "token_hash = '\\x7a03'::bytea"), until)
			for d, live := range map[time.Duration]bool{time.Hour - time.Second: true, time.Hour + time.Second: false} {
				var n int
				if err := e.super.QueryRow(f.ctx, "SELECT count(*) FROM ctrlz.api_tokens WHERE id = $1 AND expires_at > $2", token, e.app(d)).Scan(&n); err != nil {
					e.t.Fatal(err)
				}
				if (n == 1) != live {
					e.t.Errorf("api_tokens live at %v = %v, want %v", d, n == 1, live)
				}
			}
			tenant := f.db.Store(f.ctx, e.t, store.RoleTenant)
			use := func(at time.Time) {
				if err := tenant.TouchAPIToken(f.ctx, f.A.Tenant, token, at); err != nil {
					e.t.Fatal(err)
				}
			}
			first := e.app(0)
			use(first)
			e.sameInstant("api_tokens.last_used_at at the first use", e.at("api_tokens", "last_used_at", "id = $1", token), first)
			use(first.Add(9 * time.Minute))
			e.sameInstant("api_tokens.last_used_at after a use inside ten minutes", e.at("api_tokens", "last_used_at", "id = $1", token), first)
			later := first.Add(11 * time.Minute)
			use(later)
			e.sameInstant("api_tokens.last_used_at after a use past ten minutes", e.at("api_tokens", "last_used_at", "id = $1", token), later)
		}},
	}
}

func TestClockWindows(t *testing.T) {
	reg, err := clockrule.Load()
	if err != nil {
		t.Fatal(err)
	}
	cases := windowCases()
	// Every window of the registry has a case, and a case names only windows.
	windows := map[string]bool{}
	for _, w := range reg.Windows() {
		windows[w] = true
	}
	covered := map[string]bool{}
	for _, c := range cases {
		for _, col := range c.covers {
			if !windows[col] {
				t.Errorf("a case covers %s, which is not an app or db column of clocks.yaml", col)
			}
			covered[col] = true
		}
	}
	var missing []string
	for w := range windows {
		if !covered[w] {
			missing = append(missing, w)
		}
	}
	sort.Strings(missing)
	for _, w := range missing {
		t.Errorf("clocks.yaml lists %s as a window and no case moves the clock for it; add one to windowCases", w)
	}
	if t.Failed() {
		return
	}

	for name, skew := range skews {
		for _, c := range cases {
			t.Run(name+"/"+c.covers[0], func(t *testing.T) {
				f := newFixture(t)
				super := f.superConn(t)
				var dbNow time.Time
				if err := super.QueryRow(context.Background(), "SELECT pg_catalog.now()").Scan(&dbNow); err != nil {
					t.Fatal(err)
				}
				dbNow = dbNow.Truncate(time.Microsecond)
				c.run(&windowEnv{f: f, t: t, db: dbNow, super: super, app: func(d time.Duration) time.Time { return dbNow.Add(skew + d) }})
			})
		}
	}
}

// TestClockWindowTestsExist checks the list of tests that carry a window past the
// store: each file holds the test it names, and each column is a window.
func TestClockWindowTestsExist(t *testing.T) {
	reg, err := clockrule.Load()
	if err != nil {
		t.Fatal(err)
	}
	windows := map[string]bool{}
	for _, w := range reg.Windows() {
		windows[w] = true
	}
	for ref, cols := range clockWindowTests {
		file, name, _ := strings.Cut(ref, ":")
		src, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(file)))
		if err != nil {
			t.Errorf("%s: %v", ref, err)
			continue
		}
		if !strings.Contains(string(src), "func "+name+"(t *testing.T)") {
			t.Errorf("%s: the test does not exist", ref)
		}
		for _, c := range cols {
			if !windows[c] {
				t.Errorf("%s: %s is not an app or db column of clocks.yaml", ref, c)
			}
		}
	}
}
