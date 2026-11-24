package store_test

import (
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// errRolledBack ends a transaction the test only wanted to read the effect of.
var errRolledBack = errors.New("rolled back on purpose")

// liveCase is one session of the matrix: a state of the session against a state of its refresh token.
type liveCase struct {
	name    string
	user    uuid.UUID
	session uuid.UUID
	live    bool
	created time.Time
}

// TestTheLiveRuleIsTheSameForTheCapTheListTheCountAndTheRefresh is question 17 (spec 3.3, primitives-r19-2): one rule
// of what a live session is, asked by four statements, so a session the list shows is a session the cap counts, the
// ended-sessions count includes and a refresh can bring back. Every state of a session is met with every state of its
// refresh token, for two tenants at once. The expected answer is written here from the words of the spec, not read
// from the SQL: not revoked, inside the absolute limit, and either inside the idle limit or holding a refresh token
// of its own that is not rotated, not revoked and not past its expiry.
func TestTheLiveRuleIsTheSameForTheCapTheListTheCountAndTheRefresh(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleTenant)
	super := f.superConn(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	h := time.Hour

	sessionStates := []struct {
		name      string
		idle, abs time.Duration // from now
		revoked   bool
	}{
		{"inside idle", +h, +5 * h, false},
		{"past idle", -h, +5 * h, false},
		{"past absolute", -2 * h, -h, false},
		{"revoked inside idle", +h, +5 * h, true},
		{"revoked past idle", -h, +5 * h, true},
	}
	refreshStates := []string{"none", "usable", "rotated", "revoked", "expired", "another session"}

	// plant fills one tenant with the whole matrix plus a plain live holder session, and returns the cases.
	plant := func(tenant, user uuid.UUID, tag string) []liveCase {
		t.Helper()
		var out []liveCase
		start := now.Add(-10 * h)
		n := 0
		insertSession := func(label string, idle, abs time.Duration, revoked bool) (uuid.UUID, time.Time) {
			n++
			id := uuid.Must(uuid.NewV7())
			created := start.Add(time.Duration(n) * time.Minute)
			var revokedAt any
			if revoked {
				revokedAt = now.Add(-30 * time.Minute)
			}
			if _, err := super.Exec(f.ctx, `INSERT INTO ctrlz.sessions (id, tenant_id, user_id, token_hash, idle_expires_at, absolute_expires_at, revoked_at, created_at, remember_me)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true)`, id, tenant, user, []byte(fmt.Sprintf("%s-%s-%d", tag, label, n)), now.Add(idle), now.Add(abs), revokedAt, created); err != nil {
				t.Fatalf("session %s: %v", label, err)
			}
			return id, created
		}
		insertRefresh := func(session uuid.UUID, label, state string) {
			n++
			expires, rotated, revoked := now.Add(5*h), any(nil), any(nil)
			switch state {
			case "rotated":
				rotated = now.Add(-time.Minute)
			case "revoked":
				revoked = now.Add(-time.Minute)
			case "expired":
				expires = now.Add(-time.Minute)
			}
			if _, err := super.Exec(f.ctx, `INSERT INTO ctrlz.refresh_tokens (tenant_id, user_id, session_id, family_id, token_hash, expires_at, rotated_at, revoked_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, tenant, user, session, uuid.New(), []byte(fmt.Sprintf("r-%s-%s-%d", tag, label, n)), expires, rotated, revoked); err != nil {
				t.Fatalf("refresh %s: %v", label, err)
			}
		}
		// The holder of the token that "another session" points at: live on its own account, and the only session
		// in the tenant that has a usable token the matrix sessions do not own.
		holder, holderAt := insertSession("holder", +h, +5*h, false)
		insertRefresh(holder, "holder", "usable")
		out = append(out, liveCase{name: tag + "/holder", user: user, session: holder, live: true, created: holderAt})
		for _, ss := range sessionStates {
			for _, rs := range refreshStates {
				id, at := insertSession(ss.name+"/"+rs, ss.idle, ss.abs, ss.revoked)
				switch rs {
				case "none":
				case "another session":
					// The usable token is the holder's: it must not revive this one.
				default:
					insertRefresh(id, ss.name+"/"+rs, rs)
				}
				open := !ss.revoked && ss.abs > 0
				live := open && (ss.idle > 0 || rs == "usable")
				out = append(out, liveCase{name: tag + "/" + ss.name + "/" + rs, user: user, session: id, live: live, created: at})
			}
		}
		return out
	}
	// Each tenant also holds the session its seed made (live, inside its idle limit), which the matrix did not.
	// Read before the matrix is planted: afterwards a tenant holds many sessions and there is no one "the" seeded row.
	seed := map[uuid.UUID]uuid.UUID{f.A.Tenant: f.seededSession(t, super, f.A.Tenant), f.B.Tenant: f.seededSession(t, super, f.B.Tenant)}
	aCases := plant(f.A.Tenant, f.A.User, "a")
	bCases := plant(f.B.Tenant, f.B.User, "b")

	ids := func(cs []liveCase, keep func(liveCase) bool) []uuid.UUID {
		var out []uuid.UUID
		for _, c := range cs {
			if keep(c) {
				out = append(out, c.session)
			}
		}
		return out
	}
	set := func(v []uuid.UUID) string {
		var out []string
		for _, id := range v {
			out = append(out, id.String())
		}
		sort.Strings(out)
		return fmt.Sprint(out)
	}

	for _, tc := range []struct {
		who          string
		tenant, user uuid.UUID
		cases        []liveCase
		other        []liveCase // the other tenant's sessions
	}{{"A", f.A.Tenant, f.A.User, aCases, bCases}, {"B", f.B.Tenant, f.B.User, bCases, aCases}} {
		wantLive := ids(tc.cases, func(c liveCase) bool { return c.live })
		wantLive = append(wantLive, seed[tc.tenant]) // the seed's session: inside its idle limit

		f.inTenant(t, s, tc.tenant, func(tx store.Tx) {
			// The list.
			rows, err := tx.SessionsList(tc.user, now)
			if err != nil {
				t.Fatal(err)
			}
			var listed []uuid.UUID
			for _, r := range rows {
				listed = append(listed, r.ID)
			}
			if set(listed) != set(wantLive) {
				t.Errorf("%s: the list shows\n%s\nwant the live sessions\n%s", tc.who, set(listed), set(wantLive))
			}
			// The refresh's own question, one session at a time.
			for _, c := range tc.cases {
				got, err := tx.SessionLive(c.session, now)
				if err != nil {
					t.Fatal(err)
				}
				if got != c.live {
					t.Errorf("SessionLive(%s) = %v, want %v", c.name, got, c.live)
				}
			}
			// A session of the other tenant is nobody's here, whatever its state.
			for _, c := range tc.other {
				if got, err := tx.SessionLive(c.session, now); err != nil || got {
					t.Errorf("tenant %s asked about the session %s of the other tenant: %v %v", tc.who, c.name, got, err)
				}
			}
		})

		// The count of the ended-sessions answer: every live session but the one kept, then rolled back.
		var count int
		err := s.WithTenant(f.ctx, tc.tenant, store.TxOpts{}, func(tx store.Tx) error {
			n, err := tx.SessionsRevokeOthers(tc.user, uuid.Nil, now)
			count = n
			if err != nil {
				return err
			}
			return errRolledBack
		})
		if !errors.Is(err, errRolledBack) {
			t.Fatalf("%s: SessionsRevokeOthers: %v", tc.who, err)
		}
		if count != len(wantLive) {
			t.Errorf("%s: ended_sessions = %d, want the %d live sessions", tc.who, count, len(wantLive))
		}

		// The cap: keep one, and the sessions it ends are every live one but the newest of them (created_at order). The
		// seeded session was made when the fixture was, long after the matrix's hours, so it is the newest and stays.
		wantEnded := ids(tc.cases, func(c liveCase) bool { return c.live })
		var ended []uuid.UUID
		err = s.WithTenant(f.ctx, tc.tenant, store.TxOpts{}, func(tx store.Tx) error {
			var err error
			ended, err = tx.SessionsTrim(tc.user, 1, now)
			if err != nil {
				return err
			}
			return errRolledBack
		})
		if !errors.Is(err, errRolledBack) {
			t.Fatalf("%s: SessionsTrim: %v", tc.who, err)
		}
		if set(ended) != set(wantEnded) {
			t.Errorf("%s: the cap ends\n%s\nwant\n%s", tc.who, set(ended), set(wantEnded))
		}
	}
}
