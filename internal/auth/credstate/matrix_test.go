package credstate_test

import (
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/admincli"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/credstate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The coverage test of the one-time-state rule: every operation of both OpenAPI
// documents and every command of ctrlz-admin, against every credential state, compared
// with the table. An operation with no row fails, so a route added tomorrow is covered by
// its class (which the OpenAPI document must give it) or it fails until somebody decides.
// And the gates that run the request pipeline are driven for each pair, so a gate that
// forgets to ask the table, or asks it with the wrong state, differs from the table here.

func operations(t *testing.T) (tenant, admin []apispec.Operation) {
	t.Helper()
	tenant, err := apispec.Parse(api.Tenant(), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	admin, err = apispec.Parse(api.Admin(), ratelimit.Admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(tenant) < 40 || len(admin) < 30 {
		t.Fatalf("the documents gave %d and %d operations", len(tenant), len(admin))
	}
	return tenant, admin
}

// aspectOf strips the "/aspect" of a second decision inside one operation.
func aspectOf(name string) string { return strings.SplitN(name, "/", 2)[0] }

func TestEveryOperationHasARow(t *testing.T) {
	tenantOps, adminOps := operations(t)
	var missing []string
	for realm, ops := range map[credstate.Realm][]apispec.Operation{credstate.Tenant: tenantOps, credstate.Admin: adminOps} {
		for _, op := range ops {
			for _, st := range credstate.States() {
				if _, found := credstate.Resolve(realm, op.ID, op.Auth, st); !found {
					missing = append(missing, realm.String()+" "+op.ID+" ("+string(op.Auth)+") in "+st.String())
				}
			}
		}
	}
	// The command line.
	for _, cmd := range admincli.Commands() {
		for _, st := range credstate.States() {
			if _, found := credstate.Resolve(credstate.CLI, cmd, "", st); !found {
				missing = append(missing, "cli "+cmd+" in "+st.String())
			}
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("no row of the credential-state table covers %s: give the operation a class in its OpenAPI document that the table knows, or a named row in internal/auth/credstate", m)
	}
}

// TestNamedRowsNameRealOperations fails for a row that outlived its operation or that says
// a class the document does not give.
func TestNamedRowsNameRealOperations(t *testing.T) {
	tenantOps, adminOps := operations(t)
	for realm, ops := range map[credstate.Realm][]apispec.Operation{credstate.Tenant: tenantOps, credstate.Admin: adminOps} {
		byID := map[string]apispec.Auth{}
		for _, op := range ops {
			byID[op.ID] = op.Auth
		}
		for name, class := range credstate.NamedOperations(realm) {
			got, ok := byID[aspectOf(name)]
			if !ok {
				t.Errorf("%s row %q names no operation of the OpenAPI document", realm, name)
			} else if got != class {
				t.Errorf("%s row %q says class %q, the document says %q", realm, name, class, got)
			}
		}
	}
	cmds := map[string]bool{}
	for _, c := range admincli.Commands() {
		cmds[c] = true
	}
	for name := range credstate.NamedOperations(credstate.CLI) {
		if !cmds[name] {
			t.Errorf("cli row %q names no command of ctrlz-admin", name)
		}
	}
}

// TestTableInvariants pins what the table must keep saying whatever is added to it.
func TestTableInvariants(t *testing.T) {
	tenantOps, adminOps := operations(t)
	// A tenant session under a one-time password, live or expired, reaches no route that
	// is not a setup route (3.5); a user is never "chosen without second factor".
	for _, op := range tenantOps {
		for _, st := range []credstate.State{credstate.OneTimeLive, credstate.OneTimeExpired} {
			if op.Auth == apispec.Session || op.Auth == apispec.Reauth {
				if v := credstate.Class(credstate.Tenant, op.Auth, st); v.Permits() {
					t.Errorf("%s (%s) is open to a restricted session in %s: %s", op.ID, op.Auth, st, v)
				}
			}
		}
		if op.Auth == apispec.Reauth {
			if v := credstate.Class(credstate.Tenant, op.Auth, credstate.Ready); v != credstate.Fresh {
				t.Errorf("%s needs the reauth window and the table says %s", op.ID, v)
			}
		}
	}
	// An admin who is not ready reaches the setup routes and nothing else (10.3).
	for _, op := range adminOps {
		for _, st := range []credstate.State{credstate.OneTimeLive, credstate.OneTimeExpired, credstate.ChosenNoSecondFactor} {
			if op.Auth == apispec.Admin || op.Auth == apispec.AdminFresh {
				if v := credstate.Class(credstate.Admin, op.Auth, st); v.Permits() {
					t.Errorf("%s (%s) is open to an admin in %s: %s", op.ID, op.Auth, st, v)
				}
			}
			if op.Auth == apispec.AdminSetup {
				if v := credstate.Class(credstate.Admin, op.Auth, st); v != credstate.Allow {
					t.Errorf("%s is a setup route and the table says %s in %s", op.ID, v, st)
				}
			}
		}
	}
	// The zero state, and a state this build does not know, refuse everything.
	for _, c := range credstate.Classes(credstate.Tenant) {
		if c != apispec.None && credstate.Class(credstate.Tenant, c, credstate.Unknown).Permits() {
			t.Errorf("tenant class %s permits the unknown state", c)
		}
	}
	for _, c := range credstate.Classes(credstate.Admin) {
		if c != apispec.None && credstate.Class(credstate.Admin, c, credstate.Unknown).Permits() {
			t.Errorf("admin class %s permits the unknown state", c)
		}
	}
	// An expired password opens no login, whoever asks.
	for realm, name := range map[credstate.Realm]string{credstate.Tenant: "loginPassword", credstate.Admin: "adminLogin"} {
		if credstate.Named(realm, name, credstate.OneTimeExpired).Permits() {
			t.Errorf("%s lets an expired one-time password log in", name)
		}
		if !credstate.Named(realm, name, credstate.OneTimeLive).Permits() || !credstate.Named(realm, name, credstate.Ready).Permits() {
			t.Errorf("%s refuses a live one-time password or a ready account", name)
		}
	}
	// The reauth window is waived for a live one-time password only, and never past its end
	// (round 2, tenant-r2-6).
	for _, st := range credstate.States() {
		got := credstate.Named(credstate.Tenant, "changePassword", st)
		want := credstate.Fresh
		if st == credstate.OneTimeLive {
			want = credstate.FreshUnlessPassword
		}
		if st != credstate.ChosenNoSecondFactor && got != want {
			t.Errorf("changePassword in %s: %s, want %s", st, got, want)
		}
	}
	// The word of the database is closed.
	for _, st := range credstate.States() {
		back, err := credstate.Parse(st.String())
		if err != nil || back != st {
			t.Errorf("%s does not round trip: %v %v", st, back, err)
		}
	}
	for _, w := range []string{"", "unknown", "Ready", "ready ", "one_time", "live"} {
		if st, err := credstate.Parse(w); !errors.Is(err, credstate.ErrUnknown) || st != credstate.Unknown {
			t.Errorf("Parse(%q) = %v, %v", w, st, err)
		}
	}
}

// TestGatesFollowTheTable drives the real gates of the request pipeline for every
// operation of both documents in every state, and compares them with the table.
func TestGatesFollowTheTable(t *testing.T) {
	tenantOps, adminOps := operations(t)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	m := session.NewManager(nil, session.DefaultPolicy(), func() time.Time { return now })

	for _, op := range tenantOps {
		if op.Auth == apispec.None {
			continue // no session, no state
		}
		for _, st := range []credstate.State{credstate.OneTimeLive, credstate.OneTimeExpired, credstate.Ready} {
			for _, windowOpen := range []bool{false, true} {
				info := store.SessionInfo{
					TenantStatus: "active", State: st,
					IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(10 * time.Hour),
				}
				if windowOpen {
					at := now.Add(-time.Minute)
					info.ReauthAt = &at
				}
				got := m.Check(info, session.Gate{Auth: op.Auth})
				var want error
				switch credstate.Class(credstate.Tenant, op.Auth, st) {
				case credstate.Allow:
				case credstate.Fresh:
					if !windowOpen {
						want = session.ErrReauth
					}
				default:
					want = session.ErrPasswordChange
				}
				if got != want {
					t.Errorf("tenant %s (%s) in %s, window %v: gate %v, table says %v", op.ID, op.Auth, st, windowOpen, got, want)
				}
			}
		}
	}

	for _, op := range adminOps {
		if op.Auth == apispec.None {
			continue
		}
		for _, st := range credstate.States() {
			for _, checked := range []bool{false, true} {
				at := now.Add(-time.Minute)
				info := store.AdminSessionInfo{
					State: st, IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(10 * time.Hour),
				}
				if checked {
					info.TOTPVerifiedAt = &at
				}
				got := m.AdminCheck(info, op.Auth)
				var want error
				switch credstate.Class(credstate.Admin, op.Auth, st) {
				case credstate.Allow:
				case credstate.Fresh:
					if !checked {
						want = session.ErrFreshRequired
					}
				default:
					want = session.ErrSetupRequired
				}
				if got != want {
					t.Errorf("admin %s (%s) in %s, checked %v: gate %v, table says %v", op.ID, op.Auth, st, checked, got, want)
				}
			}
		}
	}
}
