package endpoints_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Shared/identity"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/locations"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

// fx is a migrated database with two seeded tenants, a store as the tenant role and the write path with a fixed clock.
type fx struct {
	ctx  context.Context
	db   *testpg.DB
	A, B catalogtest.SeedIDs
	st   *store.Store
	env  *endpoints.Env
	keys *keyring.Ring
	typ  string
	now  time.Time
}

var opts = store.TxOpts{LockWait: 5 * time.Second}

func newFx(t *testing.T) *fx {
	t.Helper()
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	db := c.NewDB(ctx, t)
	super, err := db.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(context.Background()) }()
	f := &fx{ctx: ctx, db: db, A: catalogtest.NewSeedIDs(1), B: catalogtest.NewSeedIDs(2), now: time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)}
	if err := catalogtest.SeedGlobal(ctx, super); err != nil {
		t.Fatal(err)
	}
	for _, ids := range []catalogtest.SeedIDs{f.A, f.B} {
		if err := catalogtest.SeedTenant(ctx, super, ids); err != nil {
			t.Fatal(err)
		}
	}
	f.exec(t, `DELETE FROM ctrlz.batch_jobs`)
	f.exec(t, `INSERT INTO ctrlz.locations (id, wire_id, country_code, city, label) VALUES ('00000000-0000-7000-8000-00000000d102', 102, 'NL', NULL, 'Amsterdam');
INSERT INTO ctrlz.location_availability (node_id, location_id) SELECT n.id, '00000000-0000-7000-8000-00000000d102' FROM ctrlz.nodes n`)
	f.st = db.Store(ctx, t, store.RoleTenant)
	if f.keys, err = keyring.NewEphemeral(keyring.DomainDOHToken); err != nil {
		t.Fatal(err)
	}
	f.env = &endpoints.Env{Clock: appclock.Func(func() time.Time { return f.now }), Keys: f.keys, Catalog: locations.Store{}}
	if err := db.Scan(ctx, `SELECT key FROM ctrlz.endpoint_types ORDER BY position LIMIT 1`, nil, &f.typ); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fx) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := f.db.Exec(f.ctx, sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (f *fx) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.db.Scan(f.ctx, sql, args, &n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (f *fx) scan(t *testing.T, sql string, args []any, dest ...any) {
	t.Helper()
	if err := f.db.Scan(f.ctx, sql, args, dest...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (f *fx) newProfile(t *testing.T, tenant uuid.UUID, name string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	f.exec(t, `INSERT INTO ctrlz.profiles (tenant_id, id, name) VALUES ($1, $2, $3)`, tenant, id, name)
	return id
}

func (f *fx) lock(t *testing.T, profile uuid.UUID) {
	t.Helper()
	f.exec(t, `UPDATE ctrlz.profiles SET lock_state = 'locked', lock_password_hash = 'h-ok' WHERE id = $1`, profile)
}

// fakeVerifier accepts one password, and records what it was asked.
type fakeVerifier struct {
	right string
	// wrongFor is a profile whose password is refused whatever is sent.
	wrongFor uuid.UUID
	calls    []uuid.UUID
	failed   []uuid.UUID
	used     []uuid.UUID
	accepted []uuid.UUID
	// onCheck runs inside a password check, which is where the rows of a real request can change under it.
	onCheck func()
}

func (v *fakeVerifier) CheckLockPassword(_ context.Context, profile uuid.UUID, pw, _ secret.String) (bool, error) {
	if v.onCheck != nil {
		v.onCheck()
	}
	v.calls = append(v.calls, profile)
	return profile != v.wrongFor && pw.Reveal() == v.right, nil
}

func (v *fakeVerifier) LockPasswordFailed(_ context.Context, profile, _ uuid.UUID) error {
	v.failed = append(v.failed, profile)
	return nil
}

func (v *fakeVerifier) LockPasswordUsed(_ context.Context, profile, _ uuid.UUID) error {
	v.used = append(v.used, profile)
	return nil
}

func (v *fakeVerifier) LockPasswordsAccepted(_ context.Context, profiles []uuid.UUID) {
	v.accepted = append(v.accepted, profiles...)
}

func (f *fx) auth(tenant uuid.UUID, v *fakeVerifier, pws ...endpoints.Password) endpoints.Auth {
	user := f.A.User
	if tenant == f.B.Tenant {
		user = f.B.User
	}
	return endpoints.Auth{Passwords: pws, Actor: endpoints.Actor{User: user}, Verifier: v}
}

func pw(profile uuid.UUID, text string) endpoints.Password {
	return endpoints.Password{Profile: profile, Secret: secret.New(text)}
}

func (f *fx) create(t *testing.T, tenant, profile uuid.UUID, names ...string) []store.EndpointRow {
	t.Helper()
	rows, err := f.env.Create(f.ctx, f.st, tenant, opts, endpoints.CreateIn{Type: f.typ, Names: names, ProfileID: profile})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// refusal fails the test unless err is a refusal of the write path, and returns it.
func refusal(t *testing.T, err error) *endpoints.Error {
	t.Helper()
	var e *endpoints.Error
	if !errors.As(err, &e) {
		t.Fatalf("want a refusal, got %v", err)
	}
	return e
}

func hasField(e *endpoints.Error, name, code string) bool {
	for _, x := range e.Fields {
		if x.Name == name && x.Code == code {
			return true
		}
	}
	return false
}

func (f *fx) outbox(t *testing.T, tenant uuid.UUID) int {
	return f.count(t, `SELECT count(*) FROM ctrlz.policy_outbox WHERE tenant_id = $1 AND aggregate_type = 'endpoint_set'`, tenant)
}

func (f *fx) endpointsOf(t *testing.T, tenant uuid.UUID) int {
	return f.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE tenant_id = $1`, tenant)
}

func TestCreateMakesOneEndpointPerNameWithItsOwnCredential(t *testing.T) {
	f := newFx(t)
	bBefore := f.endpointsOf(t, f.B.Tenant)
	f.exec(t, `DELETE FROM ctrlz.policy_outbox`)
	rows := f.create(t, f.A.Tenant, f.A.Profile, "one", "two", "three")
	if len(rows) != 3 {
		t.Fatalf("%d rows", len(rows))
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if !identity.ValidResolverID(r.ResolverID) || seen[r.ResolverID] {
			t.Errorf("resolver id %q is invalid or repeated", r.ResolverID)
		}
		seen[r.ResolverID] = true
		var ct, hash []byte
		f.scan(t, `SELECT doh_token_ct, doh_token_hash FROM ctrlz.endpoints WHERE id = $1`, []any{r.ID}, &ct, &hash)
		tok, err := f.keys.Open(keyring.DomainDOHToken, endpoints.TokenAAD(r.ID), ct)
		if err != nil {
			t.Fatalf("the sealed token does not open under its Endpoint's id: %v", err)
		}
		if !identity.ValidDoHToken(string(tok.Reveal())) {
			t.Error("the token is not a DoH token")
		}
		h := identity.TokenHash(string(tok.Reveal()))
		if !bytes.Equal(h[:], hash) {
			t.Error("the stored hash is not the hash of the sealed token")
		}
		// Opened under another Endpoint's id, the same ciphertext is refused.
		if _, err := f.keys.Open(keyring.DomainDOHToken, endpoints.TokenAAD(uuid.New()), ct); err == nil {
			t.Error("a token opened under the wrong Endpoint")
		}
	}
	if n := f.outbox(t, f.A.Tenant); n != 1 {
		t.Errorf("%d endpoint_set rows for three Endpoints, want one", n)
	}
	if f.endpointsOf(t, f.B.Tenant) != bBefore {
		t.Error("tenant B's Endpoints changed")
	}
}

func TestCreateRefusals(t *testing.T) {
	f := newFx(t)
	before := f.endpointsOf(t, f.A.Tenant)
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_endpoints = $2 WHERE tenant_id = $1`, f.A.Tenant, before+1)
	_, err := f.env.Create(f.ctx, f.st, f.A.Tenant, opts, endpoints.CreateIn{Type: f.typ, Names: []string{"x", "y"}, ProfileID: f.A.Profile})
	if e := refusal(t, err); !hasField(e, "max_endpoints", endpoints.CodeExceeded) {
		t.Errorf("over the cap: %v", e)
	}
	if f.endpointsOf(t, f.A.Tenant) != before {
		t.Error("a request over the cap wrote an Endpoint")
	}
	// B's profile is not A's.
	_, err = f.env.Create(f.ctx, f.st, f.A.Tenant, opts, endpoints.CreateIn{Type: f.typ, Names: []string{"x"}, ProfileID: f.B.Profile})
	if e := refusal(t, err); e.Kind != endpoints.KindNotFound {
		t.Errorf("another tenant's profile: %v", e)
	}
	_, err = f.env.Create(f.ctx, f.st, f.A.Tenant, opts, endpoints.CreateIn{Type: "no-such-type", Names: []string{"x"}, ProfileID: f.A.Profile})
	if e := refusal(t, err); !hasField(e, "/type", endpoints.CodeUnknown) {
		t.Errorf("unknown type: %v", e)
	}
}

// E2 at the database: a change marks the endpoint_set exactly when a compiled column moved.
func TestPatchMarksOnlyWhatCompiles(t *testing.T) {
	f := newFx(t)
	ep := f.create(t, f.A.Tenant, f.A.Profile, "e")[0]
	v := &fakeVerifier{}
	patch := func(p endpoints.Patch) {
		t.Helper()
		f.exec(t, `DELETE FROM ctrlz.policy_outbox`)
		if _, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v), ep.ID, p); err != nil {
			t.Fatal(err)
		}
	}
	name, comment, yes := "renamed", "a note", true
	patch(endpoints.Patch{Name: &name, Comment: &comment, AuthorizeDDNS: &yes, PreventDeactivation: &yes})
	if n := f.outbox(t, f.A.Tenant); n != 0 {
		t.Errorf("a change of columns that do not compile marked %d rows", n)
	}
	patch(endpoints.Patch{LegacyDNS: &yes})
	if n := f.outbox(t, f.A.Tenant); n != 1 {
		t.Errorf("a change of Legacy DNS marked %d rows", n)
	}
	patch(endpoints.Patch{LegacyDNS: &yes})
	if n := f.outbox(t, f.A.Tenant); n != 0 {
		t.Errorf("setting a column to the value it has marked %d rows", n)
	}
}

func TestAnotherTenantsRowsAreNotFound(t *testing.T) {
	f := newFx(t)
	own := f.create(t, f.A.Tenant, f.A.Profile, "own")[0]
	bEp := f.create(t, f.B.Tenant, f.B.Profile, "theirs")[0]
	v := &fakeVerifier{}
	a := f.auth(f.A.Tenant, v)
	name := "x"
	if _, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, a, bEp.ID, endpoints.Patch{Name: &name}); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("patch of another tenant's Endpoint")
	}
	other := f.B.Profile
	if _, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, a, own.ID, endpoints.Patch{ProfileID: &other}); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("patch to another tenant's profile")
	}
	if err := f.env.Delete(f.ctx, f.st, f.A.Tenant, opts, a, []uuid.UUID{bEp.ID}); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("delete of another tenant's Endpoint")
	}
	if _, err := f.env.Rotate(f.ctx, f.st, f.A.Tenant, opts, a, bEp.ID); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("rotate of another tenant's Endpoint")
	}
	if _, err := f.env.SetSchedule(f.ctx, f.st, f.A.Tenant, opts, a, bEp.ID, endpoints.ScheduleIn{Timezone: "UTC"}); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("schedule of another tenant's Endpoint")
	}
	if _, err := f.env.CreateClient(f.ctx, f.st, f.A.Tenant, opts, a, bEp.ID, endpoints.ClientCreate{Alias: "x"}); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("client on another tenant's Endpoint")
	}
	// A password for a profile that is not the tenant's is refused before anything is charged.
	a.Passwords = []endpoints.Password{pw(f.B.Profile, "whatever")}
	if _, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, a, own.ID, endpoints.Patch{Name: &name}); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("a password for another tenant's profile")
	}
	if len(v.calls) != 0 {
		t.Error("a password was verified")
	}
	if f.endpointsOf(t, f.B.Tenant) != 2 { // the seeded one and theirs
		t.Error("tenant B's Endpoints changed")
	}
}

func TestDeleteHeldAndMissing(t *testing.T) {
	f := newFx(t)
	rows := f.create(t, f.A.Tenant, f.A.Profile, "free", "held")
	f.exec(t, `UPDATE ctrlz.endpoints SET admin_hold = true WHERE id = $1`, rows[1].ID)
	// A client of the free Endpoint goes with it.
	if _, err := f.env.CreateClient(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, &fakeVerifier{}), rows[0].ID, endpoints.ClientCreate{Alias: "kid"}); err != nil {
		t.Fatal(err)
	}
	before := f.endpointsOf(t, f.A.Tenant)
	err := f.env.Delete(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, &fakeVerifier{}), []uuid.UUID{rows[0].ID, rows[1].ID})
	e := refusal(t, err)
	if e.Kind != endpoints.KindHeld || !hasField(e, "/ids/1", endpoints.CodeInvalid) {
		t.Errorf("a held Endpoint: %v", e)
	}
	if f.endpointsOf(t, f.A.Tenant) != before {
		t.Error("a request with a held Endpoint deleted another one")
	}
	if err := f.env.Delete(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, &fakeVerifier{}), []uuid.UUID{rows[0].ID}); err != nil {
		t.Fatal(err)
	}
	if f.count(t, `SELECT count(*) FROM ctrlz.clients WHERE endpoint_id = $1`, rows[0].ID) != 0 {
		t.Error("the clients of a deleted Endpoint stayed")
	}
	if e := refusal(t, f.env.Delete(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, &fakeVerifier{}), []uuid.UUID{uuid.New()})); e.Kind != endpoints.KindNotFound {
		t.Errorf("a missing id: %v", e)
	}
}

func TestLockPasswords(t *testing.T) {
	f := newFx(t)
	p1 := f.newProfile(t, f.A.Tenant, "locked")
	ep := f.create(t, f.A.Tenant, p1, "guarded")[0]
	f.lock(t, p1)
	v := &fakeVerifier{right: "right-password"}
	soft := "soft_disabled"
	state := func() string {
		var s string
		f.scan(t, `SELECT admin_state FROM ctrlz.endpoints WHERE id = $1`, []any{ep.ID}, &s)
		return s
	}

	// A change that removes nothing needs no password, however locked the profile is.
	name := "renamed"
	if _, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v), ep.ID, endpoints.Patch{Name: &name}); err != nil {
		t.Fatal(err)
	}
	// Putting a locked profile on a new Endpoint adds it: nothing to verify.
	if _, err := f.env.Create(f.ctx, f.st, f.A.Tenant, opts, endpoints.CreateIn{Type: f.typ, Names: []string{"second"}, ProfileID: p1}); err != nil {
		t.Fatal(err)
	}
	if len(v.calls) != 0 {
		t.Fatal("a password was verified for a change that needs none")
	}

	// Switching it off needs the password, and a request with none charges nothing.
	_, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v), ep.ID, endpoints.Patch{AdminState: &soft})
	if e := refusal(t, err); e.Kind != endpoints.KindLocked || !hasField(e, "/lock_passwords", endpoints.CodeRequired) {
		t.Errorf("no password: %v", e)
	}
	if len(v.calls) != 0 || state() != "enabled" {
		t.Error("a request with no password was charged or applied")
	}
	// A wrong one is 401, recorded, and nothing is written.
	_, err = f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v, pw(p1, "wrong")), ep.ID, endpoints.Patch{AdminState: &soft})
	if e := refusal(t, err); e.Kind != endpoints.KindInvalidCredentials || !hasField(e, "/lock_passwords/0", endpoints.CodeInvalid) {
		t.Errorf("wrong password: %v", e)
	}
	if len(v.failed) != 1 || state() != "enabled" {
		t.Errorf("failed %d, state %s", len(v.failed), state())
	}
	// An API token never presents one.
	tok := f.auth(f.A.Tenant, v, pw(p1, "right-password"))
	tok.Actor.Token = true
	_, err = f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, tok, ep.ID, endpoints.Patch{AdminState: &soft})
	if e := refusal(t, err); e.Kind != endpoints.KindTokenNotAllowed {
		t.Errorf("token: %v", e)
	}
	// The right one applies, and the use is audited.
	if _, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v, pw(p1, "right-password")), ep.ID, endpoints.Patch{AdminState: &soft}); err != nil {
		t.Fatal(err)
	}
	if state() != "soft_disabled" {
		t.Error("the right password did not apply the change")
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = 'profile.lock_password_used'`, f.A.Tenant); n != 1 {
		t.Errorf("%d audit rows for the use", n)
	}
	// Rotation and delete need it too.
	if _, err := f.env.Rotate(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v), ep.ID); refusal(t, err).Kind != endpoints.KindLocked {
		t.Error("rotation without the password")
	}
	if err := f.env.Delete(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v), []uuid.UUID{ep.ID}); refusal(t, err).Kind != endpoints.KindLocked {
		t.Error("delete without the password")
	}
	if err := f.env.Delete(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v, pw(p1, "right-password")), []uuid.UUID{ep.ID}); err != nil {
		t.Fatal(err)
	}
	// More passwords than eight is refused before anything.
	many := make([]endpoints.Password, 9)
	for i := range many {
		many[i] = pw(uuid.New(), "x")
	}
	if e := refusal(t, f.env.Delete(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v, many...), []uuid.UUID{uuid.New()})); !hasField(e, "/lock_passwords", endpoints.CodeExceeded) {
		t.Errorf("nine passwords: %v", e)
	}
}

func TestScheduleReplacesWindowsAndNeedsThePasswordOfAProfileItDrops(t *testing.T) {
	f := newFx(t)
	base := f.A.Profile
	p1 := f.newProfile(t, f.A.Tenant, "window profile")
	ep := f.create(t, f.A.Tenant, base, "scheduled")[0]
	v := &fakeVerifier{right: "right-password"}
	a := f.auth(f.A.Tenant, v)
	put := func(a endpoints.Auth, ws ...endpoints.WindowIn) (endpoints.Schedule, error) {
		return f.env.SetSchedule(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, endpoints.ScheduleIn{Timezone: "Asia/Tehran", Windows: ws})
	}
	w := func(s, e int, p uuid.UUID) endpoints.WindowIn {
		return endpoints.WindowIn{Start: s, End: e, ProfileID: p}
	}

	f.exec(t, `DELETE FROM ctrlz.policy_outbox`)
	sc, err := put(a, w(60, 120, p1), w(600, 660, base))
	if err != nil || len(sc.Windows) != 2 {
		t.Fatalf("%v %+v", err, sc)
	}
	if f.outbox(t, f.A.Tenant) != 1 {
		t.Error("a new schedule did not mark")
	}
	f.lock(t, p1)
	// The same windows with their ids: nothing changes, nothing is needed, nothing is marked, and the ids stay.
	f.exec(t, `DELETE FROM ctrlz.policy_outbox`)
	again, err := put(a, endpoints.WindowIn{ID: sc.Windows[0].ID, Start: 60, End: 120, ProfileID: p1}, endpoints.WindowIn{ID: sc.Windows[1].ID, Start: 600, End: 660, ProfileID: base})
	if err != nil || again.Windows[0].ID != sc.Windows[0].ID || again.Windows[1].ID != sc.Windows[1].ID {
		t.Fatalf("the same schedule: %v %+v", err, again)
	}
	if f.outbox(t, f.A.Tenant) != 0 {
		t.Error("an unchanged schedule marked the outbox")
	}
	// Dropping the locked profile's window needs its password.
	if _, err := put(a, w(600, 660, base)); refusal(t, err).Kind != endpoints.KindLocked {
		t.Error("dropping a locked profile's window without its password")
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.schedule_windows WHERE endpoint_id = $1`, ep.ID); n != 2 {
		t.Errorf("a refused PUT left %d windows", n)
	}
	if _, err := put(f.auth(f.A.Tenant, v, pw(p1, "right-password")), w(600, 660, base)); err != nil {
		t.Fatal(err)
	}
	// The values.
	for name, ws := range map[string][]endpoints.WindowIn{
		"overlap":  {w(0, 120, base), w(60, 180, base)},
		"grid":     {w(10, 60, base)},
		"unknown":  {{ID: uuid.New(), Start: 0, End: 60, ProfileID: base}},
		"too many": make([]endpoints.WindowIn, 65),
	} {
		if _, err := put(a, ws...); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := f.env.SetSchedule(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, endpoints.ScheduleIn{Timezone: "Mars/Base"}); refusal(t, err).Fields[0].Code != endpoints.CodeUnknown {
		t.Error("an unknown zone")
	}
}

func TestClients(t *testing.T) {
	f := newFx(t)
	ep := f.create(t, f.A.Tenant, f.A.Profile, "e")[0]
	a := f.auth(f.A.Tenant, &fakeVerifier{})
	mk := func(c endpoints.ClientCreate) (store.ClientRow, error) {
		return f.env.CreateClient(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, c)
	}
	c1, err := mk(endpoints.ClientCreate{Alias: "Laptop One"})
	if err != nil || c1.Label != "laptop-one" || c1.Source != "manual" || !c1.IsCustom {
		t.Fatalf("%v %+v", err, c1)
	}
	if _, err := mk(endpoints.ClientCreate{Alias: "Laptop One"}); !hasField(refusal(t, err), "/label", endpoints.CodeExists) {
		t.Error("a repeated label")
	}
	if _, err := mk(endpoints.ClientCreate{Label: "default"}); !hasField(refusal(t, err), "/label", endpoints.CodeReserved) {
		t.Error("the default label")
	}
	// The cap counts manual clients only.
	f.exec(t, `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, source) VALUES ($1, $2, 'seen', 'auto'), ($1, $2, 'default', 'auto')`, f.A.Tenant, ep.ID)
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_clients_per_endpoint = 1 WHERE tenant_id = $1`, f.A.Tenant)
	if _, err := mk(endpoints.ClientCreate{Alias: "second"}); !hasField(refusal(t, err), "max_clients_per_endpoint", endpoints.CodeExceeded) {
		t.Error("over the per-Endpoint cap")
	}
	// Patch: a stack of its own, then back.
	p := f.A.Profile2
	got, err := f.env.PatchClient(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, c1.ID, endpoints.ClientChange{ProfileID: &p})
	if err != nil || got.ProfileID != p {
		t.Fatalf("%v %+v", err, got)
	}
	if got, err = f.env.PatchClient(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, c1.ID, endpoints.ClientChange{ClearProfile: true}); err != nil || got.ProfileID != uuid.Nil {
		t.Fatalf("%v %+v", err, got)
	}
	// A client of another Endpoint is not found, whoever's it is.
	other := f.create(t, f.A.Tenant, f.A.Profile, "other")[0]
	if _, err := f.env.PatchClient(f.ctx, f.st, f.A.Tenant, opts, a, other.ID, c1.ID, endpoints.ClientChange{}); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("a client of another Endpoint")
	}
	// The selector: inactive clients only, and `all`.
	f.exec(t, `UPDATE ctrlz.clients SET last_seen_at = $2 WHERE endpoint_id = $1 AND label = 'seen'`, ep.ID, f.now.AddDate(0, 0, -100))
	n, more, err := f.env.BatchClients(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, endpoints.ClientBatchIn{Op: "delete", InactiveDays: 30})
	if err != nil || n != 1 || more {
		t.Fatalf("inactive: %d %v %v", n, more, err)
	}
	n, _, err = f.env.BatchClients(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, endpoints.ClientBatchIn{Op: "delete", All: true})
	if err != nil || n != 2 {
		t.Fatalf("all: %d %v", n, err)
	}
	if _, _, err := f.env.BatchClients(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, endpoints.ClientBatchIn{Op: "delete"}); err == nil {
		t.Error("a batch with neither ids nor selector")
	}
}

func TestGroups(t *testing.T) {
	f := newFx(t)
	ep := f.create(t, f.A.Tenant, f.A.Profile, "e")[0]
	bEp := f.create(t, f.B.Tenant, f.B.Profile, "b")[0]
	if _, err := f.env.CreateGroup(f.ctx, f.st, f.A.Tenant, opts, "g", []uuid.UUID{bEp.ID}); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("another tenant's Endpoint in a group")
	}
	g, err := f.env.CreateGroup(f.ctx, f.st, f.A.Tenant, opts, "home", []uuid.UUID{ep.ID})
	if err != nil || g.EndpointCount != 1 {
		t.Fatalf("%v %+v", err, g)
	}
	if _, err := f.env.RenameGroup(f.ctx, f.st, f.B.Tenant, opts, g.ID, "mine now"); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("rename of another tenant's group")
	}
	if err := f.env.DeleteGroup(f.ctx, f.st, f.B.Tenant, opts, g.ID); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("delete of another tenant's group")
	}
	if err := f.env.DeleteGroup(f.ctx, f.st, f.A.Tenant, opts, g.ID); err != nil {
		t.Fatal(err)
	}
	if f.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE id = $1 AND group_id IS NULL`, ep.ID) != 1 {
		t.Error("the Endpoint kept a deleted group")
	}
	// The cap.
	have := f.count(t, `SELECT count(*) FROM ctrlz.endpoint_groups WHERE tenant_id = $1`, f.A.Tenant)
	f.exec(t, `INSERT INTO ctrlz.endpoint_groups (tenant_id, name) SELECT $1, 'fill-' || g FROM generate_series(1, $2::int) g`, f.A.Tenant, store.MaxGroupsPerTenant-have)
	if _, err := f.env.CreateGroup(f.ctx, f.st, f.A.Tenant, opts, "one too many", nil); !hasField(refusal(t, err), "max_endpoint_groups", endpoints.CodeExceeded) {
		t.Error("the 101st group")
	}
	if _, err := f.env.CreateGroup(f.ctx, f.st, f.B.Tenant, opts, "mine", nil); err != nil {
		t.Errorf("tenant B was refused a group because A is full: %v", err)
	}
}

// T-066: a profile that targets a location loses it when it moves to an Endpoint whose pair does not have it. In v1 every
// Endpoint is on the global pair, so a pair override is set directly as owner.
func TestDestinationsLost(t *testing.T) {
	f := newFx(t)
	f.exec(t, `INSERT INTO ctrlz.nodes (id, slot, name, status, dns_advertised_ip) VALUES ('00000000-0000-7000-8000-0000000000c3', 3, 'node-3', 'active', '192.0.2.3')`)
	target := f.newProfile(t, f.A.Tenant, "targets amsterdam")
	f.exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action, target_kind, target_location_id)
		VALUES ($1, $2, 'x.example.com', 'domain', 'redirect', 'location', '00000000-0000-7000-8000-00000000d102')`, f.A.Tenant, target)
	f.create(t, f.A.Tenant, target, "uses it") // on the global pair, which has Amsterdam on both nodes
	odd := f.create(t, f.A.Tenant, f.A.Profile, "odd pair")[0]
	f.exec(t, `UPDATE ctrlz.endpoints SET pair_override_node_a = '00000000-0000-7000-8000-0000000000c1', pair_override_node_b = '00000000-0000-7000-8000-0000000000c3' WHERE id = $1`, odd.ID)
	a := f.auth(f.A.Tenant, &fakeVerifier{})
	p2 := target
	_, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, a, odd.ID, endpoints.Patch{Profile2ID: &p2})
	e := refusal(t, err)
	if e.Kind != endpoints.KindDestinationsLost || !hasField(e, "/profile2_id", endpoints.CodeLocationNotAllowed) {
		t.Fatalf("%v", e)
	}
	var got *string
	f.scan(t, `SELECT profile2_id::text FROM ctrlz.endpoints WHERE id = $1`, []any{odd.ID}, &got)
	if got != nil {
		t.Error("a refused change was written")
	}
	if _, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, a, odd.ID, endpoints.Patch{Profile2ID: &p2, ConfirmDestinations: true}); err != nil {
		t.Errorf("confirmed: %v", err)
	}
}

func TestRotateDrawsNewValuesAndEndsTheLinks(t *testing.T) {
	f := newFx(t)
	var before string
	f.scan(t, `SELECT resolver_id FROM ctrlz.endpoints WHERE id = $1`, []any{f.A.Endpoint}, &before)
	f.exec(t, `DELETE FROM ctrlz.policy_outbox`)
	row, err := f.env.Rotate(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, &fakeVerifier{}), f.A.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if row.ResolverID == before || !identity.ValidResolverID(row.ResolverID) {
		t.Errorf("resolver id %q after %q", row.ResolverID, before)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.setup_share_tokens WHERE endpoint_id = $1 AND revoked_at IS NULL`, f.A.Endpoint); n != 0 {
		t.Errorf("%d live share links after a rotation", n)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.profile_download_tokens WHERE endpoint_id = $1`, f.A.Endpoint); n != 0 {
		t.Errorf("%d download links after a rotation", n)
	}
	if f.outbox(t, f.A.Tenant) != 1 {
		t.Error("a rotation did not mark")
	}
	// B's links are its own.
	if n := f.count(t, `SELECT count(*) FROM ctrlz.setup_share_tokens WHERE endpoint_id = $1 AND revoked_at IS NULL`, f.B.Endpoint); n == 0 {
		t.Error("B's share link ended with A's rotation")
	}
}

// The passwords of a committed write are reported accepted (the api clears profile_unlock for them, as the unlock route does),
// and those of a refused one are not.
func TestLockPasswordsAreAcceptedOnlyAfterTheCommit(t *testing.T) {
	f := newFx(t)
	p1 := f.newProfile(t, f.A.Tenant, "locked")
	ep := f.create(t, f.A.Tenant, p1, "guarded")[0]
	f.lock(t, p1)
	v := &fakeVerifier{right: "right-password"}
	soft := "soft_disabled"
	if _, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v, pw(p1, "wrong")), ep.ID, endpoints.Patch{AdminState: &soft}); err == nil {
		t.Fatal("a wrong password applied")
	}
	if len(v.accepted) != 0 {
		t.Errorf("a refused request reported %v accepted", v.accepted)
	}
	if _, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v, pw(p1, "right-password")), ep.ID, endpoints.Patch{AdminState: &soft}); err != nil {
		t.Fatal(err)
	}
	if len(v.accepted) != 1 || v.accepted[0] != p1 {
		t.Errorf("accepted %v, want [%v]", v.accepted, p1)
	}
	// Committed: its use is the row of its own transaction, and the verifier is not asked to write another.
	if len(v.used) != 0 {
		t.Errorf("a committed write asked for %d out-of-transaction used rows", len(v.used))
	}
}

// A request that needs more passwords than a request can carry is 422 exceeded, not 423 required: no list of at most eight
// satisfies it, and asking for a password the owner cannot supply would never end.
func TestARequestThatNeedsMoreThanEightPasswordsIsExceeded(t *testing.T) {
	f := newFx(t)
	base := f.newProfile(t, f.A.Tenant, "base")
	ep := f.create(t, f.A.Tenant, base, "wide")[0]
	locked := []uuid.UUID{base}
	var ws []endpoints.WindowIn
	for i := 0; i < 8; i++ {
		p := f.newProfile(t, f.A.Tenant, "w"+string(rune('a'+i)))
		locked = append(locked, p)
		ws = append(ws, endpoints.WindowIn{Start: i * 60, End: i*60 + 30, ProfileID: p})
	}
	v := &fakeVerifier{right: "right-password"}
	if _, err := f.env.SetSchedule(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v), ep.ID, endpoints.ScheduleIn{Timezone: "UTC", Windows: ws}); err != nil {
		t.Fatal(err)
	}
	var pws []endpoints.Password
	for _, p := range locked {
		f.lock(t, p)
		pws = append(pws, pw(p, "right-password"))
	}
	for n := 0; n <= 8; n += 4 {
		err := f.env.Delete(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v, pws[:n]...), []uuid.UUID{ep.ID})
		if e := refusal(t, err); e.Kind != endpoints.KindValidation || !hasField(e, "/lock_passwords", endpoints.CodeExceeded) {
			t.Errorf("%d passwords sent: %v", n, e)
		}
	}
	if len(v.calls) != 0 {
		t.Error("a request that cannot be satisfied was charged")
	}
	if f.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE id = $1`, ep.ID) != 1 {
		t.Error("the Endpoint was deleted")
	}
}

// A password that was verified is in the audit trail even when the request does not commit, because a later one was wrong.
func TestAVerifiedPasswordIsRecordedWhenALaterOneIsWrong(t *testing.T) {
	f := newFx(t)
	p1 := f.newProfile(t, f.A.Tenant, "first")
	p2 := f.newProfile(t, f.A.Tenant, "second")
	ep := f.create(t, f.A.Tenant, p1, "two")[0]
	if _, err := f.env.SetSchedule(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, &fakeVerifier{}), ep.ID,
		endpoints.ScheduleIn{Timezone: "UTC", Windows: []endpoints.WindowIn{{Start: 0, End: 60, ProfileID: p2}}}); err != nil {
		t.Fatal(err)
	}
	f.lock(t, p1)
	f.lock(t, p2)
	// The profiles are checked in id order: the larger id is the wrong one, so the smaller is verified first.
	lo, hi := p1, p2
	if slices.Compare(lo[:], hi[:]) > 0 {
		lo, hi = hi, lo
	}
	v := &fakeVerifier{right: "right-password", wrongFor: hi}
	err := f.env.Delete(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v, pw(p1, "right-password"), pw(p2, "right-password")), []uuid.UUID{ep.ID})
	if e := refusal(t, err); e.Kind != endpoints.KindInvalidCredentials {
		t.Fatalf("%v", e)
	}
	if len(v.used) != 1 || v.used[0] != lo || len(v.failed) != 1 || v.failed[0] != hi {
		t.Errorf("used %v failed %v, want used [%v] failed [%v]", v.used, v.failed, lo, hi)
	}
	if len(v.accepted) != 0 || f.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE id = $1`, ep.ID) != 1 {
		t.Error("a refused request was accepted or applied")
	}
}

// An edit by selector reaches every match across the repeats that "more" asks for: a client that already holds the values is
// skipped, so each call makes progress. It used to select the first 500 by id every time.
func TestBatchEditBySelectorReachesEveryClient(t *testing.T) {
	f := newFx(t)
	ep := f.create(t, f.A.Tenant, f.A.Profile, "many")[0]
	f.exec(t, `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, source)
	  SELECT $1, $2, 'c' || g, 'auto' FROM generate_series(1, 1250) g`, f.A.Tenant, ep.ID)
	a := f.auth(f.A.Tenant, &fakeVerifier{})
	group := "kids"
	in := endpoints.ClientBatchIn{Op: "edit", All: true, Change: endpoints.ClientChange{GroupName: &group}}
	for i, want := range []struct {
		n    int
		more bool
	}{{500, true}, {500, true}, {250, false}, {0, false}} {
		n, more, err := f.env.BatchClients(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, in)
		if err != nil || n != want.n || more != want.more {
			t.Fatalf("call %d: affected %d more %v err %v, want %d %v", i+1, n, more, err, want.n, want.more)
		}
	}
	if left := f.count(t, `SELECT count(*) FROM ctrlz.clients WHERE endpoint_id = $1 AND group_name IS DISTINCT FROM 'kids'`, ep.ID); left != 0 {
		t.Errorf("%d clients were not reached", left)
	}
}

// A change of the alias or the group name of a client that has a profile moves nothing the compiler reads: no outbox row. A
// change of the profile does.
func TestClientEditMarksOnlyACompiledChange(t *testing.T) {
	f := newFx(t)
	ep := f.create(t, f.A.Tenant, f.A.Profile, "mark")[0]
	a := f.auth(f.A.Tenant, &fakeVerifier{})
	c, err := f.env.CreateClient(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, endpoints.ClientCreate{Alias: "kid", ProfileID: f.A.Profile2})
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `DELETE FROM ctrlz.policy_outbox`)
	alias, group := "renamed", "home"
	if _, err := f.env.PatchClient(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, c.ID, endpoints.ClientChange{Alias: &alias, GroupName: &group}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.env.BatchClients(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, endpoints.ClientBatchIn{Op: "edit", IDs: []uuid.UUID{c.ID}, Change: endpoints.ClientChange{GroupName: &alias}}); err != nil {
		t.Fatal(err)
	}
	if n := f.outbox(t, f.A.Tenant); n != 0 {
		t.Errorf("a rename wrote %d outbox rows", n)
	}
	if _, err := f.env.PatchClient(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, c.ID, endpoints.ClientChange{ClearProfile: true}); err != nil {
		t.Fatal(err)
	}
	if n := f.outbox(t, f.A.Tenant); n != 1 {
		t.Errorf("clearing the profile wrote %d outbox rows", n)
	}
}

// A patch answers with the row its own transaction wrote, read before the commit, so a delete that follows cannot turn the answer
// into an empty 200. The race itself needs two requests between two statements; this checks the row that is answered and the
// not-found of a client that is gone.
func TestPatchClientAnswersTheRowItWrote(t *testing.T) {
	f := newFx(t)
	ep := f.create(t, f.A.Tenant, f.A.Profile, "answer")[0]
	a := f.auth(f.A.Tenant, &fakeVerifier{})
	c, err := f.env.CreateClient(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, endpoints.ClientCreate{Alias: "kid"})
	if err != nil {
		t.Fatal(err)
	}
	alias := "x"
	got, err := f.env.PatchClient(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, c.ID, endpoints.ClientChange{Alias: &alias})
	if err != nil || got.ID != c.ID || got.Alias == nil || *got.Alias != "x" {
		t.Fatalf("%v %+v", err, got)
	}
	if _, err := f.env.PatchClient(f.ctx, f.st, f.A.Tenant, opts, a, ep.ID, uuid.New(), endpoints.ClientChange{Alias: &alias}); refusal(t, err).Kind != endpoints.KindNotFound {
		t.Error("a client that is gone")
	}
}

// A password that was verified for the probe but is not needed by the write that commits (the rows moved while Argon2 ran)
// still leaves its used row: the owner's trail shows which password was confirmed (p3-D2-r2-1, r2-3).
func TestVerifiedPasswordTheWriteNoLongerNeedsIsAudited(t *testing.T) {
	f := newFx(t)
	p1 := f.newProfile(t, f.A.Tenant, "locked")
	ep := f.create(t, f.A.Tenant, p1, "guarded")[0]
	f.lock(t, p1)
	v := &fakeVerifier{right: "right-password"}
	// While the password is checked, another request switches the Endpoint off: the write then removes nothing.
	v.onCheck = func() {
		f.exec(t, `UPDATE ctrlz.endpoints SET admin_state = 'soft_disabled' WHERE id = $1`, ep.ID)
	}
	soft := "soft_disabled"
	if _, err := f.env.Patch(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, v, pw(p1, "right-password")), ep.ID, endpoints.Patch{AdminState: &soft}); err != nil {
		t.Fatal(err)
	}
	if len(v.calls) != 1 {
		t.Fatalf("%d checks", len(v.calls))
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = 'profile.lock_password_used'`, f.A.Tenant); n != 1 {
		t.Errorf("%d used rows for a password that was verified and charged", n)
	}
	// The other tenant's trail is untouched.
	if n := f.count(t, `SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = 'profile.lock_password_used'`, f.B.Tenant); n != 0 {
		t.Errorf("%d used rows in the other tenant", n)
	}
}
