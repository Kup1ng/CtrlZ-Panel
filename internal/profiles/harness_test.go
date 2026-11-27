package profiles_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/locations"
	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

// fx is a migrated database with two seeded tenants and the development locations, a store as the tenant
// role, and a fixed application clock.
type fx struct {
	ctx  context.Context
	db   *testpg.DB
	A, B catalogtest.SeedIDs
	st   *store.Store
	env  *profiles.Env
	now  time.Time
}

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
	f := &fx{ctx: ctx, db: db, A: catalogtest.NewSeedIDs(1), B: catalogtest.NewSeedIDs(2),
		now: time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)}
	if err := catalogtest.SeedGlobal(ctx, super); err != nil {
		t.Fatal(err)
	}
	for _, ids := range []catalogtest.SeedIDs{f.A, f.B} {
		if err := catalogtest.SeedTenant(ctx, super, ids); err != nil {
			t.Fatal(err)
		}
	}
	// Each seeded tenant holds one queued job, which would be its one active job.
	f.exec(t, `DELETE FROM ctrlz.batch_jobs`)
	// The global seed has two nodes in the global pair and Frankfurt; these rows are the shape of the development
	// fixture (deploy/compose/dev-locations.sql, which has its own test) on those nodes: both nodes have
	// Frankfurt, Amsterdam, New York and edge-lab, and only the first has Los Angeles.
	f.exec(t, `INSERT INTO ctrlz.locations (id, wire_id, country_code, city, label) VALUES
  ('00000000-0000-7000-8000-00000000d102', 102, 'NL', NULL, 'Amsterdam'),
  ('00000000-0000-7000-8000-00000000d103', 103, 'US', 'New York', 'New York'),
  ('00000000-0000-7000-8000-00000000d104', 104, 'US', 'Los Angeles', 'Los Angeles'),
  ('00000000-0000-7000-8000-00000000d105', 105, NULL, NULL, 'edge-lab');
INSERT INTO ctrlz.location_availability (node_id, location_id)
SELECT n.id, l.id FROM ctrlz.nodes n CROSS JOIN ctrlz.locations l
WHERE l.id <> '00000000-0000-7000-8000-00000000d104';
INSERT INTO ctrlz.location_availability (node_id, location_id) VALUES
  ('00000000-0000-7000-8000-0000000000c1', '00000000-0000-7000-8000-00000000d104')`)
	f.st = db.Store(ctx, t, store.RoleTenant)
	f.env = &profiles.Env{Catalog: locations.Store{}, Clock: appclock.Func(func() time.Time { return f.now })}
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

// in runs fn in a transaction of the tenant with the short lock wait of the api.
func (f *fx) in(tenant uuid.UUID, fn func(tx store.Tx) error) error {
	return f.st.WithTenant(f.ctx, tenant, store.TxOpts{LockWait: 5 * time.Second}, fn)
}

// must runs fn and fails the test on an error.
func (f *fx) must(t *testing.T, tenant uuid.UUID, fn func(tx store.Tx) error) {
	t.Helper()
	if err := f.in(tenant, fn); err != nil {
		t.Fatal(err)
	}
}

// refusal runs fn and returns the refusal it ended with, failing the test if it ended any other way.
func (f *fx) refusal(t *testing.T, tenant uuid.UUID, fn func(tx store.Tx) error) *profiles.Error {
	t.Helper()
	err := f.in(tenant, fn)
	var e *profiles.Error
	if !errors.As(err, &e) {
		t.Fatalf("want a refusal, got %v", err)
	}
	return e
}

// hasField reports whether the refusal names the field with the code.
func hasField(e *profiles.Error, name, code string) bool {
	for _, x := range e.Fields {
		if x.Name == name && x.Code == code {
			return true
		}
	}
	return false
}

// digest is the content and version of a profile, so a test can show that a refused request changed nothing.
func (f *fx) digest(t *testing.T, profile uuid.UUID) string {
	t.Helper()
	var d string
	err := f.db.Scan(f.ctx, `SELECT
  COALESCE((SELECT string_agg(r::text, '|' ORDER BY r.id) FROM ctrlz.rules r WHERE r.profile_id = $1), '') || '#' ||
  COALESCE((SELECT string_agg(r::text, '|' ORDER BY r.id) FROM ctrlz.rule_folders r WHERE r.profile_id = $1), '') || '#' ||
  COALESCE((SELECT string_agg(r::text, '|' ORDER BY r.service_slug) FROM ctrlz.profile_services r WHERE r.profile_id = $1), '') || '#' ||
  COALESCE((SELECT string_agg(r::text, '|' ORDER BY r.filter_id) FROM ctrlz.profile_filters r WHERE r.profile_id = $1), '') || '#' ||
  COALESCE((SELECT r::text FROM ctrlz.profile_options r WHERE r.profile_id = $1), '') || '#' ||
  (SELECT p.name || p.version::text || COALESCE(p.disabled_until::text, '') FROM ctrlz.profiles p WHERE p.id = $1)`, []any{profile}, &d)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// outbox counts the policy_outbox rows of a profile.
func (f *fx) outbox(t *testing.T, profile uuid.UUID) int {
	return f.count(t, `SELECT count(*) FROM ctrlz.policy_outbox WHERE aggregate_type = 'profile' AND aggregate_id = $1`, profile)
}

// newProfile makes an empty profile of the tenant with the superuser connection (no endpoint uses it).
func (f *fx) newProfile(t *testing.T, tenant uuid.UUID, name string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	f.exec(t, `INSERT INTO ctrlz.profiles (tenant_id, id, name) VALUES ($1, $2, $3)`, tenant, id, name)
	return id
}

func (f *fx) lock(t *testing.T, profile uuid.UUID) {
	t.Helper()
	f.exec(t, `UPDATE ctrlz.profiles SET lock_state = 'locked', lock_password_hash = 'h' WHERE id = $1`, profile)
}

func (f *fx) unlock(t *testing.T, profile uuid.UUID) {
	t.Helper()
	f.exec(t, `UPDATE ctrlz.profiles SET lock_state = 'unlocked', lock_password_hash = NULL WHERE id = $1`, profile)
}

func block() profiles.Act { return profiles.Act{Action: "block"} }

func redirectHost(h string) profiles.Act {
	return profiles.Act{Action: "redirect", Target: profiles.Target{Kind: "host", Host: h}}
}

// loc is the id of a development location by its country and city (the rows of dev-locations.sql).
func (f *fx) loc(t *testing.T, country, city string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.db.Scan(f.ctx, `SELECT id FROM ctrlz.locations WHERE country_code = $1 AND city IS NOT DISTINCT FROM NULLIF($2, '')`, []any{country, city}, &id); err != nil {
		t.Fatal(err)
	}
	return id
}
