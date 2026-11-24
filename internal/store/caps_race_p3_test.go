package store_test

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The race drivers of the Endpoint write path (docs/specs/p3-endpoints.md 3.5, 3.6). Like the profile drivers, each one runs
// more spenders than the limit allows on a barrier, against the real database, and checks that exactly the limit got through.
// A spender keeps its transaction open until every other one has run its statement or a short time has passed: with the lock
// that serialises the writers the others wait for it and cannot arrive, so the barrier gives up and the winner commits;
// without it every spender counts the same rows and writes.

func p3Drivers() map[string]func(*testing.T, *raceEnv) {
	return map[string]func(*testing.T, *raceEnv){
		"max_endpoints":            driveMaxEndpoints,
		"max_clients_per_endpoint": driveMaxClients,
		"endpoint_group.create":    driveGroupCap,
		"endpoint.delete":          driveEndpointDelete,
		"max_authorized_ips":       driveMaxAuthorizedIPs,
		"ddns_host.create":         driveDDNSHostCap,
		"authorized_ip.last":       driveAuthorizedLast,
	}
}

// raceRID is a resolver id of 26 base32 letters that no seeded row has and no other spender has.
func raceRID(i int) string { return "zz" + strings.Repeat(string(rune('a'+i)), 24) }

func driveMaxEndpoints(t *testing.T, e *raceEnv) {
	have := e.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE tenant_id = $1`, e.A.Tenant)
	e.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_endpoints = $2 WHERE tenant_id = $1`, e.A.Tenant, have+3)
	var typ string
	if err := e.super.QueryRow(e.ctx, `SELECT type FROM ctrlz.endpoints WHERE id = $1`, e.A.Endpoint).Scan(&typ); err != nil {
		t.Fatal(err)
	}
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			hold()
			if err := tx.QuotaLock(); err != nil {
				return err
			}
			id, err := uuid.NewV7()
			if err != nil {
				return err
			}
			_, w, err = tx.EndpointsInsert([]store.EndpointNew{{ID: id, Name: fmt.Sprintf("race-%d", i), ResolverID: raceRID(i), Type: typ,
				ProfileID: e.A.Profile, AnalyticsLevel: "full", ScheduleTimezone: "Asia/Tehran"}})
			settle()
			return err
		})
		return w.Yes(), err
	})
	if got != 3 {
		t.Errorf("%d Endpoints were created into 3 free slots", got)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE tenant_id = $1`, e.A.Tenant); n != have+3 {
		t.Errorf("the tenant holds %d Endpoints, want %d", n, have+3)
	}
	// B's limit is its own: A being full costs it nothing.
	if err := e.tenant.WithTenant(e.ctx, e.B.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		if err := tx.QuotaLock(); err != nil {
			return err
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		_, w, err := tx.EndpointsInsert([]store.EndpointNew{{ID: id, Name: "b-first", ResolverID: raceRID(20), Type: typ, ProfileID: e.B.Profile,
			AnalyticsLevel: "full", ScheduleTimezone: "Asia/Tehran"}})
		if err == nil && !w.Yes() {
			t.Error("tenant B was refused an Endpoint because A is full")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// A request that creates several Endpoints at once is one statement: it adds all of them or none (spec 3.5).
func TestEndpointsInsertIsAllOrNone(t *testing.T) {
	e := newRaceEnv(t)
	have := e.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE tenant_id = $1`, e.A.Tenant)
	e.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_endpoints = $2 WHERE tenant_id = $1`, e.A.Tenant, have+2)
	var typ string
	if err := e.super.QueryRow(e.ctx, `SELECT type FROM ctrlz.endpoints WHERE id = $1`, e.A.Endpoint).Scan(&typ); err != nil {
		t.Fatal(err)
	}
	mk := func(n int) []store.EndpointNew {
		var rows []store.EndpointNew
		for i := 0; i < n; i++ {
			id, _ := uuid.NewV7()
			rows = append(rows, store.EndpointNew{ID: id, Name: fmt.Sprintf("n%d", i), ResolverID: raceRID(i), Type: typ, ProfileID: e.A.Profile,
				AnalyticsLevel: "full", ScheduleTimezone: "Asia/Tehran"})
		}
		return rows
	}
	for _, c := range []struct {
		n    int
		want bool
		held int
	}{{3, false, have}, {2, true, have + 2}} {
		var w store.Won
		if err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
			if err = tx.QuotaLock(); err != nil {
				return err
			}
			_, w, err = tx.EndpointsInsert(mk(c.n))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if w.Yes() != c.want {
			t.Errorf("%d names into 2 free slots: won %v, want %v", c.n, w.Yes(), c.want)
		}
		if n := e.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE tenant_id = $1`, e.A.Tenant); n != c.held {
			t.Errorf("after %d names the tenant holds %d Endpoints, want %d", c.n, n, c.held)
		}
	}
}

func driveMaxClients(t *testing.T, e *raceEnv) {
	have := e.count(t, `SELECT count(*) FROM ctrlz.clients WHERE tenant_id = $1 AND endpoint_id = $2 AND source = 'manual'`, e.A.Tenant, e.A.Endpoint)
	e.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_clients_per_endpoint = $2 WHERE tenant_id = $1`, e.A.Tenant, have+3)
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			hold()
			// The write path key-shares the profiles first (Guard.Begin): the statements of the Endpoint name profile columns.
			if _, err := tx.ProfilesKeyShare([]uuid.UUID{e.A.Profile}); err != nil {
				return err
			}
			if _, err := tx.EndpointsLock([]uuid.UUID{e.A.Endpoint}); err != nil {
				return err
			}
			var err error
			_, w, err = tx.ClientInsert(store.ClientNew{Endpoint: e.A.Endpoint, Label: fmt.Sprintf("race%d", i)})
			settle()
			return err
		})
		return w.Yes(), err
	})
	if got != 3 {
		t.Errorf("%d clients were added into 3 free slots", got)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.clients WHERE tenant_id = $1 AND endpoint_id = $2 AND source = 'manual'`, e.A.Tenant, e.A.Endpoint); n != have+3 {
		t.Errorf("the Endpoint holds %d manual clients, want %d", n, have+3)
	}
	// The hub's clients do not count: a seeded auto client leaves the manual room as it was.
	e.exec(t, `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, source) VALUES ($1, $2, 'autoone', 'auto')`, e.A.Tenant, e.A.Endpoint)
	if n := e.count(t, `SELECT count(*) FROM ctrlz.clients WHERE tenant_id = $1 AND endpoint_id = $2 AND source = 'manual'`, e.A.Tenant, e.A.Endpoint); n != have+3 {
		t.Errorf("an auto client changed the manual count: %d", n)
	}
}

func driveGroupCap(t *testing.T, e *raceEnv) {
	have := e.count(t, `SELECT count(*) FROM ctrlz.endpoint_groups WHERE tenant_id = $1`, e.A.Tenant)
	fill := store.MaxGroupsPerTenant - 3 - have
	e.exec(t, `INSERT INTO ctrlz.endpoint_groups (tenant_id, name) SELECT $1, 'fill-' || g FROM generate_series(1, $2::int) g`, e.A.Tenant, fill)
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			hold()
			if err := tx.QuotaLock(); err != nil {
				return err
			}
			var err error
			_, w, err = tx.GroupInsert(fmt.Sprintf("race-%d", i))
			settle()
			return err
		})
		return w.Yes(), err
	})
	if got != 3 {
		t.Errorf("%d groups were created into 3 free slots", got)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.endpoint_groups WHERE tenant_id = $1`, e.A.Tenant); n != store.MaxGroupsPerTenant {
		t.Errorf("the tenant holds %d groups, want %d", n, store.MaxGroupsPerTenant)
	}
}

func driveEndpointDelete(t *testing.T, e *raceEnv) {
	e.exec(t, `UPDATE ctrlz.ip_claims SET state = 'released' WHERE tenant_id = $1`, e.A.Tenant)
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			hold()
			if err := tx.ClientsLockOf([]uuid.UUID{e.A.Endpoint}); err != nil {
				return err
			}
			if _, err := tx.EndpointsLock([]uuid.UUID{e.A.Endpoint}); err != nil {
				return err
			}
			var err error
			_, w, err = tx.EndpointsDelete([]uuid.UUID{e.A.Endpoint})
			settle()
			return err
		})
		return w.Yes(), err
	})
	if got != 1 {
		t.Errorf("%d racing deletes of one Endpoint won", got)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE id = $1`, e.A.Endpoint); n != 0 {
		t.Errorf("the Endpoint is still there")
	}
	// B's Endpoint is its own.
	if n := e.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE id = $1`, e.B.Endpoint); n != 1 {
		t.Errorf("B's Endpoint was deleted with A's")
	}
}

// max_authorized_ips counts the tenant's manual rows under the quota lock: more spenders than the room, and exactly the room gets in.
func driveMaxAuthorizedIPs(t *testing.T, e *raceEnv) {
	have := e.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND source = 'manual'`, e.A.Tenant)
	e.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_authorized_ips = $2 WHERE tenant_id = $1`, e.A.Tenant, have+3)
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			hold()
			if err := tx.QuotaLock(); err != nil {
				return err
			}
			if _, err := tx.EndpointsLock([]uuid.UUID{e.A.Endpoint}); err != nil {
				return err
			}
			var err error
			_, w, err = tx.AuthorizedInsert(e.A.Endpoint, []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("203.0.113.%d/32", i+1))})
			settle()
			return err
		})
		return w.Yes(), err
	})
	if got != 3 {
		t.Errorf("%d prefixes were added into 3 free slots", got)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND source = 'manual'`, e.A.Tenant); n != have+3 {
		t.Errorf("the tenant holds %d manual rows, want %d", n, have+3)
	}
	// A learned row is not counted: it leaves the manual room as it was.
	e.exec(t, `INSERT INTO ctrlz.authorized_ips (tenant_id, endpoint_id, cidr, source) VALUES ($1, $2, '203.0.113.250/32', 'secure_dns')`, e.A.Tenant, e.A.Endpoint)
	if n := e.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND source = 'manual'`, e.A.Tenant); n != have+3 {
		t.Errorf("a learned row changed the manual count: %d", n)
	}
}

// ddns_host.create counts the Endpoint's hosts under its row: of eight spenders only the room under five gets in.
func driveDDNSHostCap(t *testing.T, e *raceEnv) {
	have := e.count(t, `SELECT count(*) FROM ctrlz.endpoint_ddns_hosts WHERE tenant_id = $1 AND endpoint_id = $2`, e.A.Tenant, e.A.Endpoint)
	room := store.MaxDDNSHostsPerEndpoint - have
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			hold()
			if _, err := tx.EndpointsLock([]uuid.UUID{e.A.Endpoint}); err != nil {
				return err
			}
			var err error
			_, w, err = tx.DDNSHostInsert(e.A.Endpoint, fmt.Sprintf("race%d.example.org", i))
			settle()
			return err
		})
		return w.Yes(), err
	})
	if got != room {
		t.Errorf("%d hosts were added into %d free slots", got, room)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.endpoint_ddns_hosts WHERE tenant_id = $1 AND endpoint_id = $2`, e.A.Tenant, e.A.Endpoint); n != store.MaxDDNSHostsPerEndpoint {
		t.Errorf("the Endpoint holds %d hosts", n)
	}
}

// authorized_ip.last: an Endpoint that requires authorized IPs holds two rows and eight deleters go after one or the other.
// One delete wins and one row is left, whoever races whom (spec 5, E6).
func driveAuthorizedLast(t *testing.T, e *raceEnv) {
	e.exec(t, `INSERT INTO ctrlz.authorized_ips (tenant_id, endpoint_id, cidr, source) VALUES ($1, $2, '203.0.113.77/32', 'manual')`, e.A.Tenant, e.A.Endpoint)
	e.exec(t, `UPDATE ctrlz.endpoints SET require_authorized_ips = true WHERE id = $1`, e.A.Endpoint)
	var rows []uuid.UUID
	if err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		list, err := tx.AuthorizedList(store.AuthorizedFilter{Endpoint: e.A.Endpoint, Limit: 10})
		for _, r := range list {
			rows = append(rows, r.ID)
		}
		return err
	}); err != nil || len(rows) != 2 {
		t.Fatalf("%d rows (%v), want 2", len(rows), err)
	}
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			hold()
			if _, err := tx.EndpointsLock([]uuid.UUID{e.A.Endpoint}); err != nil {
				return err
			}
			var err error
			w, err = tx.AuthorizedDelete(e.A.Endpoint, []uuid.UUID{rows[i%2]})
			settle()
			return err
		})
		return w.Yes(), err
	})
	if got != 1 {
		t.Errorf("%d deletes of the rows of an Endpoint that requires them won, want 1", got)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND endpoint_id = $2`, e.A.Tenant, e.A.Endpoint); n != 1 {
		t.Errorf("the Endpoint holds %d rows, want 1", n)
	}
	// B's rows are its own.
	if n := e.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1`, e.B.Tenant); n == 0 {
		t.Error("B's rows went with A's")
	}
}
