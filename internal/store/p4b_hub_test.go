package store_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The statements of internal/store/p4b_hub.go as ctrlz_hub and ctrlz_tenant against the migrated schema (migration 0105).

var (
	p4bNode1 = uuid.MustParse("00000000-0000-7000-8000-0000000000c1")
	p4bNode2 = uuid.MustParse("00000000-0000-7000-8000-0000000000c2")
	p4bLoc   = "00000000-0000-7000-8000-0000000000a1"
)

func (f *fixture) p4bConfig(t *testing.T, node uuid.UUID, tag string, priority int, enabled bool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if err := f.db.Exec(f.ctx, `INSERT INTO ctrlz.node_location_configs (id, node_id, location_id, tag, priority, enabled, fragment, schema_version, accepted_unknown)
		VALUES ($1, $2, $3, $4, $5, $6, '{"outbounds": [{"tag": "x"}]}'::jsonb, 'v26.10.31', '{a.b}')`, id, node, p4bLoc, tag, priority, enabled); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestHubReadsTheProxySettingsAndTheConfigsOfANode(t *testing.T) {
	f := newFixture(t)
	hub := f.db.Store(f.ctx, t, store.RoleHub)
	ps, err := hub.HubProxySettings(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ps.GrantWidth != "exact" || len(ps.ProbeURLs) != 2 || ps.ProbeURLs[0] != "http://www.gstatic.com/generate_204" {
		t.Errorf("settings %+v", ps)
	}
	x0, found, err := hub.HubNodeXray(f.ctx, p4bNode1)
	if err != nil || !found || x0.FetchVersion != "" {
		t.Fatalf("node xray %+v %v %v", x0, found, err)
	}
	low := f.p4bConfig(t, p4bNode1, "b-low", 1, true)
	high := f.p4bConfig(t, p4bNode1, "a-high", 9, true)
	f.p4bConfig(t, p4bNode1, "off", 99, false)
	f.p4bConfig(t, p4bNode2, "other-node", 50, true)
	x1, _, err := hub.HubNodeXray(f.ctx, p4bNode1)
	if err != nil || x1.Rev != x0.Rev+3 {
		t.Errorf("the counter is %d after three writes from %d (%v)", x1.Rev, x0.Rev, err)
	}
	if err := f.db.Exec(f.ctx, `UPDATE ctrlz.nodes SET xray_fetch_version = 'v26.11.9' WHERE id = $1`, p4bNode1); err != nil {
		t.Fatal(err)
	}
	x2, _, _ := hub.HubNodeXray(f.ctx, p4bNode1)
	if x2.FetchVersion != "v26.11.9" || x2.Rev != x1.Rev {
		t.Errorf("fetch version %+v", x2)
	}
	if _, found, err := hub.HubNodeXray(f.ctx, uuid.New()); err != nil || found {
		t.Errorf("a node that is not there: found %v, %v", found, err)
	}
	rev, rows, err := hub.HubNodeConfigs(f.ctx, p4bNode1)
	if err != nil {
		t.Fatal(err)
	}
	// The counter comes from the snapshot of the rows: it is the one a separate read gives while nothing writes.
	if rev != x2.Rev {
		t.Errorf("the counter read with the configs is %d, want %d", rev, x2.Rev)
	}
	if len(rows) != 2 || rows[0].ID != high || rows[1].ID != low || rows[0].Tag != "a-high" || rows[0].Priority != 9 {
		t.Fatalf("configs %+v", rows)
	}
	if rows[0].SchemaVersion != "v26.10.31" || len(rows[0].AcceptedUnknown) != 1 || rows[0].AcceptedUnknown[0] != "a.b" || !bytes.Contains(rows[0].Fragment, []byte("outbounds")) {
		t.Errorf("a row %+v", rows[0])
	}
	if r, got, err := hub.HubNodeConfigs(f.ctx, uuid.New()); err != nil || len(got) != 0 || r != 0 {
		t.Errorf("a node that is not there has %d configs at counter %d (%v)", len(got), r, err)
	}
}

func TestHubStoresTheStateOfItsOwnConfigsOnly(t *testing.T) {
	f := newFixture(t)
	hub := f.db.Store(f.ctx, t, store.RoleHub)
	own := f.p4bConfig(t, p4bNode1, "own", 1, true)
	foreign := f.p4bConfig(t, p4bNode2, "foreign", 1, true)
	yes, ms := true, int32(120)
	n, err := hub.HubConfigStates(f.ctx, p4bNode1, []store.ConfigState{
		{ConfigID: own, FragmentSHA256: bytes.Repeat([]byte{1}, 32), State: "applied", Healthy: &yes, LatencyMS: &ms},
		{ConfigID: foreign, State: "applied"},
		{ConfigID: uuid.New(), State: "applied"},
	})
	if err != nil || n != 1 {
		t.Fatalf("written %d (%v), want the one config of the reporting node", n, err)
	}
	var state string
	var healthy bool
	var lat int
	var node uuid.UUID
	if err := f.db.Scan(f.ctx, `SELECT state, healthy, latency_ms, node_id FROM ctrlz.node_location_config_state WHERE config_id = $1`, []any{own}, &state, &healthy, &lat, &node); err != nil {
		t.Fatal(err)
	}
	if state != "applied" || !healthy || lat != 120 || node != p4bNode1 {
		t.Errorf("row %s %v %d %s", state, healthy, lat, node)
	}
	var other int
	if err := f.db.Scan(f.ctx, `SELECT count(*) FROM ctrlz.node_location_config_state WHERE config_id = $1`, []any{foreign}, &other); err != nil || other != 0 {
		t.Errorf("a report for another node's config wrote %d rows (%v)", other, err)
	}
	// A second report rewrites the row, with no digest and an error.
	n, err = hub.HubConfigStates(f.ctx, p4bNode1, []store.ConfigState{{ConfigID: own, State: "refused", Error: "unknown key"}})
	if err != nil || n != 1 {
		t.Fatalf("second report: %d %v", n, err)
	}
	var sha []byte
	var msg string
	var h *bool
	if err := f.db.Scan(f.ctx, `SELECT fragment_sha256, error, healthy FROM ctrlz.node_location_config_state WHERE config_id = $1`, []any{own}, &sha, &msg, &h); err != nil {
		t.Fatal(err)
	}
	if sha != nil || msg != "unknown key" || h != nil {
		t.Errorf("after the second report: %x %q %v", sha, msg, h)
	}
	// A config the admin moved to another node: the new node's report re-keys the row, so a read by node finds it there.
	if err := f.db.Exec(f.ctx, `UPDATE ctrlz.node_location_configs SET node_id = $2 WHERE id = $1`, own, p4bNode2); err != nil {
		t.Fatal(err)
	}
	if n, err := hub.HubConfigStates(f.ctx, p4bNode1, []store.ConfigState{{ConfigID: own, State: "applied"}}); err != nil || n != 0 {
		t.Errorf("the old node reported the moved config: %d %v", n, err)
	}
	if n, err := hub.HubConfigStates(f.ctx, p4bNode2, []store.ConfigState{{ConfigID: own, State: "applied"}}); err != nil || n != 1 {
		t.Fatalf("the new node reported the moved config: %d %v", n, err)
	}
	if err := f.db.Scan(f.ctx, `SELECT node_id FROM ctrlz.node_location_config_state WHERE config_id = $1`, []any{own}, &node); err != nil || node != p4bNode2 {
		t.Errorf("the state of a moved config names node %s (%v), want the new one", node, err)
	}
	if _, err := hub.HubConfigStates(f.ctx, p4bNode2, []store.ConfigState{{ConfigID: own, State: "running"}}); !errors.Is(err, store.ErrConstraint) {
		t.Errorf("a state no page knows: %v", err)
	}
	if n, err := hub.HubConfigStates(f.ctx, p4bNode1, nil); err != nil || n != 0 {
		t.Errorf("an empty report: %d %v", n, err)
	}
}

func TestHubClosesTheAlertOfOneNodeAndKind(t *testing.T) {
	f := newFixture(t)
	hub := f.db.Store(f.ctx, t, store.RoleHub)
	for _, a := range []struct {
		kind string
		node uuid.UUID
	}{{"xray_down", p4bNode1}, {"xray_down", p4bNode2}, {"location_down", p4bNode1}, {"unrelated", p4bNode1}} {
		if err := f.db.Exec(f.ctx, `INSERT INTO ctrlz.alerts (severity, kind, params) VALUES ('warning', $1, jsonb_build_object('key', $2::text))`, a.kind, a.node.String()); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		kind string
		node uuid.UUID
		want int
	}{{"xray_down", p4bNode1, 1}, {"xray_down", p4bNode1, 0}, {"unrelated", p4bNode1, 0}, {"xray_down", uuid.New(), 0}} {
		if got, err := hub.HubAlertClose(f.ctx, c.kind, c.node); err != nil || got != c.want {
			t.Errorf("close %s of %s: %d (%v), want %d", c.kind, c.node, got, err, c.want)
		}
	}
	var open int
	if err := f.db.Scan(f.ctx, `SELECT count(*) FROM ctrlz.alerts WHERE resolved_at IS NULL`, nil, &open); err != nil || open != 3 {
		t.Errorf("%d alerts are open, want 3 (%v)", open, err)
	}
}

func TestHubGivesEveryAccountsRootItsCertificate(t *testing.T) {
	f := newFixture(t)
	hub := f.db.Store(f.ctx, t, store.RoleHub)
	if empty, err := hub.HubBlockRootsEmpty(f.ctx); err != nil || len(empty) != 2 {
		t.Fatalf("the 5 s pass sees %d empty roots (%v), want both tenants'", len(empty), err)
	}
	roots, err := hub.HubBlockRoots(f.ctx)
	if err != nil || len(roots) != 2 {
		t.Fatalf("the hub sees %d roots (%v), want both tenants'", len(roots), err)
	}
	for _, r := range roots {
		if len(r.SPKI) != 0 {
			t.Errorf("a root of the seed has a digest")
		}
	}
	spki := bytes.Repeat([]byte{9}, 32)
	now := time.Now().UTC().Truncate(time.Millisecond)
	if found, err := hub.HubBlockRootSet(f.ctx, f.A.Tenant, []byte{0x30, 0x82}, spki, now, now.Add(24*time.Hour)); err != nil || !found {
		t.Fatalf("set A: %v %v", found, err)
	}
	if found, err := hub.HubBlockRootSet(f.ctx, uuid.New(), []byte{0x30}, spki, now, now.Add(time.Hour)); err != nil || found {
		t.Errorf("an account that is not there: %v %v", found, err)
	}
	if _, err := hub.HubBlockRootSet(f.ctx, f.A.Tenant, []byte{0x30}, []byte{1}, now, now.Add(time.Hour)); !errors.Is(err, store.ErrConstraint) {
		t.Errorf("a digest of one byte: %v", err)
	}
	roots, _ = hub.HubBlockRoots(f.ctx)
	got := map[uuid.UUID]int{}
	for _, r := range roots {
		got[r.Tenant] = len(r.SPKI)
	}
	if got[f.A.Tenant] != 32 || got[f.B.Tenant] != 0 {
		t.Errorf("digests after the set: %v", got)
	}
	if empty, err := hub.HubBlockRootsEmpty(f.ctx); err != nil || len(empty) != 1 || empty[0] != f.B.Tenant {
		t.Errorf("the 5 s pass after A's certificate: %v (%v), want only B", empty, err)
	}
}

func TestBlockRootEnsureIsTheTenantsOwnRow(t *testing.T) {
	f := newFixture(t)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant)
	if err := f.db.Exec(f.ctx, `DELETE FROM ctrlz.block_roots`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // twice: the second finds the row and adds nothing
		if err := tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error { return tx.BlockRootEnsure() }); err != nil {
			t.Fatal(err)
		}
	}
	var a, b int
	if err := f.db.Scan(f.ctx, `SELECT count(*) FILTER (WHERE tenant_id = $1), count(*) FILTER (WHERE tenant_id = $2) FROM ctrlz.block_roots`, []any{f.A.Tenant, f.B.Tenant}, &a, &b); err != nil {
		t.Fatal(err)
	}
	if a != 1 || b != 0 {
		t.Errorf("tenant A has %d rows and tenant B %d after A's calls, want 1 and 0", a, b)
	}
}
