package catalogtest_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Tests of migration 0105 (P4b B2, docs/specs/p4b-proxy.md 3.2). Every constraint, trigger, policy and grant has a
// case that must be refused and one that must pass, as the role that really writes; the tenant tables (block_roots,
// tenant_assets, unblock_requests) have two tenants.

const (
	frankfurt = "00000000-0000-7000-8000-0000000000a1" // the seeded location, DE / Frankfurt, wire id 1
	relTag    = "v26.10.31"
)

// oneText runs a query as the superuser and returns its one text value.
func (h *harness) oneText(sql string, args ...any) string {
	h.t.Helper()
	var s string
	if err := h.super.QueryRow(h.ctx, sql, args...).Scan(&s); err != nil {
		h.t.Fatalf("%s: %v", sql, err)
	}
	return s
}

// cfgInsert is one config row of node for location, enabled or not, with a small fragment.
func cfgInsert(node, location, tag string, enabled bool) string {
	return fmt.Sprintf(`INSERT INTO ctrlz.node_location_configs (node_id, location_id, tag, enabled, fragment, schema_version)
		VALUES ('%s', '%s', '%s', %t, '{"outbounds": []}'::jsonb, '%s')`, node, location, tag, enabled, relTag)
}

// cfgMany inserts n configs of node in one statement, tags c1 to cn, each fragment of fragLen bytes of text.
func cfgMany(node, location string, n, fragLen int) string {
	return fmt.Sprintf(`INSERT INTO ctrlz.node_location_configs (node_id, location_id, tag, fragment, schema_version)
		SELECT '%s', '%s', 'c' || g, ('{"a": "' || repeat('x', %d) || '"}')::jsonb, '%s' FROM generate_series(1, %d) g`,
		node, location, fragLen-9, relTag, n)
}

// TestP4bLocationsFold: the unique indexes fold the city and the label as SC 10.1 does, and the names have a form.
func TestP4bLocationsFold(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	ins := func(wire int, cc, city, label string) string {
		nz := func(s string) string {
			if s == "" {
				return "NULL"
			}
			return "'" + strings.ReplaceAll(s, "'", "''") + "'"
		}
		return fmt.Sprintf(`INSERT INTO ctrlz.locations (wire_id, country_code, city, label) VALUES (%d, %s, %s, %s)`, wire, nz(cc), nz(city), nz(label))
	}
	want(t, "the same city in other case", h.seq("admin", nil, ins(10, "DE", "frankfurt", "")), "23505")
	want(t, "the same city of another country", h.seq("admin", nil, ins(10, "FR", "Frankfurt", "")), "")
	want(t, "a country with no city beside a city", h.seq("admin", nil, ins(10, "DE", "", "")), "")
	want(t, "two countries with no city", h.seq("admin", nil, ins(10, "DE", "", ""), ins(11, "DE", "", "")), "23505")
	want(t, "a label", h.seq("admin", nil, ins(10, "", "", "Lab")), "")
	want(t, "the same label in other case", h.seq("admin", nil, ins(10, "", "", "Lab"), ins(11, "", "", "lAB")), "23505")
	want(t, "a city with a space around it", h.seq("admin", nil, ins(10, "FR", " Paris", "")), "23514")
	// strings.TrimSpace of the Go fold removes more than the ASCII space, so the database refuses what it would not fold.
	for _, sp := range []string{"\u00a0", "\u2003", "\u3000", "\u202f", "\u1680"} {
		want(t, "a city that ends in "+sp, h.seq("admin", nil, ins(10, "FR", "Paris"+sp, "")), "23514")
		want(t, "a city that starts with "+sp, h.seq("admin", nil, ins(10, "FR", sp+"Paris", "")), "23514")
		want(t, "a label that ends in "+sp, h.seq("admin", nil, ins(10, "", "", "Lab"+sp)), "23514")
	}
	want(t, "a city with a no-break space inside", h.seq("admin", nil, ins(10, "FR", "Pa\u00a0ris", "")), "")
	want(t, "a city of 65 characters", h.seq("admin", nil, ins(10, "FR", strings.Repeat("x", 65), "")), "23514")
	want(t, "a city of 64 characters", h.seq("admin", nil, ins(10, "FR", strings.Repeat("x", 64), "")), "")
	want(t, "an empty city", h.seq("", nil, `INSERT INTO ctrlz.locations (wire_id, country_code, city) VALUES (10, 'FR', '')`), "23514")
	want(t, "a city with a control character", h.seq("admin", nil, `INSERT INTO ctrlz.locations (wire_id, country_code, city) VALUES (10, 'FR', E'Pa\tris')`), "23514")
	want(t, "a label with a control character", h.seq("admin", nil, `INSERT INTO ctrlz.locations (wire_id, label) VALUES (10, E'La\u0085b')`), "23514")
	want(t, "a label of 65 characters", h.seq("admin", nil, ins(10, "", "", strings.Repeat("l", 65))), "23514")
}

// TestP4bConfigs: the CHECKs of a config, the counter and the limits of the node, the cascade of a node removal.
func TestP4bConfigs(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	rev := func(node string) int {
		return h.one(`SELECT xray_rev::int FROM ctrlz.nodes WHERE id = $1`, node)
	}
	want(t, "a config as the admin", h.seq("admin", nil, cfgInsert(nodeC1, frankfurt, "exit-1", true)), "")
	for _, c := range []struct{ what, sql string }{
		{"a tag in capitals", strings.Replace(cfgInsert(nodeC1, frankfurt, "x", true), "'x'", "'Exit'", 1)},
		{"a tag that starts with a dash", strings.Replace(cfgInsert(nodeC1, frankfurt, "x", true), "'x'", "'-x'", 1)},
		{"a tag of 33 characters", strings.Replace(cfgInsert(nodeC1, frankfurt, "x", true), "'x'", "'"+strings.Repeat("a", 33)+"'", 1)},
		{"a schema version that is no tag", strings.Replace(cfgInsert(nodeC1, frankfurt, "x", true), "'"+relTag+"'", "'1'", 1)},
		{"a schema version with no patch", strings.Replace(cfgInsert(nodeC1, frankfurt, "x", true), "'"+relTag+"'", "'v26.10'", 1)},
		// xrayschema.ValidReleaseTag holds a tag to 32 bytes, and the node's config is refused above that (B2-r1-4).
		{"a schema version of 33 bytes", strings.Replace(cfgInsert(nodeC1, frankfurt, "x", true), "'"+relTag+"'", "'v1.2."+strings.Repeat("9", 28)+"'", 1)},
		{"a fragment over 32 KiB", cfgMany(nodeC1, frankfurt, 1, 32770)},
		{"a note over 500 characters", `INSERT INTO ctrlz.node_location_configs (node_id, location_id, tag, fragment, schema_version, note)
			VALUES ('` + nodeC1 + `', '` + frankfurt + `', 'n', '{}', '` + relTag + `', '` + strings.Repeat("n", 501) + `')`},
		{"a priority of 100", `INSERT INTO ctrlz.node_location_configs (node_id, location_id, tag, fragment, schema_version, priority)
			VALUES ('` + nodeC1 + `', '` + frankfurt + `', 'p', '{}', '` + relTag + `', 100)`},
		{"a negative priority", `INSERT INTO ctrlz.node_location_configs (node_id, location_id, tag, fragment, schema_version, priority)
			VALUES ('` + nodeC1 + `', '` + frankfurt + `', 'p', '{}', '` + relTag + `', -1)`},
	} {
		want(t, c.what, h.seq("admin", nil, c.sql), "23514")
	}
	want(t, "a schema version of 32 bytes", h.seq("admin", nil, strings.Replace(cfgInsert(nodeC1, frankfurt, "v32", true), "'"+relTag+"'", "'v1.2."+strings.Repeat("9", 27)+"'", 1)), "")
	want(t, "a fragment of exactly 32 KiB", h.seq("admin", nil, cfgMany(nodeC1, frankfurt, 1, 32768)), "")
	want(t, "a priority of 99", h.seq("admin", nil, `INSERT INTO ctrlz.node_location_configs (node_id, location_id, tag, fragment, schema_version, priority)
		VALUES ('`+nodeC1+`', '`+frankfurt+`', 'p', '{}', '`+relTag+`', 99)`), "")
	want(t, "the dropped last-good column", h.seq("admin", nil, `SELECT last_good_fragment FROM ctrlz.node_location_configs`), "42703")
	// The bounds of wire.ValidateNodeConfig: 64 paths of at most 256 bytes, none NULL, all ASCII. Each case writes a row
	// first and then changes it: seq rolls back, so an UPDATE alone would find no row and prove nothing.
	setUnknown := func(expr string) string {
		return h.seq("admin", nil, cfgInsert(nodeC1, frankfurt, "au", true), "UPDATE ctrlz.node_location_configs SET accepted_unknown = "+expr)
	}
	want(t, "accepted_unknown", setUnknown("'{a.b}'"), "")
	want(t, "64 accepted paths", setUnknown("(SELECT array_agg('p' || g) FROM generate_series(1, 64) g)"), "")
	want(t, "65 accepted paths", setUnknown("(SELECT array_agg('p' || g) FROM generate_series(1, 65) g)"), "23514")
	want(t, "an accepted path of 256 bytes", setUnknown("ARRAY[repeat('x', 256)]"), "")
	want(t, "an accepted path of 257 bytes", setUnknown("ARRAY['a', repeat('x', 257)]"), "23514")
	want(t, "an accepted path that is NULL", setUnknown("ARRAY['a', NULL]::text[]"), "23514")
	// A character is not a byte: 200 two-byte characters are under 256 characters and over 256 bytes, which the wire
	// validator refuses, so the database holds the paths to ASCII (B2-r2-1).
	want(t, "an accepted path of 200 two-byte characters", setUnknown("ARRAY[repeat('é', 200)]"), "23514")
	want(t, "an accepted path with one two-byte character", setUnknown("ARRAY['a.é']"), "23514")
	want(t, "an accepted path with a control character", setUnknown("ARRAY[E'a\tb']"), "23514")
	want(t, "an accepted path with a space and a tilde", setUnknown("ARRAY['a b~']"), "")

	// The counter steps on every insert, update and delete, and a statement that moves a config steps both nodes.
	n3 := h.addNode(3, "pending", "192.0.2.61")
	before := rev(nodeC1)
	h.exec(cfgInsert(nodeC1, frankfurt, "r1", true))
	if got := rev(nodeC1); got != before+1 {
		t.Errorf("xray_rev after an insert is %d, want %d", got, before+1)
	}
	h.exec(`UPDATE ctrlz.node_location_configs SET note = 'x' WHERE node_id = $1 AND tag = 'r1'`, nodeC1)
	if got := rev(nodeC1); got != before+2 {
		t.Errorf("xray_rev after an update is %d, want %d", got, before+2)
	}
	b3 := rev(n3)
	h.exec(`UPDATE ctrlz.node_location_configs SET node_id = $2 WHERE node_id = $1 AND tag = 'r1'`, nodeC1, n3)
	if rev(nodeC1) != before+3 || rev(n3) != b3+1 {
		t.Errorf("a config moved: xray_rev is %d and %d, want %d and %d", rev(nodeC1), rev(n3), before+3, b3+1)
	}
	h.exec(`DELETE FROM ctrlz.node_location_configs WHERE node_id = $1 AND tag = 'r1'`, n3)
	if got := rev(n3); got != b3+2 {
		t.Errorf("xray_rev after a delete is %d, want %d", got, b3+2)
	}
	want(t, "the admin writes the counter", h.seq("admin", nil, `UPDATE ctrlz.nodes SET xray_rev = 5 WHERE id = '`+n3+`'`), "")
	// seq rolls back, so the value the next cases move from is written for real.
	h.exec(`UPDATE ctrlz.nodes SET xray_rev = 5 WHERE id = $1`, n3)
	want(t, "the hub writes the counter", h.seq("hub", nil, `UPDATE ctrlz.nodes SET xray_rev = 5 WHERE id = '`+n3+`'`), "42501")
	// The hub reads again only when the counter moved, so a counter put back to the value it cached would hide a change
	// (B2-r1-8): it moves forward only, in a statement of its own and after a step of the trigger in the same transaction.
	want(t, "the counter moved back", h.seq("admin", nil, `UPDATE ctrlz.nodes SET xray_rev = 4 WHERE id = '`+n3+`'`), "23514")
	want(t, "the counter kept", h.seq("admin", nil, `UPDATE ctrlz.nodes SET xray_rev = 5 WHERE id = '`+n3+`'`), "")
	// A counter set to the top of bigint would make the step of the limit trigger overflow for good (B2-r2-3).
	want(t, "a step of a million", h.seq("admin", nil, `UPDATE ctrlz.nodes SET xray_rev = 1000005 WHERE id = '`+n3+`'`), "")
	want(t, "a step over a million", h.seq("admin", nil, `UPDATE ctrlz.nodes SET xray_rev = 1000006 WHERE id = '`+n3+`'`), "23514")
	want(t, "the top of bigint", h.seq("admin", nil, `UPDATE ctrlz.nodes SET xray_rev = 9223372036854775807 WHERE id = '`+n3+`'`), "23514")
	want(t, "the top of bigint by the superuser", h.seq("", nil, `UPDATE ctrlz.nodes SET xray_rev = 9223372036854775807 WHERE id = '`+n3+`'`), "23514")
	want(t, "the bottom of bigint", h.seq("", nil, `UPDATE ctrlz.nodes SET xray_rev = -9223372036854775808 WHERE id = '`+n3+`'`), "23514")
	want(t, "a config deleted and the counter put back", h.seq("admin", nil, cfgInsert(nodeC1, frankfurt, "back", true),
		`DELETE FROM ctrlz.node_location_configs WHERE node_id = '`+nodeC1+`' AND tag = 'back'`,
		`UPDATE ctrlz.nodes SET xray_rev = (SELECT xray_rev - 2 FROM ctrlz.nodes WHERE id = '`+nodeC1+`') WHERE id = '`+nodeC1+`'`), "23514")
	want(t, "the counter moved back by the superuser", h.seq("", nil, `UPDATE ctrlz.nodes SET xray_rev = 4 WHERE id = '`+n3+`'`), "23514")
	want(t, "a negative counter", h.seq("", nil, `UPDATE ctrlz.nodes SET xray_rev = -1 WHERE id = '`+n3+`'`), "23514")

	// 64 rows a node, 2 MiB of fragments: 64 rows of 32 KiB are exactly 2 MiB, and the 65th row is refused.
	h.exec(`DELETE FROM ctrlz.node_location_configs WHERE node_id = $1`, nodeC1)
	want(t, "64 configs of 32 KiB", h.seq("admin", nil, cfgMany(nodeC1, frankfurt, 64, 32768)), "")
	want(t, "65 configs", h.seq("admin", nil, cfgMany(nodeC1, frankfurt, 65, 100)), "23514")
	want(t, "the 65th config", h.seq("admin", nil, cfgMany(nodeC1, frankfurt, 64, 100), cfgInsert(nodeC1, frankfurt, "one-more", true)), "23514")
	want(t, "64 configs on each of two nodes", h.seq("admin", nil, cfgMany(nodeC1, frankfurt, 64, 100), cfgMany(nodeC2, frankfurt, 64, 100)), "")
	want(t, "a move into a full node", h.seq("admin", nil, cfgMany(nodeC1, frankfurt, 64, 100), cfgInsert(nodeC2, frankfurt, "m", true),
		`UPDATE ctrlz.node_location_configs SET node_id = '`+nodeC1+`' WHERE node_id = '`+nodeC2+`' AND tag = 'm'`), "23514")

	// A removed node takes its configs, their state and their availability with it, for the admin too.
	h.exec(cfgInsert(n3, frankfurt, "gone", true))
	h.exec(`INSERT INTO ctrlz.node_location_config_state (config_id, node_id) SELECT id, node_id FROM ctrlz.node_location_configs WHERE node_id = $1`, n3)
	want(t, "the admin removes a node with a config", h.commitAs(h.super, "admin", `DELETE FROM ctrlz.nodes WHERE id = '`+n3+`'`), "")
	for _, q := range []string{
		`SELECT count(*) FROM ctrlz.node_location_configs WHERE node_id = $1`,
		`SELECT count(*) FROM ctrlz.node_location_config_state WHERE node_id = $1`,
		`SELECT count(*) FROM ctrlz.location_availability WHERE node_id = $1`,
	} {
		if got := h.one(q, n3); got != 0 {
			t.Errorf("%s: %d rows of a removed node are left", q, got)
		}
	}
}

// TestP4bConfigGrants: the fragment is the hub's and the admin's alone.
func TestP4bConfigGrants(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	h.exec(cfgInsert(nodeC1, frankfurt, "g1", true))
	for _, r := range []string{"compiler", "worker"} {
		want(t, r+" reads the fragment", h.seq(r, nil, `SELECT fragment FROM ctrlz.node_location_configs`), "42501")
		want(t, r+" reads the tag", h.seq(r, nil, `SELECT tag FROM ctrlz.node_location_configs`), "42501")
		want(t, r+" reads every column of the whole table", h.seq(r, nil, `SELECT * FROM ctrlz.node_location_configs`), "42501")
		want(t, r+" reads which config is enabled where", h.seq(r, nil, `SELECT id, node_id, location_id, enabled FROM ctrlz.node_location_configs`), "")
		want(t, r+" writes a config", h.seq(r, nil, `UPDATE ctrlz.node_location_configs SET enabled = false`), "42501")
	}
	want(t, "the hub reads the fragment", h.seq("hub", nil, `SELECT fragment, accepted_unknown, schema_version FROM ctrlz.node_location_configs`), "")
	want(t, "the hub writes a config", h.seq("hub", nil, `UPDATE ctrlz.node_location_configs SET enabled = false`), "42501")
	for _, r := range []string{"tenant", "auth", "keytool", "domain_apply"} {
		want(t, r+" reads a config", h.seq(r, nil, `SELECT id FROM ctrlz.node_location_configs`), "42501")
	}
	want(t, "the admin edits a config", h.seq("admin", nil, `UPDATE ctrlz.node_location_configs SET note = 'n', priority = 3`), "")
	want(t, "the admin removes a config", h.seq("admin", nil, `DELETE FROM ctrlz.node_location_configs`), "")
}

// TestP4bAvailabilitySync: location_availability holds a row exactly while an enabled config exists for the pair.
func TestP4bAvailabilitySync(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	var paris string
	if err := h.super.QueryRow(h.ctx, `INSERT INTO ctrlz.locations (wire_id, country_code, city) VALUES (2, 'FR', 'Paris') RETURNING id::text`).Scan(&paris); err != nil {
		t.Fatal(err)
	}
	has := func(node, loc string) int {
		return h.one(`SELECT count(*) FROM ctrlz.location_availability WHERE node_id = $1 AND location_id = $2`, node, loc)
	}
	expect := func(what string, node, loc string, n int) {
		t.Helper()
		if got := has(node, loc); got != n {
			t.Errorf("%s: %d availability rows, want %d", what, got, n)
		}
	}
	expect("nothing yet", nodeC1, frankfurt, 0)
	// The admin is the one writer of the configs, so the trigger runs with its rights.
	want(t, "an enabled config as the admin", h.commitAs(h.super, "admin", cfgInsert(nodeC1, frankfurt, "a1", true)), "")
	expect("an enabled config", nodeC1, frankfurt, 1)
	h.exec(cfgInsert(nodeC1, frankfurt, "a2", true))
	expect("a second config of the pair", nodeC1, frankfurt, 1)
	h.exec(`UPDATE ctrlz.node_location_configs SET enabled = false WHERE tag = 'a1'`)
	expect("one of two switched off", nodeC1, frankfurt, 1)
	want(t, "the second switched off as the admin", h.commitAs(h.super, "admin", `UPDATE ctrlz.node_location_configs SET enabled = false WHERE tag = 'a2'`), "")
	expect("both switched off", nodeC1, frankfurt, 0)
	h.exec(cfgInsert(nodeC1, paris, "off", false))
	expect("a disabled config", nodeC1, paris, 0)
	h.exec(`UPDATE ctrlz.node_location_configs SET enabled = true WHERE tag = 'off'`)
	expect("switched on", nodeC1, paris, 1)
	h.exec(`UPDATE ctrlz.node_location_configs SET location_id = $1 WHERE tag = 'off'`, frankfurt)
	expect("moved to another location: the new one", nodeC1, frankfurt, 1)
	expect("moved to another location: the old one", nodeC1, paris, 0)
	h.exec(`UPDATE ctrlz.node_location_configs SET node_id = $1 WHERE tag = 'off'`, nodeC2)
	expect("moved to another node: the new one", nodeC2, frankfurt, 1)
	expect("moved to another node: the old one", nodeC1, frankfurt, 0)
	h.exec(`DELETE FROM ctrlz.node_location_configs WHERE tag = 'off'`)
	expect("the last config deleted", nodeC2, frankfurt, 0)
	// Rows an earlier version left that nothing justifies are not kept: the migration cleans them, and a write of
	// the pair puts it right, which is the same function.
	h.exec(`INSERT INTO ctrlz.location_availability (node_id, location_id) VALUES ($1, $2)`, nodeC1, paris)
	h.exec(cfgInsert(nodeC1, paris, "again", false))
	expect("a disabled config next to a stale row", nodeC1, paris, 0)
}

// TestP4bConfigState: what a node reports of a config is the hub's to write and the admin's to read.
func TestP4bConfigState(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	h.exec(cfgInsert(nodeC1, frankfurt, "s1", true))
	cfg := h.oneText(`SELECT id::text FROM ctrlz.node_location_configs WHERE tag = 's1'`)
	ins := func(cols, vals string) string {
		return fmt.Sprintf(`INSERT INTO ctrlz.node_location_config_state (config_id, node_id%s) VALUES ('%s', '%s'%s)`, cols, cfg, nodeC1, vals)
	}
	want(t, "the hub reports a state", h.seq("hub", nil, ins(", fragment_sha256, state, healthy, latency_ms, reported_at", ", decode(repeat('ab', 32), 'hex'), 'applied', true, 120, now()")), "")
	want(t, "the hub reports the last good", h.seq("hub", nil, ins(", state, error", ", 'last_good', 'refused: unknown key'")), "")
	want(t, "the hub updates a state", h.seq("hub", nil, ins("", ""), `UPDATE ctrlz.node_location_config_state SET state = 'refused', error = 'bad', healthy = false, latency_ms = NULL`), "")
	want(t, "a state no page knows", h.seq("hub", nil, ins(", state", ", 'running'")), "23514")
	want(t, "a digest of 31 bytes", h.seq("hub", nil, ins(", fragment_sha256", ", decode(repeat('ab', 31), 'hex')")), "23514")
	want(t, "an error over 500 characters", h.seq("hub", nil, ins(", error", ", '"+strings.Repeat("e", 501)+"'")), "23514")
	want(t, "a negative latency", h.seq("hub", nil, ins(", latency_ms", ", -1")), "23514")
	want(t, "a state of a config that is not there", h.seq("hub", nil, `INSERT INTO ctrlz.node_location_config_state (config_id, node_id) VALUES (gen_random_uuid(), '`+nodeC1+`')`), "23503")
	want(t, "the hub deletes a state", h.seq("hub", nil, ins("", ""), `DELETE FROM ctrlz.node_location_config_state`), "42501")
	want(t, "the admin reads the states", h.seq("admin", nil, `SELECT * FROM ctrlz.node_location_config_state`), "")
	want(t, "the admin writes a state", h.seq("admin", nil, ins("", "")), "42501")
	for _, r := range []string{"worker", "compiler", "tenant", "auth"} {
		want(t, r+" reads the states", h.seq(r, nil, `SELECT 1 FROM ctrlz.node_location_config_state`), "42501")
	}
	h.exec(ins("", ""))
	h.exec(`DELETE FROM ctrlz.node_location_configs WHERE tag = 's1'`)
	if got := h.one(`SELECT count(*) FROM ctrlz.node_location_config_state`); got != 0 {
		t.Errorf("%d states are left of a removed config", got)
	}
}

// TestP4bProxySettings: one row, the admin changes it, the hub reads it.
func TestP4bProxySettings(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	if got := h.oneText(`SELECT grant_width || ' ' || array_to_string(probe_urls, ' ') FROM ctrlz.proxy_settings`); got !=
		"exact http://www.gstatic.com/generate_204 http://cp.cloudflare.com/generate_204" {
		t.Errorf("the row holds %q", got)
	}
	want(t, "a second row", h.seq("", nil, `INSERT INTO ctrlz.proxy_settings (singleton) VALUES (false)`), "23514")
	want(t, "the same row twice", h.seq("", nil, `INSERT INTO ctrlz.proxy_settings (singleton) VALUES (true)`), "23505")
	want(t, "the hub reads it", h.seq("hub", nil, `SELECT grant_width, probe_urls, updated_at FROM ctrlz.proxy_settings`), "")
	want(t, "the hub writes it", h.seq("hub", nil, `UPDATE ctrlz.proxy_settings SET grant_width = 'carrier'`), "42501")
	want(t, "the admin reads it", h.seq("admin", nil, `SELECT * FROM ctrlz.proxy_settings`), "")
	want(t, "the admin sets a width", h.seq("admin", nil, `UPDATE ctrlz.proxy_settings SET grant_width = 'prefix24'`), "")
	want(t, "the admin sets one probe address", h.seq("admin", nil, `UPDATE ctrlz.proxy_settings SET probe_urls = ARRAY['http://example.test/204']`), "")
	want(t, "an unknown width", h.seq("admin", nil, `UPDATE ctrlz.proxy_settings SET grant_width = 'wide'`), "23514")
	want(t, "no probe address", h.seq("admin", nil, `UPDATE ctrlz.proxy_settings SET probe_urls = '{}'`), "23514")
	for _, bad := range []string{"ftp://example.test/204", "example.test/204", "http://", "http://a b/", "http://" + strings.Repeat("x", 250)} {
		want(t, "the probe address "+bad[:min(len(bad), 20)], h.seq("admin", nil, `UPDATE ctrlz.proxy_settings SET probe_urls = ARRAY['`+bad+`']`), "23514")
	}
	want(t, "a good one beside a bad one", h.seq("admin", nil, `UPDATE ctrlz.proxy_settings SET probe_urls = ARRAY['http://a.test/', 'x']`), "23514")
	want(t, "an https probe with a port and a path", h.seq("admin", nil, `UPDATE ctrlz.proxy_settings SET probe_urls = ARRAY['https://example.test:8443/p?q=1', 'http://b.test/']`), "")
	want(t, "a probe address of 256 bytes", h.seq("admin", nil, `UPDATE ctrlz.proxy_settings SET probe_urls = ARRAY['http://' || repeat('x', 249)]`), "")
	want(t, "three probe addresses", h.seq("admin", nil, `UPDATE ctrlz.proxy_settings SET probe_urls = ARRAY['a', 'b', 'c']`), "23514")
	want(t, "a probe list with a null", h.seq("admin", nil, `UPDATE ctrlz.proxy_settings SET probe_urls = ARRAY['a', NULL]`), "23514")
	want(t, "the admin writes the stamp", h.seq("admin", nil, `UPDATE ctrlz.proxy_settings SET updated_at = now()`), "42501")
	want(t, "the admin inserts", h.seq("admin", nil, `INSERT INTO ctrlz.proxy_settings (singleton) VALUES (false)`), "42501")
	want(t, "the admin deletes", h.seq("admin", nil, `DELETE FROM ctrlz.proxy_settings`), "42501")
	for _, r := range []string{"worker", "compiler", "tenant"} {
		want(t, r+" reads it", h.seq(r, nil, `SELECT 1 FROM ctrlz.proxy_settings`), "42501")
	}
}

// TestP4bNodeColumns: xray_fetch_version, the bind addresses the admin may now write, and the five refused forms.
func TestP4bNodeColumns(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	n3 := h.addNode(3, "pending", "192.0.2.62")
	upd := func(set string) string { return `UPDATE ctrlz.nodes SET ` + set + ` WHERE id = '` + n3 + `'` }
	want(t, "the admin sets the release to fetch", h.seq("admin", nil, upd(`xray_fetch_version = 'v26.11.9'`)), "")
	want(t, "the admin clears it", h.seq("admin", nil, upd(`xray_fetch_version = NULL`)), "")
	want(t, "a release that is no tag", h.seq("admin", nil, upd(`xray_fetch_version = 'latest'`)), "23514")
	want(t, "a release of 32 bytes", h.seq("admin", nil, upd(`xray_fetch_version = 'v1.2.`+strings.Repeat("9", 27)+`'`)), "")
	want(t, "a release of 33 bytes, which ValidReleaseTag refuses", h.seq("admin", nil, upd(`xray_fetch_version = 'v1.2.`+strings.Repeat("9", 28)+`'`)), "23514")
	want(t, "the admin sets the bind addresses", h.seq("admin", nil, upd(`dns_bind_ip = '192.0.2.70', proxy_bind_ip = '192.0.2.71'`)), "")
	for _, ip := range []string{"::ffff:192.0.2.1", "64:ff9b::c000:201", "::c000:201", "2002:c000:201::1", "2001::1", "192.0.2.0/24"} {
		want(t, "the proxy bind address "+ip, h.seq("admin", nil, upd(`proxy_bind_ip = '`+ip+`'`)), "23514")
		want(t, "the dns bind address "+ip, h.seq("admin", nil, upd(`dns_bind_ip = '`+ip+`'`)), "23514")
	}
	want(t, "the hub reads the two new columns", h.seq("hub", nil, `SELECT xray_fetch_version, xray_rev FROM ctrlz.nodes`), "")
	want(t, "the hub writes the release", h.seq("hub", nil, upd(`xray_fetch_version = 'v26.11.9'`)), "42501")
	want(t, "the admin inserts with a counter", h.seq("admin", nil, `INSERT INTO ctrlz.nodes (slot, name, xray_rev) VALUES (4, 'y', 7)`), "42501")
	want(t, "the admin inserts with a release", h.seq("admin", nil, `INSERT INTO ctrlz.nodes (slot, name, xray_fetch_version) VALUES (4, 'y', 'v26.11.9')`), "42501")
	for _, r := range []string{"compiler", "worker"} {
		want(t, r+" reads the release", h.seq(r, nil, `SELECT xray_fetch_version, xray_rev FROM ctrlz.nodes`), "")
	}
}

// TestP4bBlockRoots is the two-tenant test of the new tenant table: each tenant sees and inserts its own row only,
// the hub reads every row and writes the four certificate columns, nobody else reaches it.
func TestP4bBlockRoots(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a, b := h.A.Tenant.String(), h.B.Tenant.String()
	cnt := func(role string, guc *string, where string) string {
		got, code := h.texts(role, guc, `SELECT count(*)::text FROM ctrlz.block_roots `+where)
		if code != "" {
			return code
		}
		return got[0]
	}
	if got := cnt("tenant", &a, ""); got != "1" {
		t.Errorf("tenant A sees %s rows, want its own", got)
	}
	if got := cnt("tenant", &a, "WHERE tenant_id = '"+b+"'"); got != "0" {
		t.Errorf("tenant A sees %s rows of tenant B", got)
	}
	if got := cnt("tenant", &b, "WHERE tenant_id = '"+a+"'"); got != "0" {
		t.Errorf("tenant B sees %s rows of tenant A", got)
	}
	if got := cnt("tenant", nil, ""); got != "0" {
		t.Errorf("a tenant with no setting sees %s rows", got)
	}
	if got := cnt("hub", &a, ""); got != "2" {
		t.Errorf("the hub sees %s rows, want both", got)
	}
	if got := cnt("hub", nil, ""); got != "2" {
		t.Errorf("the hub with no setting sees %s rows, want both", got)
	}
	for _, r := range []string{"worker", "compiler", "admin", "auth", "keytool"} {
		want(t, r+" reads the roots", h.seq(r, &a, `SELECT 1 FROM ctrlz.block_roots`), "42501")
	}

	// The tenant's own empty row, made when a block page is first written.
	h.exec(`DELETE FROM ctrlz.block_roots WHERE tenant_id = $1`, a)
	ins := func(id string) string { return `INSERT INTO ctrlz.block_roots (tenant_id) VALUES ('` + id + `')` }
	want(t, "tenant A inserts its row", h.seq("tenant", &a, ins(a)), "")
	want(t, "tenant A inserts the row of B", h.seq("tenant", &a, ins(b)), "42501")
	want(t, "tenant B inserts the row of A", h.seq("tenant", &b, ins(a)), "42501")
	want(t, "tenant A inserts a row with a certificate", h.seq("tenant", &a, `INSERT INTO ctrlz.block_roots (tenant_id, cert_der) VALUES ('`+a+`', '\x30')`), "42501")
	want(t, "tenant A updates its row", h.seq("tenant", &a, `UPDATE ctrlz.block_roots SET cert_der = '\x30'`), "42501")
	want(t, "tenant A deletes its row", h.seq("tenant", &a, `DELETE FROM ctrlz.block_roots`), "42501")
	want(t, "the hub inserts a row", h.seq("hub", nil, ins(a)), "42501")
	want(t, "the hub deletes a row", h.seq("hub", nil, `DELETE FROM ctrlz.block_roots`), "42501")
	// The seq calls above rolled back, so A's row is made again for real: the hub's cases need both tenants' rows.
	h.exec(ins(a))

	// The hub gives every empty row its certificate.
	setRoot := func(digestLen int, after string) string {
		return fmt.Sprintf(`UPDATE ctrlz.block_roots SET cert_der = '\x3082', spki_sha256 = decode(repeat('cd', %d), 'hex'), not_before = now(), not_after = %s`, digestLen, after)
	}
	set := setRoot(32, "now() + interval '10 years'")
	if n, code := h.affected("hub", nil, set); code != "" || n != 2 {
		t.Errorf("the hub gives %d roots a certificate (%q), want 2", n, code)
	}
	if n, code := h.affected("hub", &b, set+` WHERE tenant_id = '`+b+`'`); code != "" || n != 1 {
		t.Errorf("the hub updates %d rows of one tenant (%q), want 1", n, code)
	}
	want(t, "the four columns come together: a certificate alone", h.seq("hub", nil, `UPDATE ctrlz.block_roots SET cert_der = '\x3082'`), "23514")
	want(t, "the four columns come together: a time alone", h.seq("hub", nil, `UPDATE ctrlz.block_roots SET not_before = now()`), "23514")
	want(t, "a digest of 31 bytes", h.seq("hub", nil, setRoot(31, "now() + interval '10 years'")), "23514")
	want(t, "an end before the start", h.seq("hub", nil, setRoot(32, "now() - interval '1 day'")), "23514")
	want(t, "the hub clears a root", h.seq("hub", nil, `UPDATE ctrlz.block_roots SET cert_der = NULL, spki_sha256 = NULL, not_before = NULL, not_after = NULL`), "")
	want(t, "the hub writes the stamp", h.seq("hub", nil, `UPDATE ctrlz.block_roots SET created_at = now()`), "42501")
	want(t, "the hub moves a root to another tenant", h.seq("hub", nil, `UPDATE ctrlz.block_roots SET tenant_id = gen_random_uuid()`), "42501")
	// The tenant reads the certificate of its own root and no other. affected rolls back, so the root is written for real.
	h.exec(setRoot(32, "now() + interval '10 years'") + ` WHERE tenant_id = '` + a + `'`)
	if got, code := h.texts("tenant", &a, `SELECT spki_sha256::text FROM ctrlz.block_roots`); code != "" || len(got) != 1 || got[0] == "NULL" {
		t.Errorf("tenant A reads its root: %v (%q)", got, code)
	}
}

// TestP4bBlockRootKindsRefused: nothing writes a block root as a certificate row.
func TestP4bBlockRootKindsRefused(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, k := range []string{"block_root", "block_intermediate"} {
		want(t, "a certificate of kind "+k, h.seq("", nil, `INSERT INTO ctrlz.certificates (kind, chain_pem, not_before, not_after, state, source)
			VALUES ('`+k+`', 'pem', now(), now() + interval '30 days', 'active', 'issued')`), "23514")
	}
	want(t, "a certificate of kind zone_ca", h.seq("", nil, `INSERT INTO ctrlz.certificates (kind, chain_pem, not_before, not_after, state, source)
		VALUES ('zone_ca', 'pem', now(), now() + interval '30 days', 'active', 'issued')`), "")
}

// TestP4bUnblockRequests: the hub's reads, the form of the name and the message, the index, two tenants.
func TestP4bUnblockRequests(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a, b := h.A.Tenant.String(), h.B.Tenant.String()
	ins := func(s string, qname, message string) string {
		return fmt.Sprintf(`INSERT INTO ctrlz.unblock_requests (tenant_id, profile_id, endpoint_id, qname, message) VALUES ('%s', '%s', '%s', '%s', %s)`,
			s, map[string]string{a: h.A.Profile.String(), b: h.B.Profile.String()}[s], map[string]string{a: h.A.Endpoint.String(), b: h.B.Endpoint.String()}[s], qname, message)
	}
	for _, c := range []struct{ what, q, code string }{
		{"a plain name", "blocked.example.test", ""},
		{"an underscore and a hyphen", "_dmarc.a-b.example.test", ""},
		{"a punycode label", "xn--bcher-kva.example", ""},
		{"an escaped dot and byte", `a\.b\046c.test`, ""},
		{"a single label", "localhost", ""},
		{"upper case", "Blocked.example.test", "23514"},
		{"an empty label", "a..b", "23514"},
		{"a leading dot", ".a.test", "23514"},
		{"a trailing dot", "a.test.", "23514"},
		{"the root", ".", "23514"},
		{"empty", "", "23514"},
		{"a space", "a b.test", "23514"},
		{"a slash", "a/b.test", "23514"},
		{"a bare backslash", `a\b.test`, "23514"},
		{"253 characters", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61), ""},
		{"254 characters", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62), "23514"},
	} {
		want(t, c.what, h.seq("", nil, ins(a, c.q, "NULL")), c.code)
	}
	want(t, "a message of 500 characters", h.seq("", nil, ins(a, "m.test", "'"+strings.Repeat("m", 500)+"'")), "")
	want(t, "a message of 501 characters", h.seq("", nil, ins(a, "m.test", "'"+strings.Repeat("m", 501)+"'")), "23514")
	if got := h.one(`SELECT count(*) FROM pg_indexes WHERE schemaname = 'ctrlz' AND indexname = 'unblock_requests_status_idx'
		AND indexdef LIKE '%(tenant_id, status, created_at)'`); got != 1 {
		t.Errorf("the index (tenant_id, status, created_at) is missing")
	}

	// The hub reads the four columns of its own tenant's rows (the seed holds one for each tenant).
	cnt := func(role string, guc *string, where string) string {
		got, code := h.texts(role, guc, `SELECT count(*)::text FROM ctrlz.unblock_requests `+where)
		if code != "" {
			return code
		}
		return got[0]
	}
	if got := cnt("hub", &a, "WHERE status = 'new' AND endpoint_id = '"+h.A.Endpoint.String()+"' AND qname = 'example.test' AND created_at > now() - interval '1 day'"); got != "1" {
		t.Errorf("the hub finds %s of tenant A's rows, want 1", got)
	}
	if got := cnt("hub", &a, "WHERE endpoint_id = '"+h.B.Endpoint.String()+"'"); got != "0" {
		t.Errorf("the hub sees %s rows of tenant B's Endpoint with A's setting", got)
	}
	if got := cnt("hub", nil, "WHERE status = 'new'"); got != "0" {
		t.Errorf("the hub with no setting sees %s rows", got)
	}
	want(t, "the hub reads the message", h.seq("hub", &a, `SELECT message FROM ctrlz.unblock_requests`), "42501")
	want(t, "the hub reads the profile", h.seq("hub", &a, `SELECT profile_id FROM ctrlz.unblock_requests`), "42501")
	want(t, "the hub updates a row", h.seq("hub", &a, `UPDATE ctrlz.unblock_requests SET status = 'read'`), "42501")
	want(t, "the hub inserts", h.seq("hub", &a, ins(a, "h.test", "NULL")), "")
	want(t, "the hub inserts a row of B under A's setting", h.seq("hub", &a, ins(b, "h.test", "NULL")), "42501")
	// The worker reads the age and nothing of what was asked.
	if got := cnt("worker", &a, "WHERE created_at < now() + interval '1 day'"); got != "1" {
		t.Errorf("the worker counts %s rows by age, want 1", got)
	}
	want(t, "the worker reads the name", h.seq("worker", &a, `SELECT qname FROM ctrlz.unblock_requests`), "42501")
	want(t, "the worker deletes the old ones", h.seq("worker", &a, `DELETE FROM ctrlz.unblock_requests WHERE created_at < now() - interval '90 days'`), "")
	// The tenant still reads and handles its own.
	if got := cnt("tenant", &b, ""); got != "1" {
		t.Errorf("tenant B sees %s rows, want its own", got)
	}
}

// TestP4bAssets: PNG only, 20 rows a tenant, the worker's reads of the sweep, two tenants.
func TestP4bAssets(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a, b := h.A.Tenant.String(), h.B.Tenant.String()
	many := func(id string, n int, mime string) string {
		return fmt.Sprintf(`INSERT INTO ctrlz.tenant_assets (tenant_id, kind, sha256, mime, size, bytes)
			SELECT '%s', 'logo', decode(repeat('ab', 32), 'hex'), '%s', 4, '\x89504e47' FROM generate_series(1, %d)`, id, mime, n)
	}
	want(t, "a JPEG", h.seq("tenant", &a, many(a, 1, "image/jpeg")), "23514")
	want(t, "a WebP", h.seq("", nil, many(a, 1, "image/webp")), "23514")
	// The seed holds one asset for each tenant.
	want(t, "the 20th asset of A", h.seq("tenant", &a, many(a, 19, "image/png")), "")
	want(t, "the 21st asset of A", h.seq("tenant", &a, many(a, 20, "image/png")), "23514")
	want(t, "the 21st asset of A as the owner of the setting", h.seq("tenant", &a, many(a, 19, "image/png"), many(a, 1, "image/png")), "23514")
	want(t, "B still has room", h.seq("tenant", &b, many(b, 19, "image/png")), "")
	// One statement of tenant B does not count A's rows, and A's full table does not stop B.
	h.exec(many(a, 19, "image/png"))
	want(t, "A is full", h.seq("tenant", &a, many(a, 1, "image/png")), "23514")
	want(t, "B inserts while A is full", h.seq("tenant", &b, many(b, 1, "image/png")), "")
	want(t, "A deletes one and inserts one", h.seq("tenant", &a, `DELETE FROM ctrlz.tenant_assets WHERE id = (SELECT id FROM ctrlz.tenant_assets ORDER BY id DESC LIMIT 1)`, many(a, 1, "image/png")), "")
	// The worker's sweep reads the id and the age of an asset and the logo a page names, never the bytes.
	for _, c := range []struct{ what, sql, code string }{
		{"the worker reads the age of an asset", `SELECT id, created_at FROM ctrlz.tenant_assets WHERE created_at < now() - interval '1 day'`, ""},
		{"the worker reads the bytes", `SELECT bytes FROM ctrlz.tenant_assets`, "42501"},
		{"the worker reads the digest", `SELECT sha256 FROM ctrlz.tenant_assets`, "42501"},
		{"the worker finds the assets no page names", `SELECT a.id FROM ctrlz.tenant_assets a WHERE a.created_at < now() - interval '1 day'
			AND NOT EXISTS (SELECT 1 FROM ctrlz.block_pages p WHERE p.logo_asset_id = a.id)`, ""},
		{"the worker reads the page text", `SELECT title FROM ctrlz.block_pages`, "42501"},
		{"the worker deletes an asset", `DELETE FROM ctrlz.tenant_assets WHERE created_at < now() - interval '1 day'`, ""},
		{"the worker inserts an asset", many(a, 1, "image/png"), "42501"},
	} {
		want(t, c.what, h.seq("worker", &a, c.sql), c.code)
	}
	h.exec(many(b, 1, "image/png"))
	// The sweep touches the rows of the tenant it is set to, and the page of the seed keeps its logo.
	if got, code := h.texts("worker", &a, `SELECT count(*)::text FROM ctrlz.tenant_assets`); code != "" || got[0] != "20" {
		t.Errorf("the worker under A's setting counts %v (%q) assets, want 20", got, code)
	}
	if n, code := h.affected("worker", &b, `DELETE FROM ctrlz.tenant_assets a WHERE NOT EXISTS (SELECT 1 FROM ctrlz.block_pages p WHERE p.logo_asset_id = a.id)`); code != "" || n != 1 {
		t.Errorf("the sweep of tenant B removed %d unused assets (%q), want its one", n, code)
	}
	if got := h.one(`SELECT count(*) FROM ctrlz.tenant_assets WHERE tenant_id = $1`, a); got != 20 {
		t.Errorf("tenant A holds %d assets after B's sweep, want 20", got)
	}
}

// TestP4bAdminJobKind: the new kind is the admin's, and the hub still queues domain_change only.
func TestP4bAdminJobKind(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	want(t, "the admin queues locations_changed", h.seq("admin", nil, `INSERT INTO ctrlz.admin_jobs (kind) VALUES ('locations_changed')`), "")
	want(t, "an unknown kind", h.seq("", nil, `INSERT INTO ctrlz.admin_jobs (kind) VALUES ('locations_changed_2')`), "23514")
	want(t, "the hub queues locations_changed", h.seq("hub", nil, `INSERT INTO ctrlz.admin_jobs (kind) VALUES ('locations_changed')`), "42501")
	want(t, "the hub queues domain_change", h.seq("hub", nil, `INSERT INTO ctrlz.admin_jobs (kind) VALUES ('domain_change')`), "")
	// A job that is queued or running is one per kind, as for the other kinds.
	want(t, "two locations_changed jobs", h.seq("", nil, `INSERT INTO ctrlz.admin_jobs (kind) VALUES ('locations_changed')`, `INSERT INTO ctrlz.admin_jobs (kind) VALUES ('locations_changed')`), "23505")
	// job_outbox.kind is free text, and the tenant may queue location_flags.
	a := h.A.Tenant.String()
	want(t, "the tenant queues location_flags", h.seq("tenant", &a, `INSERT INTO ctrlz.job_outbox (tenant_id, kind, args) VALUES ('`+a+`', 'location_flags', '{"profile_ids": []}')`), "")
}

// TestP4bPolicyArtifactsPageHash: the digest of the block page a profile blob names.
func TestP4bPolicyArtifactsPageHash(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	ins := func(hash, page string) string {
		return fmt.Sprintf(`INSERT INTO ctrlz.policy_artifacts (hash, kind, size, store_ref, first_seq, page_hash) VALUES (decode('%s', 'hex'), 'profile', 1, 'x', 1, %s)`, hash, page)
	}
	h1 := strings.Repeat("11", 32)
	want(t, "a profile that names a page", h.seq("compiler", nil, ins(h1, "decode(repeat('22', 32), 'hex')")), "")
	want(t, "a profile that names none", h.seq("compiler", nil, ins(h1, "NULL")), "")
	want(t, "a digest of 31 bytes", h.seq("compiler", nil, ins(h1, "decode(repeat('22', 31), 'hex')")), "23514")
	want(t, "the compiler binds the page later", h.seq("compiler", nil, ins(h1, "NULL"), `UPDATE ctrlz.policy_artifacts SET page_hash = decode(repeat('33', 32), 'hex')`), "")
	want(t, "the hub reads the page hash", h.seq("hub", nil, `SELECT hash, page_hash FROM ctrlz.policy_artifacts`), "")
	want(t, "the worker reads the page hash", h.seq("worker", nil, `SELECT page_hash FROM ctrlz.policy_artifacts`), "42501")
	want(t, "the worker still reads what it sweeps", h.seq("worker", nil, `SELECT hash, store_ref, gc_after_seq FROM ctrlz.policy_artifacts`), "")
}

// TestP4bNodeAlertClose: ctrlz_fn.node_alert_close, EXECUTE for the hub alone, the kinds of 11 and no other, the
// row of one node and one kind.
func TestP4bNodeAlertClose(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	alert := func(kind, key string) {
		h.exec(`INSERT INTO ctrlz.alerts (severity, kind, params) VALUES ('warning', $1, jsonb_build_object('key', $2::text))`, kind, key)
	}
	open := func(kind, key string) int {
		return h.one(`SELECT count(*) FROM ctrlz.alerts WHERE kind = $1 AND params ->> 'key' = $2 AND resolved_at IS NULL`, kind, key)
	}
	for _, k := range []string{"nft_failed", "xray_down", "block_key_missing", "grants_full", "xray_stuck", "location_down", "xray_upgrade_blocked", "proxy_unreachable", "something_else"} {
		alert(k, nodeC1)
	}
	alert("xray_down", nodeC2)
	call := func(role, kind, node string) string {
		got, code := h.texts(role, nil, fmt.Sprintf(`SELECT ctrlz_fn.node_alert_close('%s', '%s')::text`, kind, node))
		if code != "" {
			return code
		}
		return got[0]
	}
	// h.texts rolls back, so the closing itself goes through commitAs and the rows are read after it.
	closeAs := func(kind, node string) string {
		return h.commitAs(h.super, "hub", fmt.Sprintf(`SELECT ctrlz_fn.node_alert_close('%s', '%s')`, kind, node))
	}
	if got := call("hub", "xray_down", nodeC1); got != "1" {
		t.Errorf("the hub closes %s rows, want 1", got)
	}
	if got := call("hub", "something_else", nodeC1); got != "0" {
		t.Errorf("the hub closes %s rows of a kind that is not one of 11, want 0", got)
	}
	if got := call("hub", "xray_down", "00000000-0000-7000-8000-0000000000c9"); got != "0" {
		t.Errorf("the hub closes %s rows of a node with none, want 0", got)
	}
	want(t, "the hub closes xray_down of node 1", closeAs("xray_down", nodeC1), "")
	if open("xray_down", nodeC1) != 0 {
		t.Errorf("the alert is still open")
	}
	if open("xray_down", nodeC2) != 1 || open("proxy_unreachable", nodeC1) != 1 || open("nft_failed", nodeC1) != 1 {
		t.Errorf("an alert of another node or kind was closed")
	}
	want(t, "the hub closes a kind that is not one of 11", closeAs("something_else", nodeC1), "")
	if open("something_else", nodeC1) != 1 {
		t.Errorf("an alert of a kind outside the list was closed")
	}
	if got := h.one(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'xray_down' AND params ->> 'key' = $1 AND resolved_at IS NOT NULL`, nodeC1); got != 1 {
		t.Errorf("%d closed rows, want 1", got)
	}
	if got := call("hub", "xray_down", nodeC1); got != "0" {
		t.Errorf("a second close touches %s rows, want 0", got)
	}
	// A closed alert is a row of its own: the condition may come back as a new open one, and not before.
	want(t, "a second open alert of the same kind and node", h.seq("hub", nil, `INSERT INTO ctrlz.alerts (severity, kind, params) VALUES ('warning', 'proxy_unreachable', jsonb_build_object('key', '`+nodeC1+`'::text))`), "23505")
	want(t, "an open alert after the close", h.seq("hub", nil, `INSERT INTO ctrlz.alerts (severity, kind, params) VALUES ('warning', 'xray_down', jsonb_build_object('key', '`+nodeC1+`'::text))`), "")
	// The hub keeps INSERT only.
	want(t, "the hub updates an alert", h.seq("hub", nil, `UPDATE ctrlz.alerts SET resolved_at = now()`), "42501")
	want(t, "the hub reads an alert", h.seq("hub", nil, `SELECT id FROM ctrlz.alerts`), "42501")
	// Nobody else calls it.
	for _, r := range []string{"admin", "worker", "compiler", "tenant", "keytool", "domain_apply"} {
		if got := call(r, "xray_down", nodeC2); got != "42501" {
			t.Errorf("%s calls node_alert_close: %q, want 42501", r, got)
		}
	}
	var acl string
	if err := h.super.QueryRow(h.ctx, `SELECT coalesce(string_agg(DISTINCT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END, ','), '')
		FROM pg_proc p, aclexplode(p.proacl) a WHERE p.proname = 'node_alert_close' AND a.privilege_type = 'EXECUTE' AND a.grantee <> p.proowner`).Scan(&acl); err != nil {
		t.Fatal(err)
	}
	if acl != "ctrlz_hub" {
		t.Errorf("EXECUTE is held by %q, want the hub alone", acl)
	}
}
