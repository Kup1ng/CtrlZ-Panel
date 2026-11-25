package catalogtest_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Tests of migration 0100 (P4 W2, docs/specs/p4-nodes.md 3.2): the node tables, the triggers, the policies of
// certificates, the grants of the hub, the admin and the apply step. Every trigger, function and policy has a
// case that must be refused and a case that must pass, as the role that really writes, and what holds
// tenant rows has two tenants.

const (
	nodeC1 = "00000000-0000-7000-8000-0000000000c1" // the seeded nodes, active, in the global pair
	nodeC2 = "00000000-0000-7000-8000-0000000000c2"
)

// seq runs the statements in one transaction as role (empty: the superuser) and rolls it back. It returns the
// SQLSTATE of the first failure, "" when every statement passed. A deferred trigger does not run: see commitAs.
func (h *harness) seq(role string, guc *string, sqls ...string) string {
	h.t.Helper()
	code := ""
	run := func(tx pgx.Tx) {
		for _, s := range sqls {
			if _, err := tx.Exec(h.ctx, s); err != nil {
				if pe := pgErr(err); pe != nil {
					code = pe.Code
					return
				}
				h.t.Fatalf("%s: %v", s, err)
			}
		}
	}
	if role == "" {
		tx, err := h.super.Begin(h.ctx)
		if err != nil {
			h.t.Fatal(err)
		}
		defer tx.Rollback(h.ctx)
		run(tx)
		return code
	}
	h.inTx(h.super, role, guc, run)
	return code
}

// commitAs runs the statements on conn in one transaction as role and commits it, so the deferred constraint
// triggers run. It returns the SQLSTATE of the first failure, the commit included.
func (h *harness) commitAs(conn *pgx.Conn, role string, sqls ...string) string {
	h.t.Helper()
	tx, err := conn.Begin(h.ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	defer tx.Rollback(h.ctx)
	if role != "" {
		if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE "+pgx.Identifier{"ctrlz_" + role}.Sanitize()); err != nil {
			h.t.Fatal(err)
		}
	}
	for _, s := range sqls {
		if _, err := tx.Exec(h.ctx, s); err != nil {
			if pe := pgErr(err); pe != nil {
				return pe.Code
			}
			h.t.Fatalf("%s: %v", s, err)
		}
	}
	if err := tx.Commit(h.ctx); err != nil {
		if pe := pgErr(err); pe != nil {
			return pe.Code
		}
		h.t.Fatalf("commit: %v", err)
	}
	return ""
}

// texts runs one query as role in a rolled-back transaction and returns the first column of every row as text,
// or the SQLSTATE of its failure.
func (h *harness) texts(role string, guc *string, sql string, args ...any) (out []string, code string) {
	h.t.Helper()
	h.inTx(h.super, role, guc, func(tx pgx.Tx) {
		rows, err := tx.Query(h.ctx, sql, args...)
		if err != nil {
			if pe := pgErr(err); pe != nil {
				code = pe.Code
				return
			}
			h.t.Fatalf("%s: %v", sql, err)
		}
		defer rows.Close()
		for rows.Next() {
			var s *string
			if err := rows.Scan(&s); err != nil {
				h.t.Fatalf("%s: %v", sql, err)
			}
			if s == nil {
				out = append(out, "NULL")
			} else {
				out = append(out, *s)
			}
		}
		if err := rows.Err(); err != nil {
			if pe := pgErr(err); pe != nil {
				code = pe.Code
				return
			}
			h.t.Fatalf("%s: %v", sql, err)
		}
	})
	return out, code
}

// affected runs a statement as role and returns the rows it changed, or the SQLSTATE of its failure.
func (h *harness) affected(role string, guc *string, sql string, args ...any) (n int64, code string) {
	h.t.Helper()
	h.inTx(h.super, role, guc, func(tx pgx.Tx) {
		tag, err := tx.Exec(h.ctx, sql, args...)
		if err != nil {
			if pe := pgErr(err); pe != nil {
				code = pe.Code
				return
			}
			h.t.Fatalf("%s: %v", sql, err)
		}
		n = tag.RowsAffected()
	})
	return n, code
}

func want(t *testing.T, what, got, wantCode string) {
	t.Helper()
	if got != wantCode {
		t.Errorf("%s: SQLSTATE %q, want %q", what, got, wantCode)
	}
}

// addNode makes a node row as the superuser.
func (h *harness) addNode(slot int, status, advertised string) string {
	h.t.Helper()
	var id string
	if err := h.super.QueryRow(h.ctx, `INSERT INTO ctrlz.nodes (slot, name, status, dns_advertised_ip, dns_bind_ip)
		VALUES ($1::smallint, $2, $3, $4::inet, $4::inet) RETURNING id::text`, slot, fmt.Sprintf("node-%d", slot), status, advertised).Scan(&id); err != nil {
		h.t.Fatalf("add node %d: %v", slot, err)
	}
	return id
}

// TestP4NodeStatusMovesOneWay: the CHECK without draining, nodes_revoked_terminal for the owner and for the
// admin, the five embedded-IPv4 forms refused on both addresses, the key that stays unique and is remembered.
func TestP4NodeStatusMovesOneWay(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	n3 := h.addNode(3, "pending", "192.0.2.3")
	n4 := h.addNode(4, "pending", "192.0.2.4")

	want(t, "the old draining state", h.seq("", nil, `UPDATE ctrlz.nodes SET status = 'draining' WHERE id = '`+n3+`'`), "23514")
	// The cases run as the owner and as the admin; the start states are made by legal moves only (the trigger fires for the owner too).
	for _, c := range []struct {
		what  string
		stmts []string
		code  string
	}{
		{"pending to revoked", []string{`UPDATE ctrlz.nodes SET status = 'revoked' WHERE id = '` + n3 + `'`}, "23514"},
		{"pending to active", []string{`UPDATE ctrlz.nodes SET status = 'active' WHERE id = '` + n3 + `'`}, ""},
		{"active to revoked", []string{`UPDATE ctrlz.nodes SET status = 'active' WHERE id = '` + n3 + `'`, `UPDATE ctrlz.nodes SET status = 'revoked' WHERE id = '` + n3 + `'`}, ""},
		{"active to pending", []string{`UPDATE ctrlz.nodes SET status = 'active' WHERE id = '` + n3 + `'`, `UPDATE ctrlz.nodes SET status = 'pending' WHERE id = '` + n3 + `'`}, "23514"},
		{"revoked to active", []string{`UPDATE ctrlz.nodes SET status = 'active' WHERE id = '` + n3 + `'`, `UPDATE ctrlz.nodes SET status = 'revoked' WHERE id = '` + n3 + `'`,
			`UPDATE ctrlz.nodes SET status = 'active' WHERE id = '` + n3 + `'`}, "23514"},
		{"revoked to pending", []string{`UPDATE ctrlz.nodes SET status = 'active' WHERE id = '` + n3 + `'`, `UPDATE ctrlz.nodes SET status = 'revoked' WHERE id = '` + n3 + `'`,
			`UPDATE ctrlz.nodes SET status = 'pending' WHERE id = '` + n3 + `'`}, "23514"},
		{"revoked onto revoked", []string{`UPDATE ctrlz.nodes SET status = 'active' WHERE id = '` + n3 + `'`, `UPDATE ctrlz.nodes SET status = 'revoked' WHERE id = '` + n3 + `'`,
			`UPDATE ctrlz.nodes SET status = 'revoked' WHERE id = '` + n3 + `'`}, ""},
		{"a write of the status onto itself", []string{`UPDATE ctrlz.nodes SET status = 'pending' WHERE id = '` + n3 + `'`}, ""},
	} {
		want(t, c.what+" as the owner", h.seq("", nil, c.stmts...), c.code)
		want(t, c.what+" as ctrlz_admin", h.seq("admin", nil, c.stmts...), c.code)
	}

	// The admin's reach on nodes: the node form and the status, never the key, the slot, the serial or a failover
	// column, and an insert with no status.
	for _, c := range []struct{ what, sql, code string }{
		{"the admin renames", `UPDATE ctrlz.nodes SET name = 'renamed' WHERE id = '` + n3 + `'`, ""},
		{"the admin edits the advertised address", `UPDATE ctrlz.nodes SET dns_advertised_ip = '192.0.2.99' WHERE id = '` + n3 + `'`, ""},
		{"the admin writes the SPKI", `UPDATE ctrlz.nodes SET spki_sha256 = decode(repeat('22', 32), 'hex') WHERE id = '` + n3 + `'`, "42501"},
		{"the admin writes the slot", `UPDATE ctrlz.nodes SET slot = 2 WHERE id = '` + n3 + `'`, "42501"},
		{"the admin writes the certificate serial", `UPDATE ctrlz.nodes SET cert_serial = 'x' WHERE id = '` + n3 + `'`, "42501"},
		{"the admin writes the bind address", `UPDATE ctrlz.nodes SET dns_bind_ip = '192.0.2.98' WHERE id = '` + n3 + `'`, "42501"},
		{"the admin writes a failover column", `UPDATE ctrlz.nodes SET dns_withdrawn = true WHERE id = '` + n3 + `'`, "42501"},
		{"the admin inserts with a status", `INSERT INTO ctrlz.nodes (slot, name, status) VALUES (3, 'y', 'active')`, "42501"},
		{"the admin inserts with a failover column", `INSERT INTO ctrlz.nodes (slot, name, dns_hold) VALUES (3, 'y', true)`, "42501"},
		{"the hub writes a failover column", `UPDATE ctrlz.nodes SET dns_withdrawn = true, dns_hold = true, dns_last_failback_at = now(), dns_flap_until = now() WHERE id = '` + n3 + `'`, ""},
		{"the hub writes the previous serial", `UPDATE ctrlz.nodes SET prev_cert_serial = 'old', cert_serial = 'new' WHERE id = '` + n3 + `'`, ""},
		{"the hub writes the SPKI", `UPDATE ctrlz.nodes SET spki_sha256 = decode(repeat('22', 32), 'hex') WHERE id = '` + n3 + `'`, "42501"},
		{"the hub writes the status", `UPDATE ctrlz.nodes SET status = 'active' WHERE id = '` + n3 + `'`, "42501"},
		{"the compiler writes a node", `UPDATE ctrlz.nodes SET name = 'z' WHERE id = '` + n3 + `'`, "42501"},
	} {
		role := "admin"
		if strings.HasPrefix(c.what, "the hub") {
			role = "hub"
		} else if strings.HasPrefix(c.what, "the compiler") {
			role = "compiler"
		}
		want(t, c.what, h.seq(role, nil, c.sql), c.code)
	}

	// The two address columns refuse every form that embeds an IPv4 address, and accept the plain ones.
	for _, col := range []string{"dns_advertised_ip", "dns_bind_ip"} {
		for _, bad := range []string{"::ffff:192.0.2.1", "64:ff9b::192.0.2.1", "::192.0.2.1", "2002:c000:201::1", "2001::5", "::1"} {
			want(t, col+" "+bad, h.seq("", nil, fmt.Sprintf(`UPDATE ctrlz.nodes SET %s = '%s' WHERE id = '%s'`, col, bad, n3)), "23514")
		}
		for _, ok := range []string{"192.0.2.77", "2001:db8::1", "198.51.100.0/24"} {
			want(t, col+" "+ok, h.seq("", nil, fmt.Sprintf(`UPDATE ctrlz.nodes SET %s = '%s' WHERE id = '%s'`, col, ok, n3)), "")
		}
	}

	// A key admitted once is never admitted again: the unique index while the row lives, node_spki_retired after.
	key := `decode(repeat('ab', 32), 'hex')`
	h.exec(`UPDATE ctrlz.nodes SET spki_sha256 = ` + key + ` WHERE id = '` + n3 + `'`)
	want(t, "the same key on a second node", h.seq("", nil, `UPDATE ctrlz.nodes SET spki_sha256 = `+key+` WHERE id = '`+n4+`'`), "23505")
	if got := h.one(`SELECT count(*) FROM ctrlz.node_spki_retired`); got != 0 {
		t.Errorf("%d retired keys before anything left, want 0", got)
	}
	h.exec(`UPDATE ctrlz.nodes SET status = 'active' WHERE id = '` + n3 + `'`)
	h.exec(`UPDATE ctrlz.nodes SET status = 'revoked' WHERE id = '` + n3 + `'`)
	if got := h.one(`SELECT count(*) FROM ctrlz.node_spki_retired WHERE spki_sha256 = ` + key); got != 1 {
		t.Errorf("a revoked node's key is retired %d times, want once", got)
	}
	// Removing the revoked row leaves the retired key, and a key can then not return as a node row's key through the route's check.
	h.exec(`DELETE FROM ctrlz.nodes WHERE id = '` + n3 + `'`)
	if got := h.one(`SELECT count(*) FROM ctrlz.node_spki_retired WHERE spki_sha256 = ` + key); got != 1 {
		t.Errorf("after the removal the key is retired %d times, want once (ON CONFLICT DO NOTHING)", got)
	}
	// A node removed before it was ever revoked retires its key too, and a node with no key retires nothing.
	h.exec(`UPDATE ctrlz.nodes SET spki_sha256 = decode(repeat('cd', 32), 'hex') WHERE id = '` + n4 + `'`)
	n5 := h.addNode(3, "pending", "192.0.2.5")
	h.exec(`DELETE FROM ctrlz.nodes WHERE id IN ('` + n4 + `', '` + n5 + `')`)
	if got := h.one(`SELECT count(*) FROM ctrlz.node_spki_retired`); got != 2 {
		t.Errorf("%d retired keys, want 2", got)
	}
	// The admin may read the retired keys and add one (the trigger runs with the writer's rights), and nobody else holds the table.
	if got, code := h.texts("admin", nil, `SELECT count(*)::text FROM ctrlz.node_spki_retired`); code != "" || got[0] != "2" {
		t.Errorf("the admin reads %v (%q), want 2", got, code)
	}
	for _, r := range []string{"hub", "worker", "compiler", "tenant"} {
		want(t, r+" reads node_spki_retired", h.seq(r, nil, `SELECT 1 FROM ctrlz.node_spki_retired`), "42501")
	}
	// The status CHECK of draining on an insert.
	want(t, "an insert in the state draining", h.seq("", nil, `INSERT INTO ctrlz.nodes (slot, name, status) VALUES (3, 'd', 'draining')`), "23514")
}

// TestP4NodePairsOnePeer: (A, B) beside (B, A) is accepted, (A, B) beside (A, C) is refused at the commit in one
// transaction and in two concurrent ones, as the admin who writes the table and so needs the lock's EXECUTE.
func TestP4NodePairsOnePeer(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	n3 := h.addNode(3, "active", "192.0.2.3")
	n4 := h.addNode(4, "active", "192.0.2.4")
	c1, c2 := nodeC1, nodeC2
	pair := func(a, b string) string {
		return fmt.Sprintf(`INSERT INTO ctrlz.node_pairs (primary_node_id, fallback_node_id) VALUES ('%s', '%s')`, a, b)
	}
	// The seeded pair is (c1, c2).
	for _, role := range []string{"", "admin"} {
		who := "owner"
		if role != "" {
			who = role
		}
		want(t, who+": (c1,c2) beside (c1,c3)", h.commitAs(h.super, role, pair(c1, n3)), "23514")
		want(t, who+": (c1,c2) beside (c3,c2)", h.commitAs(h.super, role, pair(n3, c2)), "23514")
		want(t, who+": (c1,c2) beside (c3,c1)", h.commitAs(h.super, role, pair(n3, c1)), "23514")
		want(t, who+": (c1,c2) beside (c2,c3)", h.commitAs(h.super, role, pair(c2, n3)), "23514")
		// Two statements of one transaction that together break the rule are caught by the one check at commit.
		want(t, who+": two new pairs that share a node", h.commitAs(h.super, role, pair(n3, n4), pair(n3, c1)), "23514")
	}
	// The reverse pair and a pair of two free nodes are accepted; a pair can be swapped inside one transaction.
	want(t, "(c1,c2) beside (c2,c1)", h.commitAs(h.super, "admin", pair(c2, c1)), "")
	want(t, "a pair of two free nodes", h.commitAs(h.super, "admin", pair(n3, n4)), "")
	want(t, "the rule with one node paired twice with the same peer", h.commitAs(h.super, "admin", pair(n4, n3)), "")
	if got := h.one(`SELECT count(*) FROM ctrlz.node_pairs`); got != 4 {
		t.Errorf("%d pairs, want the seeded one and three accepted", got)
	}
	// Dissolving a pair is the admin's (D on node_pairs), and the global pair's foreign key refuses it.
	want(t, "the admin deletes the global pair", h.commitAs(h.super, "admin", `DELETE FROM ctrlz.node_pairs WHERE primary_node_id = '`+c1+`' AND fallback_node_id = '`+c2+`'`), "23503")
	want(t, "the admin dissolves a pair no Endpoint uses", h.commitAs(h.super, "admin", `DELETE FROM ctrlz.node_pairs WHERE primary_node_id = '`+n3+`'`), "")
	want(t, "the hub deletes a pair", h.seq("hub", nil, `DELETE FROM ctrlz.node_pairs WHERE primary_node_id = '`+n4+`'`), "42501")

	// Two transactions that commit at the same time, each valid alone: exactly one may win. Free the four nodes first.
	h.exec(`UPDATE ctrlz.public_settings SET global_pair_id = NULL`)
	h.exec(`DELETE FROM ctrlz.node_pairs`)
	second := h.fresh()
	var wg sync.WaitGroup
	codes := make([]string, 2)
	conns := []*pgx.Conn{h.super, second}
	stmts := []string{pair(c1, c2), pair(c1, n3)}
	txs := make([]pgx.Tx, 2)
	for i := range txs {
		tx, err := conns[i].Begin(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		txs[i] = tx
		if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_admin"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(h.ctx, stmts[i]); err != nil {
			t.Fatal(err)
		}
	}
	for i := range txs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := txs[i].Commit(h.ctx); err != nil {
				if pe := pgErr(err); pe != nil {
					codes[i] = pe.Code
					return
				}
				codes[i] = err.Error()
			}
		}(i)
	}
	wg.Wait()
	ok, refused := 0, 0
	for _, c := range codes {
		switch c {
		case "":
			ok++
		case "23514":
			refused++
		default:
			t.Errorf("a concurrent commit failed with %q", c)
		}
	}
	if ok != 1 || refused != 1 {
		t.Errorf("two concurrent pairs that share a node: %d accepted, %d refused (%v), want one of each", ok, refused, codes)
	}
}

// TestP4UpstreamLoops: upstream_udp_ip and the node_upstreams CHECKs, and node_upstreams_no_loop from both sides.
func TestP4UpstreamLoops(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	up := func(kind, address, bootstrap string) string {
		b := "NULL"
		if bootstrap != "" {
			b = "'" + bootstrap + "'"
		}
		return fmt.Sprintf(`INSERT INTO ctrlz.node_upstreams (node_id, group_name, position, kind, address, bootstrap_ip, tls_name)
			VALUES ('%s', 'g', (SELECT coalesce(max(position), -1) + 1 FROM ctrlz.node_upstreams WHERE node_id = '%s' AND group_name = 'g'), '%s', '%s', %s, 'x.test')`,
			nodeC1, nodeC1, kind, address, b)
	}
	for addr, ip := range map[string]string{
		"192.0.2.50:53": "192.0.2.50", "[2001:db8::7]:853": "2001:db8::7", "203.0.113.1:65535": "203.0.113.1",
		"192.0.2.50": "", "192.0.2.50:0": "", "192.0.2.50:65536": "", "999.0.0.1:53": "", "[2001:db8::7]": "", "host.test:53": "", "192.0.2.50/24:53": "", "": "",
	} {
		got, code := h.texts("admin", nil, `SELECT coalesce(ctrlz.upstream_udp_ip($1)::text, 'NULL')`, addr)
		if code != "" || len(got) != 1 {
			t.Errorf("upstream_udp_ip(%q): %v %q", addr, got, code)
			continue
		}
		w := ip
		if w == "" {
			w = "NULL"
		}
		if got[0] != w {
			t.Errorf("upstream_udp_ip(%q) = %s, want %s", addr, got[0], w)
		}
	}
	want(t, "a udp upstream", h.commitAs(h.super, "admin", up("udp", "192.0.2.50:53", "")), "")
	want(t, "a udp address with no port", h.seq("admin", nil, up("udp", "192.0.2.51", "")), "23514")
	want(t, "a udp address in the 6to4 form", h.seq("admin", nil, up("udp", "[2002:c000:201::1]:53", "")), "23514")
	want(t, "a bootstrap address in the NAT64 form", h.seq("admin", nil, up("doh", "https://x.test/dns", "64:ff9b::192.0.2.1")), "23514")
	want(t, "a bootstrap address in the mapped form", h.seq("admin", nil, up("dot", "x.test:853", "::ffff:192.0.2.9")), "23514")
	want(t, "a doh upstream with a plain bootstrap address", h.commitAs(h.super, "admin", up("doh", "https://x.test/dns", "192.0.2.60")), "")
	want(t, "a doh upstream with no bootstrap address", h.seq("admin", nil, up("doh", "https://x.test/dns", "")), "23514")
	want(t, "the hub writes an upstream", h.seq("hub", nil, up("udp", "192.0.2.52:53", "")), "42501")

	// From the upstream side: the address of a node (advertised or bind, any port) is a loop. Node c1 is 192.0.2.1.
	want(t, "a udp upstream on a node's address, port 53", h.commitAs(h.super, "admin", up("udp", "192.0.2.1:53", "")), "23514")
	want(t, "a udp upstream on a node's address, another port", h.commitAs(h.super, "admin", up("udp", "192.0.2.2:5353", "")), "23514")
	want(t, "a bootstrap address that is a node's", h.commitAs(h.super, "admin", up("doh", "https://x.test/dns", "192.0.2.1")), "23514")
	h.exec(`UPDATE ctrlz.nodes SET dns_bind_ip = '10.0.0.5' WHERE id = '` + nodeC2 + `'`)
	want(t, "a udp upstream on a node's bind address", h.commitAs(h.super, "admin", up("udp", "10.0.0.5:53", "")), "23514")
	// From the node side: an address edit or a new node that makes an existing upstream a loop.
	want(t, "an address edit onto an upstream", h.commitAs(h.super, "admin", `UPDATE ctrlz.nodes SET dns_advertised_ip = '192.0.2.50' WHERE id = '`+nodeC1+`'`), "23514")
	want(t, "an address edit onto an upstream's bootstrap", h.commitAs(h.super, "admin", `UPDATE ctrlz.nodes SET dns_advertised_ip = '192.0.2.60' WHERE id = '`+nodeC1+`'`), "23514")
	n3 := "00000000-0000-7000-8000-0000000000c3"
	want(t, "a new node on an upstream's address", h.commitAs(h.super, "admin",
		`INSERT INTO ctrlz.nodes (id, slot, name, dns_advertised_ip) VALUES ('`+n3+`', 3, 'n3', '192.0.2.50')`), "23514")
	want(t, "an address edit to a free address", h.commitAs(h.super, "admin", `UPDATE ctrlz.nodes SET dns_advertised_ip = '192.0.2.70' WHERE id = '`+nodeC1+`'`), "")
	// The address can move from an upstream to a node in one transaction, because the check is deferred.
	want(t, "an upstream moved off an address and a node onto it", h.commitAs(h.super, "admin",
		`DELETE FROM ctrlz.node_upstreams WHERE address = '192.0.2.50:53'`, `UPDATE ctrlz.nodes SET dns_advertised_ip = '192.0.2.50' WHERE id = '`+nodeC2+`'`), "")

	// A heartbeat write neither fires the trigger nor waits for its lock.
	holder := h.fresh()
	tx, err := holder.Begin(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(h.ctx)
	if _, err := tx.Exec(h.ctx, `SELECT ctrlz_fn.node_upstreams_lock()`); err != nil {
		t.Fatal(err)
	}
	hubConn := h.fresh()
	done2 := make(chan string, 1)
	go func() {
		c := hubConn
		done2 <- h.commitAs(c, "hub", `UPDATE ctrlz.nodes SET last_heartbeat_at = now(), applied_seq = 7 WHERE id = '`+nodeC1+`'`)
	}()
	select {
	case code := <-done2:
		want(t, "the hub's heartbeat while the lock is held", code, "")
	case <-time.After(5 * time.Second):
		t.Error("a heartbeat write waited for the upstream loop lock")
	}
	// Nobody but the admin can take either lock.
	for _, r := range []string{"hub", "worker", "tenant", "compiler"} {
		want(t, r+" takes the pair lock", h.seq(r, nil, `SELECT ctrlz_fn.node_pairs_lock()`), "42501")
	}
}

// TestP4FreeDNS: the version trigger, the CHECKs, the grants, the counters and free_dns_public().
func TestP4FreeDNS(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	v := func() int64 {
		var n int64
		if err := h.super.QueryRow(h.ctx, `SELECT version FROM ctrlz.free_dns_settings`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	ms := time.Now().UnixMilli()
	v0 := v()
	if v0 < ms-24*3600*1000 {
		t.Errorf("the first version %d is not the clock in milliseconds (%d)", v0, ms)
	}
	h.exec(`UPDATE ctrlz.free_dns_settings SET enabled = false`)
	v1 := v()
	h.exec(`UPDATE ctrlz.free_dns_settings SET enabled = true`) // a revert
	v2 := v()
	if !(v1 > v0 && v2 > v1) {
		t.Errorf("versions %d, %d, %d: each write, a revert included, must raise the version", v0, v1, v2)
	}
	// A version written by hand is ignored: the trigger sets it, so a version restored below the clock is raised above it.
	h.exec(`UPDATE ctrlz.free_dns_settings SET version = 5`)
	if got := v(); got < time.Now().UnixMilli()-60000 {
		t.Errorf("a restored version 5 became %d, below the clock", got)
	}
	if n := h.one(`SELECT count(*) FROM ctrlz.free_dns_settings`); n != 1 {
		t.Errorf("%d settings rows, want the one", n)
	}
	want(t, "a second settings row", h.seq("", nil, `INSERT INTO ctrlz.free_dns_settings (singleton) VALUES (false)`), "23514")
	want(t, "qps 0", h.seq("", nil, `UPDATE ctrlz.free_dns_settings SET qps = 0`), "23514")
	want(t, "qps above the wire maximum", h.seq("", nil, `UPDATE ctrlz.free_dns_settings SET qps = 50001`), "23514")
	want(t, "qps 1", h.seq("", nil, `UPDATE ctrlz.free_dns_settings SET qps = 1`), "")
	want(t, "the admin sets enabled and qps", h.seq("admin", nil, `UPDATE ctrlz.free_dns_settings SET enabled = false, qps = 1500`), "")
	want(t, "the admin writes the version", h.seq("admin", nil, `UPDATE ctrlz.free_dns_settings SET version = 1`), "42501")
	want(t, "the hub writes the settings", h.seq("hub", nil, `UPDATE ctrlz.free_dns_settings SET enabled = false`), "42501")
	want(t, "the hub reads enabled and version", h.seq("hub", nil, `SELECT enabled, version FROM ctrlz.free_dns_settings`), "")
	want(t, "the hub reads qps", h.seq("hub", nil, `SELECT qps FROM ctrlz.free_dns_settings`), "42501")
	want(t, "the compiler reads the three", h.seq("compiler", nil, `SELECT enabled, qps, version FROM ctrlz.free_dns_settings`), "")
	want(t, "the tenant reads the settings", h.seq("tenant", nil, `SELECT enabled FROM ctrlz.free_dns_settings`), "42501")

	// The counters: the hub adds, the admin reads, the worker sweeps by hour and cannot read the counts.
	row := func(proto, outcome string, rcode, count int) string {
		return fmt.Sprintf(`INSERT INTO ctrlz.free_dns_counters (node_id, bucket_start, protocol, outcome, rcode, count)
			VALUES ('%s', date_trunc('hour', now()), '%s', '%s', %d, %d)`, nodeC1, proto, outcome, rcode, count)
	}
	want(t, "the hub adds a counter", h.seq("hub", nil, row("udp", "answered", 0, 5)), "")
	want(t, "a counter over tcp", h.seq("hub", nil, row("tcp", "rate_limited", 2, 5)), "")
	want(t, "a counter over dot", h.seq("hub", nil, row("dot", "answered", 0, 5)), "23514")
	want(t, "an rcode above BADCOOKIE", h.seq("hub", nil, row("udp", "answered", 24, 5)), "23514")
	want(t, "a negative count", h.seq("hub", nil, row("udp", "answered", 0, -1)), "23514")
	want(t, "an outcome that is not a word", h.seq("hub", nil, row("udp", "Has Space", 0, 1)), "23514")
	want(t, "the same key twice", h.seq("hub", nil, row("udp", "answered", 0, 5), row("udp", "answered", 0, 5)), "23505")
	want(t, "the hub adds into an hour", h.seq("hub", nil, row("udp", "answered", 0, 5),
		`UPDATE ctrlz.free_dns_counters SET count = count + 3 WHERE node_id = '`+nodeC1+`'`), "")
	want(t, "the admin adds a counter", h.seq("admin", nil, row("udp", "answered", 0, 5)), "42501")
	want(t, "the admin reads the counters", h.seq("admin", nil, `SELECT * FROM ctrlz.free_dns_counters`), "")
	want(t, "the worker sweeps the counters", h.seq("worker", nil, `DELETE FROM ctrlz.free_dns_counters WHERE bucket_start < now() - interval '30 days'`), "")
	want(t, "the worker reads the counts", h.seq("worker", nil, `SELECT count FROM ctrlz.free_dns_counters`), "42501")
	batch := func(id int, bucket string) string {
		return fmt.Sprintf(`INSERT INTO ctrlz.free_dns_counter_batches (node_id, batch_id, bucket_start) VALUES ('%s', %d, %s)`, nodeC1, id, bucket)
	}
	want(t, "a batch", h.seq("hub", nil, batch(1, `date_trunc('hour', now())`)), "")
	want(t, "the same batch twice", h.seq("hub", nil, batch(1, `date_trunc('hour', now())`), batch(1, `date_trunc('hour', now())`)), "23505")
	want(t, "a second batch of the same bucket", h.seq("hub", nil, batch(1, `date_trunc('hour', now())`), batch(2, `date_trunc('hour', now())`)), "23505")
	want(t, "a batch of another node for the same bucket", h.seq("hub", nil, batch(1, `date_trunc('hour', now())`),
		fmt.Sprintf(`INSERT INTO ctrlz.free_dns_counter_batches (node_id, batch_id, bucket_start) VALUES ('%s', 1, date_trunc('hour', now()))`, nodeC2)), "")
	want(t, "the worker sweeps the batches", h.seq("worker", nil, `DELETE FROM ctrlz.free_dns_counter_batches WHERE received_at < now() - interval '30 days'`), "")
	// free_dns_public(): the switch and the global pair's advertised addresses, as the tenant role calls it.
	pub := func(prep ...string) string {
		var out string
		tx, err := h.super.Begin(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(h.ctx)
		for _, s := range prep {
			if _, err := tx.Exec(h.ctx, s); err != nil {
				t.Fatalf("%s: %v", s, err)
			}
		}
		if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_tenant"); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(h.ctx, `SELECT format('%s|%s|%s', enabled, coalesce(primary_dns_ip::text, '-'), coalesce(fallback_dns_ip::text, '-')) FROM ctrlz_fn.free_dns_public()`).Scan(&out); err != nil {
			t.Fatalf("free_dns_public: %v", err)
		}
		return out
	}
	h.exec(`UPDATE ctrlz.free_dns_settings SET enabled = true`)
	if got := pub(); got != "true|192.0.2.1/32|192.0.2.2/32" && got != "true|192.0.2.1|192.0.2.2" {
		t.Errorf("free_dns_public() = %q, want the two advertised addresses of the global pair", got)
	}
	if got := pub(`UPDATE ctrlz.free_dns_settings SET enabled = false`); !strings.HasPrefix(got, "false|") {
		t.Errorf("free_dns_public() with the switch off = %q", got)
	}
	if got := pub(`UPDATE ctrlz.nodes SET status = 'revoked' WHERE id = '` + nodeC2 + `'`); !strings.HasSuffix(got, "|-") || strings.Contains(got, "|-|") {
		t.Errorf("free_dns_public() with the fallback revoked = %q, want its address NULL and the primary's kept", got)
	}
	if got := pub(`UPDATE ctrlz.public_settings SET global_pair_id = NULL`); !strings.HasSuffix(got, "|-|-") {
		t.Errorf("free_dns_public() with no global pair = %q, want both NULL", got)
	}
	for _, r := range []string{"hub", "worker", "compiler", "admin"} {
		want(t, r+" calls free_dns_public", h.seq(r, nil, `SELECT * FROM ctrlz_fn.free_dns_public()`), "42501")
	}
}
