package catalogtest_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// More tests of migration 0100: the enrolment record and its trigger, the policies of certificates, the
// domain settings and the apply role, and the grants of the hub, the admin, the worker and the compiler that
// the spec gives them, with two tenants wherever a row belongs to one.

// afterPrep runs prep as the superuser, then one query as role, in a transaction that is rolled back. It
// returns the first column of the first row as text, or the SQLSTATE of a failure.
func (h *harness) afterPrep(role string, prep []string, sql string, args ...any) (string, string) {
	h.t.Helper()
	tx, err := h.super.Begin(h.ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	defer tx.Rollback(h.ctx)
	for _, s := range prep {
		if _, err := tx.Exec(h.ctx, s); err != nil {
			h.t.Fatalf("%s: %v", s, err)
		}
	}
	if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE "+pgx.Identifier{"ctrlz_" + role}.Sanitize()); err != nil {
		h.t.Fatal(err)
	}
	var out *string
	if err := tx.QueryRow(h.ctx, sql, args...).Scan(&out); err != nil {
		if pe := pgErr(err); pe != nil {
			return "", pe.Code
		}
		h.t.Fatalf("%s: %v", sql, err)
	}
	if out == nil {
		return "NULL", ""
	}
	return *out, ""
}

// newEnrolment adds a token row as the superuser and returns its id.
func (h *harness) newEnrolment() string {
	h.t.Helper()
	var id string
	if err := h.super.QueryRow(h.ctx, `INSERT INTO ctrlz.node_enrollments (token_hash, expires_at)
		VALUES (sha256(convert_to(gen_random_uuid()::text, 'UTF8')), now() + interval '15 minutes') RETURNING id::text`).Scan(&id); err != nil {
		h.t.Fatal(err)
	}
	return id
}

// recordSQL is Enroll: the whole record and the move to pending_approval in one statement. spki is 32 bytes of
// 0xab, and the fingerprint is its hex.
func recordSQL(id string, set ...string) string {
	cols := map[string]string{
		"state": `'pending_approval'`, "csr_der": `'\x3000'::bytea`, "spki_sha256": `decode(repeat('ab', 32), 'hex')`, "key_fingerprint": `repeat('ab', 32)`,
		"dns_bind_ip": `'10.0.0.5'`, "dns_advertised_ip": `'192.0.2.9'`, "proxy_bind_ip": `'10.0.0.5'`, "proxy_advertised_ip": `'192.0.2.9'`,
		"hostname": `'node-1.example.test'`, "os_release": `'Ubuntu 24.04.1 LTS'`, "node_version": `'1.0.0'`, "enrolled_at": `now()`, "enrolled_from": `'198.51.100.7'`,
	}
	for i := 0; i+1 < len(set); i += 2 {
		if set[i+1] == "-" {
			delete(cols, set[i])
		} else {
			cols[set[i]] = set[i+1]
		}
	}
	var parts []string
	for k, v := range cols {
		parts = append(parts, k+" = "+v)
	}
	return fmt.Sprintf(`UPDATE ctrlz.node_enrollments SET %s WHERE id = '%s'`, strings.Join(parts, ", "), id)
}

// TestP4EnrolmentRecordIsFrozen: node_enrollments_frozen for every role, the CHECKs on the record and the column
// grants of the four parties that touch the table.
func TestP4EnrolmentRecordIsFrozen(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	id := h.newEnrolment()
	pending := func(id string) string { return recordSQL(id) }
	setState := func(id, st string) string {
		return fmt.Sprintf(`UPDATE ctrlz.node_enrollments SET state = '%s' WHERE id = '%s'`, st, id)
	}
	approve := func(id string) string {
		return fmt.Sprintf(`UPDATE ctrlz.node_enrollments SET state = 'approved', node_id = '%s' WHERE id = '%s'`, nodeC1, id)
	}

	// The moves.
	want(t, "Enroll writes the record", h.seq("", nil, pending(id)), "")
	want(t, "Enroll as the hub", h.seq("hub", nil, pending(id)), "")
	want(t, "the record twice", h.seq("", nil, pending(id), pending(id)), "") // the second write changes nothing
	want(t, "the record with another host name", h.seq("", nil, pending(id), recordSQL(id, "hostname", `'other.example.test'`)), "23514")
	want(t, "the record with another key", h.seq("", nil, pending(id), recordSQL(id, "spki_sha256", `decode(repeat('cd', 32), 'hex')`, "key_fingerprint", `repeat('cd', 32)`)), "23514")
	want(t, "the record with another address", h.seq("", nil, pending(id), recordSQL(id, "dns_advertised_ip", `'192.0.2.10'`)), "23514")
	want(t, "an address set after the record", h.seq("", nil, recordSQL(id, "proxy_advertised_ip", "-", "proxy_bind_ip", "-"), `UPDATE ctrlz.node_enrollments SET proxy_bind_ip = '10.0.0.6' WHERE id = '`+id+`'`), "23514")
	want(t, "an incomplete record", h.seq("", nil, recordSQL(id, "csr_der", "-")), "23514")
	want(t, "a record with no host name", h.seq("", nil, recordSQL(id, "hostname", "-")), "23514")
	want(t, "a record that holds a certificate", h.seq("", nil, recordSQL(id, "cert_der", `'\x3001'::bytea`)), "23514")
	want(t, "the proxy addresses are optional", h.seq("", nil, recordSQL(id, "proxy_bind_ip", "-", "proxy_advertised_ip", "-")), "")
	want(t, "issued to approved", h.seq("", nil, approve(id)), "23514")
	want(t, "issued to expired", h.seq("", nil, setState(id, "expired")), "")
	want(t, "issued to rejected", h.seq("", nil, setState(id, "rejected")), "")
	want(t, "expired to pending_approval", h.seq("", nil, setState(id, "expired"), pending(id)), "23514")
	want(t, "rejected to approved", h.seq("", nil, setState(id, "rejected"), approve(id)), "23514")
	want(t, "pending_approval back to issued", h.seq("", nil, pending(id), setState(id, "issued")), "23514")
	want(t, "pending_approval to expired", h.seq("", nil, pending(id), setState(id, "expired")), "")
	want(t, "pending_approval to rejected", h.seq("", nil, pending(id), setState(id, "rejected")), "")
	want(t, "approved without a node", h.seq("", nil, pending(id), setState(id, "approved")), "23514")
	want(t, "approved with a node", h.seq("", nil, pending(id), approve(id)), "")
	want(t, "approved to expired", h.seq("", nil, pending(id), approve(id), setState(id, "expired")), "23514")
	cert := func(v string) string {
		return fmt.Sprintf(`UPDATE ctrlz.node_enrollments SET cert_der = '%s'::bytea WHERE id = '%s'`, v, id)
	}
	want(t, "a certificate on an approved row", h.seq("", nil, pending(id), approve(id), cert(`\x3001`)), "")
	want(t, "the certificate changes", h.seq("", nil, pending(id), approve(id), cert(`\x3001`), cert(`\x3002`)), "23514")
	want(t, "the certificate cleared", h.seq("", nil, pending(id), approve(id), cert(`\x3001`), `UPDATE ctrlz.node_enrollments SET cert_der = NULL WHERE id = '`+id+`'`), "23514")
	want(t, "a certificate on a pending row", h.seq("", nil, pending(id), cert(`\x3001`)), "23514")
	want(t, "the record of an approved row changes", h.seq("", nil, pending(id), approve(id), recordSQL(id, "node_version", `'2.0.0'`)), "23514")

	// The CHECKs of the record.
	for _, c := range []struct{ what, col, val string }{
		{"a host name that starts with a hyphen", "hostname", `'-bad'`},
		{"a host name with an underscore", "hostname", `'bad_name'`},
		{"an empty host name", "hostname", `''`},
		{"a label of 64 characters", "hostname", `repeat('a', 64) || '.test'`},
		{"a host name of 254 bytes", "hostname", `repeat('a.', 127)`},
		{"a node version with a control character", "node_version", `'1.0' || chr(7)`},
		{"an OS release of 257 characters", "os_release", `repeat('x', 257)`},
		{"a request of 4097 bytes", "csr_der", `decode(repeat('00', 4097), 'hex')`},
		{"a key of 31 bytes", "spki_sha256", `decode(repeat('ab', 31), 'hex')`},
		{"a fingerprint that is not the key's", "key_fingerprint", `repeat('cd', 32)`},
	} {
		want(t, c.what, h.seq("", nil, recordSQL(id, c.col, c.val)), "23514")
	}
	want(t, "a host name in upper case", h.seq("", nil, recordSQL(id, "hostname", `'Node-1'`)), "")
	want(t, "a host name of 253 bytes", h.seq("", nil, recordSQL(id, "hostname", `substr(repeat('a.', 127), 1, 253)`)), "")

	// Who may write what.
	ins := func(extra string) string {
		return `INSERT INTO ctrlz.node_enrollments (token_hash, expires_at, bound_ip` + extra + `) VALUES (sha256(convert_to(gen_random_uuid()::text, 'UTF8')), now() + interval '15 minutes', '198.51.100.1'`
	}
	want(t, "the admin makes a token", h.seq("admin", nil, ins("")+")"), "")
	want(t, "the admin makes a row with a state", h.seq("admin", nil, ins(", state")+", 'approved')"), "42501")
	want(t, "the hub makes a row", h.seq("hub", nil, ins("")+")"), "42501")
	want(t, "the admin rejects a pending row", h.seq("admin", nil, pending(id), setState(id, "rejected")), "42501") // the record is the hub's: pending() is refused first
	want(t, "the admin writes the record", h.seq("admin", nil, recordSQL(id)), "42501")
	want(t, "the admin writes the token hash", h.seq("admin", nil, `UPDATE ctrlz.node_enrollments SET token_hash = '\x00' WHERE id = '`+id+`'`), "42501")
	want(t, "the hub writes the expiry", h.seq("hub", nil, `UPDATE ctrlz.node_enrollments SET expires_at = now() WHERE id = '`+id+`'`), "42501")
	want(t, "the hub writes the node", h.seq("hub", nil, `UPDATE ctrlz.node_enrollments SET node_id = '`+nodeC1+`' WHERE id = '`+id+`'`), "42501")
	want(t, "the hub writes the approval", h.seq("hub", nil, `UPDATE ctrlz.node_enrollments SET approved_by = NULL WHERE id = '`+id+`'`), "42501")
	want(t, "the hub reads the token hash", h.seq("hub", nil, `SELECT token_hash FROM ctrlz.node_enrollments`), "")
	want(t, "the admin reads the token hash", h.seq("admin", nil, `SELECT token_hash FROM ctrlz.node_enrollments`), "")
	// The admin decides on a row the hub has written.
	h.exec(pending(id))
	want(t, "the admin approves", h.seq("admin", nil, approve(id)), "")
	want(t, "the admin rejects", h.seq("admin", nil, `UPDATE ctrlz.node_enrollments SET state = 'rejected', rejected_at = now() WHERE id = '`+id+`'`), "")
	want(t, "the admin writes the certificate", h.seq("admin", nil, approve(id), cert(`\x3001`)), "42501")
	want(t, "the hub issues the certificate to an approved row", h.seq("", nil, approve(id), cert(`\x3001`)), "")
	// The worker expires and sweeps and never reads the token.
	old := h.newEnrolment()
	h.exec(`UPDATE ctrlz.node_enrollments SET expires_at = now() - interval '1 hour' WHERE id = '` + old + `'`)
	n, code := h.affected("worker", nil, `UPDATE ctrlz.node_enrollments SET state = 'expired' WHERE state = 'issued' AND expires_at < now()`)
	if code != "" || n != 1 {
		t.Errorf("the worker expires %d rows (%q), want 1", n, code)
	}
	want(t, "the worker reads the token hash", h.seq("worker", nil, `SELECT token_hash FROM ctrlz.node_enrollments`), "42501")
	want(t, "the worker reads the certificate and the node", h.seq("worker", nil, `SELECT id, state, expires_at, enrolled_at, node_id, cert_der FROM ctrlz.node_enrollments`), "")
	want(t, "the worker reads the record", h.seq("worker", nil, `SELECT hostname FROM ctrlz.node_enrollments`), "42501")
	want(t, "the worker sweeps", h.seq("worker", nil, `DELETE FROM ctrlz.node_enrollments WHERE state = 'expired' AND expires_at < now() - interval '7 days'`), "")
	want(t, "the worker writes the node", h.seq("worker", nil, `UPDATE ctrlz.node_enrollments SET node_id = NULL`), "42501")
	want(t, "the compiler reads an enrolment", h.seq("compiler", nil, `SELECT 1 FROM ctrlz.node_enrollments`), "42501")
	// An approved row goes with its node.
	extra := h.addNode(3, "pending", "192.0.2.33")
	e2 := h.newEnrolment()
	h.exec(pending(e2))
	h.exec(fmt.Sprintf(`UPDATE ctrlz.node_enrollments SET state = 'approved', node_id = '%s' WHERE id = '%s'`, extra, e2))
	h.exec(`DELETE FROM ctrlz.nodes WHERE id = '` + extra + `'`)
	if got := h.one(`SELECT count(*) FROM ctrlz.node_enrollments WHERE id = $1`, e2); got != 0 {
		t.Errorf("the approved enrolment of a removed node is still there")
	}
	// The quarantine report is stored once for (node, seq, item, reason).
	q := fmt.Sprintf(`INSERT INTO ctrlz.node_quarantine (node_id, seq, item, reason) VALUES ('%s', 5, 'filter:1', 'bad_hash')`, nodeC1)
	want(t, "a quarantine report twice", h.seq("", nil, q, q), "23505")
	want(t, "a report of another reason", h.seq("", nil, q, strings.Replace(q, "bad_hash", "bad_size", 1)), "")
	want(t, "the hub stores a report", h.seq("hub", nil, q), "")
}

// TestP4CertificatePolicies: every role sees and writes the rows of its own kinds, and nothing else.
func TestP4CertificatePolicies(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, r := range [][3]string{{"wildcard", "uploaded", "{dns.example.test,*.dns.example.test}"}, {"node_ca", "issued", "{}"}, {"zone_ca", "issued", "{dns.example.test}"},
		{"panel", "uploaded", "{panel.example.test}"}, {"admin", "uploaded", "{admin.example.test}"}, {"block_root", "issued", "{}"}} {
		h.exec(`INSERT INTO ctrlz.certificates (kind, chain_pem, wrapped_key_ct, not_before, not_after, state, source, names)
			VALUES ($1, 'pem', '\x01', now() - interval '1 day', now() + interval '60 days', 'active', $2, $3::text[])`, r[0], r[1], r[2])
	}
	kinds := func(role string) string {
		got, code := h.texts(role, nil, `SELECT kind FROM ctrlz.certificates ORDER BY kind`)
		if code != "" {
			return code
		}
		return strings.Join(got, ",")
	}
	for role, w := range map[string]string{
		"hub": "node_ca,wildcard,zone_ca", "tenant": "zone_ca", "domain_apply": "admin,panel",
		"admin": "admin,block_root,node_ca,panel,wildcard,zone_ca", "worker": "admin,block_root,node_ca,panel,wildcard,zone_ca",
		"compiler": "42501", "auth": "42501",
	} {
		if got := kinds(role); got != w {
			t.Errorf("%s sees %q, want %q", role, got, w)
		}
	}
	// The sealed key: the hub reads it for the rows it serves, the apply step for the two web certificates, nobody else.
	for role, w := range map[string]int{"hub": 3, "domain_apply": 2} {
		got, code := h.texts(role, nil, `SELECT count(wrapped_key_ct)::text FROM ctrlz.certificates`)
		if code != "" || got[0] != fmt.Sprint(w) {
			t.Errorf("%s reads %v (%q) sealed keys, want %d", role, got, code, w)
		}
	}
	for _, role := range []string{"admin", "worker", "tenant"} {
		want(t, role+" reads the sealed key", h.seq(role, nil, `SELECT wrapped_key_ct FROM ctrlz.certificates`), "42501")
	}
	want(t, "the tenant reads the chain", h.seq("tenant", nil, `SELECT chain_pem FROM ctrlz.certificates`), "42501")
	want(t, "the tenant reads the root time", h.seq("tenant", nil, `SELECT kind, state, not_before FROM ctrlz.certificates`), "")

	// ins builds an insert; extraCols and extraVals add one more column.
	ins := func(kind, source, state, extraCols, extraVals string) string {
		return fmt.Sprintf(`INSERT INTO ctrlz.certificates (kind, chain_pem, not_before, not_after, state, source%s)
			VALUES ('%s', 'pem', now(), now() + interval '30 days', '%s', '%s'%s)`, extraCols, kind, state, source, extraVals)
	}
	// The hub issues the private CAs' rows, and only issued ones.
	want(t, "the hub issues a node CA", h.seq("hub", nil, ins("node_ca", "issued", "active", "", "")), "")
	want(t, "the hub issues a zone CA", h.seq("hub", nil, ins("zone_ca", "issued", "active", ", names", ", '{dns.example.test}'")), "")
	want(t, "the hub inserts an uploaded zone CA", h.seq("hub", nil, ins("zone_ca", "uploaded", "active", "", "")), "42501")
	want(t, "the hub inserts a wildcard", h.seq("hub", nil, ins("wildcard", "issued", "active", "", "")), "42501")
	want(t, "the hub inserts a panel certificate", h.seq("hub", nil, ins("panel", "issued", "active", "", "")), "42501")
	want(t, "the hub inserts a sealed key", h.seq("hub", nil, ins("node_ca", "issued", "active", ", wrapped_key_ct", ", '\\x01'")), "42501")
	n, code := h.affected("hub", nil, `UPDATE ctrlz.certificates SET state = 'retired' WHERE kind = 'zone_ca'`)
	if code != "" || n != 1 {
		t.Errorf("the hub retires %d zone CA rows (%q), want 1", n, code)
	}
	n, code = h.affected("hub", nil, `UPDATE ctrlz.certificates SET state = 'retired' WHERE kind = 'wildcard'`)
	if code != "" || n != 0 {
		t.Errorf("the hub retires %d uploaded wildcard rows (%q), want 0: it reads them and may not change them", n, code)
	}
	want(t, "the hub rewrites a chain", h.seq("hub", nil, `UPDATE ctrlz.certificates SET chain_pem = 'x' WHERE kind = 'zone_ca'`), "42501")
	want(t, "the hub deletes a row", h.seq("hub", nil, `DELETE FROM ctrlz.certificates`), "42501")
	// The admin uploads active wildcard, panel and admin certificates and retires uploaded ones.
	want(t, "the admin uploads a wildcard", h.seq("admin", nil, ins("wildcard", "uploaded", "active", ", wrapped_key_ct", ", '\\x01'")), "")
	want(t, "the admin uploads a panel certificate", h.seq("admin", nil, ins("panel", "uploaded", "active", "", "")), "")
	want(t, "the admin uploads a node CA", h.seq("admin", nil, ins("node_ca", "uploaded", "active", "", "")), "42501")
	want(t, "the admin issues a row", h.seq("admin", nil, ins("wildcard", "issued", "active", "", "")), "42501")
	want(t, "the admin uploads a pending row", h.seq("admin", nil, ins("wildcard", "uploaded", "pending", "", "")), "42501")
	n, code = h.affected("admin", nil, `UPDATE ctrlz.certificates SET state = 'retired' WHERE kind = 'panel'`)
	if code != "" || n != 1 {
		t.Errorf("the admin retires %d panel rows (%q), want 1", n, code)
	}
	n, code = h.affected("admin", nil, `UPDATE ctrlz.certificates SET state = 'retired' WHERE source = 'issued'`)
	if code != "" || n != 0 {
		t.Errorf("the admin retires %d issued rows (%q), want 0", n, code)
	}
	want(t, "the admin rewrites a chain", h.seq("admin", nil, `UPDATE ctrlz.certificates SET chain_pem = 'x' WHERE kind = 'panel'`), "42501")
	want(t, "the apply step writes a certificate", h.seq("domain_apply", nil, `UPDATE ctrlz.certificates SET state = 'retired'`), "42501")
	want(t, "the apply step inserts a certificate", h.seq("domain_apply", nil, ins("panel", "uploaded", "active", "", "")), "42501")
	// The columns.
	want(t, "names in upper case", h.seq("", nil, `UPDATE ctrlz.certificates SET names = '{Example.COM}'`), "23514")
	want(t, "names in lower case", h.seq("", nil, `UPDATE ctrlz.certificates SET names = '{example.com}'`), "")
	want(t, "an unknown kind", h.seq("", nil, ins("bogus", "issued", "active", "", "")), "23514")
	want(t, "an unknown source", h.seq("", nil, ins("panel", "pasted", "active", "", "")), "23514")
}

// TestP4DomainSettings: the hostname CHECKs, the two writers, and the host the login page reads.
func TestP4DomainSettings(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	set := func(col, val string) string { return fmt.Sprintf(`UPDATE ctrlz.domain_settings SET %s = %s`, col, val) }
	for _, c := range []struct{ col, val, code string }{
		{"dns_zone", `'dns.example.test'`, ""}, {"dns_zone", `'dns.ctrlz.invalid'`, ""}, {"dns_zone", `'dns.xn--mgbh0fb.test'`, ""}, {"dns_zone", `NULL`, ""},
		{"dns_zone", `'example.test'`, "23514"}, {"dns_zone", `'dns.Example.test'`, "23514"}, {"dns_zone", `'dns.-a.test'`, "23514"},
		{"dns_zone", `'dns.a.test.'`, "23514"}, {"dns_zone", `'dns.a b.test'`, "23514"}, {"dns_zone", `'dns.' || repeat('a', 64) || '.test'`, "23514"},
		{"dns_zone", `'dns.a=b.test'`, "23514"}, {"dns_zone", "'dns.a\nb.test'", "23514"},
		{"prev_dns_zone", `'dns.old.test'`, ""}, {"prev_dns_zone", `'old.test'`, "23514"},
		{"panel_host", `'panel.example.test'`, ""}, {"panel_host", `'Panel.example.test'`, "23514"}, {"panel_host", `'panel.example.test:443'`, "23514"},
		{"admin_host", `'admin.example.test'`, ""}, {"admin_host", `'admin_x.example.test'`, "23514"},
		{"applied_panel_host", `'panel.example.test'`, ""}, {"applied_panel_host", `'a;b'`, "23514"},
		{"applied_admin_host", `'admin.example.test'`, ""}, {"applied_admin_host", `'$(x)'`, "23514"},
	} {
		want(t, c.col+" = "+c.val, h.seq("", nil, set(c.col, c.val)), c.code)
	}
	want(t, "an applied certificate that does not exist", h.seq("", nil, set("applied_panel_cert_id", `gen_random_uuid()`)), "23503")
	// The admin writes the request and its stamp; the apply step writes what is served.
	want(t, "the admin changes the zone", h.seq("admin", nil, `UPDATE ctrlz.domain_settings SET dns_zone = 'dns.example.test', prev_dns_zone = 'dns.old.test', transition_until = now(), changed_at = now(), panel_host = 'p.example.test', admin_host = 'a.example.test'`), "")
	for _, col := range []string{"applied_panel_host", "applied_admin_host", "applied_at"} {
		val := `now()`
		if strings.HasSuffix(col, "host") {
			val = `'x.example.test'`
		}
		want(t, "the admin writes "+col, h.seq("admin", nil, set(col, val)), "42501")
	}
	want(t, "the apply step writes the served hosts", h.seq("domain_apply", nil, `UPDATE ctrlz.domain_settings SET applied_panel_host = 'p.example.test', applied_admin_host = 'a.example.test', applied_at = now()`), "")
	for _, col := range []string{"dns_zone", "panel_host", "admin_host", "prev_dns_zone", "changed_at"} {
		val := `'dns.x.test'`
		switch col {
		case "panel_host", "admin_host":
			val = `'x.test'`
		case "changed_at":
			val = `now()`
		}
		want(t, "the apply step writes "+col, h.seq("domain_apply", nil, set(col, val)), "42501")
	}
	want(t, "the apply step reads the settings", h.seq("domain_apply", nil, `SELECT * FROM ctrlz.domain_settings`), "")
	want(t, "the apply step reads a tenant table", h.seq("domain_apply", nil, `SELECT 1 FROM ctrlz.tenants`), "42501")
	want(t, "the apply step reads the nodes", h.seq("domain_apply", nil, `SELECT 1 FROM ctrlz.nodes`), "42501")
	// The login page reads the host that is served, not the one that was asked for.
	req := []string{`UPDATE ctrlz.domain_settings SET panel_host = 'asked.example.test'`}
	if got, code := h.afterPrep("tenant", req, `SELECT coalesce(panel_host, '-') FROM ctrlz_fn.auth_public_config()`); code != "" || got != "-" {
		t.Errorf("auth_public_config before any apply: %q (%q), want no host", got, code)
	}
	served := append(req, `UPDATE ctrlz.domain_settings SET applied_panel_host = 'served.example.test'`)
	if got, code := h.afterPrep("tenant", served, `SELECT panel_host FROM ctrlz_fn.auth_public_config()`); code != "" || got != "served.example.test" {
		t.Errorf("auth_public_config after an apply: %q (%q), want the served host", got, code)
	}
	if got, code := h.afterPrep("tenant", served, `SELECT panel_host FROM ctrlz.domain_settings`); code != "" || got != "asked.example.test" {
		t.Errorf("the tenant reads %q (%q) from domain_settings, want the requested host (it keeps S on the table)", got, code)
	}
}

// TestP4HubWritesOnlyWhatTheSpecGives: the hub's learned rows and marks are bounded by restrictive policies
// under tenant_isolation, with two tenants, and the other grants of 3.2 item 9.
func TestP4HubWritesOnlyWhatTheSpecGives(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	A, B := h.A, h.B
	a, b := A.Tenant.String(), B.Tenant.String()
	learn := func(tenant, source string) string {
		return fmt.Sprintf(`INSERT INTO ctrlz.authorized_ips (tenant_id, endpoint_id, cidr, source, last_seen_at, learned_by_node_id)
			VALUES ('%s', '%s', '203.0.113.9/32', '%s', now(), '%s')`, tenant, A.Endpoint, source, nodeC1)
	}
	want(t, "the hub learns a secure_dns row", h.seq("hub", &a, learn(a, "secure_dns")), "")
	want(t, "the hub inserts a manual row", h.seq("hub", &a, learn(a, "manual")), "42501")
	want(t, "the hub inserts a ddns row", h.seq("hub", &a, learn(a, "ddns")), "42501")
	want(t, "the hub learns a row for another tenant", h.seq("hub", &a, learn(b, "secure_dns")), "42501")
	want(t, "the hub learns a row with no tenant setting", h.seq("hub", nil, learn(a, "secure_dns")), "42501")
	want(t, "the hub learns the same address twice", h.seq("hub", &a, learn(a, "secure_dns"), learn(a, "secure_dns")), "23505")
	// The reporting node is the hub's trace, not the tenant's: the tenant's own insert has no such column, and naming it or reading it is refused.
	tenantRow := fmt.Sprintf(`INSERT INTO ctrlz.authorized_ips (tenant_id, endpoint_id, cidr, source, last_seen_at)
		VALUES ('%s', '%s', '203.0.113.9/32', 'manual', now())`, a, A.Endpoint)
	want(t, "the tenant inserts a manual row", h.seq("tenant", &a, tenantRow), "")
	want(t, "the tenant names the learning node", h.seq("tenant", &a, learn(a, "manual")), "42501")
	want(t, "the tenant reads the learning node", h.seq("tenant", &a, `SELECT learned_by_node_id FROM ctrlz.authorized_ips`), "42501")
	want(t, "the tenant reads its rows by name", h.seq("tenant", &a, `SELECT id, cidr, source, last_seen_at FROM ctrlz.authorized_ips`), "")
	want(t, "the tenant reads every column of its rows", h.seq("tenant", &a, `SELECT * FROM ctrlz.authorized_ips`), "42501")
	if got, code := h.texts("hub", &a, `SELECT count(*)::text FROM ctrlz.authorized_ips WHERE source = 'manual'`); code != "" || got[0] != "1" {
		t.Errorf("the hub counts %v (%q) manual rows of tenant A, want its own one", got, code)
	}
	want(t, "the hub deletes a learned row", h.seq("hub", &a, `DELETE FROM ctrlz.authorized_ips`), "42501")

	mark := func(tenant, typ, agg string) string {
		return fmt.Sprintf(`INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id) VALUES ('%s', '%s', '%s', gen_random_uuid())`, tenant, typ, agg)
	}
	want(t, "the hub marks the endpoint_set of its tenant", h.seq("hub", &a, mark(a, "endpoint_set", a)), "")
	want(t, "the hub marks a profile", h.seq("hub", &a, mark(a, "profile", A.Profile.String())), "42501")
	want(t, "the hub marks the endpoint_set of another tenant", h.seq("hub", &a, mark(a, "endpoint_set", b)), "42501")
	want(t, "the hub marks for another tenant", h.seq("hub", &a, mark(b, "endpoint_set", b)), "42501")
	want(t, "the hub reads the outbox", h.seq("hub", &a, `SELECT 1 FROM ctrlz.policy_outbox`), "42501")

	client := func(tenant string) string {
		return fmt.Sprintf(`INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, source, first_seen_at, last_seen_at, created_by_node_id)
			VALUES ('%s', '%s', 'phone', 'auto', now(), now(), '%s')`, tenant, A.Endpoint, nodeC1)
	}
	want(t, "the hub adds an auto client", h.seq("hub", &a, client(a)), "")
	want(t, "the hub adds a client of another tenant", h.seq("hub", &a, client(b)), "42501")
	want(t, "the tenant names the creating node of a client", h.seq("tenant", &a, client(a)), "42501")
	want(t, "the tenant reads the creating node of a client", h.seq("tenant", &a, `SELECT created_by_node_id FROM ctrlz.clients`), "42501")
	want(t, "the tenant adds a client with no creating node", h.seq("tenant", &a, `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, source) VALUES ('`+a+`', '`+A.Endpoint.String()+`', 'laptop', 'manual')`), "")
	if got, code := h.texts("hub", &a, `SELECT count(*)::text FROM ctrlz.clients WHERE source = 'auto'`); code != "" || got[0] != "1" {
		t.Errorf("the hub counts %v (%q) auto clients of tenant A, want the seeded one", got, code)
	}
	want(t, "the hub reads the endpoint's switch", h.seq("hub", &a, `SELECT authorize_secure_dns FROM ctrlz.endpoints`), "")
	want(t, "the hub reads the endpoint's name", h.seq("hub", &a, `SELECT name FROM ctrlz.endpoints`), "42501")

	// A proof observation names the node: the hub updates only the challenge of the tenant of its setting.
	obs := func(claim string) string {
		return fmt.Sprintf(`UPDATE ctrlz.ip_proof_challenges SET observed_by_node_id = '%s' WHERE claim_id = '%s'`, nodeC1, claim)
	}
	if n, code := h.affected("hub", &a, obs(A.Claim.String())); code != "" || n != 1 {
		t.Errorf("the hub marks %d challenges of tenant A (%q), want 1", n, code)
	}
	if n, code := h.affected("hub", &a, obs(B.Claim.String())); code != "" || n != 0 {
		t.Errorf("the hub marks %d challenges of tenant B under A's setting (%q), want 0", n, code)
	}
	want(t, "the hub reads the claim of a challenge", h.seq("hub", &a, `SELECT claim_id FROM ctrlz.ip_proof_challenges`), "")
	want(t, "the tenant reads the label", h.seq("tenant", &a, `SELECT label FROM ctrlz.ip_proof_challenges`), "")
	want(t, "the tenant reads the observing node", h.seq("tenant", &a, `SELECT observed_by_node_id FROM ctrlz.ip_proof_challenges`), "42501")

	// admin_jobs: the hub queues domain_change and nothing else; the admin queues the three new kinds.
	job := func(kind string) string {
		return fmt.Sprintf(`INSERT INTO ctrlz.admin_jobs (kind) VALUES ('%s') ON CONFLICT DO NOTHING`, kind)
	}
	want(t, "the hub queues domain_change", h.seq("hub", nil, job("domain_change")), "")
	want(t, "the hub queues domain_change twice", h.seq("hub", nil, job("domain_change"), job("domain_change")), "")
	for _, k := range []string{"registration_transition", "webauthn_rp_change", "pair_change", "node_revoked"} {
		want(t, "the hub queues "+k, h.seq("hub", nil, job(k)), "42501")
	}
	want(t, "the hub sets a job's state", h.seq("hub", nil, `INSERT INTO ctrlz.admin_jobs (kind, state) VALUES ('domain_change', 'done')`), "42501")
	for _, k := range []string{"pair_change", "domain_change", "node_revoked"} {
		want(t, "the admin queues "+k, h.seq("admin", nil, job(k)), "")
	}
	want(t, "an unknown job kind", h.seq("", nil, job("bogus")), "23514")
	want(t, "the worker reads the new kinds", h.seq("worker", nil, `SELECT kind, state FROM ctrlz.admin_jobs`), "")

	// node_dns_requests: the admin asks, the hub decides.
	req := func(cols, vals string) string {
		return fmt.Sprintf(`INSERT INTO ctrlz.node_dns_requests (node_id, kind%s) VALUES ('%s', 'hold'%s)`, cols, nodeC1, vals)
	}
	want(t, "the admin asks", h.seq("admin", nil, req(", requested_by", ", '00000000-0000-7000-8000-0000000000e1'")), "")
	for _, c := range []string{"state", "reason", "decided_at", "requested_at", "id"} {
		val := "'done'"
		switch c {
		case "decided_at", "requested_at":
			val = "now()"
		case "id":
			val = "gen_random_uuid()"
		}
		want(t, "the admin sets "+c, h.seq("admin", nil, req(", "+c, ", "+val)), "42501")
	}
	want(t, "an unknown kind of request", h.seq("", nil, strings.Replace(req("", ""), "'hold'", "'pause'", 1)), "23514")
	h.exec(req("", ""))
	want(t, "the hub decides", h.seq("hub", nil, `UPDATE ctrlz.node_dns_requests SET state = 'done', reason = 'ok', decided_at = now()`), "")
	want(t, "the hub writes an unknown state", h.seq("hub", nil, `UPDATE ctrlz.node_dns_requests SET state = 'later'`), "23514")
	want(t, "the hub writes a reason of 65 characters", h.seq("hub", nil, `UPDATE ctrlz.node_dns_requests SET reason = repeat('x', 65)`), "23514")
	want(t, "the hub rewrites the kind", h.seq("hub", nil, `UPDATE ctrlz.node_dns_requests SET kind = 'release'`), "42501")
	want(t, "the hub asks", h.seq("hub", nil, req("", "")), "42501")
	want(t, "the admin decides", h.seq("admin", nil, `UPDATE ctrlz.node_dns_requests SET state = 'done'`), "42501")
	spare := h.addNode(3, "pending", "192.0.2.44")
	h.exec(fmt.Sprintf(`INSERT INTO ctrlz.node_dns_requests (node_id, kind) VALUES ('%s', 'release')`, spare))
	h.exec(`DELETE FROM ctrlz.nodes WHERE id = '` + spare + `'`)
	if got := h.one(`SELECT count(*) FROM ctrlz.node_dns_requests WHERE node_id = $1`, spare); got != 0 {
		t.Errorf("the requests of a removed node are still there")
	}

	// pair_event_state: one row, the hub's.
	want(t, "the hub writes the event state", h.seq("hub", nil, `UPDATE ctrlz.pair_event_state SET version = 5, last_table = '\x01'`), "")
	want(t, "the hub writes the event state's stamp", h.seq("hub", nil, `UPDATE ctrlz.pair_event_state SET updated_at = now()`), "42501")
	want(t, "the admin writes the event state", h.seq("admin", nil, `UPDATE ctrlz.pair_event_state SET version = 5`), "42501")
	want(t, "the admin reads the event state", h.seq("admin", nil, `SELECT * FROM ctrlz.pair_event_state`), "")
	want(t, "the worker reads the event state", h.seq("worker", nil, `SELECT * FROM ctrlz.pair_event_state`), "42501")
	want(t, "a second event state row", h.seq("", nil, `INSERT INTO ctrlz.pair_event_state (singleton) VALUES (false)`), "23514")
	want(t, "a negative event version", h.seq("", nil, `UPDATE ctrlz.pair_event_state SET version = -1`), "23514")
}

// TestP4WorkerAndCompilerReads: the reads the log pruning and the pair bump need, with two tenants for the bump.
func TestP4WorkerAndCompilerReads(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a := h.A.Tenant.String()
	want(t, "the worker prunes the log", h.seq("worker", nil, `DELETE FROM ctrlz.config_log WHERE seq < 5`), "")
	want(t, "the worker reads the log's seq", h.seq("worker", nil, `SELECT seq FROM ctrlz.config_log`), "")
	want(t, "the worker reads the log's payload", h.seq("worker", nil, `SELECT payload FROM ctrlz.config_log`), "42501")
	want(t, "the worker reads the snapshots' seq", h.seq("worker", nil, `SELECT seq FROM ctrlz.config_snapshot`), "")
	want(t, "the worker deletes a snapshot", h.seq("worker", nil, `DELETE FROM ctrlz.config_snapshot`), "42501")
	want(t, "the worker sweeps artifacts", h.seq("worker", nil, `DELETE FROM ctrlz.policy_artifacts WHERE gc_after_seq < 5`), "")
	want(t, "the worker reads an artifact's GC fields", h.seq("worker", nil, `SELECT hash, store_ref, gc_after_seq FROM ctrlz.policy_artifacts`), "")
	want(t, "the worker reads an artifact's kind", h.seq("worker", nil, `SELECT kind FROM ctrlz.policy_artifacts`), "42501")
	want(t, "the compiler marks a catalog version failed", h.seq("compiler", nil, `UPDATE ctrlz.catalog_versions SET state = 'failed' WHERE false`), "")
	want(t, "the compiler rewrites a catalog key", h.seq("compiler", nil, `UPDATE ctrlz.catalog_versions SET key = '\x01' WHERE false`), "42501")
	// The pair bump reads and writes pair_version of the tenant of its setting only.
	if n, code := h.affected("worker", &a, `UPDATE ctrlz.endpoints SET pair_version = pair_version + 1`); code != "" || n != 1 {
		t.Errorf("the worker bumps %d endpoints under tenant A's setting (%q), want 1", n, code)
	}
	if got := h.one(`SELECT pair_version FROM ctrlz.endpoints WHERE id = $1`, h.B.Endpoint); got != 0 {
		t.Errorf("tenant B's pair_version is %d after A's bump, want it untouched", got)
	}
}

// TestP4NodeTakenClaims: the claims taken on one node's observations, across tenants, for the admin alone.
func TestP4NodeTakenClaims(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	// One instant for the claim and its challenge, as a take writes them (both now() of one transaction).
	taken := time.Now().UTC().Add(-time.Minute)
	for _, s := range []string{h.A.Tenant.String(), h.B.Tenant.String()} {
		h.exec(`UPDATE ctrlz.ip_claims SET proven_at = $2 WHERE tenant_id = $1`, s, taken)
		h.exec(`UPDATE ctrlz.ip_proof_challenges SET observed_by_node_id = $2, consumed_at = $3 WHERE tenant_id = $1`, s, nodeC1, taken)
	}
	list := func(node string, since int64, role string) ([]string, string) {
		return h.texts(role, nil, `SELECT tenant_id::text FROM ctrlz_fn.node_taken_claims($1::uuid, $2::bigint) ORDER BY tenant_id`, node, since)
	}
	got, code := list(nodeC1, 0, "admin")
	if code != "" || len(got) != 2 {
		t.Fatalf("the admin lists %v (%q), want the claims of both tenants", got, code)
	}
	if got, _ := list(nodeC2, 0, "admin"); len(got) != 0 {
		t.Errorf("another node's list holds %v, want none", got)
	}
	if got, _ := list(nodeC1, 4102444800, "admin"); len(got) != 0 {
		t.Errorf("a window that starts in 2100 holds %v, want none", got)
	}
	// A challenge a wrong code consumed (the fifth try) proved nothing: its claim was not taken at that time.
	h.exec(`UPDATE ctrlz.ip_claims SET proven_at = now() - interval '1 hour' WHERE tenant_id = $1`, h.B.Tenant)
	got, _ = list(nodeC1, 0, "admin")
	if len(got) != 1 || got[0] != h.A.Tenant.String() {
		t.Errorf("the list after B's challenge was consumed with no take holds %v, want tenant A's only", got)
	}
	for _, r := range []string{"tenant", "hub", "worker", "compiler", "domain_apply"} {
		_, code := list(nodeC1, 0, r)
		want(t, r+" lists the taken claims", code, "42501")
	}
	// The observation of a challenge is visible to ctrlz_auth only when a node made it: a challenge nobody observed is not listed.
	h.exec(`UPDATE ctrlz.ip_proof_challenges SET observed_by_node_id = NULL`)
	if got, _ := list(nodeC1, 0, "admin"); len(got) != 0 {
		t.Errorf("challenges no node observed are listed: %v", got)
	}
}
