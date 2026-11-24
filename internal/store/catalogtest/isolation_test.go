package catalogtest_test

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// rowsPer is how many seed rows each tenant has in a table.
func rowsPer(tbl string) int {
	if tbl == "profiles" {
		return 2 // a profile pair, for the endpoint and schedule keys
	}
	return 1
}

func pick(cond bool, yes, no int) int {
	if cond {
		return yes
	}
	return no
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// TestSeedCoversEveryTable is how a new tenant table without a fixture row is
// caught: the seed must leave the expected rows per tenant in every tenant
// table, and the behaviour tests below are generated from the same list.
func TestSeedCoversEveryTable(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, tbl := range h.fx.Tables.Tenant {
		key := h.fx.KeyColumn(tbl)
		for _, id := range []uuid.UUID{h.A.Tenant, h.B.Tenant} {
			var n int
			if err := h.super.QueryRow(h.ctx, "SELECT count(*) FROM "+ident(tbl)+" WHERE "+key+" = $1", id).Scan(&n); err != nil {
				t.Fatalf("%s: %v", tbl, err)
			}
			if n != rowsPer(tbl) {
				t.Errorf("%s has %d seed rows for tenant %s, want %d; add a row to seed.go", tbl, n, id, rowsPer(tbl))
			}
		}
	}
}

// TestTwoTenantIsolation is spec test 21, generated from tables.yaml and
// grants.yaml. For every tenant table and every role with a grant on it:
//
//   - with the setting at tenant A the role sees A's rows and not B's;
//   - UPDATE and DELETE touch A's rows and never B's;
//   - INSERT of a row that carries B's tenant id fails on WITH CHECK;
//   - an unset, empty or foreign setting sees nothing.
//
// The only exceptions are the roles a named policy deliberately lets read or
// write across tenants, and they are exactly the ones in policies.yaml.
func TestTwoTenantIsolation(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	third := uuid.Must(uuid.NewV7()).String()
	fresh := h.fresh()
	a, b := h.A.Tenant.String(), h.B.Tenant.String()

	for _, tbl := range h.fx.Tables.Tenant {
		key := h.fx.KeyColumn(tbl)
		q := ident(tbl)
		own := rowsPer(tbl)
		for _, role := range serviceRoles() {
			if len(h.privs[tbl][role]) == 0 {
				continue
			}
			t.Run(tbl+"/"+role, func(t *testing.T) {
				h.t = t

				if h.has(tbl, role, "SELECT") {
					all := h.namedAll(tbl, role, "SELECT")
					for _, c := range []struct {
						what string
						conn *pgx.Conn
						guc  *string
						want int
					}{
						{"tenant A", h.super, &a, pick(all, 2*own, own)},
						{"tenant B", h.super, &b, pick(all, 2*own, own)},
						{"a tenant with no rows", h.super, &third, pick(all, 2*own, 0)},
						{"an empty setting", h.super, str(""), pick(all, 2*own, 0)},
						{"an unset setting", fresh, nil, pick(all, 2*own, 0)},
					} {
						h.inTx(c.conn, role, c.guc, func(tx pgx.Tx) {
							n, err := count(h.ctx, tx, "SELECT count(*) FROM "+q)
							if err != nil {
								t.Errorf("select as %s with %s: %v", role, c.what, err)
							} else if n != c.want {
								t.Errorf("select as %s with %s sees %d rows, want %d", role, c.what, n, c.want)
							}
						})
					}
				}

				if cols, _ := h.privCols(tbl, role, "UPDATE"); len(cols) > 0 {
					// Prefer a column the role can also read, so SET c = c leaves
					// the data alone. Roles that write a column they cannot read
					// (the hub stamping last_seen_at) use SET c = DEFAULT on a
					// column that accepts it.
					col, setTo := "", ""
					sc, whole := h.privCols(tbl, role, "SELECT")
					for _, c := range cols {
						if whole || contains(sc, c) {
							col, setTo = c, pgx.Identifier{c}.Sanitize()
							break
						}
					}
					if col == "" {
						for _, c := range cols {
							if h.defaultable(tbl, c) {
								col, setTo = c, "DEFAULT"
								break
							}
						}
					}
					if col == "" {
						t.Fatalf("%s can update %v but no column can be set for the test", role, cols)
					}
					all := h.namedAll(tbl, role, "UPDATE")
					for _, c := range []struct {
						what string
						guc  *string
						want int64
					}{
						{"tenant A", &a, int64(pick(all, 2*own, own))},
						{"a tenant with no rows", &third, int64(pick(all, 2*own, 0))},
						{"an empty setting", str(""), int64(pick(all, 2*own, 0))},
					} {
						h.inTx(h.super, role, c.guc, func(tx pgx.Tx) {
							ct, err := tx.Exec(h.ctx, fmt.Sprintf("UPDATE %s SET %s = %s", q, pgx.Identifier{col}.Sanitize(), setTo))
							if err != nil {
								t.Errorf("update as %s with %s: %v", role, c.what, err)
							} else if ct.RowsAffected() != c.want {
								t.Errorf("update as %s with %s touched %d rows, want %d", role, c.what, ct.RowsAffected(), c.want)
							}
						})
					}
				}

				if h.has(tbl, role, "DELETE") {
					all := h.namedAll(tbl, role, "DELETE")
					// A tenant with no rows deletes nothing, unless a named policy
					// reaches across tenants by design.
					h.inTx(h.super, role, &third, func(tx pgx.Tx) {
						ct, err := tx.Exec(h.ctx, "DELETE FROM "+q)
						if err != nil {
							t.Errorf("delete as %s with a foreign setting: %v", role, err)
						} else if want := int64(pick(all, 2*own, 0)); ct.RowsAffected() != want {
							t.Errorf("delete as %s with a foreign setting removed %d rows, want %d", role, ct.RowsAffected(), want)
						}
					})
					// With A's setting, A's rows may go (or be held by a foreign
					// key), and B's rows must survive.
					h.inTx(h.super, role, &a, func(tx pgx.Tx) {
						if _, err := tx.Exec(h.ctx, "SAVEPOINT d"); err != nil {
							t.Fatal(err)
						}
						ct, err := tx.Exec(h.ctx, "DELETE FROM "+q)
						pe := pgErr(err)
						switch {
						case err == nil:
							if want := int64(pick(all, 2*own, ownDeletable(tbl, role, own))); ct.RowsAffected() != want {
								t.Errorf("delete as %s with tenant A removed %d rows, want %d", role, ct.RowsAffected(), want)
							}
						case pe != nil && (pe.Code == "23503" || pe.Code == "23001") && !all:
							// A dependent row of A's own blocks it. Not a leak.
						default:
							t.Errorf("delete as %s with tenant A: %v", role, err)
						}
						if err != nil {
							if _, err := tx.Exec(h.ctx, "ROLLBACK TO SAVEPOINT d"); err != nil {
								t.Fatal(err)
							}
						}
						if _, err := tx.Exec(h.ctx, "RESET ROLE"); err != nil {
							t.Fatal(err)
						}
						n, err := count(h.ctx, tx, "SELECT count(*) FROM "+q+" WHERE "+key+" = $1", h.B.Tenant)
						if err != nil {
							t.Fatal(err)
						}
						if want := pick(all, 0, own); n != want {
							t.Errorf("after delete as %s with tenant A, tenant B has %d rows, want %d", role, n, want)
						}
					})
				}

				if cols, _ := h.privCols(tbl, role, "INSERT"); len(cols) > 0 {
					all := h.namedAll(tbl, role, "INSERT")
					var rowB, rowA string
					if err := h.super.QueryRow(h.ctx, "SELECT to_jsonb(t)::text FROM "+q+" t WHERE "+key+" = $1 LIMIT 1", h.B.Tenant).Scan(&rowB); err != nil {
						t.Fatal(err)
					}
					if err := h.super.QueryRow(h.ctx, "SELECT to_jsonb(t)::text FROM "+q+" t WHERE "+key+" = $1 LIMIT 1", h.A.Tenant).Scan(&rowA); err != nil {
						t.Fatal(err)
					}
					idents := make([]string, len(cols))
					for i, c := range cols {
						idents[i] = pgx.Identifier{c}.Sanitize()
					}
					list := strings.Join(idents, ", ")
					stmt := fmt.Sprintf("INSERT INTO %[1]s (%[2]s) SELECT %[2]s FROM jsonb_populate_record(NULL::%[1]s, $1::jsonb)", q, list)

					// B's row, with A's setting: refused by WITH CHECK.
					h.inTx(h.super, role, &a, func(tx pgx.Tx) {
						_, err := tx.Exec(h.ctx, stmt, rowB)
						if all {
							if isRLSViolation(err) {
								t.Errorf("insert as %s of another tenant's row hit WITH CHECK, but a named policy allows it", role)
							}
						} else if !isRLSViolation(err) {
							t.Errorf("insert as %s of tenant B's row with tenant A's setting: %v, want a row-level security violation", role, err)
						}
					})
					// Positive control: A's own row passes WITH CHECK. It then
					// fails on the unique key, which proves the refusal above came
					// from the policy and not from a missing privilege.
					h.inTx(h.super, role, &a, func(tx pgx.Tx) {
						_, err := tx.Exec(h.ctx, stmt, rowA)
						if pe := pgErr(err); pe != nil && pe.Code == "42501" {
							t.Errorf("insert as %s of the tenant's own row was refused: %v", role, err)
						}
					})
				}
			})
		}
	}
}

// TestCompositeForeignKeys is spec test 22. For every foreign key between two
// tenant tables, a child that carries A's tenant id and points at B's parent is
// rejected. The statements run as the superuser, so row level security cannot
// be what stops them: only the composite key can.
func TestCompositeForeignKeys(t *testing.T) {
	c := testpg.Need(t, cluster)
	h := newHarness(t, c)
	rows, err := h.super.Query(h.ctx, `
SELECT cl.relname, pl.relname,
  (SELECT array_agg(a.attname::text ORDER BY k.ord) FROM unnest(c.conkey) WITH ORDINALITY k(attnum, ord) JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum),
  (SELECT array_agg(a.attname::text ORDER BY k.ord) FROM unnest(c.confkey) WITH ORDINALITY k(attnum, ord) JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.attnum),
  c.conname
FROM pg_constraint c JOIN pg_class cl ON cl.oid = c.conrelid JOIN pg_class pl ON pl.oid = c.confrelid
WHERE c.contype = 'f' AND c.connamespace = 'ctrlz'::regnamespace`)
	if err != nil {
		t.Fatal(err)
	}
	type fk struct {
		child, parent, name string
		ccols, pcols        []string
	}
	var fks []fk
	for rows.Next() {
		var f fk
		if err := rows.Scan(&f.child, &f.parent, &f.ccols, &f.pcols, &f.name); err != nil {
			t.Fatal(err)
		}
		fks = append(fks, f)
	}
	rows.Close()
	tested := 0
	for _, f := range fks {
		if !h.fx.IsTenant(f.child) || !h.fx.IsTenant(f.parent) || f.parent == "tenants" {
			continue
		}
		tested++
		t.Run(f.child+"/"+f.name, func(t *testing.T) {
			var set, sel []string
			for i, cc := range f.ccols {
				if cc == "tenant_id" {
					continue
				}
				set = append(set, pgx.Identifier{cc}.Sanitize())
				sel = append(sel, pgx.Identifier{f.pcols[i]}.Sanitize())
			}
			stmt := fmt.Sprintf("UPDATE %s SET (%s) = (SELECT %s FROM %s WHERE tenant_id = $1 LIMIT 1) WHERE tenant_id = $2",
				ident(f.child), strings.Join(set, ", "), strings.Join(sel, ", "), ident(f.parent))
			tx, err := h.super.Begin(h.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(h.ctx)
			_, err = tx.Exec(h.ctx, stmt, h.B.Tenant, h.A.Tenant)
			if err == nil {
				// A deferred key (foreign_keys.yaml) is checked at commit; ask for the check now, so it is the
				// key and not the end of the test that answers. Harmless for an immediate key.
				_, err = tx.Exec(h.ctx, "SET CONSTRAINTS ALL IMMEDIATE")
			}
			if pe := pgErr(err); pe == nil || pe.Code != "23503" {
				t.Errorf("pointing %s at tenant B's %s was not rejected by a foreign key: %v", f.child, f.parent, err)
			}
		})
	}
	// Every composite key in the fixture was exercised.
	want := 0
	for _, s := range h.fx.ForeignKeys.ForeignKeys {
		child, rest, _ := strings.Cut(s, "(")
		parent := strings.TrimSpace(strings.SplitN(strings.SplitN(rest, "->", 2)[1], "(", 2)[0])
		if h.fx.IsTenant(child) && h.fx.IsTenant(parent) && parent != "tenants" {
			want++
		}
	}
	if tested != want || want < 30 {
		t.Errorf("tested %d composite foreign keys, fixture has %d", tested, want)
	}
}

// TestForeignKeyToGlobalNeedsNoGrant is spec test 23: a tenant-role insert
// whose foreign key points at a global table works even when the role has no
// privilege on that table, because the referential check runs with the
// table owner's rights. The privilege is taken away inside the transaction.
func TestForeignKeyToGlobalNeedsNoGrant(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a := h.A.Tenant.String()
	tx, err := h.super.Begin(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(h.ctx)
	for _, tbl := range []string{"locations", "endpoint_types", "catalog_service"} {
		if _, err := tx.Exec(h.ctx, "REVOKE ALL ON "+ident(tbl)+" FROM ctrlz_tenant"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_tenant"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(h.ctx, "SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)", a); err != nil {
		t.Fatal(err)
	}
	// Probe: the role really cannot read the parent now.
	if _, err := tx.Exec(h.ctx, "SAVEPOINT p"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(h.ctx, "SELECT count(*) FROM "+ident("locations")); err == nil {
		t.Fatal("the grant on locations is still there; the test would prove nothing")
	}
	if _, err := tx.Exec(h.ctx, "ROLLBACK TO SAVEPOINT p"); err != nil {
		t.Fatal(err)
	}
	// rules.target_location_id -> locations
	if _, err := tx.Exec(h.ctx, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action, target_kind, target_location_id)
VALUES ($1, $2, 'fk.example.test', 'domain', 'redirect', 'location', '00000000-0000-7000-8000-0000000000a1')`, h.A.Tenant, h.A.Profile); err != nil {
		t.Errorf("foreign key to locations needed a grant: %v", err)
	}
	// profile_services.service_slug -> catalog_service
	if _, err := tx.Exec(h.ctx, `INSERT INTO ctrlz.profile_services (tenant_id, profile_id, service_slug, action) VALUES ($1, $2, 'youtube', 'block')`, h.A.Tenant, h.A.Profile2); err != nil {
		t.Errorf("foreign key to catalog_service needed a grant: %v", err)
	}
	// endpoints.type -> endpoint_types
	if _, err := tx.Exec(h.ctx, `INSERT INTO ctrlz.endpoints (tenant_id, name, type, resolver_id, profile_id) VALUES ($1, 'x', 'doh_client', $2, $3)`,
		h.A.Tenant, strings.Repeat("b", 26), h.A.Profile); err != nil {
		t.Errorf("foreign key to endpoint_types needed a grant: %v", err)
	}
}

// TestFunctionIsolation is spec 16.5 test 18 and rule isolation-success-coverage, generated
// from functions.yaml. Every SECURITY DEFINER function says in functions.yaml what it does with
// tenants (`isolation`), and the kind is checked against the body in the database, so a
// function cannot claim to be tenant-free while it names a tenant table, nor skip the fixture
// by calling itself something else. Then:
//
//   - tenant, key, create: a fixture brings B's call to success while A holds the very same
//     state; B's own rows must change (or, for a read, stay put) and A's rows must not move.
//   - tenant functions that take an id also get the call a request from B could make with A's
//     id: the same statement with the setting at B and A's id in the argument. It must be
//     refused and move nothing. A statement with its tenant predicate dropped answers a call
//     with B's own id exactly as before, which is why the success call alone proved nothing.
//   - none: the body names no tenant table.
//
// A function with no fixture, a fixture with no function, and a function with no kind all fail.
func TestFunctionIsolation(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	fixtures := h.fnFixtures()
	A, B := h.A, h.B

	bodies := map[string]string{}
	rows, err := h.super.Query(h.ctx, `SELECT p.proname, p.prosrc FROM pg_proc p WHERE p.pronamespace = 'ctrlz_fn'::regnamespace`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name, src string
		if err := rows.Scan(&name, &src); err != nil {
			t.Fatal(err)
		}
		bodies[name] = src
	}
	rows.Close()
	tenantRef := regexp.MustCompile(`\bctrlz\.(` + strings.Join(h.fx.Tables.Tenant, "|") + `)\b`)

	repl := strings.NewReplacer(
		A.Tenant.String(), "A.tenant", B.Tenant.String(), "B.tenant", A.User.String(), "A.user", B.User.String(), "B.user",
		A.Endpoint.String(), "A.endpoint", B.Endpoint.String(), "B.endpoint", A.Claim.String(), "A.claim", B.Claim.String(), "B.claim")

	known := map[string]bool{}
	for _, fn := range h.fx.Functions.SecurityDefiner {
		known[fn.Name] = true
		t.Run(fn.Name, func(t *testing.T) {
			h.t = t
			src, ok := bodies[fn.Name]
			if !ok {
				t.Fatalf("%s is in functions.yaml and not in the database", fn.Name)
			}
			fix, hasFixture := fixtures[fn.Name]
			problem, stop := classifyIsolation(fn, src, tenantRef, hasFixture)
			if problem != "" {
				t.Error(problem)
			}
			if problem != "" || stop {
				return
			}
			// A function that takes an id of a tenant row needs the call that names A's.
			takesID := strings.Contains(fn.Args, "uuid") || strings.Contains(fn.Args, "cidr")
			if fn.Isolation == "tenant" && takesID && fix.noCross {
				t.Fatalf("%s takes an id: it needs the cross call (B's setting, A's id), and noCross hides it", fn.Name)
			}
			role := fn.Execute[0]
			h.runFunctionCase(t, fn.Name, fix, role, fn.Isolation == "tenant", repl, B, B, fix.own, false, false)
			if fn.Isolation == "tenant" {
				// Every tenant function, once with no setting at all.
				h.runNoSettingCase(t, fn.Name, fix, role, repl, B)
			}
			if !fix.noCross {
				// Twice: as deployed, where row level security already keeps B off A's rows, and with
				// the definer role exempt from it, where the statement's own tenant predicate is the only
				// thing left. A predicate that row level security makes redundant is still a layer, and the
				// cross call is the only way to see that it is gone.
				h.runFunctionCase(t, fn.Name, fix, role, fn.Isolation == "tenant", repl, B, A, fix.cross, true, false)
				h.runFunctionCase(t, fn.Name, fix, role, fn.Isolation == "tenant", repl, B, A, fix.cross, true, true)
			}
		})
	}
	for name := range fixtures {
		if !known[name] {
			t.Errorf("a fixture exists for %s, which is not in functions.yaml", name)
		}
	}
}

// runFunctionCase runs one call in a transaction that is rolled back. caller is the tenant of
// the setting, subject the tenant whose ids the arguments carry.
func (h *harness) runFunctionCase(t *testing.T, fn string, fix fnFix, role string, withSetting bool, repl *strings.Replacer,
	caller, subject catalogtest.SeedIDs, want string, cross, noRLS bool) {
	t.Helper()
	what := "success call"
	if cross {
		what = "cross call (B's setting, A's id)"
		if noRLS {
			what = "cross call with row level security off for the definer"
		}
	}
	tx, err := h.super.Begin(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	f := &fnCtx{h: h, tx: tx, ids: map[string]uuid.UUID{}, repl: repl}
	if fix.arrange != nil {
		fix.arrange(f, h.A)
		fix.arrange(f, h.B)
	}
	if a, b := f.shape(h.A), f.shape(h.B); a != b {
		t.Fatalf("A is not in the same state as B before the %s, so it proves nothing:\nA: %s\nB: %s", what, a, b)
	}
	a0, b0 := f.digest(h.A), f.digest(h.B)
	if noRLS {
		// Transactional, like everything else here: the role is as it was when the case ends.
		if _, err := tx.Exec(h.ctx, "ALTER ROLE ctrlz_auth BYPASSRLS"); err != nil {
			t.Fatal(err)
		}
	}
	tenants0 := f.count(`SELECT count(*) FROM ctrlz.tenants`)

	args := []any(nil)
	if fix.args != nil {
		args = fix.args(caller, subject)
	}
	if ids, ok := f.argsWithIDs(fn, caller, subject); ok {
		args = ids
	}
	if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE "+pgx.Identifier{"ctrlz_" + role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if withSetting {
		if _, err := tx.Exec(h.ctx, "SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)", caller.Tenant.String()); err != nil {
			t.Fatal(err)
		}
	}
	qrows, err := tx.Query(h.ctx, fix.call, args...)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	got := f.summary(qrows)
	if _, err := tx.Exec(h.ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	if want != "*" && got != want {
		t.Errorf("%s answered %q, want %q", what, got, want)
	}
	a1, b1 := f.digest(h.A), f.digest(h.B)
	if d := diffDigest(a0, a1); d != "" {
		t.Errorf("%s changed A's rows in %s", what, d)
	}
	switch {
	case cross:
		if d := diffDigest(b0, b1); d != "" {
			t.Errorf("the refused %s changed B's rows in %s", what, d)
		}
	case fix.effect == fxChanges:
		if diffDigest(b0, b1) == "" {
			t.Errorf("%s left B's own rows as they were: it wrote nothing, so the case proves nothing", what)
		}
	case fix.effect == fxReads:
		if d := diffDigest(b0, b1); d != "" {
			t.Errorf("%s is labelled a read and changed B's rows in %s", what, d)
		}
	case fix.effect == fxElsewhere:
		if d := diffDigest(b0, b1); d != "" {
			t.Errorf("%s is labelled elsewhere and changed B's rows in %s", what, d)
		}
		if f.count(`SELECT count(*) FROM ctrlz.tenants`) != tenants0+1 {
			t.Errorf("%s made no tenant, so the case proves nothing", what)
		}
	}
}

func diffDigest(before, after map[string]string) string {
	var out []string
	for k, v := range before {
		if after[k] != v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func (f *fnCtx) count(sql string) int {
	f.h.t.Helper()
	var n int
	if err := f.tx.QueryRow(f.h.ctx, sql).Scan(&n); err != nil {
		f.h.t.Fatal(err)
	}
	return n
}

// digest fingerprints every row the tenant owns, table by table, and the rows that belong to
// it through its phones and its subject columns (codes, tickets, invites).
func (f *fnCtx) digest(s catalogtest.SeedIDs) map[string]string {
	f.h.t.Helper()
	tl := "'" + s.Tenant.String() + "'"
	ph := "ARRAY['" + strings.Join(f.phones(s), "','") + "']::text[]"
	d := func(tbl, where string) string {
		return fmt.Sprintf("'%s', (SELECT coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') FROM ctrlz.%s x WHERE %s)", tbl, tbl, where)
	}
	var parts []string
	for _, tbl := range f.h.fx.Tables.Tenant {
		parts = append(parts, d(tbl, f.h.fx.KeyColumn(tbl)+" = "+tl))
	}
	parts = append(parts, d("otp_challenges", "phone_e164 = ANY("+ph+")"), d("invites", "phone_e164 = ANY("+ph+")"), d("auth_tickets", "subject_tenant = "+tl))
	var js string
	if err := f.tx.QueryRow(f.h.ctx, "SELECT jsonb_build_object("+strings.Join(parts, ", ")+")::text").Scan(&js); err != nil {
		f.h.t.Fatal(err)
	}
	out := map[string]string{}
	if err := json.Unmarshal([]byte(js), &out); err != nil {
		f.h.t.Fatal(err)
	}
	return out
}

// shape is what "the same state" means: how many rows each tenant owns in every table.
func (f *fnCtx) shape(s catalogtest.SeedIDs) string {
	f.h.t.Helper()
	tl := "'" + s.Tenant.String() + "'"
	ph := "ARRAY['" + strings.Join(f.phones(s), "','") + "']::text[]"
	var parts []string
	for _, tbl := range f.h.fx.Tables.Tenant {
		parts = append(parts, fmt.Sprintf("'%[1]s=' || (SELECT count(*) FROM ctrlz.%[1]s WHERE %[2]s = %[3]s)", tbl, f.h.fx.KeyColumn(tbl), tl))
	}
	parts = append(parts,
		"'otp=' || (SELECT count(*) FROM ctrlz.otp_challenges WHERE phone_e164 = ANY("+ph+"))",
		"'invites=' || (SELECT count(*) FROM ctrlz.invites WHERE phone_e164 = ANY("+ph+"))",
		"'tickets=' || (SELECT count(*) FROM ctrlz.auth_tickets WHERE subject_tenant = "+tl+")")
	var out string
	if err := f.tx.QueryRow(f.h.ctx, "SELECT concat_ws(' ', "+strings.Join(parts, ", ")+")").Scan(&out); err != nil {
		f.h.t.Fatal(err)
	}
	return out
}

// classifyIsolation checks the `isolation` a function declares in functions.yaml against its
// body in the database and against the fixture table. The body is what the database runs, so a
// label cannot say what the code does not: a body that reads the tenant setting is a tenant
// function, one that names a tenant table is not `none`, and a kind with no fixture fails.
// stop is true for a function that needs no fixture.
func classifyIsolation(fn catalogtest.SDFunction, src string, tenantRef *regexp.Regexp, hasFixture bool) (problem string, stop bool) {
	src = regexp.MustCompile(`(?m)--.*$`).ReplaceAllString(src, "")
	usesSetting := strings.Contains(src, "current_tenant_id")
	named := tenantRef.FindAllString(src, -1)
	switch fn.Isolation {
	case "":
		return fn.Name + " has no `isolation` in functions.yaml; say tenant, key, create or none", true
	case "none":
		switch {
		case fn.IsolationReason == "":
			return fn.Name + ": `isolation: none` needs an isolation_reason", true
		case usesSetting || len(named) > 0:
			return fmt.Sprintf("%s says none and its body names %v (the setting: %v): give it a fixture and the kind it is", fn.Name, named, usesSetting), true
		case hasFixture:
			return fn.Name + ": a none function has no fixture; delete it", true
		}
		return "", true
	case "tenant":
		if !usesSetting {
			return fn.Name + " says tenant and its body never reads the tenant setting", true
		}
	case "key", "create":
		if usesSetting {
			return fmt.Sprintf("%s says %s and its body reads the tenant setting: it is a tenant function", fn.Name, fn.Isolation), true
		}
		if fn.Isolation == "create" && fn.IsolationReason == "" {
			return fn.Name + ": `isolation: create` needs an isolation_reason", true
		}
	default:
		return fmt.Sprintf("%s: unknown isolation %q", fn.Name, fn.Isolation), true
	}
	if !hasFixture {
		return fn.Name + " has no two-tenant success fixture (isolation_fixtures_test.go)", true
	}
	return "", false
}

// TestFunctionIsolationKindsCanFail plants each lie a functions.yaml entry can tell and requires
// classifyIsolation to refuse it. It needs no database.
func TestFunctionIsolationKindsCanFail(t *testing.T) {
	tenantRef := regexp.MustCompile(`\bctrlz\.(users|sessions)\b`)
	reads := "SELECT 1 FROM ctrlz.users u WHERE u.tenant_id = ctrlz.current_tenant_id()"
	global := "SELECT 1 FROM ctrlz.auth_throttle"
	byKey := "SELECT 1 FROM ctrlz.sessions s WHERE s.token_hash = p_hash"
	for name, c := range map[string]struct {
		fn      catalogtest.SDFunction
		src     string
		fixture bool
		want    string
	}{
		"no kind":                        {catalogtest.SDFunction{Name: "f"}, global, true, "has no `isolation`"},
		"an unknown kind":                {catalogtest.SDFunction{Name: "f", Isolation: "maybe"}, global, true, "unknown isolation"},
		"none without a reason":          {catalogtest.SDFunction{Name: "f", Isolation: "none"}, global, false, "needs an isolation_reason"},
		"none that reads the setting":    {catalogtest.SDFunction{Name: "f", Isolation: "none", IsolationReason: "r"}, reads, false, "says none"},
		"none that names a tenant table": {catalogtest.SDFunction{Name: "f", Isolation: "none", IsolationReason: "r"}, byKey, false, "says none"},
		"none with a fixture":            {catalogtest.SDFunction{Name: "f", Isolation: "none", IsolationReason: "r"}, global, true, "has no fixture"},
		"tenant that never reads it":     {catalogtest.SDFunction{Name: "f", Isolation: "tenant"}, byKey, true, "never reads the tenant setting"},
		"key that reads the setting":     {catalogtest.SDFunction{Name: "f", Isolation: "key"}, reads, true, "it is a tenant function"},
		"create without a reason":        {catalogtest.SDFunction{Name: "f", Isolation: "create"}, global, true, "needs an isolation_reason"},
		"tenant with no fixture":         {catalogtest.SDFunction{Name: "f", Isolation: "tenant"}, reads, false, "no two-tenant success fixture"},
	} {
		t.Run(name, func(t *testing.T) {
			if p, _ := classifyIsolation(c.fn, c.src, tenantRef, c.fixture); !strings.Contains(p, c.want) {
				t.Fatalf("got %q, want it to say %q", p, c.want)
			}
		})
	}
	if p, stop := classifyIsolation(catalogtest.SDFunction{Name: "f", Isolation: "tenant"}, reads, tenantRef, true); p != "" || stop {
		t.Fatalf("a correct tenant function was refused: %q (stop %v)", p, stop)
	}
}

// runNoSettingCase calls a tenant function with B's own ids and NO tenant setting, as a
// connection of the tenant role would that never set one (db-r5-9). The function acts for
// ctrlz.current_tenant_id(), so with none it must neither answer as it does for B's own call
// nor change a row of either tenant. A refusal by an error is as good as an empty answer.
// A branch that treats "no setting" as "any tenant" (auth_totp_seed had one, for a login
// lookup that no longer exists) answers the success summary here and fails.
func (h *harness) runNoSettingCase(t *testing.T, fn string, fix fnFix, role string, repl *strings.Replacer, B catalogtest.SeedIDs) {
	t.Helper()
	tx, err := h.super.Begin(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	f := &fnCtx{h: h, tx: tx, ids: map[string]uuid.UUID{}, repl: repl}
	if fix.arrange != nil {
		fix.arrange(f, h.A)
		fix.arrange(f, h.B)
	}
	a0, b0 := f.digest(h.A), f.digest(h.B)
	args := []any(nil)
	if fix.args != nil {
		args = fix.args(B, B)
	}
	if ids, ok := f.argsWithIDs(fn, B, B); ok {
		args = ids
	}
	if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE "+pgx.Identifier{"ctrlz_" + role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	// A savepoint, so that a function that raises leaves the transaction usable for the digests.
	if _, err := tx.Exec(h.ctx, "SAVEPOINT no_setting"); err != nil {
		t.Fatal(err)
	}
	answer, refused := "", false
	if qrows, qerr := tx.Query(h.ctx, fix.call, args...); qerr != nil {
		refused = true
	} else {
		answer = f.summary(qrows)
	}
	if refused {
		// The failed statement aborted the transaction; the digests below need it open.
		// An answered call is not rolled back, or the digests would not see its writes.
		if _, err := tx.Exec(h.ctx, "ROLLBACK TO SAVEPOINT no_setting"); err != nil {
			t.Fatalf("no tenant setting: %v", err)
		}
	}
	if _, err := tx.Exec(h.ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	// A fixture whose cross answer is "*" says the answer carries no information (a void
	// function reports a constant); the digests below are its whole proof.
	if !refused && fix.own != "*" && fix.cross != "*" && answer == fix.own {
		t.Errorf("with no tenant setting the function answered %q, as it does for B's own call", answer)
	}
	if d := diffDigest(a0, f.digest(h.A)); d != "" {
		t.Errorf("with no tenant setting the call changed A's rows in %s", d)
	}
	if d := diffDigest(b0, f.digest(h.B)); d != "" {
		t.Errorf("with no tenant setting the call changed B's rows in %s", d)
	}
}
