package catalogtest_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// P1 auth review round 8, database area (db-r8-1, db-r8-2).

// breakCheck applies the statements in a transaction that is rolled back and returns what the
// catalog check with that number says about the broken database.
func breakCheck(t *testing.T, h *harness, fx *catalogtest.Fixtures, id string, sql ...string) []string {
	t.Helper()
	tx, err := h.super.Begin(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	for _, s := range sql {
		if _, err := tx.Exec(h.ctx, s); err != nil {
			t.Fatalf("mutation %.80q does not apply: %v", s, err)
		}
	}
	for _, c := range catalogtest.Checks() {
		if c.ID == id {
			v, err := c.Run(h.ctx, tx, fx)
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
	}
	t.Fatalf("no catalog check %s", id)
	return nil
}

// TestInertTablePremiseIsReadFromTheGrants is db-r8-1. lockrank.Inert ignores a key share on
// tenants and admin_users because nothing locks them above NO KEY UPDATE, and an UPDATE of a
// unique-index column (admin_users.username) or a DELETE does. The premise used to be a sentence;
// check 21 reads it from the grants of every login role, so a role or a column added tomorrow is
// judged the day it exists.
func TestInertTablePremiseIsReadFromTheGrants(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	if v := breakCheck(t, h, h.fx, "21"); len(v) != 0 {
		t.Fatalf("the migrated database is not clean for check 21: %v", v)
	}
	for _, m := range []struct {
		name, want string
		sql        []string
	}{
		{"the admin may rename an admin (the finding)", "ctrlz_admin can UPDATE admin_users.username",
			[]string{"GRANT UPDATE (username) ON ctrlz.admin_users TO ctrlz_admin"}},
		{"a table-level UPDATE counts for the unique columns too", "ctrlz_hub can UPDATE admin_users.username",
			[]string{"GRANT UPDATE ON ctrlz.admin_users TO ctrlz_hub"}},
		{"the primary key of a tenant", "ctrlz_worker can UPDATE tenants.id",
			[]string{"GRANT UPDATE (id) ON ctrlz.tenants TO ctrlz_worker"}},
		{"a column that joins a unique index tomorrow", "ctrlz_admin can UPDATE admin_users.pending_notice",
			[]string{"CREATE UNIQUE INDEX admin_users_notice_uq ON ctrlz.admin_users (pending_notice)"}},
		{"a delete of a tenant", "ctrlz_worker can DELETE from tenants",
			[]string{"GRANT DELETE ON ctrlz.tenants TO ctrlz_worker"}},
		{"a delete of an admin", "ctrlz_admin can DELETE from admin_users",
			[]string{"GRANT DELETE ON ctrlz.admin_users TO ctrlz_admin"}},
		{"a login role made tomorrow", "ctrlz_later can UPDATE admin_users.username",
			[]string{"CREATE ROLE ctrlz_later LOGIN", "GRANT UPDATE (username) ON ctrlz.admin_users TO ctrlz_later"}},
		// db-r9-5: ctrlz_auth owns every definer function and is NOLOGIN, so a LOGIN-only read of
		// the grants never judged the role that writes most.
		{"a rename granted to the NOLOGIN definer owner", "ctrlz_auth can UPDATE admin_users.username",
			[]string{"GRANT UPDATE (username) ON ctrlz.admin_users TO ctrlz_auth"}},
		{"a tenant delete granted to the NOLOGIN definer owner", "ctrlz_auth can DELETE from tenants",
			[]string{"GRANT DELETE ON ctrlz.tenants TO ctrlz_auth"}},
		{"an admin delete granted to the NOLOGIN definer owner", "ctrlz_auth can DELETE from admin_users",
			[]string{"GRANT DELETE ON ctrlz.admin_users TO ctrlz_auth"}},
		{"the backfill role", "ctrlz_backfill can UPDATE tenants.id",
			[]string{"GRANT UPDATE (id) ON ctrlz.tenants TO ctrlz_backfill"}},
		{"a NOLOGIN group role the writers inherit from", "ctrlz_group can UPDATE admin_users.username",
			[]string{"CREATE ROLE ctrlz_group NOLOGIN", "GRANT UPDATE (username) ON ctrlz.admin_users TO ctrlz_group"}},
		// The bodies: a grant is half of the reach, a definer function is the other half.
		{"a definer function that renames an admin", "ctrlz_fn.admin_rename(): UPDATE of admin_users.username",
			[]string{`CREATE FUNCTION ctrlz_fn.admin_rename() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, ctrlz AS $$ BEGIN UPDATE ctrlz.admin_users SET username = 'x' WHERE true; END $$`}},
		{"a definer function that renames through the DO UPDATE arm", "ctrlz_fn.admin_upsert(): UPDATE of admin_users.username",
			[]string{`CREATE FUNCTION ctrlz_fn.admin_upsert() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, ctrlz AS $$ BEGIN INSERT INTO ctrlz.admin_users (id) VALUES (gen_random_uuid()) ON CONFLICT (id) DO UPDATE SET username = excluded.username; END $$`}},
		{"a definer function that sets a column list", "ctrlz_fn.tenant_move(): UPDATE of tenants.id",
			[]string{`CREATE FUNCTION ctrlz_fn.tenant_move() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, ctrlz AS $$ BEGIN UPDATE ctrlz.tenants SET (id) = (gen_random_uuid()); END $$`}},
		{"a definer function that deletes a tenant (the purge, not declared)", "ctrlz_fn.tenant_purge(): DELETE FROM tenants",
			[]string{`CREATE FUNCTION ctrlz_fn.tenant_purge() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, ctrlz AS $$ BEGIN DELETE FROM ctrlz.tenants WHERE true; END $$`}},
		{"a body that cannot be read", "ctrlz_fn.tenant_dyn(): the body cannot be read",
			[]string{`CREATE FUNCTION ctrlz_fn.tenant_dyn() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, ctrlz AS $$ BEGIN EXECUTE 'DELETE FROM ctrlz.tenants'; END $$`}},
	} {
		t.Run(m.name, func(t *testing.T) {
			v := breakCheck(t, h, h.fx, "21", m.sql...)
			if !strings.Contains(strings.Join(v, "\n"), m.want) {
				t.Errorf("check 21 did not report %q for %v: %v", m.want, m.sql, v)
			}
		})
	}
	// A non-key column of an inert table is what the admin does hold, and is fine.
	if v := breakCheck(t, h, h.fx, "21", "GRANT UPDATE (disabled_at) ON ctrlz.admin_users TO ctrlz_hub"); len(v) != 0 {
		t.Errorf("an UPDATE of a column that is in no unique index was reported: %v", v)
	}
	// The one declared exception is a delete: a function whose entry says inert_delete is not
	// reported for it, and a note on a function that deletes nothing is.
	fx, err := catalogtest.Load()
	if err != nil {
		t.Fatal(err)
	}
	purge := `CREATE FUNCTION ctrlz_fn.tenant_purge() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, ctrlz AS $$ BEGIN DELETE FROM ctrlz.tenants WHERE true; END $$`
	fx.Functions.SecurityDefiner = append(fx.Functions.SecurityDefiner, catalogtest.SDFunction{Name: "tenant_purge", InertDelete: "the purge of a deleting tenant"})
	if v := breakCheck(t, h, fx, "21", purge); strings.Contains(strings.Join(v, "\n"), "DELETE FROM tenants") {
		t.Errorf("a declared purge was reported for its delete: %v", v)
	}
	noop := `CREATE FUNCTION ctrlz_fn.tenant_purge() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, ctrlz AS $$ BEGIN PERFORM 1; END $$`
	if v := breakCheck(t, h, fx, "21", noop); !strings.Contains(strings.Join(v, "\n"), "says inert_delete, but the body deletes from no inert table") {
		t.Errorf("a stale inert_delete note passed: %v", v)
	}
}

// TestTheAdminRoleCannotRenameAnAdmin shows the revoke of migration 0037 on the live role: a
// rename is refused by the database, whatever the statement guard would have said about it.
func TestTheAdminRoleCannotRenameAnAdmin(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	h.inTx(h.super, "admin", nil, func(tx pgx.Tx) {
		_, err := tx.Exec(h.ctx, `UPDATE ctrlz.admin_users SET username = 'renamed'`)
		if pe := pgErr(err); pe == nil || pe.Code != "42501" {
			t.Errorf("the admin role renamed an admin: %v", err)
		}
	})
}

// TestTheCompilerRoleCannotReadWhereATenantsPeopleAre is db-r8-2: the compiler writes prefixes,
// not cities, providers, host names or client addresses, and its P0 table-level SELECT on
// authorized_ips and clients reached every tenant's. Migration 0037 narrows it; the prefix it
// does write into the policy stays readable.
func TestTheCompilerRoleCannotReadWhereATenantsPeopleAre(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, c := range []struct {
		table, col string
		allowed    bool
	}{
		{"authorized_ips", "cidr", true},
		{"authorized_ips", "city", false},
		{"authorized_ips", "isp", false},
		{"clients", "label", true},
		{"clients", "hostname", false},
		{"clients", "mac", false},
		{"clients", "ip", false},
		{"ip_claims", "cidr", true},
	} {
		t.Run(c.table+"."+c.col, func(t *testing.T) {
			h.inTx(h.super, "compiler", nil, func(tx pgx.Tx) {
				_, err := tx.Exec(h.ctx, `SELECT `+c.col+` FROM ctrlz.`+c.table)
				pe := pgErr(err)
				switch {
				case c.allowed && err != nil:
					t.Errorf("the compiler cannot read %s.%s: %v", c.table, c.col, err)
				case !c.allowed && (pe == nil || pe.Code != "42501"):
					t.Errorf("the compiler read %s.%s: %v", c.table, c.col, err)
				}
			})
		})
	}
}

// TestPersonalDataIsDecidedByTypeAndNotOnlyByName is db-r8-2: the personal class failed open the
// way the secret test did in rounds 6 and 7, by name and by type exemption. An address column is
// personal whatever it is called, a numeric column named like a phone is asked, every `open` table
// says why none of its columns is about a person, and the places of the clients of a tenant are
// not readable by a role that is not declared.
func TestPersonalDataIsDecidedByTypeAndNotOnlyByName(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, m := range []struct {
		name, want string
		sql        []string
	}{
		{"a bigint phone", "otp_challenges.msisdn (bigint) looks like personal data",
			[]string{"ALTER TABLE ctrlz.otp_challenges ADD COLUMN msisdn bigint", "GRANT SELECT (msisdn) ON ctrlz.otp_challenges TO ctrlz_hub"}},
		{"an address with a name no pattern knows", "sessions.remote_addr (inet) looks like personal data",
			[]string{"ALTER TABLE ctrlz.sessions ADD COLUMN remote_addr inet"}},
		{"a network column named cidr", "endpoints.cidr (cidr) looks like personal data",
			[]string{"ALTER TABLE ctrlz.endpoints ADD COLUMN cidr cidr"}},
		{"a column of networks under an unrelated name", "sessions.seen_from (inet[]) looks like personal data",
			[]string{"ALTER TABLE ctrlz.sessions ADD COLUMN seen_from inet[]"}},
		{"a hardware address", "endpoints.peer (macaddr) looks like personal data",
			[]string{"ALTER TABLE ctrlz.endpoints ADD COLUMN peer macaddr"}},
		{"a provider name in text", "endpoints.isp (text) looks like personal data",
			[]string{"ALTER TABLE ctrlz.endpoints ADD COLUMN isp text"}},
		{"a city in text", "endpoints.city (text) looks like personal data",
			[]string{"ALTER TABLE ctrlz.endpoints ADD COLUMN city text"}},
		{"an integer named like an address", "endpoints.max_phone_ips (integer) looks like personal data",
			[]string{"ALTER TABLE ctrlz.endpoints ADD COLUMN max_phone_ips integer"}},
		// The reach itself, at HEAD: a role reading where a client is.
		{"the admin reads the networks of every tenant", "ctrlz_admin can SELECT authorized_ips.cidr",
			[]string{"GRANT SELECT (cidr, city, isp) ON ctrlz.authorized_ips TO ctrlz_admin"}},
		{"the admin reads where they are", "ctrlz_admin can SELECT authorized_ips.city",
			[]string{"GRANT SELECT (cidr, city, isp) ON ctrlz.authorized_ips TO ctrlz_admin"}},
		{"the compiler gets the provider back", "ctrlz_compiler can SELECT authorized_ips.isp",
			[]string{"GRANT SELECT (isp) ON ctrlz.authorized_ips TO ctrlz_compiler"}},
		{"the compiler gets the host name of a device back", "ctrlz_compiler can SELECT clients.hostname",
			[]string{"GRANT SELECT (hostname, mac) ON ctrlz.clients TO ctrlz_compiler"}},
		{"the hub reads the claimed prefix", "ctrlz_hub can SELECT ip_claims.cidr",
			[]string{"GRANT SELECT (cidr) ON ctrlz.ip_claims TO ctrlz_hub"}},
		{"the hub reads the domains visitors asked to unblock", "ctrlz_hub can SELECT unblock_requests.qname",
			[]string{"GRANT SELECT (qname) ON ctrlz.unblock_requests TO ctrlz_hub"}},
	} {
		t.Run(m.name, func(t *testing.T) {
			v := breakIn(t, h, h.fx, m.sql...)
			if !strings.Contains(strings.Join(v, "\n"), m.want) {
				t.Errorf("check 22 did not report %q for %v: %v", m.want, m.sql, v)
			}
		})
	}
	// An `open` table that gives no reason of its own is refused: one copied sentence about
	// credentials never asked the question.
	fx, err := catalogtest.Load()
	if err != nil {
		t.Fatal(err)
	}
	o := fx.Guarded.Open["rules"]
	o.NoPersonal = ""
	fx.Guarded.Open["rules"] = o
	if v := breakIn(t, h, fx); !strings.Contains(strings.Join(v, "\n"), "open.rules: no_personal is missing") {
		t.Errorf("an open table with no reason about personal data passed: %v", v)
	}
}
