package admincli_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/admincli"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
)

// Rule console-state-change-is-audited (round 8, admin-r8-2 and admin-r8-7). The rule was enforced by
// one case test of `unlock`, so `reset-password` and `reset-totp`, which also clear the throttle after
// their transaction, reported two stores as one ("could not be cleared; run unlock", false when only
// Valkey had failed) and left no record of whether the clear worked, and the database half of
// `unlock` itself (exit 1 with the row written) had no test at all. The enforcement now goes over
// admincli.Commands: a command that is not in the table below fails, and every command that clears
// the throttle is run under each fault of each store.

// The kinds a console command can be, a closed set (round 9, admin-r9-5). Round 8 made the table a map
// of commands to free text and only checked that the text was 20 characters long, so `rekey` carried
// "moves no credential and no lock; the operator records it with audit-note" and nobody could tell a
// true reason from a false one: the command rewrites stored ciphertext, commits the rows it rewrote
// when another value fails, and wrote no row. A kind is a promise that a test below runs against a
// database, so a new command cannot choose a kind its behaviour does not keep.
const (
	// kindThrottle clears the login throttle; driven by TestEveryCommandThatClearsTheThrottleReportsAndAuditsEachStore.
	kindThrottle = "throttle"
	// kindAudited may change a table the console role can write (grants.yaml, see consoleWatchedTables), and does so only together with an
	// audit_log row (the row may be the whole change).
	kindAudited = "audited-change"
	// kindReads changes none of them and writes no audit row.
	kindReads = "reads-only"
)

type consoleKind struct{ kind, why string }

// consoleCommandKinds says, for every command of the console, which promise it keeps. A new command
// must choose, and TestEveryNonThrottleConsoleCommandKeepsItsKind runs it.
var consoleCommandKinds = map[string]consoleKind{
	"unlock":         {kindThrottle, ""},
	"reset-password": {kindThrottle, ""},
	"reset-totp":     {kindThrottle, ""},
	"bootstrap":      {kindAudited, "creates the first account; its row is written in the transaction of the change"},
	"keys":           {kindAudited, "status reads counts; declare-lost writes its row and changes no table the check watches"},
	"rekey":          {kindAudited, "rewrites sealed values (admin_users.totp_secret_ct, sms_gateways.credentials_ct) and writes key.rekeyed in the same transaction whatever the other values did"},
	"audit-note":     {kindAudited, "the row is the whole change"},
	"audit":          {kindReads, "verifies the chain and changes nothing"},
	"sms":            {kindAudited, "pending reads; confirm makes pending gateway credentials the active ones and writes sms.gateway_change in the same transaction"},
}

func TestEveryConsoleCommandSaysWhetherItClearsTheThrottle(t *testing.T) {
	var cmds []string
	cmds = append(cmds, admincli.Commands()...)
	sort.Strings(cmds)
	var listed []string
	for k, v := range consoleCommandKinds {
		listed = append(listed, k)
		switch v.kind {
		case kindThrottle:
		case kindAudited, kindReads:
			if len(v.why) < 20 {
				t.Errorf("%s: say why it keeps the promise of its kind", k)
			}
		default:
			t.Errorf("%s: kind %q is not one of the closed set", k, v.kind)
		}
	}
	sort.Strings(listed)
	if !slices.Equal(cmds, listed) {
		t.Fatalf("admincli.Commands() = %v, the table of consolestate_test.go lists %v: a new command says whether it clears the throttle", cmds, listed)
	}
}

// auditTable is counted apart: it is where a command's row goes, so a change to it is the promise
// being kept and not a change to watch.
const auditTable = "audit_log"

// watchedAlways are tables a console command is known to reach through another role than ctrlz_admin
// (`rekey user_totp` runs per tenant), kept in the set even though the admin role has no write
// grant on them: the set is the catalog's plus these, never less than before.
var watchedAlways = []string{"admin_users", "users", "sms_gateways"}

var writeLetters = regexp.MustCompile(`[IUD]`)

// consoleWatchedTables is every table the console role can write, read from migrations/catalog/grants.yaml
// and not picked by hand (round 10, admin-r10-3). Round 9 hashed three tables, and the role can also
// write admin_sessions, tenants.status, alerts, settings rows and about twenty more, so a command that
// revoked sessions or suspended a tenant with no audit row passed as "reads-only". A table that is
// granted later joins the set by being granted: the list does not have to be remembered.
// Column notation puts column names in lower case, so an upper case I, U or D is a write privilege.
func consoleWatchedTables(t *testing.T) []string {
	t.Helper()
	fx, err := catalogtest.Load()
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, tbl := range watchedAlways {
		set[tbl] = true
	}
	for tbl, roles := range fx.Grants.Tables {
		if tbl != auditTable && writeLetters.MatchString(roles["admin"]) {
			set[tbl] = true
		}
	}
	// The role also writes through the SECURITY DEFINER functions it may execute, and the tables of
	// those are not in its grants: auth_throttle (the lock-out state itself, through admin_throttle_*),
	// sessions and refresh_tokens (admin_revoke_user_sessions), auth_tickets (auth_tickets_revoke).
	// `ranks` names the tables each function locks or writes (admin-r11-5), so the set is the union of
	// both catalogs; a lock-only table is watched too, which costs nothing when nothing changes it.
	for _, fn := range fx.Functions.SecurityDefiner {
		if !slices.Contains(fn.Execute, "admin") || fn.Ranks == nil {
			continue
		}
		for _, rk := range *fn.Ranks {
			name, _, _ := strings.Cut(rk, ":")
			if name != auditTable {
				set[name] = true
			}
		}
	}
	var out []string
	for tbl := range set {
		if !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(tbl) {
			t.Fatalf("grants.yaml names a table %q that is not a plain identifier", tbl)
		}
		out = append(out, tbl)
	}
	sort.Strings(out)
	return out
}

// seedLockOutState plants a counter in a network scope of the admin login, so a command that clears
// the throttle changes a row the fingerprint sees: with the table empty, a reads-only command that
// cleared it would change nothing and the kind check would pass it (admin-r11-5).
func (r *rig) seedLockOutState() {
	r.t.Helper()
	r.env.Exec(r.t, `INSERT INTO ctrlz.auth_throttle (scope, key, window_start, count)
		VALUES ('admin_login_net', decode(repeat('ab', 32), 'hex'), now(), 3) ON CONFLICT (scope, key) DO UPDATE SET count = 3`)
}

// consoleStateSnapshot fingerprints every table the console role can write, one hash each, and counts
// the audit rows. The tables are read as the owner, so a row-level policy hides nothing.
func (r *rig) consoleStateSnapshot() (state map[string]string, audit int) {
	r.t.Helper()
	state = map[string]string{}
	for _, tbl := range consoleWatchedTables(r.t) {
		var h string
		r.env.Scan(r.t, `SELECT md5(coalesce(string_agg(t::text, '|' ORDER BY t::text), '')) FROM ctrlz.`+tbl+` t`, nil, &h)
		state[tbl] = h
	}
	audit = r.count(`SELECT count(*) FROM ctrlz.audit_log`)
	return state, audit
}

// movedTables names the tables whose fingerprint differs.
func movedTables(a, b map[string]string) []string {
	var moved []string
	for tbl, h := range b {
		if a[tbl] != h {
			moved = append(moved, tbl)
		}
	}
	sort.Strings(moved)
	return moved
}

// TestTheSnapshotCoversWhatTheConsoleRoleCanWrite pins the derivation: the set holds the tables the
// role is known to write today (so a parser that returned nothing cannot make the kind check vacuous)
// and each of them is a real table the snapshot can read.
func TestTheSnapshotCoversWhatTheConsoleRoleCanWrite(t *testing.T) {
	got := consoleWatchedTables(t)
	for _, must := range []string{"admin_users", "users", "sms_gateways", "admin_sessions", "tenants", "endpoints", "invites", "alerts", "admin_jobs", "sms_outbox", "profiles",
		"auth_throttle", "sessions", "refresh_tokens", "auth_tickets"} {
		if !slices.Contains(got, must) {
			t.Errorf("the watched set %v lacks %s, a table the console role writes", got, must)
		}
	}
	if slices.Contains(got, auditTable) {
		t.Errorf("%s is counted apart and must not be fingerprinted", auditTable)
	}
	r := newRig(t)
	if state, _ := r.consoleStateSnapshot(); len(state) != len(got) {
		t.Errorf("%d fingerprints for %d tables", len(state), len(got))
	}
}

// seedRekey seals the admin's TOTP seed under key 1 only and gives the rig a ring whose newest key is
// 2, so `rekey admin_totp` has one value to rewrite. It returns the old ring, to seal other values.
func seedRekey(t *testing.T, r *rig) *keyring.Ring {
	t.Helper()
	root := secret.NewBytes(bytes.Repeat([]byte{7}, 32))
	one, err := keyring.FromRoot(root, map[string][]uint16{keyring.DomainAdminTOTP: {1}, keyring.DomainSMSCred: {1}})
	if err != nil {
		t.Fatal(err)
	}
	both, err := keyring.FromRoot(root, map[string][]uint16{keyring.DomainAdminTOTP: {1, 2}, keyring.DomainSMSCred: {1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := totp.NewSecret()
	ct, err := one.Seal(keyring.DomainAdminTOTP, totp.AdminAAD(seedAdmin), seed.Reveal())
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET totp_secret_ct = $2 WHERE id = $1`, seedAdmin, ct)
	r.keys = both
	return one
}

// plantGateways puts one gateway whose credentials open under key 1 and one whose credentials open
// under nothing, so `rekey sms_cred` rewrites one value and cannot open the other.
func plantGateways(t *testing.T, r *rig, old *keyring.Ring) {
	t.Helper()
	gw := uuid.New()
	cct, err := sms.SealCredentials(old, gw, "sms_ir", secret.NewBytes([]byte(`{"api_key":"k-1234567"}`)))
	if err != nil {
		t.Fatal(err)
	}
	r.env.ResetSMS(t)
	r.env.Exec(t, `INSERT INTO ctrlz.sms_gateways (id, provider, role, credentials_ct) VALUES ($1, 'sms_ir', 'disabled', $2)`, gw, cct)
	r.env.Exec(t, `INSERT INTO ctrlz.sms_gateways (id, provider, role, credentials_ct) VALUES ($1, 'melipayamak', 'disabled', $2)`, uuid.New(), bytes.Repeat([]byte{0xEE}, 64))
}

type consoleSample struct {
	name    string
	setup   func(t *testing.T, r *rig)
	args    []string
	code    int
	changes bool // the run must change state or write a row: a sample that changes nothing proves nothing about a kind
}

// consoleSamples are the runs that hold every command that is not a throttle command to its kind.
var consoleSamples = map[string][]consoleSample{
	"bootstrap": {
		{"the first account", func(t *testing.T, r *rig) { r.noAdmin() }, []string{"bootstrap", "--username", "fresh"}, 0, true},
	},
	"keys": {
		{"status", nil, []string{"keys", "status", "admin_totp"}, 0, false},
		{"declare a lost key", nil, []string{"keys", "declare-lost", "user_totp", "--key-number", "1", "--yes"}, 0, true},
	},
	"rekey": {
		{"admin_totp under an older key", func(t *testing.T, r *rig) { seedRekey(t, r) }, []string{"rekey", "admin_totp"}, 0, true},
		{"sms_cred with a value that does not open", func(t *testing.T, r *rig) { plantGateways(t, r, seedRekey(t, r)) }, []string{"rekey", "sms_cred"}, 1, true},
		{"admin_totp with nothing to rewrite", nil, []string{"rekey", "admin_totp"}, 0, false},
		{"a domain with nothing stored", nil, []string{"rekey", "auth_mac"}, 0, false},
	},
	"audit-note": {
		{"a rotation", nil, []string{"audit-note", "key.rotated", "--domain", "admin_totp", "--key-number", "2"}, 0, true},
	},
	"sms": {
		{"pending", func(t *testing.T, r *rig) { plantPending(t, r, "1234") }, []string{"sms", "pending"}, 0, false},
		{"confirm", func(t *testing.T, r *rig) { plantPending(t, r, "1234") }, []string{"sms", "confirm", "sms_ir", "--hint", "1234"}, 0, true},
	},
	"audit": {
		{"verify", nil, []string{"audit", "verify"}, 0, false},
	},
}

// TestEveryNonThrottleConsoleCommandKeepsItsKind is the check behind the table (round 9, admin-r9-5):
// every command that is not a throttle command has samples, and a run of each leaves either nothing
// changed (reads-only) or an audit row whenever a watched table changed (audited-change). It fails for
// `rekey` without its row: it changed admin_users and sms_gateways and wrote nothing, and, since round 10 (admin-r10-3),
// for a command that touches any other table the role can write, such as admin_sessions or tenants.
func TestEveryNonThrottleConsoleCommandKeepsItsKind(t *testing.T) {
	for _, cmd := range admincli.Commands() {
		k := consoleCommandKinds[cmd]
		if k.kind == kindThrottle {
			continue
		}
		samples := consoleSamples[cmd]
		if len(samples) == 0 {
			t.Errorf("%s has no sample: a kind nobody runs is a sentence", cmd)
			continue
		}
		changed := false
		for _, s := range samples {
			t.Run(cmd+"/"+s.name, func(t *testing.T) {
				r := newRig(t)
				r.readyAdmin()
				if s.setup != nil {
					s.setup(t, r)
				}
				r.seedLockOutState()
				state0, audit0 := r.consoleStateSnapshot()
				if code := r.run(s.args...); code != s.code {
					t.Fatalf("exit %d, want %d; stderr %q", code, s.code, r.errb.String())
				}
				state1, audit1 := r.consoleStateSnapshot()
				moved := movedTables(state0, state1)
				stateMoved, rowWritten := len(moved) > 0, audit1 > audit0
				switch k.kind {
				case kindReads:
					if stateMoved || rowWritten {
						t.Errorf("a reads-only command changed %v or wrote an audit row (%v)", moved, rowWritten)
					}
				case kindAudited:
					if stateMoved && !rowWritten {
						t.Errorf("%v changed %v and wrote no audit row", s.args, moved)
					}
				}
				if s.changes && !stateMoved && !rowWritten {
					t.Errorf("the sample is meant to change something and changed nothing: it proves nothing")
				}
			})
			changed = changed || s.changes
		}
		if k.kind == kindAudited && !changed {
			t.Errorf("%s: no sample of an audited-change command changes anything", cmd)
		}
	}
}

// TestRekeyWritesItsRowWhateverTheOtherValuesDid: a value that cannot be opened ends the command with
// exit 1 after the others were committed, and the row says so, with counts and nothing else. A run
// that rewrites nothing writes nothing.
func TestRekeyWritesItsRowWhateverTheOtherValuesDid(t *testing.T) {
	r := newRig(t)
	r.readyAdmin()
	old := seedRekey(t, r)
	plantGateways(t, r, old)

	const row = `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'key.rekeyed' AND target = $1 AND params = $2::jsonb`
	if code := r.run("rekey", "admin_totp"); code != 0 {
		t.Fatalf("rekey admin_totp: %d %q", code, r.errb.String())
	}
	if n := r.count(row, "domain:admin_totp", `{"key_number":2,"rewritten":1,"changed":0,"failed":0}`); n != 1 {
		t.Fatalf("%d key.rekeyed rows for the admin seed", n)
	}
	if code := r.run("rekey", "sms_cred"); code != 1 {
		t.Fatalf("rekey sms_cred with a value that does not open: exit %d, want 1", code)
	}
	if n := r.count(row, "domain:sms_cred", `{"key_number":2,"rewritten":1,"changed":0,"failed":1}`); n != 1 {
		t.Fatalf("%d key.rekeyed rows for the run that stopped half way: the committed rewrite has no record", n)
	}
	sealedUnder2 := r.count(`SELECT count(*) FROM ctrlz.sms_gateways WHERE get_byte(credentials_ct, 3) = 0 AND get_byte(credentials_ct, 4) = 2`)
	if sealedUnder2 != 1 {
		t.Fatalf("%d gateways are sealed under key 2: the rewrite the row describes did not commit", sealedUnder2)
	}
	before := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'key.rekeyed'`)
	if code := r.run("rekey", "admin_totp"); code != 0 {
		t.Fatalf("a second rekey: %d", code)
	}
	if after := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'key.rekeyed'`); after != before {
		t.Errorf("a rekey that rewrote nothing wrote a row (%d to %d)", before, after)
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'key.rekeyed' AND params::text ~ '[^0-9a-z_{}": ,]'`); n != 0 {
		t.Errorf("a key.rekeyed row holds more than closed names and counts")
	}
}

// plantFailingScopeReset makes the reset of one scope fail while the rest go through: the scopes are
// cleared one by one and a run that stopped half way is the case the rule is about.
func (r *rig) plantFailingScopeReset() {
	r.t.Helper()
	r.env.Exec(r.t, `CREATE FUNCTION ctrlz.test_fail_one_scope() RETURNS trigger LANGUAGE plpgsql AS $$
	BEGIN IF OLD.scope = 'admin_totp' THEN RAISE EXCEPTION 'planted fault'; END IF; RETURN NEW; END $$`)
	r.env.Exec(r.t, `CREATE TRIGGER test_fail_one_scope BEFORE UPDATE ON ctrlz.auth_throttle
	  FOR EACH ROW EXECUTE FUNCTION ctrlz.test_fail_one_scope()`)
}

func TestEveryCommandThatClearsTheThrottleReportsAndAuditsEachStore(t *testing.T) {
	const (
		valkeyOnly = `{"via":"cli","database_cleared":true,"valkey_cleared":false}`
		dbOnly     = `{"via":"cli","database_cleared":false,"valkey_cleared":true}`
		both       = `{"via":"cli","database_cleared":true,"valkey_cleared":true}`
	)
	driven := 0
	for _, cmd := range admincli.Commands() {
		if consoleCommandKinds[cmd].kind != kindThrottle {
			continue
		}
		driven++
		args := []string{cmd, "--user", "root"}
		resets := cmd != "unlock"

		t.Run(cmd+"/valkey down", func(t *testing.T) {
			r := newRig(t)
			r.readyAdmin()
			svc := r.lockLogin("root")
			r.clearRateLimits = func(context.Context) error { return errors.New("valkey down") }
			if code := r.run(args...); code != 0 {
				t.Fatalf("exit %d, stderr %q: the database part is done and nothing else failed", code, r.errb.String())
			}
			if !strings.Contains(r.errb.String(), "Valkey could not be cleared") {
				t.Errorf("no warning about Valkey: %q", r.errb.String())
			}
			if strings.Contains(r.errb.String(), "run unlock") || strings.Contains(r.errb.String()+r.out.String(), "valkey down") {
				t.Errorf("a Valkey failure was reported as a database one, or leaked its text: %q", r.errb.String())
			}
			r.assertUnlocked(svc, "root")
			if n := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'admin.unlock_cli' AND params = $1::jsonb`, valkeyOnly); n != 1 {
				t.Fatalf("%d unlock rows with the Valkey part undone: the clear has no record", n)
			}
		})

		t.Run(cmd+"/a scope of the database cannot be cleared", func(t *testing.T) {
			r := newRig(t)
			r.readyAdmin()
			r.lockLogin("root")
			r.plantFailingScopeReset()
			r.clearRateLimits = func(context.Context) error { return nil }
			code := r.run(args...)
			if resets && code != 0 {
				t.Fatalf("%s exit %d: the reset committed and its password is written, the command must not fail", cmd, code)
			}
			if !resets && code != 1 {
				t.Fatalf("%s exit %d, want 1: the lock-out was not cleared", cmd, code)
			}
			want := "could not be cleared"
			if !strings.Contains(r.errb.String(), want) {
				t.Errorf("stderr %q does not say the throttle could not be cleared", r.errb.String())
			}
			if strings.Contains(r.errb.String()+r.out.String(), "planted fault") {
				t.Errorf("the database error text reached the operator: %q", r.errb.String())
			}
			if strings.Contains(r.errb.String(), "Valkey") {
				t.Errorf("a database failure was reported as a Valkey one: %q", r.errb.String())
			}
			if n := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'admin.unlock_cli' AND params = $1::jsonb`, dbOnly); n != 1 {
				t.Fatalf("%d unlock rows with database_cleared false: a run that stopped half way left no record", n)
			}
		})

		t.Run(cmd+"/both stores work", func(t *testing.T) {
			r := newRig(t)
			r.readyAdmin()
			svc := r.lockLogin("root")
			r.clearRateLimits = func(context.Context) error { return nil }
			if code := r.run(args...); code != 0 {
				t.Fatalf("exit %d, stderr %q", code, r.errb.String())
			}
			if strings.Contains(r.errb.String(), "could not be cleared") {
				t.Errorf("a warning on a run that cleared everything: %q", r.errb.String())
			}
			r.assertUnlocked(svc, "root")
			if n := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'admin.unlock_cli' AND params = $1::jsonb`, both); n != 1 {
				t.Fatalf("%d complete unlock rows", n)
			}
		})
	}
	if driven < 3 {
		t.Fatalf("only %d commands are driven: the table lost one", driven)
	}
}

// TestAResetWritesItsPasswordBeforeItClearsAnything is admin-r10-2. The reset commits, and from then on
// the old password is dead and every session is revoked, so the new one-time password is the one thing
// that must reach the file before anything else can stall or be killed: the clear that follows runs
// a Valkey call and a second database transaction, and the admin container has a small cgroup that it
// shares with the live service. The Valkey step is the seam: it reads the file at the moment it runs.
func TestAResetWritesItsPasswordBeforeItClearsAnything(t *testing.T) {
	for _, cmd := range []string{"reset-password", "reset-totp"} {
		t.Run(cmd, func(t *testing.T) {
			r := newRig(t)
			r.readyAdmin()
			var seen string
			var auditRowsThen int
			ran := false
			r.clearRateLimits = func(context.Context) error {
				ran = true
				raw, err := os.ReadFile(r.lastOut)
				if err != nil {
					t.Errorf("the out-file at the clear: %v", err)
				}
				seen = strings.TrimSpace(string(raw))
				auditRowsThen = r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'admin.unlock_cli'`)
				return nil
			}
			if code := r.run(cmd, "--user", "root"); code != 0 {
				t.Fatalf("exit %d: %q", code, r.errb.String())
			}
			if !ran {
				t.Fatal("the Valkey step never ran: the test proves nothing")
			}
			pw, ok := strings.CutPrefix(seen, "one-time password: ")
			if !ok || pw == "" {
				t.Fatalf("at the clear the out-file held %d bytes and no password: a stop there loses the only copy", len(seen))
			}
			if !r.verify(pw, seedAdmin) {
				t.Error("the password in the file at the clear is not the one the reset stored")
			}
			if auditRowsThen != 0 {
				t.Errorf("%d unlock rows at the clear: the audit row of the clear came before the password was written", auditRowsThen)
			}
			if r.printed() != pw {
				t.Error("the file changed after the clear")
			}
		})
	}
}
