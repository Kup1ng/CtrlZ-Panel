package admincli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/adminapi"
	"github.com/Kup1ng/CtrlZ-Panel/internal/admincli"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	// The key-identity matrix runs scripts/gen-secrets.sh with a stand-in `docker` that
	// starts this test binary as `ctrlz keys ...`, so the script meets the real
	// derive code and not a stub that writes placeholders. This must come first:
	// it needs no database.
	if os.Getenv("CTRLZ_TEST_AS_CTRLZ_KEYS") == "1" {
		os.Exit(admincli.RunKeys(context.Background(), os.Args[1:], admincli.Env{}))
	}
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

var seedAdmin = uuid.MustParse("00000000-0000-7000-8000-0000000000e1")

// rig is one database and the pieces a command needs.
type rig struct {
	t       *testing.T
	env     *authtest.Env
	st      *store.Store
	keys    *keyring.Ring
	hasher  *password.Hasher
	stdin   string
	outDir  string // where the injected --out-file paths live
	lastOut string // the file the last command was told to write
	seq     int
	out     bytes.Buffer
	errb    bytes.Buffer
	mu      sync.Mutex
	// clearRateLimits, when set, is the Valkey step of unlock (Tools.ClearRateLimits).
	clearRateLimits func(context.Context) error
}

func newRig(t *testing.T) *rig {
	t.Helper()
	env := authtest.New(t, cluster)
	return &rig{t: t, env: env, st: env.Admin(t), keys: authtest.AdminKeys(t), hasher: authtest.FastHasher(t), outDir: t.TempDir()}
}

func (r *rig) cliEnv(out, errb io.Writer) admincli.Env {
	return admincli.Env{
		Stdin: strings.NewReader(r.stdin), Stdout: out, Stderr: errb,
		Open: func(context.Context) (*admincli.Tools, error) {
			return &admincli.Tools{Store: r.st, Keys: r.keys, Hasher: r.hasher, ClearRateLimits: r.clearRateLimits}, nil
		},
	}
}

// run executes a command and returns its exit code; the output is in r.out / r.errb.
// A command that issues a one-time password is given a fresh --out-file unless the
// arguments name one, since the command refuses to run without it (10.1).
func (r *rig) run(args ...string) int {
	r.t.Helper()
	return r.runBare(r.withOutFile(args)...)
}

// runBare is run with the arguments exactly as given.
func (r *rig) runBare(args ...string) int {
	r.t.Helper()
	r.out.Reset()
	r.errb.Reset()
	return admincli.RunWith(r.env.Ctx, args, r.cliEnv(&r.out, &r.errb))
}

func (r *rig) withOutFile(args []string) []string {
	if len(args) == 0 || (args[0] != "bootstrap" && args[0] != "reset-password" && args[0] != "reset-totp") {
		return args
	}
	for _, a := range args {
		if a == "--out-file" {
			return args
		}
	}
	r.seq++
	r.lastOut = filepath.Join(r.outDir, "otp"+strconv.Itoa(r.seq))
	return append(append([]string(nil), args...), "--out-file", r.lastOut)
}

// printed reads the one-time password the last command wrote to its --out-file.
// It must not be on stdout: stdout holds the path only.
func (r *rig) printed() string {
	r.t.Helper()
	const label = "one-time password: "
	raw, err := os.ReadFile(r.lastOut)
	if err != nil {
		r.t.Fatalf("the out-file of the last command: %v", err)
	}
	pw, ok := strings.CutPrefix(strings.TrimSpace(string(raw)), label)
	if !ok || pw == "" {
		r.t.Fatalf("the out-file has no one-time password line (%d bytes)", len(raw))
	}
	if strings.Contains(r.out.String()+r.errb.String(), pw) {
		r.t.Fatal("the one-time password is on stdout or stderr")
	}
	return pw
}

func (r *rig) count(sql string, args ...any) int {
	r.t.Helper()
	var n int
	r.env.Scan(r.t, sql, args, &n)
	return n
}

func (r *rig) verify(pw string, adminID uuid.UUID) bool {
	r.t.Helper()
	var hash string
	r.env.Scan(r.t, `SELECT password_hash FROM ctrlz.admin_users WHERE id = $1`, []any{adminID}, &hash)
	ok, err := r.hasher.Verify(r.env.Ctx, secret.New(pw), secret.New(hash))
	if err != nil {
		r.t.Fatal(err)
	}
	return ok
}

// noAdmin removes the seeded admin, as on a fresh install.
func (r *rig) noAdmin() { r.env.Exec(r.t, `DELETE FROM ctrlz.admin_users`) }

func TestBootstrap(t *testing.T) {
	r := newRig(t)
	r.noAdmin()

	// No --out-file: refused as a usage error before anything changes (10.1).
	if code := r.runBare("bootstrap", "--username", "root"); code != 2 || !strings.Contains(r.errb.String(), "--out-file PATH is required") {
		t.Fatalf("exit %d, stderr %q", code, r.errb.String())
	}
	if r.count(`SELECT count(*) FROM ctrlz.admin_users`) != 0 || r.count(`SELECT count(*) FROM ctrlz.audit_log`) != 0 {
		t.Fatal("a refused bootstrap wrote something")
	}

	// --out-file: a new file with mode 0600.
	file := filepath.Join(t.TempDir(), "otp")
	if code := r.run("bootstrap", "--username", "root", "--out-file", file); code != 0 || r.out.String() != file+"\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, r.out.String(), r.errb.String())
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	pw := strings.TrimSpace(strings.TrimPrefix(string(raw), "one-time password: "))
	if len(pw) != 24 || strings.Contains(r.out.String()+r.errb.String(), pw) {
		t.Fatalf("password %d characters; stdout/stderr hold it: %v", len(pw), strings.Contains(r.out.String()+r.errb.String(), pw))
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v", fi.Mode().Perm())
		}
	}
	var id uuid.UUID
	var must bool
	var life bool
	r.env.Scan(t, `SELECT id, must_change_password, password_expires_at BETWEEN now() + interval '23 hours 55 minutes' AND now() + interval '24 hours 5 minutes' FROM ctrlz.admin_users`, nil, &id, &must, &life)
	if !must || !life || !r.verify(pw, id) {
		t.Fatalf("must_change_password %v, 24h expiry %v, hash verifies %v", must, life, r.verify(pw, id))
	}
	// The audit row: admin_id NULL, target the new admin, via cli. No password anywhere.
	var actor *uuid.UUID
	var target, params string
	r.env.Scan(t, `SELECT admin_id, target, params::text FROM ctrlz.audit_log WHERE action = 'admin.bootstrap'`, nil, &actor, &target, &params)
	if actor != nil || target != "admin:"+id.String() || !strings.Contains(params, `"via": "cli"`) {
		t.Fatalf("audit row: %v %s %s", actor, target, params)
	}
	if r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE row_to_json(audit_log)::text LIKE '%' || $1 || '%'`, pw) != 0 ||
		r.count(`SELECT count(*) FROM ctrlz.admin_sessions WHERE row_to_json(admin_sessions)::text LIKE '%' || $1 || '%'`, pw) != 0 {
		t.Fatal("the password is in the audit log or the sessions")
	}

	// A second bootstrap, with a terminal or a file, is refused and writes nothing.
	before := r.count(`SELECT count(*) FROM ctrlz.audit_log`)
	if code := r.run("bootstrap", "--username", "second"); code != 1 || !strings.Contains(r.errb.String(), "already exists") || r.out.Len() != 0 {
		t.Fatalf("exit %d, stderr %q", code, r.errb.String())
	}
	file2 := filepath.Join(t.TempDir(), "otp2")
	if code := r.run("bootstrap", "--username", "second", "--out-file", file2); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(file2); err == nil {
		t.Fatal("a refused bootstrap left its output file")
	}
	if r.count(`SELECT count(*) FROM ctrlz.admin_users`) != 1 || r.count(`SELECT count(*) FROM ctrlz.audit_log`) != before {
		t.Fatal("a refused bootstrap wrote something")
	}
	// An existing output file is never overwritten, and nothing changes.
	if code := r.run("reset-password", "--user", "root", "--out-file", file); code != 1 || !strings.Contains(r.errb.String(), "already exists") {
		t.Fatalf("exit %d, stderr %q", code, r.errb.String())
	}
	if !r.verify(pw, id) {
		t.Fatal("a refused reset changed the password")
	}
}

func TestBootstrapUsernameAndPrompt(t *testing.T) {
	r := newRig(t)
	r.noAdmin()
	if code := r.run("bootstrap", "--username", strings.Repeat("a", 65)); code != 2 || r.lastOutExists() {
		t.Fatalf("a 65 character username: exit %d", code)
	}
	if code := r.run("bootstrap", "--username", "has space"); code != 2 {
		t.Fatalf("a username with a space: exit %d", code)
	}
	// admin-r6-2: a private-use or unassigned code point is refused by the login schema, so the CLI
	// must refuse it before it writes an account nobody can sign in to (bootstrap runs only once).
	for _, name := range []string{"ad\U000f0000min", "ad͸min", "ad​min"} {
		if code := r.run("bootstrap", "--username", name); code != 2 || r.lastOutExists() {
			t.Fatalf("username %q: exit %d", name, code)
		}
	}
	if r.count(`SELECT count(*) FROM ctrlz.admin_users`) != 0 {
		t.Fatal("an invalid username created an admin")
	}
	r.stdin = "prompted\n"
	if code := r.run("bootstrap"); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, r.errb.String())
	}
	var name string
	r.env.Scan(t, `SELECT username FROM ctrlz.admin_users`, nil, &name)
	if name != "prompted" {
		t.Fatalf("username = %q", name)
	}
}

func TestParallelBootstrap(t *testing.T) {
	r := newRig(t)
	r.noAdmin()
	codes := make(chan int, 4)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var o, e bytes.Buffer
			<-start
			codes <- admincli.RunWith(r.env.Ctx, []string{"bootstrap", "--username", "racer", "--out-file", filepath.Join(r.outDir, "racer"+strconv.Itoa(i))}, r.cliEnv(&o, &e))
		}()
	}
	close(start)
	wg.Wait()
	close(codes)
	ok := 0
	for c := range codes {
		if c == 0 {
			ok++
		}
	}
	if ok != 1 || r.count(`SELECT count(*) FROM ctrlz.admin_users`) != 1 || r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'admin.bootstrap'`) != 1 {
		t.Fatalf("%d bootstraps won; %d admins", ok, r.count(`SELECT count(*) FROM ctrlz.admin_users`))
	}
}

// readyAdmin makes the seeded admin a ready one with a session and a locked login
// throttle, so a reset has something to clear.
func (r *rig) readyAdmin() (secret.Bytes, string) {
	r.t.Helper()
	const pw = "Granite-lantern-Harbor-4471-quill"
	hash, err := r.hasher.Hash(r.env.Ctx, secret.New(pw))
	if err != nil {
		r.t.Fatal(err)
	}
	seed, err := totp.NewSecret()
	if err != nil {
		r.t.Fatal(err)
	}
	ct, err := r.keys.Seal(keyring.DomainAdminTOTP, totp.AdminAAD(seedAdmin), seed.Reveal())
	if err != nil {
		r.t.Fatal(err)
	}
	r.env.Exec(r.t, `UPDATE ctrlz.admin_users SET username = 'root', password_hash = $2, must_change_password = false, password_expires_at = NULL,
	  totp_secret_ct = $3, totp_enabled_at = now() WHERE id = $1`, seedAdmin, hash.Reveal(), ct)
	r.env.Exec(r.t, `INSERT INTO ctrlz.admin_sessions (admin_id, token_hash, idle_expires_at, absolute_expires_at, created_at)
	  VALUES ($1, '\x0102', now() + interval '10 minutes', now() + interval '1 hour', now())`, seedAdmin)
	return seed, pw
}

// lockLogin counts the admin's login throttle to its limits.
func (r *rig) lockLogin(username string) *throttle.Service {
	r.t.Helper()
	svc := throttle.NewAdmin(r.st.Admin(), r.keys)
	// Every key is counted to its own limit (they differ: 5, 30, 20), so that the
	// refusal below and the clear after a command are real.
	for _, hit := range r.lockedKeys(svc, username) {
		for i := 0; i < 200 && hit() == nil; i++ {
		}
	}
	for name, hit := range r.lockedKeys(svc, username) {
		if hit() == nil {
			r.t.Fatalf("%s did not lock", name)
		}
	}
	return svc
}

func TestResetPasswordAndTOTP(t *testing.T) {
	r := newRig(t)
	_, oldPW := r.readyAdmin()
	svc := r.lockLogin("root")

	// No --out-file: nothing changes.
	if code := r.runBare("reset-password", "--user", "root"); code != 2 {
		t.Fatalf("exit %d", code)
	}
	if !r.verify(oldPW, seedAdmin) {
		t.Fatal("a refused reset changed the password")
	}
	if code := r.run("reset-password", "--user", "nobody"); code != 1 || !strings.Contains(r.errb.String(), "no such admin") {
		t.Fatalf("unknown admin: exit %d %q", code, r.errb.String())
	}

	if code := r.run("reset-password", "--user", "root"); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, r.errb.String())
	}
	pw := r.printed()
	var must, life, revoked, hasTOTP bool
	r.env.Scan(t, `SELECT must_change_password, password_expires_at BETWEEN now() + interval '23 hours 55 minutes' AND now() + interval '24 hours 5 minutes',
	  (SELECT bool_and(revoked_at IS NOT NULL) FROM ctrlz.admin_sessions WHERE admin_id = $1), totp_enabled_at IS NOT NULL FROM ctrlz.admin_users WHERE id = $1`,
		[]any{seedAdmin}, &must, &life, &revoked, &hasTOTP)
	if !must || !life || !revoked || !hasTOTP {
		t.Fatalf("must %v, 24h %v, sessions revoked %v, totp kept %v", must, life, revoked, hasTOTP)
	}
	if !r.verify(pw, seedAdmin) || r.verify(oldPW, seedAdmin) {
		t.Fatal("the password is not the new one-time password")
	}
	// The login throttle is clear.
	r.assertUnlocked(svc, "root")
	var notice, target string
	r.env.Scan(t, `SELECT pending_notice::text FROM ctrlz.admin_users WHERE id = $1`, []any{seedAdmin}, &notice)
	r.env.Scan(t, `SELECT target FROM ctrlz.audit_log WHERE action = 'admin.password_reset_cli'`, nil, &target)
	if !strings.Contains(notice, "password_reset") || target != "admin:"+seedAdmin.String() {
		t.Fatalf("notice %s target %s", notice, target)
	}

	// reset-totp does the same and forgets the authenticator.
	svc = r.lockLogin("root")
	if code := r.run("reset-totp", "--user", "root"); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, r.errb.String())
	}
	pw2 := r.printed()
	r.assertUnlocked(svc, "root")
	var ct *[]byte
	var enabledAt, step *time.Time
	r.env.Scan(t, `SELECT totp_secret_ct, totp_enabled_at, NULL::timestamptz FROM ctrlz.admin_users WHERE id = $1`, []any{seedAdmin}, &ct, &enabledAt, &step)
	if ct != nil || enabledAt != nil || pw2 == pw || r.verify(pw, seedAdmin) || !r.verify(pw2, seedAdmin) {
		t.Fatal("reset-totp did not reset both the password and the authenticator")
	}
	r.env.Scan(t, `SELECT pending_notice::text FROM ctrlz.admin_users WHERE id = $1`, []any{seedAdmin}, &notice)
	if !strings.Contains(notice, "password_reset") || !strings.Contains(notice, "totp_reset") {
		t.Fatalf("notice %s", notice)
	}
	if r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'admin.totp_reset_cli'`) != 1 {
		t.Fatal("no admin.totp_reset_cli row")
	}
	for _, p := range []string{pw, pw2} {
		if r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE row_to_json(audit_log)::text LIKE '%' || $1 || '%'`, p) != 0 {
			t.Fatal("a password is in the audit log")
		}
	}
}

func TestUnlock(t *testing.T) {
	r := newRig(t)
	r.readyAdmin()
	svc := r.lockLogin("root")
	if code := r.run("unlock", "--user", "nobody"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if code := r.run("unlock", "--user", "root"); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, r.errb.String())
	}
	// Every registered admin scope is clear, among them admin_login_net, which does
	// not reset on success and which only the console clears (review round 1).
	r.assertUnlocked(svc, "root")
	if r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'admin.unlock_cli'`) != 1 {
		t.Fatal("no admin.unlock_cli row")
	}
	// It changed nothing else.
	if r.count(`SELECT count(*) FROM ctrlz.admin_sessions WHERE revoked_at IS NOT NULL`) != 0 {
		t.Fatal("unlock ended a session")
	}
}

// TestUnlockClearsTheValkeyLimitsToo is admin-r6-7: the admin-login speed bumps live in Valkey and
// unlock cleared only the database scopes, so a spent bucket (a neighbour on the owner's carrier
// address group fills it) had no way back from the console.
//
// Round 7 (admin-r7-3 and -7): a Valkey that cannot be cleared no longer fails the command after the
// database scopes were already cleared and leaves no audit row. The database part is the lock-out, so
// it is cleared and audited whatever Valkey does; the command says plainly that the Valkey part was not
// done, and the row records both stores.
func TestUnlockClearsTheValkeyLimitsToo(t *testing.T) {
	r := newRig(t)
	r.readyAdmin()
	cleared := 0
	r.clearRateLimits = func(context.Context) error { cleared++; return nil }
	if code := r.run("unlock", "--user", "root"); code != 0 || cleared != 1 {
		t.Fatalf("exit %d, Valkey cleared %d times, stderr %q", code, cleared, r.errb.String())
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'admin.unlock_cli' AND params = '{"via":"cli","database_cleared":true,"valkey_cleared":true}'::jsonb`); n != 1 {
		t.Fatalf("%d complete unlock rows", n)
	}

	// A Valkey that is configured and cannot be reached, with the database scopes spent.
	svc := r.lockLogin("root")
	r.clearRateLimits = func(context.Context) error { return errors.New("valkey down") }
	r.out.Reset()
	r.errb.Reset()
	if code := r.run("unlock", "--user", "root"); code != 0 || r.out.String() != "unlocked in the database\n" {
		t.Fatalf("exit %d, stdout %q: the database part is done and the command must say only that", code, r.out.String())
	}
	if !strings.Contains(r.errb.String(), "Valkey could not be cleared") {
		t.Errorf("no warning about Valkey: %q", r.errb.String())
	}
	if strings.Contains(r.errb.String()+r.out.String(), "valkey down") {
		t.Errorf("the Valkey error text reached the operator: %q", r.errb.String())
	}
	r.assertUnlocked(svc, "root")
	if n := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'admin.unlock_cli' AND params = '{"via":"cli","database_cleared":true,"valkey_cleared":false}'::jsonb`); n != 1 {
		t.Fatalf("%d unlock rows for the run that could not clear Valkey: the state change has no record", n)
	}
}

// A reset writes its own row and, after the throttle clear, the row of the clear (admin.unlock_cli),
// so the chain of this test holds three rows: the reset, its clear and the note.
func TestAuditVerify(t *testing.T) {
	r := newRig(t)
	r.readyAdmin()
	if code := r.run("reset-password", "--user", "root"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if code := r.run("audit-note", "key.rotated", "--domain", "admin_totp", "--key-number", "2"); code != 0 {
		t.Fatalf("audit-note: exit %d %q", code, r.errb.String())
	}
	if code := r.run("audit-note", "key.nonsense", "--domain", "admin_totp", "--key-number", "2"); code != 2 {
		t.Fatalf("a bad action: exit %d", code)
	}
	if code := r.run("audit", "verify"); code != 0 || !strings.Contains(r.out.String(), "audit chain ok: 3 rows") {
		t.Fatalf("exit %d, %q %q", code, r.out.String(), r.errb.String())
	}
	// Edit a row as the superuser: the chain notices.
	r.env.Exec(t, `ALTER TABLE ctrlz.audit_log DISABLE TRIGGER USER`)
	r.env.Exec(t, `UPDATE ctrlz.audit_log SET target = 'admin:tampered' WHERE action = 'admin.password_reset_cli'`)
	if code := r.run("audit", "verify"); code != 1 || !strings.Contains(r.errb.String(), "broken at row") {
		t.Fatalf("a tampered chain: exit %d %q", code, r.errb.String())
	}
}

// TestKeyStatusAndRekey re-encrypts under a second key (8.4): the admin's two
// domains, the counts before and after, and the one-shot tool for user_totp.
func TestKeyStatusAndRekey(t *testing.T) {
	r := newRig(t)
	r.readyAdmin()
	// A root, so key 2 is derived the way `keys derive --rotate` does.
	raw := bytes.Repeat([]byte{7}, 32)
	root := secret.NewBytes(raw)
	one, err := keyring.FromRoot(root, map[string][]uint16{keyring.DomainAdminTOTP: {1}, keyring.DomainSMSCred: {1}, keyring.DomainAdminMAC: {1}})
	if err != nil {
		t.Fatal(err)
	}
	both, err := keyring.FromRoot(root, map[string][]uint16{keyring.DomainAdminTOTP: {1, 2}, keyring.DomainSMSCred: {1, 2}, keyring.DomainAdminMAC: {1}})
	if err != nil {
		t.Fatal(err)
	}
	// Seal the admin's seed and a gateway's credentials under key 1.
	s, _ := totp.NewSecret()
	ct, _ := one.Seal(keyring.DomainAdminTOTP, totp.AdminAAD(seedAdmin), s.Reveal())
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET totp_secret_ct = $2 WHERE id = $1`, seedAdmin, ct)
	gw := uuid.New()
	cct, _ := sms.SealCredentials(one, gw, "sms_ir", secret.NewBytes([]byte(`{"api_key":"k-1234567"}`)))
	r.env.ResetSMS(t)
	r.env.Exec(t, `INSERT INTO ctrlz.sms_gateways (id, provider, role, credentials_ct) VALUES ($1, 'sms_ir', 'disabled', $2)`, gw, cct)

	r.keys = both
	if code := r.run("keys", "status", "admin_totp"); code != 0 || !strings.Contains(r.out.String(), "key 1: 1") {
		t.Fatalf("status before: %d %q", code, r.out.String())
	}
	if code := r.run("rekey", "admin_totp"); code != 0 || !strings.Contains(r.out.String(), "1 rewritten") {
		t.Fatalf("rekey admin_totp: %d %q %q", code, r.out.String(), r.errb.String())
	}
	if code := r.run("rekey", "sms_cred"); code != 0 || !strings.Contains(r.out.String(), "1 rewritten") {
		t.Fatalf("rekey sms_cred: %d %q %q", code, r.out.String(), r.errb.String())
	}
	if code := r.run("rekey", "admin_totp"); code != 0 || !strings.Contains(r.out.String(), "0 rewritten, 1 already current") {
		t.Fatalf("a second rekey: %d %q", code, r.out.String())
	}
	if code := r.run("keys", "status", "sms_cred"); code != 0 || !strings.Contains(r.out.String(), "key 2: 1") {
		t.Fatalf("status after: %d %q", code, r.out.String())
	}
	// Both values now open with key 2 alone.
	two, err := keyring.FromRoot(root, map[string][]uint16{keyring.DomainAdminTOTP: {2}, keyring.DomainSMSCred: {2}})
	if err != nil {
		t.Fatal(err)
	}
	var ct2, cct2 []byte
	r.env.Scan(t, `SELECT totp_secret_ct FROM ctrlz.admin_users WHERE id = $1`, []any{seedAdmin}, &ct2)
	r.env.Scan(t, `SELECT credentials_ct FROM ctrlz.sms_gateways WHERE id = $1`, []any{gw}, &cct2)
	if got, err := two.Open(keyring.DomainAdminTOTP, totp.AdminAAD(seedAdmin), ct2); err != nil || string(got.Reveal()) != string(s.Reveal()) {
		t.Fatalf("the rekeyed seed does not open: %v", err)
	}
	if _, err := sms.OpenCredentials(two, gw, "sms_ir", cct2); err != nil {
		t.Fatalf("the rekeyed credentials do not open: %v", err)
	}
	// Domains with nothing to rewrite, and the one for the other tool.
	if code := r.run("rekey", "auth_mac"); code != 0 {
		t.Fatalf("rekey auth_mac: %d", code)
	}
	if code := r.run("rekey", "user_totp"); code != 1 {
		t.Fatalf("rekey user_totp on admin: %d", code)
	}
	if code := r.run("rekey", "nonsense"); code != 2 {
		t.Fatalf("rekey nonsense: %d", code)
	}

	// The user_totp tool, on the worker's role: both tenants' seeds.
	uone, _ := keyring.FromRoot(root, map[string][]uint16{keyring.DomainUserTOTP: {1}})
	uboth, _ := keyring.FromRoot(root, map[string][]uint16{keyring.DomainUserTOTP: {1, 2}})
	utwo, _ := keyring.FromRoot(root, map[string][]uint16{keyring.DomainUserTOTP: {2}})
	for _, ids := range []struct{ tenant, user uuid.UUID }{{r.env.A.Tenant, r.env.A.User}, {r.env.B.Tenant, r.env.B.User}} {
		c, err := uone.Seal(keyring.DomainUserTOTP, totp.UserAAD(ids.tenant, ids.user), s.Reveal())
		if err != nil {
			t.Fatal(err)
		}
		r.env.Exec(t, `UPDATE ctrlz.users SET totp_secret_ct = $3, totp_enabled_at = now() WHERE tenant_id = $1 AND id = $2`, ids.tenant, ids.user, c)
	}
	worker := r.env.Keytool(t)
	env := r.cliEnv(&r.out, &r.errb)
	env.OpenRekey = func(context.Context) (*admincli.RekeyTools, error) {
		return &admincli.RekeyTools{Store: worker, Keys: uboth}, nil
	}
	r.out.Reset()
	if code := admincli.RunRekey(r.env.Ctx, []string{"user_totp"}, env); code != 0 || !strings.Contains(r.out.String(), "2 rewritten") {
		t.Fatalf("user_totp rekey: %d %q %q", code, r.out.String(), r.errb.String())
	}
	for _, ids := range []struct{ tenant, user uuid.UUID }{{r.env.A.Tenant, r.env.A.User}, {r.env.B.Tenant, r.env.B.User}} {
		var c []byte
		r.env.Scan(t, `SELECT totp_secret_ct FROM ctrlz.users WHERE tenant_id = $1 AND id = $2`, []any{ids.tenant, ids.user}, &c)
		if got, err := utwo.Open(keyring.DomainUserTOTP, totp.UserAAD(ids.tenant, ids.user), c); err != nil || string(got.Reveal()) != string(s.Reveal()) {
			t.Fatalf("user seed after rekey: %v", err)
		}
	}
	// The re-seal of every tenant's second factor has its rows in the admin chain (admin-r18-6): one per
	// tenant, in the transaction of the rewrite, with counts only, and the chain verifies.
	if n := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'key.rekeyed' AND target = 'domain:user_totp' AND params->>'key_number' = '2' AND params->>'rewritten' = '1' AND params->>'failed' = '0' AND admin_id IS NULL`); n != 2 {
		t.Fatalf("%d key.rekeyed rows for the tenants, want 2", n)
	}
	if code := r.run("audit", "verify"); code != 0 {
		t.Fatalf("the chain does not verify after the key tool wrote rows: %d %q", code, r.errb.String())
	}
	// The other tool refuses other domains.
	if code := admincli.RunRekey(r.env.Ctx, []string{"admin_totp"}, env); code != 2 {
		t.Fatalf("rekey tool with admin_totp: %d", code)
	}

	// declare-lost user_totp on the admin side only records the declaration (review
	// round 3, db-r3-1 and db-r3-5): the admin role cannot switch off a second
	// factor. It needs --yes and a number, as before.
	if code := r.run("keys", "declare-lost", "user_totp", "--key-number", "1"); code != 2 {
		t.Fatalf("without --yes: %d", code)
	}
	if code := r.run("keys", "declare-lost", "user_totp", "--yes"); code != 2 {
		t.Fatalf("without --key-number: %d", code)
	}
	if code := r.run("keys", "declare-lost", "admin_totp", "--key-number", "1", "--yes"); code != 1 || !strings.Contains(r.errb.String(), "reset-totp") {
		t.Fatalf("admin_totp: %d %q", code, r.errb.String())
	}
	// Put both seeds back under key 1, the key that is about to be lost.
	for _, ids := range []struct{ tenant, user uuid.UUID }{{r.env.A.Tenant, r.env.A.User}, {r.env.B.Tenant, r.env.B.User}} {
		c, err := uone.Seal(keyring.DomainUserTOTP, totp.UserAAD(ids.tenant, ids.user), s.Reveal())
		if err != nil {
			t.Fatal(err)
		}
		r.env.Exec(t, `UPDATE ctrlz.users SET totp_secret_ct = $3, totp_enabled_at = now() WHERE tenant_id = $1 AND id = $2`, ids.tenant, ids.user, c)
	}
	if code := r.run("keys", "declare-lost", "user_totp", "--key-number", "1", "--yes"); code != 0 || !strings.Contains(r.out.String(), "declare-lost user_totp --key-number 1") {
		t.Fatalf("declare-lost: %d %q %q", code, r.out.String(), r.errb.String())
	}
	if r.count(`SELECT count(*) FROM ctrlz.users WHERE totp_enabled_at IS NOT NULL AND totp_secret_ct IS NOT NULL`) != 2 {
		t.Fatal("the admin command cleared a second factor")
	}
	if r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'key.declared_lost' AND target = 'domain:user_totp' AND params->>'key_number' = '1'`) != 1 {
		t.Fatal("no key.declared_lost row")
	}

	// The worker's tool clears them. It needs --yes and a number, refuses another
	// domain. It no longer refuses for a key that is in the ring (round 13, admin-r13-3): it opens
	// the seeds and leaves the ones that open.
	for _, bad := range [][]string{{"user_totp", "--key-number", "1"}, {"user_totp", "--yes"}} {
		if code := admincli.RunDeclareLost(r.env.Ctx, bad, env); code != 2 {
			t.Fatalf("declare-lost %v: %d", bad, code)
		}
	}
	if code := admincli.RunDeclareLost(r.env.Ctx, []string{"admin_totp", "--key-number", "1", "--yes"}, env); code != 2 {
		t.Fatalf("declare-lost admin_totp on the worker tool: %d", code)
	}
	r.errb.Reset()
	// Every seed that names key 1 opens with the ring: nothing is lost, and the tool refuses before it
	// writes anything (admin-r18-7), instead of finishing with "0 users" and a record of a loss that did
	// not happen.
	before := r.count(`SELECT count(*) FROM ctrlz.audit_log`)
	if code := admincli.RunDeclareLost(r.env.Ctx, []string{"user_totp", "--key-number", "1", "--yes"}, env); code != 1 || !strings.Contains(r.errb.String(), "not lost") {
		t.Fatalf("a key that is in the ring and opens every seed was declared lost: %d %q %q", code, r.out.String(), r.errb.String())
	}
	if r.count(`SELECT count(*) FROM ctrlz.audit_log`) != before {
		t.Fatal("the refused declaration wrote an audit row")
	}
	if r.count(`SELECT count(*) FROM ctrlz.users WHERE totp_enabled_at IS NOT NULL AND totp_secret_ct IS NOT NULL`) != 2 {
		t.Fatal("the run cleared a second factor that opens")
	}
	// Key 1 is gone from the ring: only key 2 is left.
	env.OpenRekey = func(context.Context) (*admincli.RekeyTools, error) {
		return &admincli.RekeyTools{Store: worker, Keys: utwo}, nil
	}
	r.out.Reset()
	if code := admincli.RunDeclareLost(r.env.Ctx, []string{"user_totp", "--key-number", "1", "--yes"}, env); code != 0 || !strings.Contains(r.out.String(), "2 users") {
		t.Fatalf("declare-lost: %d %q %q", code, r.out.String(), r.errb.String())
	}
	if r.count(`SELECT count(*) FROM ctrlz.users WHERE totp_enabled_at IS NOT NULL OR totp_secret_ct IS NOT NULL`) != 0 {
		t.Fatal("TOTP is still set after declare-lost")
	}
	if r.count(`SELECT count(*) FROM ctrlz.notifications WHERE kind = 'totp_lost'`) != 2 {
		t.Fatal("the tenants were not told to enrol again")
	}
	if r.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'totp.declared_lost' AND params->>'key_number' = '1'`) != 2 {
		t.Fatal("no tenant audit row for the declaration")
	}
	// The tool also wrote its rows in the admin chain, one in each tenant's transaction (admin-r18-7): the
	// one of the console command above and two of the tool, and the chain still verifies with the Go verifier.
	if n := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'key.declared_lost' AND target = 'domain:user_totp' AND params->>'key_number' = '1'`); n != 3 {
		t.Fatalf("%d key.declared_lost rows, want 3", n)
	}
	if code := r.run("audit", "verify"); code != 0 {
		t.Fatalf("the chain does not verify after the key tool wrote rows: %d %q", code, r.errb.String())
	}
}

// TestDeriveKeys runs `ctrlz keys derive` on a directory (8.3).
func TestDeriveKeys(t *testing.T) {
	dir := t.TempDir()
	var out, errb bytes.Buffer
	env := admincli.Env{Stdout: &out, Stderr: &errb}
	if code := admincli.RunKeys(context.Background(), []string{"derive", "--dir", dir}, env); code != 1 {
		t.Fatalf("without a root: %d", code)
	}
	root := bytes.Repeat([]byte{0x42}, 32)
	if err := os.WriteFile(filepath.Join(dir, "kek_root"), root, 0o400); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := admincli.RunKeys(context.Background(), []string{"derive", "--dir", dir}, env); code != 0 {
		t.Fatalf("derive: %d %q", code, errb.String())
	}
	for _, d := range keyring.Domains() {
		if _, err := os.Stat(filepath.Join(dir, "kek_"+d)); err != nil {
			t.Errorf("no key file for %s", d)
		}
		if !strings.Contains(out.String(), "kek_"+d) {
			t.Errorf("the output does not name %s", d)
		}
	}
	// Nothing printed is a key: no base64 of 43 characters.
	for _, w := range strings.Fields(out.String()) {
		if len(w) >= 40 {
			t.Errorf("the output holds a long token: %q", w)
		}
	}
	ring, err := keyring.Load(dir, keyring.DomainUserTOTP, keyring.DomainAdminTOTP)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := ring.Seal(keyring.DomainUserTOTP, keyring.RowContext([]uuid.UUID{uuid.MustParse("0b6c1d1e-6c1f-4a52-9d6c-3f3c0f4f9a11")}, "ctx"), []byte("plain"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(filepath.Join(dir, "kek_user_totp")); fi.Mode().Perm() != 0o444 {
			t.Fatalf("mode = %v", fi.Mode().Perm())
		}
	}
	// Run again: existing files are kept.
	out.Reset()
	if code := admincli.RunKeys(context.Background(), []string{"derive", "--dir", dir}, env); code != 0 || strings.Contains(out.String(), "wrote") {
		t.Fatalf("second derive: %d %q", code, out.String())
	}
	// The root and the files agree with keyring.FromRoot.
	want, _ := keyring.FromRoot(secret.NewBytes(root), map[string][]uint16{keyring.DomainUserTOTP: {1}})
	if _, err := want.Open(keyring.DomainUserTOTP, keyring.RowContext([]uuid.UUID{uuid.MustParse("0b6c1d1e-6c1f-4a52-9d6c-3f3c0f4f9a11")}, "ctx"), ct); err != nil {
		t.Fatalf("a file written by derive does not match the derivation: %v", err)
	}
	// Rotate.
	out.Reset()
	if code := admincli.RunKeys(context.Background(), []string{"derive", "--dir", dir, "--rotate", "user_totp"}, env); code != 0 || !strings.Contains(out.String(), "key 2 added") {
		t.Fatalf("rotate: %d %q %q", code, out.String(), errb.String())
	}
	ring, err = keyring.Load(dir, keyring.DomainUserTOTP)
	if err != nil {
		t.Fatal(err)
	}
	if n := ring.Numbers(keyring.DomainUserTOTP); len(n) != 2 || n[0] != 1 || n[1] != 2 {
		t.Fatalf("numbers = %v", n)
	}
	if _, err := ring.Open(keyring.DomainUserTOTP, keyring.RowContext([]uuid.UUID{uuid.MustParse("0b6c1d1e-6c1f-4a52-9d6c-3f3c0f4f9a11")}, "ctx"), ct); err != nil {
		t.Fatalf("a value sealed under key 1 no longer opens: %v", err)
	}
	// A root that is not the one the files came from (a wrong backup, or one made
	// again after the old was lost) must not be allowed to rotate (review round 1).
	before, _ := os.ReadFile(filepath.Join(dir, "kek_user_totp"))
	if err := os.Remove(filepath.Join(dir, "kek_root")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "kek_root"), bytes.Repeat([]byte{0x24}, 32), 0o400); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := admincli.RunKeys(context.Background(), []string{"derive", "--dir", dir, "--rotate", "user_totp"}, env); code != admincli.ExitRefused {
		t.Fatalf("rotate with another root: %d %q", code, out.String())
	}
	if !strings.Contains(errb.String(), "user_totp") || strings.Contains(out.String(), "added") {
		t.Fatalf("rotate with another root: out %q err %q", out.String(), errb.String())
	}
	after, _ := os.ReadFile(filepath.Join(dir, "kek_user_totp"))
	if !bytes.Equal(before, after) {
		t.Fatal("a refused rotation changed the key file")
	}
	// The deliberate act of spec 8.5: kek_root was lost and made again. The older
	// line stays, the new key comes from the new root.
	out.Reset()
	errb.Reset()
	if code := admincli.RunKeys(context.Background(), []string{"derive", "--dir", dir, "--rotate", "user_totp", "--new-root"}, env); code != 0 || !strings.Contains(out.String(), "key 3 added") {
		t.Fatalf("rotate onto a new root: %d %q %q", code, out.String(), errb.String())
	}
	// --new-root alone is the same act for the plain derive (gen-secrets.sh passes it
	// with CTRLZ_NEW_KEK_ROOT=1): files the root does not own are kept as they are.
	if code := admincli.RunKeys(context.Background(), []string{"derive", "--dir", dir, "--new-root"}, env); code != 0 {
		t.Fatalf("--new-root without --rotate: %d", code)
	}
	if code := admincli.RunKeys(context.Background(), []string{"derive", "--dir", dir, "--rotate", "nonsense"}, env); code != 2 {
		t.Fatalf("rotate nonsense: %d", code)
	}
	if code := admincli.RunKeys(context.Background(), []string{"nope"}, env); code != 2 {
		t.Fatalf("unknown keys command: %d", code)
	}
}

func TestUsageAndHelp(t *testing.T) {
	var out, errb bytes.Buffer
	env := admincli.Env{Stdout: &out, Stderr: &errb}
	if code := admincli.RunWith(context.Background(), []string{"--help"}, env); code != 0 || !strings.Contains(out.String(), "bootstrap") {
		t.Fatalf("--help: %d %q", code, out.String())
	}
	if code := admincli.RunWith(context.Background(), nil, env); code != 2 {
		t.Fatalf("no command: %d", code)
	}
	if code := admincli.RunWith(context.Background(), []string{"frobnicate"}, env); code != 2 {
		t.Fatalf("unknown command: %d", code)
	}
	// A missing database is a plain failure naming the variable, not a panic.
	env.Getenv = func(string) string { return "" }
	if code := admincli.RunWith(context.Background(), []string{"unlock", "--user", "x"}, env); code != 1 || !strings.Contains(errb.String(), "CTRLZ_DB_HOST") {
		t.Fatalf("no database: %d %q", code, errb.String())
	}
}

// TestBootstrapThenLoginOverHTTP runs the console and the admin API together
// (T-323, 18.2): the printed password opens a setup session, a reset ends it and
// shows the banner, and after reset-totp the old password is dead.
func TestBootstrapThenLoginOverHTTP(t *testing.T) {
	r := newRig(t)
	r.noAdmin()
	if code := r.run("bootstrap", "--username", "root"); code != 0 {
		t.Fatalf("bootstrap: %d %q", code, r.errb.String())
	}
	pw1 := r.printed()

	// The sessions run on the wall clock, like the console that writes the reset
	// notice: a clock frozen before the reset would date the session earlier than
	// the notice and the ack could never clear it (admin-r4-1 made created_at the
	// application time).
	now := func() time.Time { return time.Now().UTC() }
	m := session.NewManager(r.st, session.DefaultPolicy(), now)
	lim := ratelimit.New(ratelimit.Config{Service: ratelimit.Admin, LocalOnly: true, Now: now})
	h, err := adminapi.New(adminapi.Deps{
		Log: slog.New(slog.DiscardHandler), Store: r.st, Sessions: m, Limiter: lim, Keys: r.keys, Hasher: r.hasher,
		AdminHost: "admin.example.test", PanelHost: "panel.example.test", Env: adminapi.EnvTest, Strict: true,
	}, httpx.NewHealth(http.NotFoundHandler()))
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path string, body any, cookie *http.Cookie, ip string) *httptest.ResponseRecorder {
		var rd io.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rd = bytes.NewReader(raw)
		}
		req := httptest.NewRequest(method, "/api/v1"+path, rd)
		req.Host = "admin.example.test"
		req.Header.Set("X-Forwarded-For", ip)
		if rd != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	login := func(pw, ip string) (*httptest.ResponseRecorder, *http.Cookie) {
		w := call("POST", "/auth/login", map[string]any{"username": "root", "password": pw}, nil, ip)
		for _, c := range w.Result().Cookies() {
			if c.Name == session.CookieAdmin {
				return w, c
			}
		}
		return w, nil
	}
	w, c1 := login(pw1, "198.51.1.1")
	if w.Code != 200 || c1 == nil || !strings.Contains(w.Body.String(), "setup_required") {
		t.Fatalf("login with the bootstrap password: %d %s", w.Code, w.Body)
	}
	if call("GET", "/users", nil, c1, "198.51.1.1").Code != 403 {
		t.Fatal("a setup session reached /users")
	}

	// reset-password: the session ends, the old password is dead, the banner shows.
	if code := r.run("reset-password", "--user", "root"); code != 0 {
		t.Fatalf("reset-password: %d", code)
	}
	pw2 := r.printed()
	if w := call("GET", "/me", nil, c1, "198.51.1.1"); w.Code != 401 {
		t.Fatalf("the session survived a reset: %d", w.Code)
	}
	if w, _ := login(pw1, "198.51.2.1"); w.Code != 401 || !strings.Contains(w.Body.String(), "invalid_credentials") {
		t.Fatalf("the old password: %d %s", w.Code, w.Body)
	}
	_, c2 := login(pw2, "198.51.3.1")
	if c2 == nil {
		t.Fatal("the new one-time password did not log in")
	}
	var me struct {
		Notices []struct {
			Kind string `json:"kind"`
		} `json:"notices"`
	}
	if err := json.Unmarshal(call("GET", "/me", nil, c2, "198.51.3.1").Body.Bytes(), &me); err != nil || len(me.Notices) != 1 || me.Notices[0].Kind != "password_reset" {
		t.Fatalf("banner: %+v %v", me, err)
	}
	if call("POST", "/me/notices/ack", nil, c2, "198.51.3.1").Code != 204 {
		t.Fatal("ack failed")
	}
	if err := json.Unmarshal(call("GET", "/me", nil, c2, "198.51.3.1").Body.Bytes(), &struct{}{}); err != nil {
		t.Fatal(err)
	}
	var me2 struct {
		Notices []any `json:"notices"`
	}
	_ = json.Unmarshal(call("GET", "/me", nil, c2, "198.51.3.1").Body.Bytes(), &me2)
	if len(me2.Notices) != 0 {
		t.Fatalf("the banner was not cleared: %+v", me2)
	}

	// An expired one-time password is a wrong password (10.2).
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_expires_at = now() - interval '1 minute'`)
	if w, _ := login(pw2, "198.51.4.1"); w.Code != 401 {
		t.Fatalf("an expired one-time password: %d", w.Code)
	}

	// reset-totp: the old password gives 401 invalid_credentials.
	if code := r.run("reset-totp", "--user", "root"); code != 0 {
		t.Fatalf("reset-totp: %d", code)
	}
	pw3 := r.printed()
	// Both console commands store the cheap one-time hash (admin-r3-11): 120 bits
	// gain nothing from a slow hash, and a cheap one takes no slot of the Argon2
	// gate, so strangers cannot keep the owner's first login waiting for one.
	var stored string
	r.env.Scan(t, `SELECT password_hash FROM ctrlz.admin_users`, nil, &stored)
	if !strings.Contains(stored, "$m=8,t=1,p=1$") {
		t.Fatalf("a one-time password was stored under the full-cost parameters: %.30s", stored)
	}
	if w, _ := login(pw2, "198.51.5.1"); w.Code != 401 {
		t.Fatalf("the password before reset-totp: %d", w.Code)
	}
	if w, c := login(pw3, "198.51.6.1"); w.Code != 200 || c == nil {
		t.Fatalf("the password after reset-totp: %d", w.Code)
	}
}

// A run of declare-lost that stops part way leaves every tenant whole (review
// round 1, admin-r1-19, spec 13.1; round 3, db-r3-1). The admin command records the
// declaration before anything changes. The worker tool then clears one tenant per
// transaction, and the database function writes the tenant's notice and audit row in
// the same statement, so a tenant is either untouched or cleared with both.
func TestDeclareLostLeavesEveryTenantWhole(t *testing.T) {
	r := newRig(t)
	var raw [32]byte
	raw[0] = 9
	root := secret.NewBytes(raw[:])
	uone, _ := keyring.FromRoot(root, map[string][]uint16{keyring.DomainUserTOTP: {1}})
	utwo, _ := keyring.FromRoot(root, map[string][]uint16{keyring.DomainUserTOTP: {2}})
	seed := secret.NewBytes(bytes.Repeat([]byte{3}, 20))
	for _, ids := range []struct{ tenant, user uuid.UUID }{{r.env.A.Tenant, r.env.A.User}, {r.env.B.Tenant, r.env.B.User}} {
		c, err := uone.Seal(keyring.DomainUserTOTP, totp.UserAAD(ids.tenant, ids.user), seed.Reveal())
		if err != nil {
			t.Fatal(err)
		}
		r.env.Exec(t, `UPDATE ctrlz.users SET totp_secret_ct = $3, totp_enabled_at = now() WHERE tenant_id = $1 AND id = $2`, ids.tenant, ids.user, c)
	}
	// The admin command records the declaration and changes nothing.
	if code := r.run("keys", "declare-lost", "user_totp", "--key-number", "1", "--yes"); code != 0 {
		t.Fatalf("declare-lost on the admin side: %d %q", code, r.errb.String())
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'key.declared_lost' AND target = 'domain:user_totp'`); n != 1 {
		t.Fatalf("%d audit rows after the declaration, want 1", n)
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.users WHERE totp_secret_ct IS NULL`); n != 0 {
		t.Fatalf("the admin command cleared %d seeds", n)
	}

	// The tenants are cleared in id order. The later one fails, like a database
	// fault at tenant N.
	later := r.env.A.Tenant
	if r.env.B.Tenant.String() > later.String() {
		later = r.env.B.Tenant
	}
	r.env.Exec(t, `CREATE FUNCTION ctrlz.test_declare_lost_fault() RETURNS trigger LANGUAGE plpgsql AS $$
	BEGIN
	  IF OLD.tenant_id = '`+later.String()+`' AND OLD.totp_secret_ct IS NOT NULL AND NEW.totp_secret_ct IS NULL THEN
	    RAISE EXCEPTION 'injected fault';
	  END IF;
	  RETURN NEW;
	END $$`)
	r.env.Exec(t, `CREATE TRIGGER test_declare_lost_fault BEFORE UPDATE ON ctrlz.users
	  FOR EACH ROW EXECUTE FUNCTION ctrlz.test_declare_lost_fault()`)
	worker := r.env.Keytool(t)
	env := r.cliEnv(&r.out, &r.errb)
	env.OpenRekey = func(context.Context) (*admincli.RekeyTools, error) {
		return &admincli.RekeyTools{Store: worker, Keys: utwo}, nil
	}
	if code := admincli.RunDeclareLost(r.env.Ctx, []string{"user_totp", "--key-number", "1", "--yes"}, env); code != 1 {
		t.Fatalf("a failing run exited %d, want 1 (out %q err %q)", code, r.out.String(), r.errb.String())
	}
	first := r.env.A.Tenant
	if first == later {
		first = r.env.B.Tenant
	}
	for tenant, cleared := range map[uuid.UUID]int{first: 1, later: 0} {
		sql := func(table, cond string) int {
			return r.count(`SELECT count(*) FROM ctrlz.` + table + ` WHERE tenant_id = '` + tenant.String() + `' AND ` + cond)
		}
		if n := sql("users", "totp_secret_ct IS NULL"); n != cleared {
			t.Errorf("tenant %s: %d seeds cleared, want %d", tenant, n, cleared)
		}
		if n := sql("notifications", "kind = 'totp_lost'"); n != cleared {
			t.Errorf("tenant %s: %d notices, want %d", tenant, n, cleared)
		}
		if n := sql("tenant_audit_log", "action = 'totp.declared_lost'"); n != cleared {
			t.Errorf("tenant %s: %d audit rows, want %d", tenant, n, cleared)
		}
	}
	// A run that stopped is repeated: the tenant that was cleared has nothing left
	// to clear, and the other finishes once the fault is gone.
	r.env.Exec(t, `DROP TRIGGER test_declare_lost_fault ON ctrlz.users`)
	r.out.Reset()
	if code := admincli.RunDeclareLost(r.env.Ctx, []string{"user_totp", "--key-number", "1", "--yes"}, env); code != 0 || !strings.Contains(r.out.String(), "1 users") {
		t.Fatalf("the repeat: %d %q %q", code, r.out.String(), r.errb.String())
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.notifications WHERE kind = 'totp_lost'`); n != 2 {
		t.Errorf("%d notices after the repeat, want 2 (one per tenant, none twice)", n)
	}
	// A run after a complete one finds no seed that names the key (admin-r18-22, documented under admin-r18-21):
	// it says so, exits 0 and records nothing, which is not the exit 1 of "not lost" that a key whose seeds all
	// open gets.
	r.out.Reset()
	if code := admincli.RunDeclareLost(r.env.Ctx, []string{"user_totp", "--key-number", "1", "--yes"}, env); code != 0 || !strings.Contains(r.out.String(), "no stored seed names key 1") {
		t.Fatalf("a run after a complete one: %d %q %q", code, r.out.String(), r.errb.String())
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.notifications WHERE kind = 'totp_lost'`); n != 2 {
		t.Errorf("%d notices after a run with nothing to clear, want 2", n)
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'totp.declared_lost'`); n != 2 {
		t.Errorf("%d audit rows after a run with nothing to clear, want 2", n)
	}
}

// lockedKeys is one attempt on each key an admin can be locked out by, and the list
// is the registry of internal/budget, not a hand-written one (rule budget-keying):
// a scope that is declared but that `unlock` forgets fails assertUnlocked the day it
// is declared. The username scopes and the network scope are what a stranger fills;
// admin_totp, the reauth scope of POST /me/password and the marker scope are what a
// stolen cookie or a guessed password spends (10.1, 10.3).
func (r *rig) lockedKeys(svc *throttle.Service, username string) map[string]func() error {
	ctx := r.env.Ctx
	who := throttle.Who{Username: username, Admin: seedAdmin, Session: seedAdmin, IP: netip.MustParseAddr("198.51.100.7"), Marker: "marker-of-a-browser"}
	out := map[string]func() error{}
	for _, b := range budget.Of(budget.Throttle, budget.Admin) {
		sc := throttle.Scope(b.Name)
		out[b.Name] = func() error { return svc.Charge(ctx, sc, who) }
	}
	return out
}

// assertUnlocked fails unless every key lockLogin filled is clear again. Review
// round 2 (admin-r2-3): a dropped Reset for admin_totp or the reauth key left
// "unlocked" printed and every test green.
func (r *rig) assertUnlocked(svc *throttle.Service, username string) {
	r.t.Helper()
	for name, hit := range r.lockedKeys(svc, username) {
		if err := hit(); err != nil {
			r.t.Errorf("%s is still locked: %v", name, err)
		}
	}
}

// lastOutExists says whether the last injected --out-file is on disk. A command
// that failed must not leave an empty file that looks like a result.
func (r *rig) lastOutExists() bool {
	_, err := os.Stat(r.lastOut)
	return err == nil
}
