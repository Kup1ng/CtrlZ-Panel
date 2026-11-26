package admincli_test

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/admincli"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
)

// The key-identity matrix (review round 5, rule key-identity; spec 8.3 to 8.5).
//
// Rule: no key tool decides which key it has from a key number or from a file being
// there or missing. It proves identity by deriving from the root and comparing, or by
// opening the sealed data. Every key command of the ctrlz-admin and ctrlz tables,
// and gen-secrets.sh, runs here over every generated key history (keyhist_test.go),
// and what it does is compared with the ground truth of that history. A command
// of the tables with no row below fails TestEveryKeyCommandHasAMatrixRow, and a row
// whose command is gone fails it too.

// keyRows maps each key command to the matrix block that runs it. A block runs once,
// over every history, even when several commands share it (one database serves
// the commands that only read or record).
func keyRows() map[string]string {
	return map[string]string{
		"scripts/gen-secrets.sh":        "gen-secrets",
		"ctrlz keys derive":             "derive ctrlz",
		"ctrlz-admin keys derive":       "derive ctrlz-admin",
		"ctrlz-admin keys status":       "status declare-lost audit-note",
		"ctrlz-admin keys declare-lost": "status declare-lost audit-note",
		"ctrlz-admin audit-note":        "status declare-lost audit-note",
		"ctrlz-admin rekey":             "rekey",
		"ctrlz rekey":                   "rekey",
		"ctrlz declare-lost":            "declare-lost user_totp",
	}
}

func matrixBlocks() map[string]func(*testing.T) {
	return map[string]func(*testing.T){
		"gen-secrets":                    rowGenSecrets,
		"derive ctrlz":                   func(t *testing.T) { rowDerive(t, runCtrlzKeys) },
		"derive ctrlz-admin":             func(t *testing.T) { rowDerive(t, runAdminKeys) },
		"status declare-lost audit-note": rowStatusDeclareNote,
		"rekey":                          rowRekey,
		"declare-lost user_totp":         rowDeclareLostUser,
	}
}

// notKeyCommands are dispatched commands that read no key file, derive nothing and judge
// no sealed value. Each needs a reason, so adding one here is a decision.
func notKeyCommands() map[string]string {
	return map[string]string{
		"ctrlz-admin bootstrap":      "creates the first admin; no key is read",
		"ctrlz-admin reset-password": "writes a password hash; no key is read",
		"ctrlz-admin reset-totp":     "clears an admin's authenticator column; it opens nothing and judges no key",
		"ctrlz-admin unlock":         "clears throttle rows",
		"ctrlz-admin audit":          "walks the audit hash chain",
		"ctrlz catalog":              "the lab command that loads a catalog fixture: it reads no key file and judges no sealed value (the catalog key is data of the fixture)",
		"ctrlz domain-apply":         "opens the sealed key of an uploaded panel or admin certificate with the web intake key (an X25519 key of its own, not a keyring key); it derives no keyring key and decides no keyring identity",
		"ctrlz-admin sms":            "copies pending sealed SMS credentials over the active ones without opening them; a rekey re-seals both",
	}
}

func TestKeyIdentityMatrix(t *testing.T) {
	blocks := matrixBlocks()
	for _, id := range slices.Sorted(maps.Keys(blocks)) {
		t.Run(id, blocks[id])
	}
}

// TestEveryMatrixRowHasABlock keeps keyRows and matrixBlocks in step, so a row cannot
// name a block that does not run.
func TestEveryMatrixRowHasABlock(t *testing.T) {
	blocks := matrixBlocks()
	used := map[string]bool{}
	for name, id := range keyRows() {
		if blocks[id] == nil {
			t.Errorf("%s names the block %q, which does not exist", name, id)
		}
		used[id] = true
	}
	for id := range blocks {
		if !used[id] {
			t.Errorf("block %q is run for no command", id)
		}
	}
}

// ---- the command table -----------------------------------------------------

func TestEveryKeyCommandHasAMatrixRow(t *testing.T) {
	got := dispatchedCommands(t)
	rows, notKey := keyRows(), notKeyCommands()
	for _, name := range got {
		_, isRow := rows[name]
		_, isNot := notKey[name]
		switch {
		case isRow && isNot:
			t.Errorf("%s is both a matrix row and listed as not a key command", name)
		case !isRow && !isNot:
			t.Errorf("%s is dispatched and has no row in keyRows (a key command) or reason in notKeyCommands", name)
		}
	}
	for name := range rows {
		if !slices.Contains(got, name) {
			t.Errorf("keyRows has a row for %s, which no table dispatches", name)
		}
	}
	for name := range notKey {
		if !slices.Contains(got, name) {
			t.Errorf("notKeyCommands lists %s, which no table dispatches", name)
		}
	}
}

// dispatchedCommands reads the three dispatch tables from the source: RunWith and
// runKeysAdmin for ctrlz-admin, run in cmd/ctrlz and RunKeys for ctrlz, and adds
// gen-secrets.sh. A new case in any of them appears here without anyone listing it.
func dispatchedCommands(t *testing.T) []string {
	t.Helper()
	admin := caseStrings(t, "admincli.go", "RunWith")
	adminKeys := caseStrings(t, "keys.go", "runKeysAdmin")
	ctrlzKeys := caseStrings(t, "derive.go", "RunKeys")
	main := caseStrings(t, filepath.Join("..", "..", "cmd", "ctrlz", "main.go"), "run")
	var out []string
	for _, c := range admin {
		if c == "keys" {
			for _, s := range adminKeys {
				out = append(out, "ctrlz-admin keys "+s)
			}
			continue
		}
		out = append(out, "ctrlz-admin "+c)
	}
	for _, c := range main {
		switch c {
		case "ctrlz-admin": // the same table as above
		case "keys":
			for _, s := range ctrlzKeys {
				out = append(out, "ctrlz keys "+s)
			}
		default:
			out = append(out, "ctrlz "+c)
		}
	}
	if _, err := os.Stat(filepath.Join("..", "..", "scripts", "gen-secrets.sh")); err == nil {
		out = append(out, "scripts/gen-secrets.sh")
	}
	if len(admin) < 8 || len(adminKeys) < 3 || len(ctrlzKeys) < 1 || len(main) < 3 {
		t.Fatalf("the dispatch tables read as %v %v %v %v; the parser lost the switches", admin, adminKeys, ctrlzKeys, main)
	}
	return out
}

// caseStrings returns the string literals of the case clauses in a function.
func caseStrings(t *testing.T, file, fn string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn {
			return true
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if cc, ok := n.(*ast.CaseClause); ok {
				for _, e := range cc.List {
					if l, ok := e.(*ast.BasicLit); ok && l.Kind == token.STRING {
						s, _ := strconv.Unquote(l.Value)
						if s != "" && s[0] != '-' && s != "help" {
							out = append(out, s)
						}
					}
				}
			}
			return true
		})
		return false
	})
	return out
}

// ---- derive and rotate (no database) ----------------------------------------

// keysRunner runs `keys <args>` through one of the two command tables.
type keysRunner func(args []string, out, errb *bytes.Buffer) int

func runCtrlzKeys(args []string, out, errb *bytes.Buffer) int {
	return admincli.RunKeys(context.Background(), args, admincli.Env{Stdout: out, Stderr: errb})
}

func runAdminKeys(args []string, out, errb *bytes.Buffer) int {
	return admincli.RunWith(context.Background(), append([]string{"keys"}, args...), admincli.Env{Stdout: out, Stderr: errb})
}

func snapshot(t testing.TB, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		m[e.Name()] = string(b)
	}
	return m
}

// noKeys fails when text holds a key of any file in the directory, before or after
// the command. Paths and domain names are fine; a key is never.
func noKeys(t *testing.T, text string, snaps ...map[string]string) {
	t.Helper()
	for _, snap := range snaps {
		for name, content := range snap {
			if name == "kek_root" {
				continue
			}
			for _, ln := range strings.Split(content, "\n") {
				if f := strings.Fields(ln); len(f) == 2 && len(f[1]) == 43 && strings.Contains(text, f[1]) {
					t.Errorf("the output holds a key of %s", name)
				}
			}
		}
	}
}

func rowDerive(t *testing.T, run keysRunner) {
	for _, h := range histories() {
		for _, newRoot := range []bool{false, true} {
			t.Run(fmt.Sprintf("derive/%s/new-root=%v", h.name, newRoot), func(t *testing.T) {
				dir := t.TempDir()
				h.write(t, dir)
				before := snapshot(t, dir)
				args := []string{"derive", "--dir", dir}
				if newRoot {
					args = append(args, "--new-root")
				}
				var out, errb bytes.Buffer
				code := run(args, &out, &errb)
				after := snapshot(t, dir)
				noKeys(t, out.String()+errb.String(), before, after)
				plan := h.deriveTruth(newRoot)
				if !plan.ok {
					if code == 0 {
						t.Errorf("derive succeeded on a host where it must refuse")
					}
					// A refusal that leaves a key file missing is told apart from one that does not, so a
					// script cannot take the one for the other.
					if want := map[bool]int{false: admincli.ExitRefused, true: admincli.ExitRefusedMissing}[plan.refusedMissing]; h.disk != "" && code != want {
						t.Errorf("derive exited %d, want %d (a key file missing: %v)", code, want, plan.refusedMissing)
					}
					if !maps.Equal(before, after) {
						t.Errorf("a refused derive changed the directory")
					}
					return
				}
				if code != 0 {
					t.Fatalf("derive refused a host it must serve: %d %q", code, errb.String())
				}
				for name, b := range before {
					if after[name] != b {
						t.Errorf("derive rewrote %s", name)
					}
				}
				for _, d := range plan.created {
					want := h.clone("").install("", h.disk).fileText(d)
					if after["kek_"+d] != string(want) {
						t.Errorf("kek_%s is not key 1 derived from the root on disk", d)
					}
				}
				// A public file is made whenever it is missing, from the key file the host has by then (spec 8.3, D67).
				madePublic := 0
				for _, d := range keyring.PublicDomains() {
					name := keyring.PublicFileName(d)
					if _, had := before[name]; !had {
						madePublic++
					}
					want, err := keyring.PublicText(d, secret.NewBytes([]byte(after["kek_"+d])))
					if err != nil || after[name] != string(want) {
						t.Errorf("%s is not the public text of kek_%s", name, d)
					}
				}
				if len(after) != len(before)+len(plan.created)+madePublic {
					t.Errorf("derive left %d files, want %d", len(after), len(before)+len(plan.created)+madePublic)
				}
			})
		}
		// Rotation does not depend on the domain beyond its name; two of them, one that is
		// missing in the "one key file missing" history and one that never is, keep the run short.
		for _, d := range []string{keyring.DomainUserTOTP, keyring.DomainAdminMAC, keyring.DomainInviteSign} {
			for _, newRoot := range []bool{false, true} {
				t.Run(fmt.Sprintf("rotate/%s/%s/new-root=%v", h.name, d, newRoot), func(t *testing.T) {
					dir := t.TempDir()
					h.write(t, dir)
					before := snapshot(t, dir)
					args := []string{"derive", "--dir", dir, "--rotate", d}
					if newRoot {
						args = append(args, "--new-root")
					}
					var out, errb bytes.Buffer
					code := run(args, &out, &errb)
					after := snapshot(t, dir)
					noKeys(t, out.String()+errb.String(), before, after)
					ok, next := h.rotateTruth(d, newRoot)
					if !ok {
						if code == 0 {
							t.Errorf("rotate succeeded where it must refuse")
						}
						if !maps.Equal(before, after) {
							t.Errorf("a refused rotation changed the directory")
						}
						return
					}
					if code != 0 {
						t.Fatalf("rotate refused: %d %q", code, errb.String())
					}
					lines := h.files[d]
					expect := h.clone("")
					expect.files[d] = append(slices.Clone(lines), keyLine{next, h.disk})
					if after["kek_"+d] != string(expect.fileText(d)) {
						t.Errorf("kek_%s did not get key %d derived from the root on disk", d, next)
					}
					for name, b := range before {
						if name != "kek_"+d && name != keyring.PublicFileName(d) && after[name] != b {
							t.Errorf("rotating %s rewrote %s", d, name)
						}
					}
					// A domain with a public half has it follow the new key at once, so the api can be recreated first.
					if slices.Contains(keyring.PublicDomains(), d) {
						want, err := keyring.PublicText(d, secret.NewBytes(expect.fileText(d)))
						if err != nil || after[keyring.PublicFileName(d)] != string(want) {
							t.Errorf("rotating %s did not bring %s up to date", d, keyring.PublicFileName(d))
						}
					}
				})
			}
		}
	}
}

// ---- gen-secrets.sh ----------------------------------------------------------

func shellForScripts(t *testing.T) string {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		git := `C:\Program Files\Git\usr\bin\sh.exe`
		if _, statErr := os.Stat(git); statErr != nil {
			t.Skip("no sh on PATH")
		}
		sh = git
	}
	return sh
}

// stubDockerRunningDerive puts a `docker` on PATH that answers `image inspect` and
// runs the real `keys` command (this test binary, see TestMain) for `docker run ...
// IMAGE keys ARGS`, on the directory mounted as /secrets.
func stubDockerRunningDerive(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	script := "#!/bin/sh\n" +
		"case \"$1\" in\n" +
		"image) exit 0 ;;\n" +
		"run)\n" +
		"  prev=''; dir=''; seen=''; args=''\n" +
		"  for a in \"$@\"; do\n" +
		"    if [ \"$prev\" = '-v' ]; then dir=${a%:/secrets}; fi\n" +
		"    if [ -n \"$seen\" ]; then args=\"$args $a\"; fi\n" +
		"    if [ \"$a\" = keys ]; then seen=1; fi\n" +
		"    prev=$a\n" +
		"  done\n" +
		"  CTRLZ_TEST_AS_CTRLZ_KEYS=1 exec '" + filepath.ToSlash(self) + "' $args --dir \"$dir\" ;;\n" +
		"esac\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func rowGenSecrets(t *testing.T) {
	sh := shellForScripts(t)
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "gen-secrets.sh"))
	if err != nil {
		t.Fatal(err)
	}
	bin := stubDockerRunningDerive(t)
	for _, h := range histories() {
		for _, flag := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/new-root=%v", h.name, flag), func(t *testing.T) {
				dir := t.TempDir()
				h.write(t, dir)
				// The passwords are not what this matrix is about, and making them costs a
				// process per secret; they are in place already and the script keeps them.
				for _, name := range []string{"pg_superuser_password", "pg_migrator_password", "pg_tenant_password", "pg_hub_password",
					"pg_compiler_password", "pg_worker_password", "pg_keytool_password", "pg_domain_apply_password", "pg_admin_password", "clickhouse_password", "valkey_password_api", "valkey_password_admin", "proof_key"} {
					if err := os.WriteFile(filepath.Join(dir, name), []byte("Zq3vNn7hQw1xKs9dZq3vNn7hQw1xKs9d\n"), 0o444); err != nil {
						t.Fatal(err)
					}
				}
				before := snapshot(t, dir)
				cmd := exec.Command(sh, filepath.ToSlash(script), filepath.ToSlash(dir))
				cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
				// Git Bash rewrites the "/CN=..." subject of the node CA certificate into a Windows path unless told not to;
				// the production host is Linux and never sees it.
				cmd.Env = append(cmd.Env, "MSYS_NO_PATHCONV=1")
				if flag {
					cmd.Env = append(cmd.Env, "CTRLZ_NEW_KEK_ROOT=1")
				}
				outb, runErr := cmd.CombinedOutput()
				noKeys(t, string(outb), before, snapshot(t, dir))
				out := string(outb)
				code := 0
				if ee, ok := runErr.(*exec.ExitError); ok {
					code = ee.ExitCode()
				} else if runErr != nil {
					t.Fatal(runErr)
				}
				after := snapshot(t, dir)
				// A script that has no root yet makes one. The truth does not know its
				// bytes, only that it is not the root of any generated history.
				host := h
				if h.disk == "" {
					host = h.withRoot("", "made by the script")
				}
				plan := host.deriveTruth(flag)
				if !plan.ok {
					// A host with no kek_root is the one refusal that is not a failure (admin-r13-6): the
					// owner took the root off the server as the script advises, so the run cannot prove the
					// files and says so, and the plain secrets after it are still made. It leaves no root
					// and changes no key file. A root that is present and wrong, or an explicit new root
					// over files that are not its own, is still refused.
					if h.disk == "" && !flag && plan.refusedMissing {
						// A key file is missing too: the notice would be a lie, because the file cannot be made
						// without the root, and the run has to stop (admin-r14-7).
						if code == 0 {
							t.Errorf("gen-secrets went on with a key file missing and no root to make it\n%s", out)
						}
						if _, hasRoot := after["kek_root"]; hasRoot || !maps.Equal(before, after) {
							t.Errorf("a stopped run changed the directory: %v", changedNames(before, after))
						}
						if strings.Contains(out, "secrets: ") && strings.Contains(out, " created in ") {
							t.Errorf("the run printed its success line\n%s", out)
						}
						return
					}
					if h.disk == "" && !flag {
						if code != 0 {
							t.Errorf("gen-secrets refused a host whose kek_root is off the server: %d\n%s", code, out)
						}
						if _, hasRoot := after["kek_root"]; hasRoot {
							t.Errorf("a run that could not prove the key files left a kek_root behind")
						}
						if !strings.Contains(out, "kek_root is not on this host") {
							t.Errorf("the run skips the key check and does not say so\n%s", out)
						}
						// The run still makes the plain secrets it finds missing (the message above says so), among
						// them the node trust keys of P4 3.3, which are generated by openssl and owe nothing to
						// kek_root. What it must not do is touch anything that was there, the key files above all.
						for name, was := range before {
							if now, ok := after[name]; !ok || now != was {
								t.Errorf("a run that skipped the key check changed %s", name)
							}
						}
						for name := range after {
							if _, was := before[name]; !was && !slices.Contains(trustSecretNames, name) {
								t.Errorf("a run that skipped the key check made %s, which is neither a plain secret nor a node trust file", name)
							}
						}
						return
					}
					if code == 0 {
						t.Errorf("gen-secrets succeeded where the key files are not the root's\n%s", out)
					}
					if !maps.Equal(before, after) {
						t.Errorf("a refused gen-secrets left changes behind: %v", changedNames(before, after))
					}
					return
				}
				if code != 0 {
					t.Fatalf("gen-secrets refused a host it must serve: %d\n%s", code, out)
				}
				root, ok := after["kek_root"]
				if !ok || len(root) != 32 {
					t.Fatalf("no 32-byte kek_root after a successful run")
				}
				if h.disk != "" && root != string(h.disk.raw()) {
					t.Errorf("gen-secrets replaced an existing kek_root")
				}
				rootSecret := secret.NewBytes([]byte(root))
				foreign := false
				for _, d := range keyring.Domains() {
					name := "kek_" + d
					if prev, existed := before[name]; existed {
						if after[name] != prev {
							t.Errorf("gen-secrets rewrote %s", name)
						}
						if ls := h.files[d]; ls[len(ls)-1].from != host.disk {
							foreign = true
						}
						continue
					}
					prov, err := keyring.Identify(rootSecret, d, secret.NewBytes([]byte(after[name])))
					if err != nil || !prov.NewestFromRoot() || len(prov.Lines) != 1 {
						t.Errorf("%s was made but is not key 1 of the root on disk", name)
					}
				}
				if foreign && !strings.Contains(out, "NOT derived from") {
					t.Errorf("the run keeps key files that are not the root's and does not say so\n%s", out)
				}
				if !foreign && strings.Contains(out, "NOT derived from") {
					t.Errorf("the run warns about key files although every one belongs to the root\n%s", out)
				}
			})
		}
	}
}

// trustSecretNames are the files gen-secrets makes with openssl for the panel-node trust (P4 3.3), beside the
// passwords: no key of the kek_ family, so a host without kek_root still gets them.
var trustSecretNames = []string{"policy_key", "policy_key_pub", "node_ca_key", "node_ca_pem", "hub_tls_key", "zone_ca_key",
	"wildcard_intake_key", "wildcard_intake_pub", "web_intake_key", "web_intake_pub", "spool_key"}

func changedNames(a, b map[string]string) []string {
	var out []string
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			out = append(out, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// ---- commands on the database ------------------------------------------------

func matrixSeedBytes() secret.Bytes { return secret.NewBytes(bytes.Repeat([]byte{3}, 20)) }

// planted is where the sealed values of a history went.
type planted struct {
	sms map[int]uuid.UUID // gateway id by slot
}

func smsProviders() []string { return []string{"sms_ir", "melipayamak"} }

func (r *rig) userIDs(slot int) (tenant, user uuid.UUID) {
	if slot == 0 {
		return r.env.A.Tenant, r.env.A.User
	}
	return r.env.B.Tenant, r.env.B.User
}

// plant seals every value of the history, under the root and number that made it,
// into its column.
func (r *rig) plant(h history) planted {
	r.t.Helper()
	p := planted{sms: map[int]uuid.UUID{}}
	if len(h.dataOf(keyring.DomainSMSCred)) > 0 {
		r.env.ResetSMS(r.t)
	}
	for _, s := range h.data {
		ring, err := keyring.FromRoot(s.from.secret(), map[string][]uint16{s.domain: {s.n}})
		if err != nil {
			r.t.Fatal(err)
		}
		switch s.domain {
		case keyring.DomainUserTOTP:
			tenant, user := r.userIDs(s.slot)
			ct, err := ring.Seal(s.domain, totp.UserAAD(tenant, user), matrixSeedBytes().Reveal())
			if err != nil {
				r.t.Fatal(err)
			}
			r.env.Exec(r.t, `UPDATE ctrlz.users SET totp_secret_ct = $3, totp_enabled_at = now() WHERE tenant_id = $1 AND id = $2`, tenant, user, ct)
		case keyring.DomainAdminTOTP:
			ct, err := ring.Seal(s.domain, totp.AdminAAD(seedAdmin), matrixSeedBytes().Reveal())
			if err != nil {
				r.t.Fatal(err)
			}
			r.env.Exec(r.t, `UPDATE ctrlz.admin_users SET totp_secret_ct = $2 WHERE id = $1`, seedAdmin, ct)
		case keyring.DomainSMSCred:
			id := uuid.New()
			ct, err := sms.SealCredentials(ring, id, smsProviders()[s.slot], secret.NewBytes([]byte(`{"api_key":"k-1234567"}`)))
			if err != nil {
				r.t.Fatal(err)
			}
			r.env.Exec(r.t, `INSERT INTO ctrlz.sms_gateways (id, provider, role, credentials_ct) VALUES ($1, $2, 'disabled', $3)`, id, smsProviders()[s.slot], ct)
			p.sms[s.slot] = id
		}
	}
	return p
}

// column reads the sealed bytes of one slot as the superuser; nil when the column is NULL.
func (r *rig) column(p planted, domain string, slot int) []byte {
	r.t.Helper()
	var ct []byte
	switch domain {
	case keyring.DomainUserTOTP:
		tenant, user := r.userIDs(slot)
		r.env.Scan(r.t, `SELECT totp_secret_ct FROM ctrlz.users WHERE tenant_id = $1 AND id = $2`, []any{tenant, user}, &ct)
	case keyring.DomainAdminTOTP:
		r.env.Scan(r.t, `SELECT totp_secret_ct FROM ctrlz.admin_users WHERE id = $1`, []any{seedAdmin}, &ct)
	case keyring.DomainSMSCred:
		if id, ok := p.sms[slot]; ok {
			r.env.Scan(r.t, `SELECT credentials_ct FROM ctrlz.sms_gateways WHERE id = $1`, []any{id}, &ct)
		}
	}
	return ct
}

func (r *rig) openColumn(ring *keyring.Ring, p planted, s stored, ct []byte) error {
	switch s.domain {
	case keyring.DomainUserTOTP:
		tenant, user := r.userIDs(s.slot)
		_, err := ring.Open(s.domain, totp.UserAAD(tenant, user), ct)
		return err
	case keyring.DomainAdminTOTP:
		_, err := ring.Open(s.domain, totp.AdminAAD(seedAdmin), ct)
		return err
	}
	_, err := sms.OpenCredentials(ring, p.sms[s.slot], smsProviders()[s.slot], ct)
	return err
}

func adminDomains() []string {
	return []string{keyring.DomainAdminTOTP, keyring.DomainSMSCred, keyring.DomainAdminMAC}
}

// rowStatusDeclareNote covers `keys status`, `keys declare-lost` and `audit-note` of
// ctrlz-admin: none changes a sealed value, so one database serves a history.
func rowStatusDeclareNote(t *testing.T) {
	for _, h := range histories() {
		ring, ok := h.ring(t, adminDomains()...)
		if !ok {
			continue // the container does not start without its files (18.3)
		}
		t.Run(h.name, func(t *testing.T) {
			r := newRig(t)
			r.keys = ring
			p := r.plant(h)

			// keys status counts by key number and says how many of them open.
			for domain, label := range map[string]string{keyring.DomainAdminTOTP: "admin_users.totp_secret_ct", keyring.DomainSMSCred: "sms_gateways.credentials_ct"} {
				if code := r.run("keys", "status", domain); code != 0 {
					t.Fatalf("status %s: %d %q", domain, code, r.errb.String())
				}
				want := "  " + label + ": " + statusTruth(h, domain) + "\n"
				if !strings.Contains(r.out.String(), want) {
					t.Errorf("status %s printed\n%swant the line %q", domain, r.out.String(), want)
				}
			}

			// keys declare-lost proves a loss by opening where it can. The admin role
			// cannot read user_totp, so for it the declaration is a record and the tools
			// container's check is the proof.
			before := map[string][]byte{}
			for _, s := range h.data {
				before[fmt.Sprint(s.domain, s.slot)] = r.column(p, s.domain, s.slot)
			}
			for _, domain := range []string{keyring.DomainSMSCred, keyring.DomainUserTOTP, keyring.DomainAdminMAC} {
				nums := h.numbersOf(domain)
				if len(nums) == 0 {
					nums = []uint16{1}
				}
				for _, n := range nums {
					refuse := domain == keyring.DomainSMSCred && h.declareLostRefuses(domain, n)
					code := r.run("keys", "declare-lost", domain, "--key-number", fmt.Sprint(n), "--yes")
					rows := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'key.declared_lost' AND target = $1 AND params->>'key_number' = $2`, "domain:"+domain, fmt.Sprint(n))
					if refuse && (code == 0 || rows != 0) {
						t.Errorf("declare-lost %s %d: a credential under that key opens, yet exit %d and %d audit rows", domain, n, code, rows)
					}
					if !refuse && (code != 0 || rows != 1) {
						t.Errorf("declare-lost %s %d: exit %d and %d audit rows, want a recorded declaration (%q)", domain, n, code, rows, r.errb.String())
					}
				}
			}
			for _, s := range h.data {
				if !bytes.Equal(before[fmt.Sprint(s.domain, s.slot)], r.column(p, s.domain, s.slot)) {
					t.Errorf("the admin declare-lost changed %s slot %d", s.domain, s.slot)
				}
			}

			// audit-note writes what the operator said and consults no key.
			for _, action := range []string{"key.rotated", "key.declared_lost"} {
				if code := r.run("audit-note", action, "--domain", "auth_mac", "--key-number", "7"); code != 0 {
					t.Fatalf("audit-note %s: %d %q", action, code, r.errb.String())
				}
				if n := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = $1 AND target = 'domain:auth_mac' AND params->>'key_number' = '7'`, action); n != 1 {
					t.Errorf("audit-note %s wrote %d rows, want 1", action, n)
				}
			}
		})
	}
}

// statusTruth is the status line for a domain: values grouped by the number they
// name, each group with how many of them the container's keys really open.
func statusTruth(h history, domain string) string {
	data := h.dataOf(domain)
	if len(data) == 0 {
		return "no rows"
	}
	var parts []string
	for _, n := range h.numbersOf(domain) {
		total, open := 0, 0
		for _, s := range data {
			if s.n == n {
				total++
				if h.opens(s) {
					open++
				}
			}
		}
		if open == total {
			parts = append(parts, fmt.Sprintf("key %d: %d (all open)", n, total))
		} else {
			parts = append(parts, fmt.Sprintf("key %d: %d (%d open, %d not readable)", n, total, open, total-open))
		}
	}
	return strings.Join(parts, ", ")
}

// rowRekey covers `ctrlz-admin rekey` (admin_totp, sms_cred) and `ctrlz rekey
// user_totp`. A value is current only when it opens under the newest key, and one
// that names the newest number but does not open is reported as unreadable.
func rowRekey(t *testing.T) {
	for _, h := range histories() {
		adminRing, adminOK := h.ring(t, adminDomains()...)
		userRing, userOK := h.ring(t, keyring.DomainUserTOTP)
		if !adminOK && !userOK {
			continue
		}
		t.Run(h.name, func(t *testing.T) {
			r := newRig(t)
			if adminOK {
				r.keys = adminRing
			}
			p := r.plant(h)
			type step struct {
				domain string
				run    func() int
				ring   *keyring.Ring
			}
			var steps []step
			if adminOK {
				for _, d := range []string{keyring.DomainAdminTOTP, keyring.DomainSMSCred} {
					steps = append(steps, step{d, func() int { return r.run("rekey", d) }, adminRing})
				}
			}
			if userOK {
				worker := r.env.Keytool(t)
				env := r.cliEnv(&r.out, &r.errb)
				env.OpenRekey = func(context.Context) (*admincli.RekeyTools, error) {
					return &admincli.RekeyTools{Store: worker, Keys: userRing}, nil
				}
				steps = append(steps, step{keyring.DomainUserTOTP, func() int {
					r.out.Reset()
					r.errb.Reset()
					return admincli.RunRekey(r.env.Ctx, []string{keyring.DomainUserTOTP}, env)
				}, userRing})
			}
			for _, st := range steps {
				before := map[int][]byte{}
				for _, s := range h.dataOf(st.domain) {
					before[s.slot] = r.column(p, st.domain, s.slot)
				}
				code := st.run()
				want := h.rekeyTruth(st.domain)
				line := fmt.Sprintf("rekey %s to key %d: %d rewritten, %d already current, 0 changed meanwhile, %d could not be opened",
					st.domain, h.newest(st.domain), want.rewritten, want.current, want.failed)
				if !strings.Contains(r.out.String(), line) {
					t.Errorf("%s: output %q, want %q", st.domain, r.out.String(), line)
				}
				if (code != 0) != (want.failed > 0) {
					t.Errorf("%s: exit %d with %d unreadable values", st.domain, code, want.failed)
				}
				for _, s := range h.dataOf(st.domain) {
					after := r.column(p, st.domain, s.slot)
					switch {
					case !h.opens(s) || s.n == h.newest(st.domain):
						if !bytes.Equal(before[s.slot], after) {
							t.Errorf("%s slot %d (key %d, opens=%v) was rewritten", st.domain, s.slot, s.n, h.opens(s))
						}
					default:
						if n, _ := keyring.KeyNumber(after); n != h.newest(st.domain) {
							t.Errorf("%s slot %d is under key %d after the rekey, want %d", st.domain, s.slot, n, h.newest(st.domain))
						}
						if err := r.openColumn(st.ring, p, s, after); err != nil {
							t.Errorf("%s slot %d does not open after the rekey", st.domain, s.slot)
						}
					}
				}
			}
		})
	}
}

// rowDeclareLostUser covers `ctrlz declare-lost user_totp`: it clears exactly the seeds that
// name key N and do not open, and leaves the ones that open (admin-r13-3).
func rowDeclareLostUser(t *testing.T) {
	for _, h := range histories() {
		ring, ok := h.ring(t, keyring.DomainUserTOTP)
		if !ok {
			continue
		}
		for _, n := range h.numbersOf(keyring.DomainUserTOTP) {
			t.Run(fmt.Sprintf("%s/key %d", h.name, n), func(t *testing.T) {
				r := newRig(t)
				p := r.plant(h)
				worker := r.env.Keytool(t)
				env := r.cliEnv(&r.out, &r.errb)
				env.OpenRekey = func(context.Context) (*admincli.RekeyTools, error) {
					return &admincli.RekeyTools{Store: worker, Keys: ring}, nil
				}
				before := map[int][]byte{}
				for _, s := range h.dataOf(keyring.DomainUserTOTP) {
					before[s.slot] = r.column(p, keyring.DomainUserTOTP, s.slot)
				}
				// Since round 18 (admin-r18-7) the tool refuses, before it writes anything, when every seed that
				// names the key opens (nothing is lost); it clears per seed otherwise, as before.
				named, cleared := 0, 0
				for _, s := range h.dataOf(keyring.DomainUserTOTP) {
					if s.n == n {
						named++
					}
					if h.declareLostClears(s, n) {
						cleared++
					}
				}
				wantCode := 0
				if named > 0 && cleared == 0 {
					wantCode = 1
				}
				code := admincli.RunDeclareLost(r.env.Ctx, []string{keyring.DomainUserTOTP, "--key-number", fmt.Sprint(n), "--yes"}, env)
				if code != wantCode {
					t.Errorf("declare-lost for key %d: exit %d, want %d: %q", n, code, wantCode, r.errb.String())
				}
				for _, s := range h.dataOf(keyring.DomainUserTOTP) {
					after := r.column(p, keyring.DomainUserTOTP, s.slot)
					switch want := h.declareLostClears(s, n); {
					case want && after != nil:
						t.Errorf("slot %d names key %d, does not open, and was not cleared", s.slot, n)
					case !want && after == nil:
						t.Errorf("slot %d (key %d, opens=%v) was cleared by a declaration for key %d", s.slot, s.n, h.opens(s), n)
					case !want && !bytes.Equal(after, before[s.slot]):
						t.Errorf("slot %d was rewritten", s.slot)
					}
				}
			})
		}
	}
}
