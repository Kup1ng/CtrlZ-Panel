package admincli_test

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/admincli"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// TestRekeyOfSeedsKeepsTheCredentialGeneration pins db-r6-4 (it replaced admin-r5-3's test of the
// opposite). Re-encrypting a TOTP seed in force rewrites totp_secret_ct and not the second factor,
// so `rekey admin_totp` and `rekey user_totp` leave the generation of every account they rewrite
// alone: no device marker ends, no sign-in in flight is refused, and the tool has no quiet period to
// ask for. The trigger reads totp_enabled_at to know the factor is the same one. An account of
// another tenant that was not rewritten keeps its generation too.
func TestRekeyOfSeedsKeepsTheCredentialGeneration(t *testing.T) {
	r := newRig(t)
	r.readyAdmin()
	root := secret.NewBytes(bytes.Repeat([]byte{7}, 32))
	one, err := keyring.FromRoot(root, map[string][]uint16{keyring.DomainAdminTOTP: {1}, keyring.DomainUserTOTP: {1}})
	if err != nil {
		t.Fatal(err)
	}
	both, err := keyring.FromRoot(root, map[string][]uint16{keyring.DomainAdminTOTP: {1, 2}, keyring.DomainUserTOTP: {1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := totp.NewSecret()

	ct, _ := one.Seal(keyring.DomainAdminTOTP, totp.AdminAAD(seedAdmin), seed.Reveal())
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET totp_secret_ct = $2, totp_enabled_at = now() WHERE id = $1`, seedAdmin, ct)
	// Tenant A's user has a seed under key 1; tenant B's has none, so a rekey does not touch it.
	cu, _ := one.Seal(keyring.DomainUserTOTP, totp.UserAAD(r.env.A.Tenant, r.env.A.User), seed.Reveal())
	r.env.Exec(t, `UPDATE ctrlz.users SET totp_secret_ct = $3, totp_enabled_at = now() WHERE tenant_id = $1 AND id = $2`, r.env.A.Tenant, r.env.A.User, cu)

	gen := func(table string, tenant, id uuid.UUID) int64 {
		var g int64
		if table == "admin_users" {
			r.env.Scan(t, `SELECT credential_gen FROM ctrlz.admin_users WHERE id = $1`, []any{id}, &g)
		} else {
			r.env.Scan(t, `SELECT credential_gen FROM ctrlz.users WHERE tenant_id = $1 AND id = $2`, []any{tenant, id}, &g)
		}
		return g
	}
	adminBefore := gen("admin_users", uuid.Nil, seedAdmin)
	userA, userB := gen("users", r.env.A.Tenant, r.env.A.User), gen("users", r.env.B.Tenant, r.env.B.User)

	const note = "moved their account's credential generation"
	r.keys = both
	r.out.Reset()
	if code := r.run("rekey", "admin_totp"); code != 0 || !strings.Contains(r.out.String(), "1 rewritten") {
		t.Fatalf("rekey admin_totp: %d %q %q", code, r.out.String(), r.errb.String())
	}
	if strings.Contains(r.out.String(), note) {
		t.Errorf("the rekey of the admin seed says it moved a generation, which it must not: %q", r.out.String())
	}
	if got := gen("admin_users", uuid.Nil, seedAdmin); got != adminBefore {
		t.Errorf("rekey admin_totp moved the admin's credential generation from %d to %d", adminBefore, got)
	}

	// The user seeds: tenant A's row is rewritten and moves; tenant B's has no seed and does not.
	worker := r.env.Keytool(t)
	env := r.cliEnv(&r.out, &r.errb)
	env.OpenRekey = func(context.Context) (*admincli.RekeyTools, error) {
		return &admincli.RekeyTools{Store: worker, Keys: both}, nil
	}
	r.out.Reset()
	if code := admincli.RunRekey(r.env.Ctx, []string{"user_totp"}, env); code != 0 || !strings.Contains(r.out.String(), "1 rewritten") {
		t.Fatalf("rekey user_totp: %d %q %q", code, r.out.String(), r.errb.String())
	}
	if strings.Contains(r.out.String(), note) {
		t.Errorf("the rekey of the user seeds says it moved a generation, which it must not: %q", r.out.String())
	}
	if got := gen("users", r.env.A.Tenant, r.env.A.User); got != userA {
		t.Errorf("rekey user_totp moved tenant A's credential generation from %d to %d", userA, got)
	}
	if got := gen("users", r.env.B.Tenant, r.env.B.User); got != userB {
		t.Errorf("rekey user_totp moved the generation of tenant B, which has no seed: %d to %d", userB, got)
	}

	// A second run rewrites nothing, moves nothing and has nothing to say.
	adminAfter, userAfter := gen("admin_users", uuid.Nil, seedAdmin), gen("users", r.env.A.Tenant, r.env.A.User)
	r.out.Reset()
	if code := r.run("rekey", "admin_totp"); code != 0 || !strings.Contains(r.out.String(), "0 rewritten, 1 already current") {
		t.Fatalf("a second rekey: %d %q", code, r.out.String())
	}
	if strings.Contains(r.out.String(), note) {
		t.Errorf("a rekey that rewrote nothing says it moved generations: %q", r.out.String())
	}
	r.out.Reset()
	if code := admincli.RunRekey(r.env.Ctx, []string{"user_totp"}, env); code != 0 || strings.Contains(r.out.String(), note) {
		t.Errorf("a second user rekey: %d %q", code, r.out.String())
	}
	if gen("admin_users", uuid.Nil, seedAdmin) != adminAfter || gen("users", r.env.A.Tenant, r.env.A.User) != userAfter {
		t.Error("a rekey that rewrote nothing moved a credential generation")
	}
}

// stubDockerThatFails is a `docker` that finds the image and then fails the `run` the way a
// daemon that is restarting does (exit 125), optionally after it left one key file in the
// directory mounted as /secrets, the way a derive that was killed half way would.
func stubDockerThatFails(t *testing.T, exit int, leave string) string {
	t.Helper()
	bin := t.TempDir()
	script := "#!/bin/sh\n" +
		"case \"$1\" in\n" +
		"image) exit 0 ;;\n" +
		"run)\n" +
		"  prev=''; dir=''\n" +
		"  for a in \"$@\"; do\n" +
		"    if [ \"$prev\" = '-v' ]; then dir=${a%:/secrets}; fi\n" +
		"    prev=$a\n" +
		"  done\n"
	if leave != "" {
		script += "  printf 'x' > \"$dir/" + leave + "\"\n"
	}
	script += "  exit " + fmt.Sprint(exit) + " ;;\n" +
		"esac\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

// TestGenSecretsKeepsNoRootThatOwnsNothing is admin-r5-6. Key files are in the directory, the
// host copy of kek_root was deleted as the installer allows, and the script is run again while
// the Docker daemon is restarting. It makes a random root and the derive never runs. The root
// must not stay: it owns no file and would sit beside the old ones looking like the real root.
// Only a derive that wrote a key file with it may leave it.
func TestGenSecretsKeepsNoRootThatOwnsNothing(t *testing.T) {
	sh := shellForScripts(t)
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "gen-secrets.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		exit     int
		leave    string
		wantRoot bool
		// soft: the one refusal that is not a failure (admin-r13-6). The run says the keys were not
		// checked and carries on to the plain secrets, which do not depend on the root.
		soft bool
	}{
		"daemon down":                  {exit: 125},
		"killed":                       {exit: 137},
		"any other failure":            {exit: 1},
		"a refusal":                    {exit: 3, soft: true},
		"failed after writing one key": {exit: 1, leave: "kek_admin_totp", wantRoot: true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			// Key files of an earlier root, and no kek_root.
			for _, n := range []string{"kek_admin_mac", "kek_auth_mac"} {
				if err := os.WriteFile(filepath.Join(dir, n), bytes.Repeat([]byte{1}, 32), 0o444); err != nil {
					t.Fatal(err)
				}
			}
			before := snapshot(t, dir)
			bin := stubDockerThatFails(t, c.exit, c.leave)
			cmd := exec.Command(sh, filepath.ToSlash(script), filepath.ToSlash(dir))
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			out, runErr := cmd.CombinedOutput()
			if c.soft {
				if runErr != nil || !strings.Contains(string(out), "kek_root is not on this host") {
					t.Fatalf("a refusal with no root on the host must go on to the plain secrets: %v\n%s", runErr, out)
				}
				after := snapshot(t, dir)
				if _, hasRoot := after["kek_root"]; hasRoot {
					t.Error("a refused derive left a kek_root behind")
				}
				for name, v := range before {
					if after[name] != v {
						t.Errorf("%s changed", name)
					}
				}
				for _, name := range []string{"pg_superuser_password", "valkey_password_api", "proof_key"} {
					if _, ok := after[name]; !ok {
						t.Errorf("%s was not made", name)
					}
				}
				return
			}
			if runErr == nil {
				t.Fatalf("the script succeeded after a failed derive\n%s", out)
			}
			after := snapshot(t, dir)
			_, hasRoot := after["kek_root"]
			switch {
			case c.wantRoot && !hasRoot:
				t.Errorf("a derive that wrote a key file lost the root that owns it")
			case !c.wantRoot && hasRoot:
				t.Errorf("a stray kek_root was left after a derive that wrote nothing")
			}
			if !c.wantRoot && !maps.Equal(before, after) {
				t.Errorf("the directory is not as the run found it: %v", changedNames(before, after))
			}
		})
	}
}

// TestGenSecretsMakesANewPlainSecretWithoutTheRootOnTheHost is admin-r13-6. The owner moved kek_root
// off the server, as the script advises, and a later release adds a secret file. The run must make
// that secret, leave no root behind and exit 0: the plain secrets do not depend on the root, and
// making the owner put the root key back on the internet-facing host would undo the advice. The
// derive is the real one, run through the stand-in docker, so "the key files are another root's"
// is the real answer and not a canned exit code.
func TestGenSecretsMakesANewPlainSecretWithoutTheRootOnTheHost(t *testing.T) {
	sh := shellForScripts(t)
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "gen-secrets.sh"))
	if err != nil {
		t.Fatal(err)
	}
	bin := stubDockerRunningDerive(t)
	var h history
	for _, c := range histories() {
		if c.name == "root deleted" {
			h = c
		}
	}
	if h.name == "" {
		t.Fatal("the history 'root deleted' is gone from the matrix")
	}
	dir := t.TempDir()
	h.write(t, dir)
	plain := []string{"pg_superuser_password", "pg_migrator_password", "pg_tenant_password", "pg_hub_password",
		"pg_compiler_password", "pg_worker_password", "pg_keytool_password", "pg_admin_password", "clickhouse_migrator_password", "clickhouse_ingest_password", "clickhouse_api_password", "clickhouse_preview_password", "clickhouse_janitor_password", "valkey_password_admin", "proof_key", "spool_key_prev"}
	for _, name := range plain {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("Zq3vNn7hQw1xKs9dZq3vNn7hQw1xKs9d\n"), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	// valkey_password_api is the secret a release adds: it is not there.
	before := snapshot(t, dir)
	if _, ok := before["kek_root"]; ok {
		t.Fatal("the history has a root on disk")
	}
	cmd := exec.Command(sh, filepath.ToSlash(script), filepath.ToSlash(dir))
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		t.Fatalf("the run stopped for a missing root: %v\n%s", runErr, out)
	}
	after := snapshot(t, dir)
	if v, ok := after["valkey_password_api"]; !ok || len(v) < 32 {
		t.Error("the new secret was not made")
	}
	if _, ok := after["kek_root"]; ok {
		t.Error("the run left a kek_root on the host")
	}
	for name, v := range before {
		if after[name] != v {
			t.Errorf("%s changed", name)
		}
	}
	if !strings.Contains(string(out), "kek_root is not on this host") {
		t.Errorf("the run does not say the keys were not checked\n%s", out)
	}
	if strings.Contains(string(out), "copy "+dir) {
		t.Errorf("the run tells the owner to copy a root that is not there\n%s", out)
	}
}
