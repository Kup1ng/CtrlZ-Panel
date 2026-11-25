package app_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/app"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// keyDir writes key files for the given domains from a fixed root.
func keyDir(t *testing.T, domains ...string) string {
	t.Helper()
	root := make([]byte, 32)
	for i := range root {
		root[i] = byte(i*7 + 3)
	}
	dir := t.TempDir()
	for _, d := range domains {
		txt, err := keyring.FileText(secret.NewBytes(root), d, 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, keyring.FileName(d)), txt.Reveal(), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// runRole starts a role and returns what it did: nil and its log if it got as
// far as listening (then it is stopped), or the error that stopped it.
func runRole(t *testing.T, role app.Role, vars map[string]string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out syncBuffer
	if _, ok := vars["CTRLZ_LISTEN"]; !ok {
		vars["CTRLZ_LISTEN"] = "127.0.0.1:0"
	}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- app.Run(runCtx, role, app.Options{Getenv: env(vars), Stdout: &out, Ready: ready}) }()
	select {
	case <-ready:
		stop()
		return out.String(), <-done
	case err := <-done:
		return out.String(), err
	case <-ctx.Done():
		t.Fatal("role neither started nor failed")
		return "", nil
	}
}

func TestRoleKeyDomains(t *testing.T) {
	want := map[app.Role]string{
		app.RoleAPI:     "user_totp otp_delivery auth_mac doh_token",
		app.RoleAdmin:   "admin_totp sms_cred admin_mac",
		app.RoleWorker:  "sms_cred otp_delivery",
		app.RoleHub:     "",
		app.RoleMigrate: "",
	}
	for role, w := range want {
		if got := strings.Join(role.KeyDomains(), " "); got != w {
			t.Errorf("%s holds [%s], spec 2.1 says [%s]", role, got, w)
		}
	}
	// The split that matters: api cannot read SMS credentials or admin seeds,
	// and the worker cannot read TOTP seeds.
	has := func(r app.Role, d string) bool {
		for _, x := range r.KeyDomains() {
			if x == d {
				return true
			}
		}
		return false
	}
	if has(app.RoleAPI, "sms_cred") || has(app.RoleAPI, "admin_totp") || has(app.RoleWorker, "user_totp") || has(app.RoleWorker, "auth_mac") || has(app.RoleAdmin, "user_totp") {
		t.Error("a role holds a domain it must not")
	}
}

func TestProductionRefusesToStartWithoutKeys(t *testing.T) {
	for _, role := range []app.Role{app.RoleAPI, app.RoleAdmin, app.RoleWorker} {
		for _, envName := range []string{"production", "dev"} {
			_, err := runRole(t, role, map[string]string{"CTRLZ_ENV": envName})
			if err == nil || !strings.Contains(err.Error(), "CTRLZ_KEK_DIR") {
				t.Errorf("%s with CTRLZ_ENV=%q and no key directory: %v", role, envName, err)
			}
		}
	}
	// Unset means production, not test.
	cfg, err := app.LoadConfig(app.RoleAPI, func(string) string { return "" })
	if err != nil || cfg.Env != app.EnvProduction {
		t.Errorf("default env = %q, %v", cfg.Env, err)
	}
	// hub holds no domain and needs no directory.
	if out, err := runRole(t, app.RoleHub, map[string]string{"CTRLZ_ENV": "production"}); err != nil {
		t.Errorf("hub: %v %s", err, out)
	}
}

func TestStartsWithKeyFiles(t *testing.T) {
	for _, role := range []app.Role{app.RoleAPI, app.RoleAdmin, app.RoleWorker} {
		dir := keyDir(t, role.KeyDomains()...)
		out, err := runRole(t, role, map[string]string{"CTRLZ_ENV": "production", "CTRLZ_KEK_DIR": dir, "CTRLZ_ARGON2_M_KIB": "19456"})
		if err != nil {
			t.Fatalf("%s: %v\n%s", role, err, out)
		}
		if !strings.Contains(out, `"msg":"keys loaded"`) {
			t.Errorf("%s: no keys line: %s", role, out)
		}
		for _, d := range role.KeyDomains() {
			if !strings.Contains(out, d) {
				t.Errorf("%s: the log does not name domain %s", role, d)
			}
		}
	}
}

// TestMissingKeyFileNamesTheDomain is 18.3 "Key file missing": start refused,
// names the domain, not a value.
func TestMissingKeyFileNamesTheDomain(t *testing.T) {
	dir := keyDir(t, "user_totp", "auth_mac", "doh_token") // otp_delivery is missing
	out, err := runRole(t, app.RoleAPI, map[string]string{"CTRLZ_ENV": "production", "CTRLZ_KEK_DIR": dir})
	if err == nil || !strings.Contains(err.Error(), "otp_delivery") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "user_totp") || strings.Contains(out, "keys loaded") {
		t.Errorf("a loaded domain is reported as a problem, or the role started: %v / %s", err, out)
	}

	// A malformed file is refused the same way, and the text is not repeated.
	bad := keyDir(t, "user_totp", "auth_mac", "otp_delivery", "doh_token")
	const junk = "KEY-CANARY-3b7f"
	if err := os.Remove(filepath.Join(bad, "kek_auth_mac")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "kek_auth_mac"), []byte("# ctrlz keyring domain=auth_mac\n1 "+junk+"\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	out, err = runRole(t, app.RoleAPI, map[string]string{"CTRLZ_ENV": "production", "CTRLZ_KEK_DIR": bad})
	if err == nil || !strings.Contains(err.Error(), "auth_mac") {
		t.Fatalf("malformed: %v", err)
	}
	if strings.Contains(err.Error(), junk) || strings.Contains(out, junk) {
		t.Error("key text reached the error or the log")
	}
}

func TestTestEnvironmentUsesThrowAwayKeys(t *testing.T) {
	out, err := runRole(t, app.RoleAPI, map[string]string{"CTRLZ_ENV": "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "throw-away keys") {
		t.Errorf("the log does not warn: %s", out)
	}
}

func TestEnvAndArgonSettingsAreValidated(t *testing.T) {
	for name, c := range map[string]struct {
		role app.Role
		vars map[string]string
		want string
	}{
		"unknown env":    {app.RoleAPI, map[string]string{"CTRLZ_ENV": "staging"}, "CTRLZ_ENV"},
		"upper-case env": {app.RoleAPI, map[string]string{"CTRLZ_ENV": "Production"}, "CTRLZ_ENV"},
		"argon memory":   {app.RoleAPI, map[string]string{"CTRLZ_ENV": "production", "CTRLZ_ARGON2_M_KIB": "512"}, "CTRLZ_ARGON2_M_KIB"},
		"argon time":     {app.RoleAdmin, map[string]string{"CTRLZ_ARGON2_T": "0"}, "CTRLZ_ARGON2_T"},
		"argon gate":     {app.RoleAPI, map[string]string{"CTRLZ_ARGON2_CONCURRENCY": "x"}, "CTRLZ_ARGON2_CONCURRENCY"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := app.LoadConfig(c.role, func(k string) string { return c.vars[k] })
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("got %v, want an error mentioning %s", err, c.want)
			}
		})
	}
	// The worker does not hash passwords, so a bad Argon2 value is not its business.
	if _, err := app.LoadConfig(app.RoleWorker, func(k string) string {
		return map[string]string{"CTRLZ_ARGON2_T": "0", "CTRLZ_ENV": "test"}[k]
	}); err != nil {
		t.Errorf("worker: %v", err)
	}
	c, err := app.LoadConfig(app.RoleAPI, func(k string) string { return map[string]string{"CTRLZ_KEK_DIR": "/run/secrets"}[k] })
	if err != nil || c.Env != app.EnvProduction || c.KEKDir != "/run/secrets" || c.Argon2.Params.MemoryKiB != 47104 || c.Argon2.Concurrency != 2 {
		t.Errorf("defaults: %+v %v", c, err)
	}
}

// TestAPIRefusesToStartWithoutTheDOHTokenKey is P3 11.5 "doh_token key missing at api start": the api seals the DoH token of every
// new Endpoint and opens it for every resolver view, so a deployment that forgot kek_doh_token must fail here, naming the domain,
// and not answer 500 at the first Endpoint (p3-D6-r1-6).
func TestAPIRefusesToStartWithoutTheDOHTokenKey(t *testing.T) {
	dir := keyDir(t, "user_totp", "otp_delivery", "auth_mac")
	out, err := runRole(t, app.RoleAPI, map[string]string{"CTRLZ_ENV": "production", "CTRLZ_KEK_DIR": dir})
	if err == nil || !strings.Contains(err.Error(), "doh_token") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(out, "keys loaded") {
		t.Errorf("the api started: %s", out)
	}
	// Its siblings do not hold the domain, so they start without it.
	for _, role := range []app.Role{app.RoleAdmin, app.RoleWorker} {
		for _, d := range role.KeyDomains() {
			if d == "doh_token" {
				t.Errorf("%s holds doh_token", role)
			}
		}
	}
}
