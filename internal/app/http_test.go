package app_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/app"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestRolesServeTheirAPIThroughThePipeline starts api and admin against a real
// database and talks to them over a socket: health stays outside /api and answers
// the container's Host, and /api is behind the pipeline (host check, JSON errors,
// no-store, request id).
func TestRolesServeTheirAPIThroughThePipeline(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)

	for _, tc := range []struct {
		role   app.Role
		dbRole string
		hostV  string
		public string // an operation that needs no session
		secure string // one that does
	}{
		{app.RoleAPI, "ctrlz_tenant", "CTRLZ_PANEL_HOST", "/api/v1/auth/config", "/api/v1/auth/logout-all"},
		{app.RoleAdmin, "ctrlz_admin", "CTRLZ_ADMIN_HOST", "", "/api/v1/auth/logout"},
	} {
		t.Run(string(tc.role), func(t *testing.T) {
			vars := dbEnv(t, d, tc.dbRole)
			vars[tc.hostV] = "svc.example.test"
			addr, stop, _ := start(t, tc.role, vars)
			defer stop()

			do := func(method, path, host string) (*http.Response, string) {
				req, _ := http.NewRequest(method, "http://"+addr+path, nil)
				req.Host = host
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				return resp, string(b)
			}

			// Health is not behind the host check.
			if resp, _ := do("GET", "/healthz", "127.0.0.1:1"); resp.StatusCode != 200 {
				t.Errorf("/healthz = %d", resp.StatusCode)
			}
			// /api answers only to the service's own host.
			resp, body := do("GET", "/api/v1/nope", "evil.example.test")
			if resp.StatusCode != 400 || !strings.Contains(body, `"code":"bad_request"`) {
				t.Errorf("wrong host: %d %s", resp.StatusCode, body)
			}
			resp, body = do("GET", "/api/v1/nope", "svc.example.test")
			if resp.StatusCode != 404 || !strings.Contains(body, `"code":"not_found"`) || resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Request-Id") == "" {
				t.Errorf("unknown route: %d %s %v", resp.StatusCode, body, resp.Header)
			}
			if tc.public != "" {
				resp, body = do("GET", tc.public, "svc.example.test")
				if resp.StatusCode != 200 || !strings.Contains(body, "registration_mode") {
					t.Errorf("public route: %d %s", resp.StatusCode, body)
				}
			}
			method := "POST"
			resp, body = do(method, tc.secure, "svc.example.test")
			if resp.StatusCode != 401 || !strings.Contains(body, `"code":"session_expired"`) {
				t.Errorf("session route with no cookie: %d %s", resp.StatusCode, body)
			}
		})
	}
}

func TestNewConfigVariables(t *testing.T) {
	cfg, err := app.LoadConfig(app.RoleAPI, env(map[string]string{
		"CTRLZ_PANEL_HOST": "panel.example.test", "CTRLZ_ADMIN_HOST": "admin.example.test",
		"CTRLZ_VALKEY_ADDR": "valkey:6379", "CTRLZ_VALKEY_USER": "api", "CTRLZ_VALKEY_PASSWORD_FILE": writeSecret(t, "vp", "valkey-secret"),
		"CTRLZ_NOOP_SMS_FILE": "/tmp/noop-sms",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PanelHost != "panel.example.test" || cfg.AdminHost != "admin.example.test" || cfg.ValkeyAddr != "valkey:6379" || cfg.NoopSMSFile != "/tmp/noop-sms" {
		t.Fatalf("%+v", cfg)
	}
	if cfg.ValkeyUsername != "api" {
		t.Fatalf("the Valkey ACL user was not read: %q", cfg.ValkeyUsername)
	}
	if cfg.ValkeyPassword.Reveal() != "valkey-secret" {
		t.Fatal("the Valkey password was not read from its file")
	}
	// Defaults are the ones Compose passes.
	cfg, err = app.LoadConfig(app.RoleAPI, env(nil))
	if err != nil || cfg.PanelHost != "panel.localhost" || cfg.AdminHost != "admin.localhost" || cfg.ValkeyAddr != "" {
		t.Fatalf("defaults: %+v %v", cfg, err)
	}
	// The noop gateway file is for dev and test only.
	_, err = app.LoadConfig(app.RoleWorker, func(k string) string {
		switch k {
		case "CTRLZ_ENV":
			return "production"
		case "CTRLZ_NOOP_SMS_FILE":
			return "/tmp/x"
		}
		return ""
	})
	if err == nil {
		t.Fatal("CTRLZ_NOOP_SMS_FILE must be refused in production")
	}
	// A missing Valkey password file is a start error that names no content.
	if _, err := app.LoadConfig(app.RoleAPI, env(map[string]string{"CTRLZ_VALKEY_PASSWORD_FILE": "/nonexistent/vp"})); err == nil {
		t.Fatal("a missing password file must fail")
	}
}

// CTRLZ_TRUSTED_PROXY is read as a list of addresses and prefixes, and a bad
// entry is a start error (review round 3, admin-r3-13).
func TestTrustedProxyVariable(t *testing.T) {
	cfg, err := app.LoadConfig(app.RoleAdmin, env(map[string]string{"CTRLZ_TRUSTED_PROXY": "10.213.78.10, fd00:213::/64"}))
	if err != nil || len(cfg.TrustedProxies) != 2 {
		t.Fatalf("trusted proxies: %+v %v", cfg.TrustedProxies, err)
	}
	if _, err := app.LoadConfig(app.RoleAdmin, env(map[string]string{"CTRLZ_TRUSTED_PROXY": "caddy"})); err == nil {
		t.Fatal("a host name must be refused: the list is addresses")
	}
}

// Production without the list does not serve: every container on the network
// could otherwise write X-Forwarded-For (admin-r3-13).
func TestProductionNeedsATrustedProxy(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)
	vars := dbEnv(t, d, "ctrlz_tenant")
	vars["CTRLZ_ENV"] = "production"
	vars["CTRLZ_KEK_DIR"] = keyDir(t, "user_totp", "otp_delivery", "auth_mac")
	vars["CTRLZ_LISTEN"] = "127.0.0.1:0"
	err := app.Run(ctx, app.RoleAPI, app.Options{Getenv: env(vars), Stdout: &syncBuffer{}, Ready: make(chan string, 1)})
	if err == nil || !strings.Contains(err.Error(), "CTRLZ_TRUSTED_PROXY") {
		t.Fatalf("api started in production without a trusted proxy: %v", err)
	}
}

// ownNonLoopbackAddress is an address of this host that is not loopback: connecting to it makes the
// peer of the server this address too, which is what a neighbour on the backend network is.
func ownNonLoopbackAddress(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		skipUnlessCI(t, "no interface addresses: "+err.Error())
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && ipn.IP.IsGlobalUnicast() && !ipn.IP.IsLoopback() {
			return ipn.IP.String()
		}
	}
	skipUnlessCI(t, "this host has no non-loopback IPv4 address")
	return ""
}

// TestTheHealthMuxOfApiAndAdminAnswersLoopbackOnly is admin-r11-4. api and admin serve /api behind the
// peer check and the health mux at the root outside it, on every interface; /readyz pings on the
// role's own pool with no authentication, so a neighbour on the backend network looping on it could
// hold the admin's five connections and keep the owner out. The role listens on every interface here,
// as in Compose, and the same /readyz and /healthz are asked from loopback (served) and from the
// host's own non-loopback address (not served, no database work, nothing about the role or release).
func TestTheHealthMuxOfApiAndAdminAnswersLoopbackOnly(t *testing.T) {
	other := ownNonLoopbackAddress(t)
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)
	for _, tc := range []struct {
		role   app.Role
		dbRole string
	}{{app.RoleAPI, "ctrlz_tenant"}, {app.RoleAdmin, "ctrlz_admin"}} {
		t.Run(string(tc.role), func(t *testing.T) {
			vars := dbEnv(t, d, tc.dbRole)
			vars["CTRLZ_LISTEN"] = ":0"
			addr, stop, _ := start(t, tc.role, vars)
			defer stop()
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/healthz", "/readyz"} {
				if code, _ := get(t, "http://127.0.0.1:"+port+path); code != 200 {
					t.Errorf("%s from loopback = %d, want 200", path, code)
				}
				code, body := get(t, "http://"+net.JoinHostPort(other, port)+path)
				if code != 404 || strings.Contains(body, string(tc.role)) || strings.Contains(body, "ready") {
					t.Errorf("%s from %s = %d %q: a neighbour was served the health mux", path, "a non-loopback peer", code, body)
				}
			}
		})
	}
}

// skipUnlessCI skips a test whose host lacks something it needs, except in the CI run
// (scripts/ci.sh sets CTRLZ_CI), where a missing address is a failure: the check that a neighbour is
// refused the health mux (rule 28, admin-r12-2) must not read as a pass on a host that cannot run it.
func skipUnlessCI(t *testing.T, why string) {
	t.Helper()
	if os.Getenv("CTRLZ_CI") != "" {
		t.Fatalf("%s, and the CI run may not skip this check", why)
	}
	t.Skip(why)
}
