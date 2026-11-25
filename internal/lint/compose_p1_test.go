package lint_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/deploy"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// The network of every service after the split of spec 17.2 (finding 10).
// Afterwards only caddy shares a network with the web containers, and only
// caddy joins them to api and admin.
func TestComposeNetworks(t *testing.T) {
	c := loadCompose(t)
	want := map[string][]string{
		"caddy":        {"app", "ingress", "web"},
		"web-panel":    {"web"},
		"web-admin":    {"web"},
		"api":          {"app", "backend", "vk_api"},
		"admin":        {"app", "backend", "vk_admin"},
		"worker":       {"backend", "egress"},
		"hub":          {"backend", "hub_ingress"},
		"rekey":        {"backend"},
		"migrate":      {"backend"},
		"postgres":     {"backend"},
		"clickhouse":   {"backend"},
		"valkey-api":   {"vk_api"},
		"valkey-admin": {"vk_admin"},
	}
	for name, nets := range want {
		s, ok := c.Services[name]
		if !ok {
			t.Errorf("no service %s", name)
			continue
		}
		got := append([]string(nil), s.Networks.names...)
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(nets, ",") {
			t.Errorf("%s is on %v, want %v", name, got, nets)
		}
	}
	for _, n := range []string{"web", "app", "backend", "vk_api", "vk_admin"} {
		if !c.Networks[n].Internal {
			t.Errorf("network %s must be internal: no route out", n)
		}
	}
	for _, n := range []string{"ingress", "hub_ingress", "egress"} {
		if c.Networks[n].Internal {
			t.Errorf("network %s is internal, so it cannot publish a port or reach out", n)
		}
	}
	if _, ok := c.Networks["edge"]; ok {
		t.Error("the shared edge network is back")
	}
	// The point of the split: a web container has no path to api or admin.
	share := func(a, b string) bool {
		for _, x := range c.Services[a].Networks.names {
			if contains(c.Services[b].Networks.names, x) {
				return true
			}
		}
		return false
	}
	for _, web := range []string{"web-panel", "web-admin"} {
		for _, goSvc := range []string{"api", "admin", "worker", "hub", "postgres", "valkey-api", "valkey-admin"} {
			if share(web, goSvc) {
				t.Errorf("%s shares a network with %s", web, goSvc)
			}
		}
	}
	// A Valkey server shares a network with the one service of its own zone and with nobody else (round 16,
	// admin-r16-6): a container that reaches the port can hold its client slots, so the worker, the hub,
	// Postgres and ClickHouse (and the other zone's service) must not.
	for _, zone := range []string{"api", "admin"} {
		srv := "valkey-" + zone
		for name := range c.Services {
			if name != srv && name != zone && share(srv, name) {
				t.Errorf("%s shares a network with %s: only %s may reach it", srv, name, zone)
			}
		}
	}
	// Only caddy, hub and worker can reach out: the services on a non-internal
	// network. api and admin must not be among them (spec 15.2 relies on it).
	for name, s := range c.Services {
		out := false
		for _, n := range s.Networks.names {
			out = out || !c.Networks[n].Internal
		}
		switch name {
		case "caddy", "hub", "worker":
			if !out {
				t.Errorf("%s has no route out but needs one", name)
			}
		default:
			if out {
				t.Errorf("%s has a route out", name)
			}
		}
	}
}

// Each Go service mounts the key files of its own domains and no other
// (spec 2.1, 8.1): a compromised api cannot read SMS credentials or admin TOTP
// seeds. kek_root is never a Compose secret at all.
func TestComposeKeyFilesFollowTheDomains(t *testing.T) {
	c := loadCompose(t)
	want := map[string][]string{
		"api":    {"kek_auth_mac", "kek_otp_delivery", "kek_user_totp"},
		"admin":  {"kek_admin_mac", "kek_admin_totp", "kek_sms_cred"},
		"worker": {"kek_otp_delivery", "kek_sms_cred"},
		"rekey":  {"kek_user_totp"},
	}
	for name, s := range c.Services {
		var got []string
		for _, sec := range s.Secrets {
			if strings.HasPrefix(sec, "kek_") {
				got = append(got, sec)
			}
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(want[name], ",") {
			t.Errorf("%s mounts key files %v, want %v", name, got, want[name])
		}
	}
	if _, ok := c.Secrets["kek_root"]; ok {
		t.Error("kek_root is a Compose secret; it must stay on the host")
	}
	for _, name := range []string{"api", "admin", "worker", "rekey"} {
		s := c.Services[name]
		if s.Environment["CTRLZ_KEK_DIR"] != "/run/secrets" {
			t.Errorf("%s: CTRLZ_KEK_DIR = %q", name, s.Environment["CTRLZ_KEK_DIR"])
		}
		if s.Environment["CTRLZ_ENV"] != "${CTRLZ_ENV:-production}" {
			t.Errorf("%s: CTRLZ_ENV = %q; production must be the default", name, s.Environment["CTRLZ_ENV"])
		}
	}
	// No Go service may depend on Valkey being up (spec 17.2).
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "compose", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "depends_on: [valkey") || strings.Contains(string(b), "      valkey:\n        condition") {
		t.Error("a service depends on valkey")
	}
}

// The Dockerfile carries the ctrlz-admin link and the CA bundle (spec 17.2).
func TestDockerfileHasTheAdminLinkAndCABundle(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "docker", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	df := string(b)
	for _, want := range []string{
		"ln -s ctrlz /out/bin/ctrlz-admin",
		"COPY --from=build /out/bin/ /usr/local/bin/",
		"COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt",
		`ENTRYPOINT ["/usr/local/bin/ctrlz"]`,
		"USER 65532:65532",
	} {
		if !strings.Contains(df, want) {
			t.Errorf("the Dockerfile lacks %q", want)
		}
	}
	if strings.Contains(df, "needs no CA bundle") {
		t.Error("the header still says no CA bundle is needed")
	}
}

// The Caddyfile writes X-Forwarded-For itself for every proxy to a Go service.
func TestCaddyWritesForwardedFor(t *testing.T) {
	cf := readDeploy(t, "caddy", "Caddyfile")
	if strings.Contains(cf, "trusted_proxies") {
		t.Error("trusted_proxies is set: a client-written X-Forwarded-For could pass")
	}
	// Every proxy to a Go service writes the header, whatever number of routes reaches it: the panel's /api, the panel's /p download
	// links (P3 7.1) and the admin's /api. Counting the proxies and the writes against each other, and not a fixed number, means a
	// route added later cannot forward a client-written value, and a route removed cannot leave the test passing on its own count.
	proxies := len(regexp.MustCompile(`(?m)^\s*reverse_proxy (api|admin):\d+`).FindAllString(cf, -1))
	writes := strings.Count(cf, "header_up X-Forwarded-For {remote_host}")
	if proxies < 3 || writes != proxies {
		t.Errorf("%d proxies to a Go service and %d that overwrite X-Forwarded-For, want the same number and at least 3 (panel api, panel download, admin)", proxies, writes)
	}
}

// echoUpstream starts a server the Caddyfile reaches as api:8080. It answers
// every request with the X-Forwarded-For header it received as the body, one
// line per header, so a test can see what Caddy sent on. The Caddy image is
// Alpine, so its busybox nc and a fifo are the whole server.
func (l *caddyLab) echoUpstream() {
	l.t.Helper()
	script := `rm -f /tmp/f /tmp/h; mkfifo /tmp/f
while true; do
  { while IFS= read -r line; do
      line=$(printf '%s' "$line" | tr -d '\r')
      [ -z "$line" ] && break
      case "$line" in [Xx]-[Ff]orwarded-[Ff]or:*) echo "$line" >> /tmp/h ;; esac
    done
    body=$(cat /tmp/h 2>/dev/null); rm -f /tmp/h
    printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' "${#body}" "$body"
  } < /tmp/f | nc -l -p 8080 > /tmp/f
done`
	l.run([]string{"-d", "--name", l.name + "-up", "--network", l.network, "--network-alias", "api", "--entrypoint", "sh"}, "-c", script)
}

// TestCaddyDropsAClientForwardedFor is the "X-Forwarded-For spoof" row of 18.5:
// through the real Caddyfile, a client-written X-Forwarded-For does not reach
// the upstream. The upstream sees exactly one header, and it is the address
// Caddy saw, never the forged value. The Go services take the rightmost value
// of the header as the client (spec 2.3 step 5), so this is what keeps a forged
// address out of every network-keyed limit.
func TestCaddyDropsAClientForwardedFor(t *testing.T) {
	l := newCaddyLab(t)
	l.echoUpstream()
	client := l.start()
	l.ready()
	const forged = "203.0.113.77"
	seen := ""
	testwait.UntilEvery(t, 20*time.Second, 500*time.Millisecond, "the echo upstream to answer through Caddy", func() bool {
		req, _ := http.NewRequest("GET", "https://panel.localhost/api/v1/auth/config", nil)
		req.Header.Set("X-Forwarded-For", forged)
		req.Header.Add("X-Forwarded-For", "198.51.100.200, 192.0.2.1")
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return false
		}
		seen = string(b)
		return true
	})
	t.Logf("the upstream saw %q", seen)
	for _, bad := range []string{forged, "198.51.100.200", "192.0.2.1"} {
		if strings.Contains(seen, bad) {
			t.Errorf("a client-written X-Forwarded-For value reached the upstream: %q", seen)
		}
	}
	if n := strings.Count(strings.ToLower(seen), "x-forwarded-for:"); n != 1 {
		t.Errorf("the upstream received %d X-Forwarded-For headers, want 1: %q", n, seen)
	}
}

// TestImageSmoke runs scripts/image-smoke.sh against the built image: the
// ctrlz-admin link survived COPY, the entrypoint reaches the admin command line,
// the CA bundle is there. It skips when the image has not been built, because
// building it needs the Go module proxy and takes minutes; the Compose smoke and
// the phase gate build it.
func TestImageSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: container tests skipped")
	}
	image := os.Getenv("CTRLZ_IMAGE")
	if image == "" {
		image = "ctrlz/panel:dev"
	}
	if err := deploy.Docker(context.Background(), "image", "inspect", image).Run(); err != nil {
		t.Skipf("image %s is not built", image)
	}
	sh := shellPath(t)
	cmd := exec.Command(sh, filepath.ToSlash(filepath.Join(repoRoot(t), "scripts", "image-smoke.sh")))
	cmd.Env = append(os.Environ(), "CTRLZ_IMAGE="+image)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("image-smoke.sh: %v\n%s", err, out)
	}
}

// api and admin take X-Forwarded-For from caddy alone: caddy has a fixed address
// on the app network and both services are told it (review round 3, admin-r3-13).
// Without this, hub, worker or any container on backend or app could write the
// header and pick its own address for every per-address limit.
func TestOnlyCaddyMaySetForwardedFor(t *testing.T) {
	c := loadCompose(t)
	addr := c.Services["caddy"].Networks.addr["app"]
	if addr == "" {
		t.Fatal("caddy has no fixed address on the app network")
	}
	var app *struct {
		Subnet  string `yaml:"subnet"`
		IPRange string `yaml:"ip_range"`
	}
	for i := range c.Networks["app"].IPAM.Config {
		app = &c.Networks["app"].IPAM.Config[i]
	}
	if app == nil || app.Subnet == "" || app.IPRange == "" {
		t.Fatal("the app network has no fixed subnet and range")
	}
	_, sub, err := net.ParseCIDR(app.Subnet)
	if err != nil {
		t.Fatal(err)
	}
	_, rng, err := net.ParseCIDR(app.IPRange)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(addr)
	if ip == nil || !sub.Contains(ip) || rng.Contains(ip) {
		t.Errorf("caddy's address %s must be inside %s and outside the dynamic range %s", addr, app.Subnet, app.IPRange)
	}
	for _, name := range []string{"api", "admin"} {
		if got := c.Services[name].Environment["CTRLZ_TRUSTED_PROXY"]; got != addr {
			t.Errorf("%s has CTRLZ_TRUSTED_PROXY=%q, want caddy's address %s", name, got, addr)
		}
	}
	for name, s := range c.Services {
		if _, ok := s.Environment["CTRLZ_TRUSTED_PROXY"]; ok && name != "api" && name != "admin" {
			t.Errorf("%s sets CTRLZ_TRUSTED_PROXY; only api and admin read it", name)
		}
	}
}

// ingress is dual stack, so an IPv6 client reaches caddy under its own address
// and not as the userland proxy's gateway (admin-r3-10).
func TestIngressKeepsIPv6SourceAddresses(t *testing.T) {
	c := loadCompose(t)
	in := c.Networks["ingress"]
	if !in.EnableIPv6 {
		t.Fatal("ingress has no enable_ipv6: Docker would serve IPv6 clients through the userland proxy, as one address")
	}
	ula := false
	for _, cfg := range in.IPAM.Config {
		if ip, _, err := net.ParseCIDR(cfg.Subnet); err == nil && ip.To4() == nil && strings.HasPrefix(strings.ToLower(ip.String()), "fd") {
			ula = true
		}
	}
	if !ula {
		t.Error("ingress has no ULA IPv6 subnet")
	}
}
