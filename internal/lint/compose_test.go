package lint_test

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Kup1ng/CtrlZ-Panel/internal/app"
)

// compose is the part of docker-compose.yml these rules look at.
type compose struct {
	Services map[string]struct {
		Image       string            `yaml:"image"`
		Ports       []string          `yaml:"ports"`
		Networks    serviceNets       `yaml:"networks"`
		Environment map[string]string `yaml:"environment"`
		Secrets     []string          `yaml:"secrets"`
		SecurityOpt []string          `yaml:"security_opt"`
		CapDrop     []string          `yaml:"cap_drop"`
		ReadOnly    bool              `yaml:"read_only"`
		User        string            `yaml:"user"`
		CapAdd      []string          `yaml:"cap_add"`
		NetworkMode string            `yaml:"network_mode"`
		MemLimit    string            `yaml:"mem_limit"`
		Logging     struct {
			Driver  string            `yaml:"driver"`
			Options map[string]string `yaml:"options"`
		} `yaml:"logging"`
		Command    []string `yaml:"command"`
		Entrypoint []string `yaml:"entrypoint"`
		// StopGracePeriod is how long Docker waits after SIGTERM before SIGKILL (round 15, admin-r15-2).
		StopGracePeriod string `yaml:"stop_grace_period"`
		Healthcheck     struct {
			Test []string `yaml:"test"`
		} `yaml:"healthcheck"`
	} `yaml:"services"`
	Networks map[string]struct {
		Internal   bool `yaml:"internal"`
		EnableIPv6 bool `yaml:"enable_ipv6"`
		IPAM       struct {
			Config []struct {
				Subnet  string `yaml:"subnet"`
				IPRange string `yaml:"ip_range"`
			} `yaml:"config"`
		} `yaml:"ipam"`
	} `yaml:"networks"`
	Secrets map[string]struct {
		File string `yaml:"file"`
	} `yaml:"secrets"`
}

// serviceNets reads the networks of a service in either compose spelling: a
// list of names, or a map from name to settings such as ipv4_address.
type serviceNets struct {
	names []string
	addr  map[string]string
}

func (n *serviceNets) UnmarshalYAML(v *yaml.Node) error {
	n.addr = map[string]string{}
	switch v.Kind {
	case yaml.SequenceNode:
		return v.Decode(&n.names)
	case yaml.MappingNode:
		var m map[string]struct {
			IPv4 string `yaml:"ipv4_address"`
		}
		if err := v.Decode(&m); err != nil {
			return err
		}
		for name, cfg := range m {
			n.names = append(n.names, name)
			n.addr[name] = cfg.IPv4
		}
		sort.Strings(n.names)
	}
	return nil
}

func loadCompose(t *testing.T) compose {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "compose", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var c compose
	if err := yaml.Unmarshal(b, &c); err != nil {
		t.Fatalf("docker-compose.yml: %v", err)
	}
	return c
}

func TestComposeServices(t *testing.T) {
	c := loadCompose(t)
	want := []string{"caddy", "caddy-init", "api", "admin", "worker", "hub", "web-panel", "web-admin", "postgres", "clickhouse", "valkey-api", "valkey-admin", "migrate", "migrate-analytics", "rekey"}
	var got []string
	for n := range c.Services {
		got = append(got, n)
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("services are %v, want %v", got, want)
	}
}

// Only the front door is published in P1, and nothing else, no database port, ever. Rule 28: the
// host publishes the ports of caddy, exactly 80 and 443 (admin-r11-3: the count of two was checked,
// so a second mapping of 443 to another port, or a bind of the admin port through caddy, passed).
func TestComposePublishesNoDatabasePort(t *testing.T) {
	c := loadCompose(t)
	for name, s := range c.Services {
		switch name {
		case "caddy":
			seen := map[string]int{}
			for _, p := range s.Ports {
				seen[containerPort(p)]++
			}
			if len(s.Ports) != 2 || seen["80"] != 1 || seen["443"] != 1 {
				t.Errorf("caddy publishes %v, want container ports 80 and 443, once each, and nothing else", s.Ports)
			}
		default:
			// The hub is in this list since round 10 (admin-r10-4): in P1 it serves the health mux
			// and nothing else, and a published port gave the internet an unauthenticated /readyz that
			// takes a pooled database connection. It joins caddy here when P4 gives it an mTLS listener.
			if len(s.Ports) != 0 {
				t.Errorf("%s publishes %v; only caddy may publish a port", name, s.Ports)
			}
		}
	}
	for _, db := range []string{"postgres", "clickhouse"} {
		s := c.Services[db]
		if len(s.Networks.names) != 1 || s.Networks.names[0] != "backend" {
			t.Errorf("%s is on networks %v, want only backend", db, s.Networks.names)
		}
	}
	// A Valkey server is on the internal network of its own zone and on no other (round 16, admin-r16-6).
	for _, zone := range []string{"api", "admin"} {
		s := c.Services["valkey-"+zone]
		if len(s.Networks.names) != 1 || s.Networks.names[0] != "vk_"+zone {
			t.Errorf("valkey-%s is on networks %v, want only vk_%s", zone, s.Networks.names, zone)
		}
	}
	if !c.Networks["backend"].Internal {
		t.Error("the backend network must be internal: no route in or out")
	}
}

// containerPort is the container side of a compose ports entry, with the host side (an address, a
// port, or an interpolation such as ${X:-80}) and a /tcp suffix removed. The container side is
// what the service listens on and what the rule is about.
func containerPort(entry string) string {
	i := strings.LastIndex(entry, ":")
	return strings.TrimSuffix(entry[i+1:], "/tcp")
}

// Passwords are Docker secrets, files under /run/secrets. What a service has as its environment is a closed
// table (TestComposeEnvironmentIsAClosedTable, composeenv_test.go), not a list of names that look like secrets,
// and every host variable the file expands is on a list too: a credential that a word list did not name had a
// way in until round 17 (admin-r17-5). This test keeps the secrets themselves: declared, used, one owner.
func TestComposeSecretsAreFiles(t *testing.T) {
	c := loadCompose(t)
	for name, s := range c.Services {
		for _, sec := range s.Secrets {
			def, ok := c.Secrets[sec]
			if !ok {
				t.Errorf("%s uses secret %s that is not defined", name, sec)
			} else if !strings.Contains(def.File, "/"+sec) {
				t.Errorf("secret %s reads %s", sec, def.File)
			}
		}
	}
	// Every defined secret is used by someone.
	used := map[string]bool{}
	for _, s := range c.Services {
		for _, sec := range s.Secrets {
			used[sec] = true
		}
	}
	for sec := range c.Secrets {
		if !used[sec] {
			t.Errorf("secret %s is defined and unused", sec)
		}
	}
	// Each database role has its own secret, used by its own service only.
	// The rekey container has its own role, ctrlz_keytool (db-r4-3), so a
	// leaked worker password cannot reach the second factor.
	owner := map[string][]string{
		"pg_tenant_password": {"api"}, "pg_admin_password": {"admin"}, "pg_hub_password": {"hub"},
		"pg_worker_password": {"worker"}, "pg_keytool_password": {"rekey"}, "pg_compiler_password": {"worker"}, "pg_migrator_password": {"migrate"},
		// The five ClickHouse users, one secret and one holder each (P5 3.4); clickhouse, which writes their
		// hashes, holds all five and is excused below like postgres. spool_key_prev is the hub's alone.
		"clickhouse_migrator_password": {"migrate-analytics"}, "clickhouse_ingest_password": {"hub"}, "clickhouse_api_password": {"api"},
		"clickhouse_preview_password": {"worker"}, "clickhouse_janitor_password": {"worker"}, "spool_key_prev": {"hub"},
	}
	for sec, holders := range owner {
		// The database that makes the role from the secret holds it too: postgres for pg_*, clickhouse for
		// clickhouse_* (its wrapper writes the hash of each).
		creator := ""
		switch {
		case strings.HasPrefix(sec, "pg_"):
			creator = "postgres"
		case strings.HasPrefix(sec, "clickhouse_"):
			creator = "clickhouse"
		}
		for name, s := range c.Services {
			has := contains(s.Secrets, sec)
			holder := contains(holders, name)
			switch {
			case holder && !has:
				t.Errorf("%s lacks its secret %s", name, sec)
			case creator != "" && name == creator && !has:
				t.Errorf("%s needs %s to create the role", name, sec)
			case !holder && name != creator && has:
				t.Errorf("%s holds %s, which belongs to %v", name, sec, holders)
			}
		}
	}
}

func TestComposeContainersAreLimitedAndRotated(t *testing.T) {
	c := loadCompose(t)
	// The official Postgres and ClickHouse images start as root to fix
	// ownership of their data directory and then drop to their own user, so
	// they cannot run with every capability dropped or a read-only root.
	needsRoot := map[string]bool{"postgres": true, "clickhouse": true}
	for name, s := range c.Services {
		if s.Logging.Driver != "json-file" || s.Logging.Options["max-size"] == "" || s.Logging.Options["max-file"] == "" {
			t.Errorf("%s has no log rotation: %+v", name, s.Logging)
		}
		if s.MemLimit == "" {
			t.Errorf("%s has no memory limit", name)
		}
		if !contains(s.SecurityOpt, "no-new-privileges:true") {
			t.Errorf("%s may gain privileges", name)
		}
		if !needsRoot[name] {
			if !contains(s.CapDrop, "ALL") {
				t.Errorf("%s keeps capabilities", name)
			}
			if !s.ReadOnly {
				t.Errorf("%s has a writable root filesystem", name)
			}
		}
	}
}

// Every container runs as a user that is not root, except the two official
// database images, which start as root only to fix the ownership of their data
// directory and then drop (review round 1, admin-r1-20), and caddy-init, a
// one-shot that does one chown for caddy's volumes and exits. The Go images set
// their user in the Dockerfile, which is checked below. Caddy and Valkey have to
// say it here, because their images run as root unless told otherwise.
func TestComposeContainersRunAsNonRoot(t *testing.T) {
	c := loadCompose(t)
	dropsItself := map[string]bool{"postgres": true, "clickhouse": true}
	for name, s := range c.Services {
		switch {
		case dropsItself[name]:
			continue
		case name == "caddy-init":
			if s.User != "0:0" || len(s.CapAdd) != 1 || s.CapAdd[0] != "CHOWN" || s.NetworkMode != "none" || len(s.Ports) != 0 {
				t.Errorf("caddy-init is the one root container and must stay a CHOWN-only one-shot with no network: %+v", s)
			}
		case strings.Contains(s.Image, "CTRLZ_IMAGE"):
			if s.User != "" {
				t.Errorf("%s overrides the user of the Go image", name)
			}
		default:
			uid, _, _ := strings.Cut(s.User, ":")
			if n, err := strconv.Atoi(uid); err != nil || n == 0 {
				t.Errorf("%s runs as %q; a container must set a user that is not root", name, s.User)
			}
		}
	}
	// Caddy holds one capability and no other: its binary carries the file
	// capability cap_net_bind_service, so with none in the bounding set the
	// container cannot start it at all (checked on caddy:2.10).
	caddy := c.Services["caddy"]
	if len(caddy.CapAdd) != 1 || caddy.CapAdd[0] != "NET_BIND_SERVICE" {
		t.Errorf("caddy adds capabilities %v, want NET_BIND_SERVICE only", caddy.CapAdd)
	}
	df, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "docker", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	if got := lastUser(df); got != "65532:65532" {
		t.Errorf("the Go image ends as USER %q, want 65532:65532", got)
	}
}

// lastUser is the user the image ends as: the argument of the last USER instruction, whatever
// the line ending or the case of the keyword. It replaced a regexp with a lost backslash
// (`s*` for `\s*`) that only matched a line with no byte after the user, so a checkout with CRLF
// endings failed a correct file, and one that said USER root after the right line passed
// (round 5, admin-r5-7).
func lastUser(df []byte) string {
	user := ""
	for _, ln := range strings.Split(string(df), "\n") {
		f := strings.Fields(ln)
		if len(f) == 2 && strings.EqualFold(f[0], "USER") {
			user = f[1]
		}
	}
	return user
}

func TestLastUserReadsTheUserTheImageEndsAs(t *testing.T) {
	for name, c := range map[string]struct{ file, want string }{
		"plain":                {"FROM a\nUSER 65532:65532\n", "65532:65532"},
		"crlf":                 {"FROM a\r\nUSER 65532:65532\r\nCMD x\r\n", "65532:65532"},
		"trailing space":       {"FROM a\nUSER 65532:65532  \n", "65532:65532"},
		"no final newline":     {"FROM a\nUSER 65532:65532", "65532:65532"},
		"lower case keyword":   {"from a\nuser 65532:65532\n", "65532:65532"},
		"root":                 {"FROM a\nUSER root\n", "root"},
		"zero":                 {"FROM a\nUSER 0\n", "0"},
		"root after the user":  {"FROM a\nUSER 65532:65532\nUSER root\n", "root"},
		"another uid":          {"FROM a\nUSER 1000:1000\n", "1000:1000"},
		"no user":              {"FROM a\n", ""},
		"a comment is no user": {"FROM a\n# USER 65532:65532\n", ""},
	} {
		if got := lastUser([]byte(c.file)); got != c.want {
			t.Errorf("%s: lastUser = %q, want %q", name, got, c.want)
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// readEnv parses KEY=VALUE lines.
func readEnv(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			t.Fatalf("%s: bad line %q", path, ln)
		}
		out[k] = v
	}
	return out
}

func mib(t *testing.T, s string) int {
	t.Helper()
	m := regexp.MustCompile(`^([0-9]+)([mg])$`).FindStringSubmatch(s)
	if m == nil {
		t.Fatalf("bad memory size %q", s)
	}
	n, _ := strconv.Atoi(m[1])
	if m[2] == "g" {
		n *= 1024
	}
	return n
}

// TestComposeProfiles: the two profiles define the same keys, the small one
// fits the plan's 8 GB floor with room for the kernel and page cache, and the
// standard one is larger in every memory limit.
func TestComposeProfiles(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "deploy", "compose", "profiles")
	small, std := readEnv(t, filepath.Join(dir, "small.env")), readEnv(t, filepath.Join(dir, "standard.env"))
	for k := range std {
		if _, ok := small[k]; !ok {
			t.Errorf("small.env lacks %s", k)
		}
	}
	for k := range small {
		if _, ok := std[k]; !ok {
			t.Errorf("standard.env lacks %s", k)
		}
	}
	// A profile variable is taken by every service that names it in its mem_limit, so the total counts it once
	// for each of them (admin-r16-25: MEM_VALKEY was counted once while two Valkey servers take it, and the
	// sum was 128 or 256 MiB short). The multiplier is read from the Compose file, not typed here, so a service
	// added tomorrow that takes a variable is counted by itself; a MEM_ variable no service takes is a stale
	// line of the profile and fails.
	takers := map[string]int{}
	for _, svc := range loadCompose(t).Services {
		if m := regexp.MustCompile(`\$\{(MEM_[A-Z0-9_]+):-`).FindStringSubmatch(svc.MemLimit); m != nil {
			takers[m[1]]++
		}
	}
	for k := range small {
		if strings.HasPrefix(k, "MEM_") && takers[k] == 0 {
			t.Errorf("%s is in the profile and no service takes it in its mem_limit", k)
		}
	}
	total := func(env map[string]string) int { return memTotal(t, env, takers) }
	if s := total(small); s > 6*1024 {
		t.Errorf("the small profile limits add up to %d MiB; an 8 GB host needs them under 6 GiB", s)
	}
	for k, v := range small {
		if strings.HasPrefix(k, "MEM_") && mib(t, std[k]) <= mib(t, v) {
			t.Errorf("%s: standard (%s) is not larger than small (%s)", k, std[k], v)
		}
	}
	// Everything a role's processes can hold at once must fit inside its connection limit:
	// the one pool (a request holds one connection at a time and a store has no second pool,
	// rule one-connection-per-request) and the one-connection command-line tools that run
	// beside the service (ctrlz-admin: 1; the worker's rekey: 1). A flood must not leave
	// the recovery CLI without a connection (db-r2-6).
	for _, env := range []map[string]string{small, std} {
		for pool, c := range map[string]struct {
			limit    string
			headroom int
		}{
			"CTRLZ_API_DB_MAX_CONNS":    {"CTRLZ_PG_CONN_TENANT", 0},
			"CTRLZ_ADMIN_DB_MAX_CONNS":  {"CTRLZ_PG_CONN_ADMIN", 1},
			"CTRLZ_WORKER_DB_MAX_CONNS": {"CTRLZ_PG_CONN_WORKER", 1},
			"CTRLZ_HUB_DB_MAX_CONNS":    {"CTRLZ_PG_CONN_HUB", 0},
		} {
			p, _ := strconv.Atoi(env[pool])
			l, _ := strconv.Atoi(env[c.limit])
			if need := p + c.headroom; p == 0 || l == 0 || need > l {
				t.Errorf("%s=%d needs %d connections (pool, CLI) but %s=%d", pool, p, need, c.limit, l)
			}
		}
		conns := 0
		for k, v := range env {
			if strings.HasPrefix(k, "CTRLZ_PG_CONN_") {
				n, _ := strconv.Atoi(v)
				conns += n
			}
		}
		if max, _ := strconv.Atoi(env["PG_MAX_CONNECTIONS"]); conns > max {
			t.Errorf("the per-role limits add up to %d, above max_connections %d", conns, max)
		}
	}
}

// TestProofKeyIsMountedIntoTheHubOnly: proof_key derives the TXT code of a UDP
// proof (contract 3.5). Whoever has it can compute the code that went to
// somebody else's address, so it lives with the hub and the nodes and nowhere
// else: not in Postgres, and not in api, admin, worker, migrate or the database
// containers (review NEW-1).
func TestProofKeyIsMountedIntoTheHubOnly(t *testing.T) {
	c := loadCompose(t)
	hub, ok := c.Services["hub"]
	if !ok {
		t.Fatal("no hub service")
	}
	if !contains(hub.Secrets, "proof_key") {
		t.Error("the hub does not mount proof_key")
	}
	if got := hub.Environment["CTRLZ_PROOF_KEY_FILE"]; got != "/run/secrets/proof_key" {
		t.Errorf("the hub reads the key from %q", got)
	}
	for name, s := range c.Services {
		if name == "hub" {
			continue
		}
		if contains(s.Secrets, "proof_key") {
			t.Errorf("%s mounts proof_key", name)
		}
		for k, v := range s.Environment {
			if strings.Contains(strings.ToLower(k+v), "proof_key") {
				t.Errorf("%s names the proof key in its environment: %s", name, k)
			}
		}
	}
	if def, ok := c.Secrets["proof_key"]; !ok || !strings.HasSuffix(def.File, "/proof_key") {
		t.Errorf("the secret definition: %+v", def)
	}
	gen, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "gen-secrets.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gen), "proof_key") {
		t.Error("scripts/gen-secrets.sh does not create proof_key")
	}

	// Not in the database: no migration statement and no bootstrap file names it
	// (comments may explain why).
	root := repoRoot(t)
	var files []string
	for _, pattern := range []string{"migrations/postgres/*.sql", "migrations/postgres/bootstrap/*.sql", "deploy/compose/postgres/initdb/*"} {
		m, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(pattern)))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) < 10 {
		t.Fatalf("found only %d database files; the glob is wrong", len(files))
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, ln := range strings.Split(string(b), "\n") {
			code := ln
			if j := strings.Index(code, "--"); j >= 0 {
				code = code[:j]
			}
			if strings.Contains(strings.ToLower(code), "proof_key") {
				t.Errorf("%s:%d names proof_key in code", f, i+1)
			}
		}
	}
}

// allowedSecretLines are the only lines of a compose command, entrypoint or
// healthcheck that may mention a Docker secret. A secret read out of a file can
// become part of a process's arguments, or of the environment of a process that
// keeps running, and both are readable by other users of the host
// (/proc/<pid>/cmdline and environ), which the compose header says no password
// is. There are too many spellings of that mistake to list (a variable
// assigned and used later, a pipe, "$(< file)", backticks, a quoted path, export
// in another statement), so the rule is the other way round: a line that
// mentions a secret must be one of these, character for character, and
// anything else is a problem. What counts as a mention is mentionsSecret, and
// that is the limit of this lint: a line that names no secret path, expands no
// variable called *_FILE or *PASSWORD*, and has no glob in a path word that a
// reader in globReader opens is not examined. So a path assembled from pieces
// at run time gets past it, and so does a glob read by a tool that is not on
// the list of globReader, and a variable named without its dollar sign
// ("printenv NAME"). The list is what keeps `find ... -name '/x/*.log'` clean;
// extend it when a tool that opens its file argument turns up. The lint also
// fails closed on lines that merely look like a glob path: a sed or awk
// expression such as 's/[[:space:]]*$//' or '/foo*/ {print}', and an XML line
// such as <path>/var/lib/x/*</path> in a heredoc. The remedy for such a line
// is to put it on this list with the reason it is safe, as for any other line.
// Every line here is one that the compose file really uses; add a line only
// together with the reason it is safe:
//
//   - the ClickHouse lines read the file into a pipe or a test, never into a
//     variable, an argument or an environment;
//   - printf is a shell builtin, so no process is started that /proc could show;
//   - the Valkey start file (deploy/compose/valkey/start.sh, judged by the same list below) reads its own
//     zone's secret inside the argument of a printf, a shell builtin that starts no process whose arguments
//     /proc could show, and in the shape test of the secret (admin-r17-7). It keeps the secret in no variable (admin-r16-21): a
//     variable is a second place the lint cannot follow, so no line on this list may bind the raw secret to
//     one (TestAllowedSecretLinesBindNoRawSecretToAVariable); the file the printf writes is a private file in
//     a tmpfs.
var allowedSecretLines = []string{
	`if [ -z "$(tr -d '\r\n' < /run/secrets/clickhouse_migrator_password)" ]; then`,
	`if [ -z "$(tr -d '\r\n' < /run/secrets/clickhouse_ingest_password)" ]; then`,
	`if [ -z "$(tr -d '\r\n' < /run/secrets/clickhouse_api_password)" ]; then`,
	`if [ -z "$(tr -d '\r\n' < /run/secrets/clickhouse_preview_password)" ]; then`,
	`if [ -z "$(tr -d '\r\n' < /run/secrets/clickhouse_janitor_password)" ]; then`,
	`hash_migrator=$(tr -d '\r\n' < /run/secrets/clickhouse_migrator_password | sha256sum | cut -d' ' -f1)`,
	`hash_ingest=$(tr -d '\r\n' < /run/secrets/clickhouse_ingest_password | sha256sum | cut -d' ' -f1)`,
	`hash_api=$(tr -d '\r\n' < /run/secrets/clickhouse_api_password | sha256sum | cut -d' ' -f1)`,
	`hash_preview=$(tr -d '\r\n' < /run/secrets/clickhouse_preview_password | sha256sum | cut -d' ' -f1)`,
	`hash_janitor=$(tr -d '\r\n' < /run/secrets/clickhouse_janitor_password | sha256sum | cut -d' ' -f1)`,
	`if [ "$(grep -c '' "/run/secrets/valkey_password_$zone")" != 1 ] || ! grep -Eqx "[A-Za-z0-9]{32,}$cr?" "/run/secrets/valkey_password_$zone"; then`,
}

// allowedSecretShapes are the lines that read a secret in a shape and not character for character: the ACL
// line of one zone's user, whose text (the commands) is judged by valkeyACLProblems and not here. The
// secret is the argument of a printf and nothing else on the line holds it.
var allowedSecretShapes = []*regexp.Regexp{
	regexp.MustCompile(`^(api|admin)\) printf 'user (api|admin) on >%s [^']*' "\$\(tr -d '\\r\\n' < "/run/secrets/valkey_password_\$zone"\)" ;;$`),
}

// secretLineAllowed says whether a line that mentions a secret is one the file may have.
func secretLineAllowed(ln string) bool {
	if contains(allowedSecretLines, ln) {
		return true
	}
	for _, re := range allowedSecretShapes {
		if re.MatchString(ln) {
			return true
		}
	}
	return false
}

// secretMention finds a line that has anything to do with the secret store. It
// is wider than the path on purpose: "cd /run; cat secrets/x" names no path
// that contains "/run/secrets", and it is still a read. The compose file also
// puts secret paths into the environment (POSTGRES_PASSWORD_FILE and the like),
// so a line that expands a variable called *_FILE or containing PASSWORD reads
// a secret without naming its path.
var secretMention = regexp.MustCompile(`(?i)secrets|/run\b|\$\{?[a-z0-9_]*(password[a-z0-9_]*|_file)\b`)

// globPath finds a path word with a glob character in it, which can name a
// secret without spelling "secrets" ("/r*/s*/valkey_password"). It counts as a
// mention only on a line that reads a file (globReader), so a pattern given to a
// tool that does not open the match is not caught.
var globPath = regexp.MustCompile(`[^\s"']*/[^\s"']*[*?\[]`)

// globReader finds a line that opens a file: a redirection, a command
// substitution, backticks, or a tool from the list. Only the tools listed
// count; xargs -a, rev, cp, nl and tee are there because each of them opens a
// file argument and hands the content on, which is how a password reaches an
// argument. dd is not: it does not expand a glob in "if=".
var globReader = regexp.MustCompile("<|\\$\\(|`|\\b(cat|tac|head|tail|more|less|cut|tr|sed|awk|grep|od|xxd|base64|paste|read|source|sort|xargs|rev|cp|nl|tee)\\b")

// urlVar is a variable in a URL, with an optional plain default: ${PORT}, ${PORT:-8080}.
const urlVar = `\$\{[a-z_][a-z0-9_]*(?::-[\w.-]*)?\}`

// plainURL is the one shape of URL the secret lint skips: http or https, a host,
// an optional port, and an optional path and query in characters a shell does
// nothing with, with a variable allowed as the host or the port. A URL is skipped
// at all because the "?" of a query string reads as a glob. This is an allow list
// on purpose. Listing what a URL must not hold cannot end, because a shell has too
// many ways to split a word: a brace expansion, a command substitution, a quote.
// What the pattern does not take stays in the line and is examined, so a shape
// nobody thought of fails closed, and its remedy is a line on the list. The scheme
// is on the list too: file: opens a local file, and a shell can build that word
// out of pieces, so a pattern for any scheme would take the last piece as a scheme.
var plainURL = regexp.MustCompile("(?i)\\bhttps?://(?:" + urlVar + "|[\\w.-]+)(?::(?:" + urlVar + "|\\d+))?(?:/[\\w.~%/=?*+@-]*)?")

// withoutURLs blanks every plain URL of the line. A URL that names IFS stays: an
// unquoted ${IFS} splits the word, so what follows it is a path the shell globs,
// and in the host or the port it has the shape of an ordinary variable.
func withoutURLs(ln string) string {
	return plainURL.ReplaceAllStringFunc(ln, func(u string) string {
		if strings.Contains(u, "IFS") {
			return u
		}
		return " "
	})
}

func mentionsSecret(ln string) bool {
	return secretMention.MatchString(ln) || (globPath.MatchString(withoutURLs(ln)) && globReader.MatchString(ln))
}

// secretLines returns the lines of a compose script that mention a secret, with
// the compose escape for a dollar undone, backslash-newline joins applied (the
// shell reads "/run/sec\<newline>rets/x" as one word) and blanks trimmed.
func secretLines(script string) []string {
	s := strings.ReplaceAll(script, "$$", "$")
	s = strings.ReplaceAll(s, "\\\n", "")
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if mentionsSecret(ln) {
			out = append(out, ln)
		}
	}
	return out
}

// secretUseProblems reports every line of the script that mentions a secret
// and is not one of allowedSecretLines.
func secretUseProblems(script string) []string {
	var out []string
	for _, ln := range secretLines(script) {
		if !secretLineAllowed(ln) {
			out = append(out, "a line that reads a secret in a shape that is not on the list: "+ln)
		}
	}
	return out
}

func TestSecretUseProblems(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		bad          bool
	}{
		{"valkey-cli -a", `valkey-cli --no-auth-warning -a "$$(cat /run/secrets/valkey_password)" ping | grep -q PONG`, true},
		{"flag inside quotes", `mycli --password "$(cat /run/secrets/x)"`, true},
		{"exec with the secret in its environment", `CLICKHOUSE_PASSWORD="$$(cat /run/secrets/clickhouse_password)" exec /entrypoint.sh`, true},
		{"export", `export PW="$(cat /run/secrets/x)"; exec server`, true},
		{"the former env prefix of the Valkey healthcheck, no longer on the list", `REDISCLI_AUTH="$$(tr -d '\r\n' < /run/secrets/valkey_password)" valkey-cli --no-auth-warning ping | grep -q PONG`, true},
		{"the former Valkey healthcheck, which keeps a CR", `REDISCLI_AUTH="$$(cat /run/secrets/valkey_password)" valkey-cli --no-auth-warning ping | grep -q PONG`, true},
		{"the former requirepass line, no longer on the list", "umask 077\nprintf 'requirepass %s\n' \"$$(cat /run/secrets/valkey_password)\" > /tmp/auth.conf", true},
		{"builtin printf of one ACL user", "umask 077\n{\n" + `api) printf 'user api on >%s ~ctrlz:rl:api:* -@all +ping\n' "$(tr -d '\r\n' < "/run/secrets/valkey_password_$zone")" ;;` + "\n} > /tmp/users.acl", false},
		{"the shape test of the Valkey start file", `if [ "$(grep -c '' "/run/secrets/valkey_password_$zone")" != 1 ] || ! grep -Eqx "[A-Za-z0-9]{32,}$cr?" "/run/secrets/valkey_password_$zone"; then`, false},
		// admin-r16-21: the secret held in a variable made every later use of the variable invisible.
		{"the secret in a shell variable", `svc_pw=$(tr -d '\r\n' < "/run/secrets/valkey_password_$zone")`, true},
		{"a printf arm that also writes the secret elsewhere", `api) printf 'user api on >%s ~x\n' "$(tr -d '\r\n' < "/run/secrets/valkey_password_$zone")" > /tmp/leak ;;`, true},
		{"a printf arm that gives the secret to a command", `api) valkey-cli -a "$(tr -d '\r\n' < "/run/secrets/valkey_password_$zone")" ping ;;`, true},
		{"a printf arm of a user that is no zone", `x) printf 'user x on >%s ~x\n' "$(tr -d '\r\n' < "/run/secrets/valkey_password_$zone")" ;;`, true},
		{"hash in a subshell", `hash_api=$$(tr -d '\r\n' < /run/secrets/clickhouse_api_password | sha256sum | cut -d' ' -f1)`, false},
		{"empty check without a variable", `if [ -z "$$(tr -d '\r\n' < /run/secrets/clickhouse_api_password)" ]; then`, false},
		{"no secret", `pg_isready -h 127.0.0.1`, false},

		// The spellings the second review found that the first lint let through.
		{"assigned, then an argument", "pw=$(cat /run/secrets/valkey_password); valkey-cli -a \"$pw\" ping", true},
		{"assigned on its own line, then an argument", "pw=$(cat /run/secrets/valkey_password)\nvalkey-cli -a \"$pw\" ping", true},
		{"pipe after cat inside an argument", `valkey-cli -a "$(cat /run/secrets/x | tr -d '\n')" ping`, true},
		{"input redirection", `valkey-cli -a "$(< /run/secrets/x)" ping`, true},
		{"backticks", "valkey-cli -a \"`cat /run/secrets/x`\" ping", true},
		{"quoted path", `valkey-cli -a "$(cat "/run/secrets/x")" ping`, true},
		{"prefix without exec", `CLICKHOUSE_PASSWORD="$(cat /run/secrets/clickhouse_password)" /entrypoint.sh`, true},
		{"export in a statement of its own", "X=\"$(cat /run/secrets/x)\"; export X; exec server", true},
		{"export on one line, exec on the next", "export PW=\"$(cat /run/secrets/x)\"\nexec server", true},
		{"exec with the secret in its environment, escaped", `CLICKHOUSE_PASSWORD="$$(cat /run/secrets/clickhouse_password)" exec /entrypoint.sh`, true},

		// Ways to hide the path, and a line that is only close to a listed one.
		{"path split by a line continuation", "valkey-cli -a \"$(cat /ru\\\nn/sec\\\nrets/x)\" ping", true},
		{"changing directory first", "cd /run\nvalkey-cli -a \"$(cat secrets/x)\" ping", true},
		{"a listed line with something after it", `hash_api=$$(tr -d '\r\n' < /run/secrets/clickhouse_api_password | sha256sum | cut -d' ' -f1); echo $$hash_api`, true},
		{"a listed line with another secret", `hash=$$(tr -d '\r\n' < /run/secrets/valkey_password | sha256sum | cut -d' ' -f1)`, true},
		{"the previous ClickHouse hash line", `hash=$$(printf %s "$$(cat /run/secrets/clickhouse_password)" | sha256sum | cut -d' ' -f1)`, true},

		// A secret reached through a variable that holds its path, or a glob.
		{"path in a _FILE variable", `valkey-cli -a "$$(cat $POSTGRES_PASSWORD_FILE)" ping`, true},
		{"path in a braced and quoted variable", `psql "postgres://u:$$(cat "${CTRLZ_DB_PASSWORD_FILE}")@db/x"`, true},
		{"glob in the path", `valkey-cli -a "$$(cat /r*/s*/valkey_password)" ping`, true},
		// A glob with a redirection and no "/run" in it, so that it reaches the glob
		// branch instead of being caught as a mention of the secret store.
		{"glob with a redirection", `valkey-cli -a "$$(< /r?n/s*/x)" ping`, true},
		{"a glob pattern given to a tool that reads no file", `find /var/log -name '/x/*.log'`, false},
		{"an unrelated variable", `exec valkey-server --maxmemory ${VALKEY_MAXMEMORY:-128mb}`, false},

		// Each branch of the three expressions has a row of its own that no other
		// branch catches, so a branch dropped from one of them fails here.
		{"a PASSWORD variable that is no _FILE", `valkey-cli -a "$PGPASSWORD" ping`, true},
		{"a _FILE variable that is no PASSWORD", `valkey-cli -a "$(cat $TOKEN_FILE)" ping`, true},
		{"a secret key path variable", `cat "$CTRLZ_PROOF_KEY_FILE"`, true},
		{"PASSWORD at the start of a name", `valkey-cli -a "$PASSWORD_X" ping`, true},
		{"a glob with only a question mark", `x=$(cat /r?n/s?crets/v)`, true},
		{"a glob with only a bracket", `x=$(cat /r[u]n/s[e]crets/v)`, true},
		{"a glob read by a redirection only", `valkey-cli < /r*/s*/v`, true},
		{"a glob read by a command substitution only", `echo "$(mycli /r*/s*/v)"`, true},
		{"a glob read by backticks only", "x=`mycli /r*/s*/v`", true},
		{"a glob read by a reader word only", `head -c9 /r*/s*/v`, true},
		{"a glob read by cat into a pipe", `cat /r*/s*/x | valkey-cli -x auth`, true},
		{"a glob read by a redirection into tr", `tr -d x < /r*/s*/x`, true},
		{"a relative glob without a leading slash", `cat r*/s*/x`, true},
		{"a relative glob with a dot", `cat ./r*/s*/x`, true},

		// Readers that are not in the first list: xargs -a opens the file and puts its
		// content into the arguments of the next command.
		{"xargs -a on a glob", `xargs -a /r*/s*/valkey_password valkey-cli --no-auth-warning -a`, true},
		{"rev on a glob", `rev /r*/s*/valkey_password | rev`, true},
		{"cp of a glob", `cp /r*/s*/valkey_password /tmp/p`, true},
		{"nl on a glob", `nl /r*/s*/x`, true},
		{"tee with a glob", `tee /tmp/p /r*/s*/x`, true},
		{"rev, then xargs", `rev /r*/s*/valkey_password | rev | xargs -I{} valkey-cli -a {} ping`, true},

		// A URL is no path word, so a query string or a glob character in one is not
		// a glob. A file: URL opens a local file and stays one.
		{"a URL with a query, read by grep", `wget -qO- 'http://127.0.0.1:8123/replicas_status?verbose=1' | grep -q Ok`, false},
		{"an unquoted URL with a query", `wget -qO- http://127.0.0.1:8123/ping?x=1 | grep -q Ok`, false},
		{"a URL with a star", `wget -qO- "http://127.0.0.1:8123/a*b" | grep -q Ok`, false},
		{"a file URL with a glob", `valkey-cli -a "$(curl file:///r*/s*/x)" ping`, true},
		{"a glob straight after a URL and a semicolon", `wget -qO- http://127.0.0.1:8123/ping?x=1;tr</r*/s*/x`, true},
		{"a glob after a URL on the same line", `wget -qO- http://127.0.0.1:8123/ping?x=1 | cat /r*/s*/x`, true},
		// A backtick substitution that follows a URL with no space is a command the
		// shell runs, so the URL ends at the backtick. ${IFS} and brace expansion
		// write a command without a space.
		{"a brace expansion in backticks after a URL", "curl http://h/`{cat,/r*/s*/x}`", true},
		{"IFS in backticks after a URL", "curl http://h/`cat${IFS}/r*/s*/x`", true},
		{"backticks with a space after a URL", "curl http://h/`cat /r*/s*/x`", true},
		// An unquoted IFS splits the word in two, so what follows it is a separate
		// argument that the shell globs. A variable such as ${PORT} in a URL is fine.
		{"IFS in braces splits a URL", `valkey-cli -a "$(cat http://h${IFS}/r*/s*/x)" ping`, true},
		{"IFS without braces splits a URL", `valkey-cli -a "$(cat http://h$IFS/r*/s*/x)" ping`, true},
		{"a variable port in a URL", `wget -qO- http://127.0.0.1:${PORT}/ping?x=1 | grep -q ok`, false},
		// A brace expansion around the scheme makes the "URL" one alternative of a
		// word: {a://,}/r*/s*/x is a://… and /r*/s*/x, and the shell globs the second.
		{"a brace expansion opens right before a URL", `cat {a://,}/r*/s*/x`, true},
		{"a URL is the last alternative of a brace expansion", `cat {b,a://}/r*/s*/x`, true},
		{"a URL follows an empty alternative", `cat {,a://}/r*/s*/x`, true},
		{"a quote before the closing brace of an expansion", `cat {a://,/r*/s*/x''}`, true},
		{"a substitution before the closing brace of an expansion", `cat {a://,/r*/s*/x$(:)}`, true},
		{"a host in the URL alternative of an expansion", `cat {a://h,/r*/s*/x}`, true},
		{"IFS in the port of a URL", `cat http://h:${IFS}/r*/s*/x`, true},

		// Only http and https are skipped, so a scheme the shell builds out of pieces
		// is not read as a shorter scheme.
		{"a file URL with a host", `valkey-cli -a "$(curl file://localhost/r*/s*/x)" ping`, true},
		{"a scheme split by quotes", `valkey-cli -a "$(curl f''ile://localhost/ru[m-o]/s\ecrets/x)" ping`, true},
		{"a scheme split by a brace expansion", `valkey-cli -a "$(curl {f,}ile://localhost/ru[m-o]/s\ecrets/x)" ping`, true},

		// Each operator ends a URL by itself: no other stop character stands in the row.
		{"a redirection in right after a URL", `cat http://h/x</r*/s*/x`, true},
		{"a redirection out right after a URL", `cat http://h/x>/r*/s*/x`, true},
		{"a pipe right after a URL", `cat http://h/x|/r*/s*/x`, true},
		{"an ampersand right after a URL", `cat http://h/x&/r*/s*/x`, true},
		{"a semicolon right after a URL", `cat http://h/x;/r*/s*/x`, true},
		{"a parenthesis right after a URL", `cat http://h/x(/r*/s*/x`, true},
		{"a comma inside a brace expansion after a URL", `cat {http://h/x,/r*/s*/x}`, true},

		// Only a plain URL is skipped, and a variable is plain as the host or the port.
		{"a default in the port of a URL", `wget -qO- http://127.0.0.1:${PORT:-8080}/ping?x=1 | grep -q ok`, false},
		{"variables as the host and the port", `wget -qO- http://${HOST}:${PORT}/ping?x=1 | grep -q ok`, false},
		{"a URL as the default of a variable", `wget -qO- ${URL:-http://h/ping?x=1} | grep -q ok`, false},
		// Anything else in a URL fails closed: the line needs its place on the list.
		{"a nested variable in a URL fails closed", `wget -qO- http://127.0.0.1:${PORT:-${P2}}/ping?x=1 | grep -q ok`, true},
		{"a brace expansion in a URL path fails closed", `curl -s http://h/{a,b}/ping?x=1 | grep -q ok`, true},
	} {
		got := secretUseProblems(tc.script)
		if (len(got) > 0) != tc.bad {
			t.Errorf("%s: problems %q, want a problem: %v", tc.name, got, tc.bad)
		}
	}
}

// TestComposeSecretsStayOutOfArgumentsAndEnvironments applies the rule to every
// command, entrypoint and healthcheck in the compose file (review C13).
func TestComposeSecretsStayOutOfArgumentsAndEnvironments(t *testing.T) {
	c := loadCompose(t)
	seen := map[string]bool{}
	for name, s := range c.Services {
		for kind, words := range map[string][]string{"command": s.Command, "entrypoint": s.Entrypoint, "healthcheck": s.Healthcheck.Test} {
			for _, w := range words {
				for _, ln := range secretLines(w) {
					seen[ln] = true
				}
				for _, problem := range secretUseProblems(w) {
					t.Errorf("%s %s: %s", name, kind, problem)
				}
			}
		}
	}
	// The Valkey start file is a script the Compose file mounts and runs, and the one place the two zones'
	// secrets are read, so the same list judges it (comments are not code).
	start, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "compose", "valkey", "start.sh"))
	if err != nil {
		t.Fatal(err)
	}
	var code []string
	for _, ln := range strings.Split(string(start), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(ln), "#") {
			code = append(code, ln)
		}
	}
	for _, ln := range secretLines(strings.Join(code, "\n")) {
		seen[ln] = true
	}
	for _, problem := range secretUseProblems(strings.Join(code, "\n")) {
		t.Errorf("valkey/start.sh: %s", problem)
	}
	// Every listed shape is one the file really uses. A line that is listed and
	// unused is a shape someone may bring back later without the lint noticing.
	for _, want := range allowedSecretLines {
		if !seen[want] {
			t.Errorf("allowed line %q is not used by any command, entrypoint or healthcheck; remove it from the list", want)
		}
	}
	for _, re := range allowedSecretShapes {
		used := false
		for ln := range seen {
			used = used || re.MatchString(ln)
		}
		if !used {
			t.Errorf("allowed shape %v matches no line of the stack; remove it from the list", re)
		}
	}
	// The ClickHouse server must not get the password from its environment, and
	// the official entrypoint must not be left to build the user: it writes the
	// password in clear into users.d, and onto the command line of
	// clickhouse-client when CLICKHOUSE_DB asks it to create a database.
	ch := c.Services["clickhouse"]
	if ch.Environment["CLICKHOUSE_SKIP_USER_SETUP"] != "1" {
		t.Error("clickhouse: the official entrypoint creates the user itself unless CLICKHOUSE_SKIP_USER_SETUP=1")
	}
	if _, set := ch.Environment["CLICKHOUSE_DB"]; set {
		t.Error("clickhouse: CLICKHOUSE_DB makes the entrypoint run clickhouse-client with --password on its command line")
	}
	if !strings.Contains(strings.Join(ch.Entrypoint, " "), "password_sha256_hex") {
		t.Error("clickhouse: the entrypoint wrapper does not write a password_sha256_hex user")
	}
}

// TestClickHouseWrapperFailsClosed pins the shape of the entrypoint wrapper:
// with the official user setup switched off, nothing but this script keeps the
// built-in default user and an empty password out. The containers behind it are
// started by the TestClickHouseWrapper tests in deploy_test.go; this one runs
// without Docker.
func TestClickHouseWrapperFailsClosed(t *testing.T) {
	ch := loadCompose(t).Services["clickhouse"]
	if len(ch.Entrypoint) != 3 {
		t.Fatalf("entrypoint: %q", ch.Entrypoint)
	}
	script := strings.ReplaceAll(ch.Entrypoint[2], "$$", "$")
	lines := strings.Split(script, "\n")
	first := ""
	for _, ln := range lines {
		if strings.TrimSpace(ln) != "" {
			first = strings.TrimSpace(ln)
			break
		}
	}
	// -e so that a failed write or chown stops the script; -u so that a typo in
	// a variable name cannot turn into an empty hash.
	if first != "set -eu" {
		t.Errorf("the wrapper starts with %q, want set -eu", first)
	}
	at := func(prefix string) int {
		for i, ln := range lines {
			if strings.HasPrefix(strings.TrimSpace(ln), prefix) {
				return i
			}
		}
		t.Errorf("the wrapper has no line starting with %q", prefix)
		return -1
	}
	check, exit1 := at("if [ -z"), at("exit 1")
	write, chown, handOver := at("cat > /etc/clickhouse-server/users.d/"), at("chown "), at("exec /entrypoint.sh")
	if !(0 <= check && check < exit1 && exit1 < write && write < chown && chown < handOver) {
		t.Errorf("order wrong: the empty check (%d), its exit (%d), the users.d write (%d), chown (%d) and the hand-over (%d) must come in that order", check, exit1, write, chown, handOver)
	}
	if exit1 > 0 && !strings.Contains(lines[exit1-1], ">&2") {
		t.Error("the refusal does not say why on stderr")
	}
	// The two files that carry the grants, profiles, constraints and row-policy settings must be regular,
	// non-empty files before anything is written: a config user with no <grants> has every right, and Docker
	// turns a missing bind source into a directory. The checks do not start with "if [ -z", which counts the
	// five secret files below.
	for _, f := range []string{"/etc/clickhouse-server/users.d/ctrlz-users.xml", "/etc/clickhouse-server/config.d/ctrlz.xml"} {
		i := strings.Index(script, f)
		if i < 0 {
			t.Errorf("the wrapper does not check %s", f)
			continue
		}
		if j := strings.Index(script, "cat > /etc/clickhouse-server/users.d/"); j >= 0 && i > j {
			t.Errorf("the check of %s comes after the users.d write", f)
		}
	}
	if !strings.Contains(script, `[ ! -f "$f" ] || [ ! -s "$f" ]`) {
		t.Error("the wrapper does not test that the two config files are regular and non-empty")
	}
	// Five users, five files: every one is checked before the first byte is written, so a single empty
	// file stops the container with no user file at all (P5 3.4). A sixth user without a check would be a
	// user with no password.
	checks := 0
	for i, ln := range lines {
		if strings.HasPrefix(strings.TrimSpace(ln), "if [ -z") {
			checks++
			if write >= 0 && i > write {
				t.Errorf("the empty check on line %d comes after the users.d write", i)
			}
		}
	}
	if checks != 5 {
		t.Errorf("the wrapper checks %d secret files, want 5 (one for each ClickHouse user)", checks)
	}
	if got := strings.Count(script, "<password_sha256_hex>"); got != 5 {
		t.Errorf("the user file gives %d users a password hash, want 5", got)
	}
	// set -e does not apply to a command that is part of ||, && or an if, so
	// the commands that make the file must stand alone.
	for _, i := range []int{write, chown} {
		if i >= 0 && (strings.Contains(lines[i], "||") || strings.Contains(lines[i], "&&") || strings.Contains(lines[i], "; true")) {
			t.Errorf("line %q can fail without stopping the script", strings.TrimSpace(lines[i]))
		}
	}
}

// runGenSecrets runs scripts/gen-secrets.sh into dir with the given extra
// directory first on PATH, and returns its exit code.
func runGenSecrets(t *testing.T, dir, firstOnPath string, extraEnv ...string) (int, string) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		git := `C:\Program Files\Git\usr\bin\sh.exe`
		if _, statErr := os.Stat(git); statErr != nil {
			t.Skip("no sh on PATH")
		}
		sh = git
	}
	script := filepath.Join(repoRoot(t), "scripts", "gen-secrets.sh")
	cmd := exec.Command(sh, filepath.ToSlash(script), filepath.ToSlash(dir))
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, extraEnv...)
	if firstOnPath != "" {
		cmd.Env = append(cmd.Env, "PATH="+firstOnPath+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, string(out)
}

func TestGenSecretsNeverLeavesAnEmptyFile(t *testing.T) {
	t.Run("generator fails", func(t *testing.T) {
		dir := t.TempDir()
		bin, _ := stubDocker(t, true)
		if err := os.WriteFile(filepath.Join(bin, "openssl"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		code, out := runGenSecrets(t, dir, bin)
		if code == 0 {
			t.Errorf("exit code 0 although no secret could be made\n%s", out)
		}
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			t.Errorf("a file was left behind: %s", e.Name())
		}
	})
	t.Run("an existing empty file is reported", func(t *testing.T) {
		dir := t.TempDir()
		empty := filepath.Join(dir, "clickhouse_api_password")
		if err := os.WriteFile(empty, nil, 0o444); err != nil {
			t.Fatal(err)
		}
		bin, _ := stubDocker(t, true)
		code, out := runGenSecrets(t, dir, bin)
		if code == 0 {
			t.Errorf("exit code 0 with an empty secret in place\n%s", out)
		}
		if !strings.Contains(out, "clickhouse_api_password") {
			t.Errorf("the message does not name the file:\n%s", out)
		}
	})
	t.Run("a normal run", func(t *testing.T) {
		dir := t.TempDir()
		bin, log := stubDocker(t, true)
		if code, out := runGenSecrets(t, dir, bin); code != 0 {
			t.Fatalf("exit code %d\n%s", code, out)
		}
		entries, _ := os.ReadDir(dir)
		// 16 passwords (eight Postgres roles, five ClickHouse users, two Valkey servers), the proof key, the empty spool_key_prev (P5 3.4), kek_root, and 8 key files derived by
		// the (stubbed) throwaway container, and the public half of the invite signing key beside them (D67).
		if len(entries) != 28 {
			t.Errorf("%d secret files, want 28", len(entries))
		}
		for _, e := range entries {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Errorf("%s: %v", e.Name(), err)
				continue
			}
			switch {
			case e.Name() == "kek_root":
				if len(b) != 32 {
					t.Errorf("kek_root is %d bytes, want 32", len(b))
				}
			case e.Name() == "spool_key_prev":
				// Empty on purpose: no rotation is going on (P5 3.4).
				if len(b) != 0 {
					t.Errorf("spool_key_prev is %d bytes, want an empty file", len(b))
				}
			case !strings.HasPrefix(e.Name(), "kek_") && len(b) < 32:
				t.Errorf("%s: %d bytes", e.Name(), len(b))
			}
		}
		// The throwaway container is the spec 8.3 command, with nothing more:
		// no network, a read-only root, no capabilities, the host user and the
		// secrets directory as the only mount.
		args, _ := os.ReadFile(log)
		for _, want := range []string{"run --pull never --rm --network none --read-only --cap-drop ALL --user ", ":/secrets ctrlz/panel:dev keys derive"} {
			if !strings.Contains(string(args), want) {
				t.Errorf("docker was called as %q, want it to contain %q", strings.TrimSpace(string(args)), want)
			}
		}
		// A second run changes nothing: replacing a database password in a
		// file does not change it in the database, and a new root would not
		// match the key files derived from the old one.
		before, _ := os.ReadFile(filepath.Join(dir, "pg_tenant_password"))
		root1, _ := os.ReadFile(filepath.Join(dir, "kek_root"))
		_ = os.Remove(log)
		if code, out := runGenSecrets(t, dir, bin); code != 0 {
			t.Fatalf("second run: exit code %d\n%s", code, out)
		}
		after, _ := os.ReadFile(filepath.Join(dir, "pg_tenant_password"))
		root2, _ := os.ReadFile(filepath.Join(dir, "kek_root"))
		if string(before) != string(after) || string(root1) != string(root2) {
			t.Error("a second run replaced an existing secret")
		}
		if _, err := os.Stat(log); err != nil {
			t.Error("a second run did not run the derive: the key files must be proved against the root on every run, not skipped because they exist")
		}
	})
	// Review round 5, rule key-identity and admin-r5-6: whether a failed run takes its root away
	// is decided by whether the derive wrote anything (the directory grew), never by the exit
	// code and never by which kek_ files are in the directory. The matrix in internal/admincli
	// runs the real derive through this script; here the derive is a stand-in with a chosen
	// exit code and, for two rows, a file it leaves behind, to pin what the script does with each.
	for _, tc := range []struct {
		name     string
		exit     int
		leaves   string
		rootKept bool
		// soft: a refusal (exit 3) that wrote nothing is the one end that is not a failure of the run
		// (admin-r13-6): the root is not on the host, so the key files cannot be proved and the run
		// says so and goes on to the secrets that do not depend on it.
		soft bool
	}{
		{"a refused derive takes back the root made in this run and goes on to the plain secrets", 3, "", false, true},
		{"a refusal that also left a key file missing stops the run and takes the root back (admin-r14-7)", 4, "", false, false},
		{"a failure that wrote nothing takes it back too", 1, "", false, false},
		{"a docker failure takes it back", 125, "", false, false},
		{"a kill before anything was written takes it back", 137, "", false, false},
		{"a derive that failed after writing a file keeps the root, whose files are proved again next run", 1, "kek_admin_mac", true, false},
		{"so does a kill after the first file", 137, "kek_admin_mac", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := t.TempDir()
			leave := ""
			if tc.leaves != "" {
				leave = "  prev=''; dir=''\n  for a in \"$@\"; do\n    if [ \"$prev\" = '-v' ]; then dir=${a%:/secrets}; fi\n    prev=$a\n  done\n  printf x > \"$dir/" + tc.leaves + "\"\n"
			}
			script := "#!/bin/sh\ncase \"$1\" in\nimage) exit 0 ;;\nrun)\n" + leave + "  exit " + strconv.Itoa(tc.exit) + " ;;\nesac\n"
			if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			code, out := runGenSecrets(t, dir, bin)
			if tc.soft {
				if code != 0 || !strings.Contains(out, "kek_root is not on this host") {
					t.Errorf("a refusal with no root on the host stopped the run (exit %d)\n%s", code, out)
				}
				if _, err := os.Stat(filepath.Join(dir, "kek_root")); err == nil {
					t.Error("the candidate root was left behind")
				}
				if _, err := os.Stat(filepath.Join(dir, "valkey_password_api")); err != nil {
					t.Error("the plain secrets were not made after the notice")
				}
				return
			}
			if code == 0 {
				t.Errorf("exit code 0 although the derive failed\n%s", out)
			}
			_, err := os.Stat(filepath.Join(dir, "kek_root"))
			if kept := err == nil; kept != tc.rootKept {
				t.Errorf("kek_root kept = %v, want %v", kept, tc.rootKept)
			}
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				if e.Name() != "kek_root" && e.Name() != tc.leaves {
					t.Errorf("a failed derive left %s behind: secrets are made only after the key files are proved", e.Name())
				}
			}
		})
	}
	t.Run("the image is missing", func(t *testing.T) {
		dir := t.TempDir()
		bin, _ := stubDocker(t, false)
		code, out := runGenSecrets(t, dir, bin)
		if code == 0 {
			t.Errorf("exit code 0 with no image\n%s", out)
		}
		if !strings.Contains(out, "docker build -f deploy/docker/Dockerfile -t ctrlz/panel:dev .") {
			t.Errorf("the message does not name the build command:\n%s", out)
		}
	})
}

// shellPath finds a POSIX sh, or skips the test.
func shellPath(t *testing.T) string {
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

// stubDocker puts a docker on PATH that answers `image inspect` (found or not)
// and, for `run`, appends its arguments to a log and writes the key files that
// `keys derive` would. The real command is covered by the image smoke check.
func stubDocker(t *testing.T, haveImage bool) (binDir, logFile string) {
	t.Helper()
	binDir = t.TempDir()
	logFile = filepath.Join(t.TempDir(), "docker.log")
	inspect := "exit 0"
	if !haveImage {
		inspect = "exit 1"
	}
	script := "#!/bin/sh\n" +
		"case \"$1\" in\n" +
		"image) " + inspect + " ;;\n" +
		"run) echo \"$@\" >> '" + filepath.ToSlash(logFile) + "'\n" +
		"  prev=''; dir=''\n" +
		"  for a in \"$@\"; do if [ \"$prev\" = '-v' ]; then dir=${a%:/secrets}; fi; prev=$a; done\n" +
		"  for d in user_totp admin_totp sms_cred otp_delivery auth_mac admin_mac invite_sign doh_token cert_wrap; do echo '# keyring' > \"$dir/kek_$d\"; done; echo '# ctrlz public keys domain=invite_sign' > \"$dir/pub_invite_sign\" ;;\n" +
		"esac\n"
	if err := os.WriteFile(filepath.Join(binDir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return binDir, logFile
}

// TestComposeHeaderNamesTheServicesThatAreNotHardened: the header of the Compose file is the security
// posture an operator or auditor reads, and it said every container drops all capabilities and has a
// read-only root while postgres and clickhouse do neither (round 9, admin-r9-2). The services that do
// not are computed from the file, and the hardening paragraph of the header must name each of them
// and must not make the blanket claim again.
func TestComposeHeaderNamesTheServicesThatAreNotHardened(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "compose", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	header, _, ok := strings.Cut(string(b), "\nname: ctrlz")
	if !ok {
		t.Fatal("no header before `name: ctrlz`")
	}
	if strings.Contains(header, "Every container runs with all capabilities dropped") {
		t.Error("the header makes the blanket claim again that every container drops all capabilities")
	}
	start := strings.Index(header, "Every container has no-new-privileges")
	if start < 0 {
		t.Fatal("the header has no hardening paragraph that starts with \"Every container has no-new-privileges\"")
	}
	para := header[start:]
	if end := strings.Index(para, "\n#   - "); end > 0 {
		para = para[:end]
	}
	c := loadCompose(t)
	exceptions := 0
	for name, s := range c.Services {
		if contains(s.CapDrop, "ALL") && s.ReadOnly {
			continue
		}
		exceptions++
		if !strings.Contains(para, name) {
			t.Errorf("%s keeps capabilities or a writable root and the hardening paragraph of the header does not name it", name)
		}
	}
	if exceptions == 0 {
		t.Error("no service is an exception any more: the header's list of them is stale")
	}
}

// TestComposeHealthOnlyRolesListenOnLoopback (admin-r10-4): a Go role that serves nothing but the
// health mux listens on loopback, because its /readyz takes a pooled database connection for anyone
// who can reach it. The app refuses to start otherwise (internal/app
// TestAHealthOnlyRoleRefusesAnAddressOthersCanReach); this keeps the Compose file honest before a
// container is ever started. api and admin serve routes and listen on every interface of their
// networks, behind caddy, and their health mux answers loopback peers only (httpx.LoopbackOnly, admin-r11-4).
func TestComposeHealthOnlyRolesListenOnLoopback(t *testing.T) {
	c := loadCompose(t)
	seen := 0
	for name, s := range c.Services {
		if len(s.Command) != 1 || (s.Command[0] != "hub" && s.Command[0] != "worker") {
			continue
		}
		seen++
		host, _, err := net.SplitHostPort(s.Environment["CTRLZ_LISTEN"])
		if err != nil || host != "127.0.0.1" {
			t.Errorf("%s (a health-only role) listens on %q, want 127.0.0.1:PORT", name, s.Environment["CTRLZ_LISTEN"])
		}
	}
	if seen != 2 {
		t.Errorf("found %d health-only services, want hub and worker", seen)
	}
}

// TestComposeHeaderPublishBulletMatchesThePorts (admin-r11-2, admin-r11-6): the header of the Compose
// file is what an operator reads to decide what to open on the host firewall, and it kept saying the
// hub's node port is published after the port was taken out (round 10). The services that have
// `ports` are computed from the file. Each must be named in the publish bullet with its container
// ports, and a sentence of the bullet that says a service publishes must not name a service with no
// `ports` unless it says none, so a P4 edit that adds the hub's port has to change the header with it.
func TestComposeHeaderPublishBulletMatchesThePorts(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "compose", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	header, _, ok := strings.Cut(string(b), "\nname: ctrlz")
	if !ok {
		t.Fatal("no header before `name: ctrlz`")
	}
	const start = "#   - Only "
	i := strings.Index(header, start)
	if i < 0 {
		t.Fatal("the header has no publish bullet that starts with \"Only \"")
	}
	bullet := header[i+len("#   - "):]
	if end := strings.Index(bullet, "\n#   - "); end > 0 {
		bullet = bullet[:end]
	}
	bullet = strings.Join(strings.Fields(strings.ReplaceAll(bullet, "#", " ")), " ")

	c := loadCompose(t)
	published := 0
	for name, s := range c.Services {
		if len(s.Ports) == 0 {
			continue
		}
		published++
		first, _, _ := strings.Cut(bullet, ". ")
		if !regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`).MatchString(first) {
			t.Errorf("%s publishes %v and the first sentence of the header's publish bullet does not name it: %q", name, s.Ports, first)
		}
		for _, p := range s.Ports {
			if cp := containerPort(p); !strings.Contains(first, cp) {
				t.Errorf("%s publishes container port %s and the header's publish bullet does not say so: %q", name, cp, first)
			}
		}
	}
	if published == 0 {
		t.Error("no service publishes a port: the header's publish bullet is stale")
	}
	negation := regexp.MustCompile(`(?i)\b(none|no|not|never)\b`)
	for _, sentence := range strings.SplitAfter(bullet, ". ") {
		if !strings.Contains(sentence, "publish") || negation.MatchString(sentence) {
			continue
		}
		for name, s := range c.Services {
			if len(s.Ports) == 0 && regexp.MustCompile(`\b`+regexp.QuoteMeta(name)+`\b`).MatchString(sentence) {
				t.Errorf("the header's publish bullet says %s publishes, and it has no ports: %q", name, sentence)
			}
		}
	}
}

// graceProblems judges stop_grace_period against the process's shutdown budget (round 15, admin-r15-2).
// app.Run gives the HTTP server `budget` to finish its requests and then, in the api, the queue of work
// owed after an answer another `budget` to drain before the pool closes; the worker's own stop is the same
// length. Docker sends SIGKILL when the grace ends, so a grace that is not longer than the two budgets
// together kills a shutdown that is working as designed, and the rows the drain exists for vanish with no
// line. A service with no grace gets Docker's 10 s, which is the same defect.
func graceProblems(grace map[string]string, budget time.Duration) []string {
	var out []string
	names := make([]string, 0, len(grace))
	for n := range grace {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		g := grace[n]
		if g == "" {
			out = append(out, n+": no stop_grace_period, so Docker kills it after its default 10 s")
			continue
		}
		d, err := time.ParseDuration(g)
		if err != nil {
			out = append(out, n+": stop_grace_period "+g+" is not a duration")
			continue
		}
		if d <= 2*budget {
			out = append(out, n+": stop_grace_period "+g+" is not longer than server shutdown plus drain ("+(2*budget).String()+")")
		}
	}
	return out
}

// goGrace returns the stop_grace_period of every service that runs the Go image, which is the process
// whose shutdown app.Run budgets.
func goGrace(c compose) map[string]string {
	out := map[string]string{}
	for n, s := range c.Services {
		if strings.Contains(s.Image, "CTRLZ_IMAGE") {
			out[n] = s.StopGracePeriod
		}
	}
	return out
}

func TestComposeGraceCoversTheShutdownBudget(t *testing.T) {
	cfg, err := app.LoadConfig(app.RoleAPI, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ShutdownTimeout <= 0 {
		t.Fatalf("the shutdown budget is %v", cfg.ShutdownTimeout)
	}
	grace := goGrace(loadCompose(t))
	if len(grace) < 5 {
		t.Fatalf("only %d services run the Go image: the lint no longer sees them", len(grace))
	}
	if p := graceProblems(grace, cfg.ShutdownTimeout); len(p) != 0 {
		t.Fatalf("%s", strings.Join(p, "\n"))
	}
}

func TestComposeGraceCheckCanFail(t *testing.T) {
	b := 15 * time.Second
	for name, g := range map[string]map[string]string{
		"no grace":          {"api": ""},
		"Docker's default":  {"api": "10s"},
		"only one budget":   {"api": "15s"},
		"exactly two":       {"api": "30s"},
		"not a duration":    {"api": "soon"},
		"one of several":    {"api": "45s", "worker": "20s"},
		"a longer budget":   {"api": "45s"},
		"the budget grows":  {"api": "45s"},
		"an empty services": {},
	} {
		want := name != "an empty services"
		budget := b
		if name == "the budget grows" {
			budget = 30 * time.Second
		}
		if name == "a longer budget" {
			budget = 25 * time.Second
		}
		if got := len(graceProblems(g, budget)) != 0; got != want {
			t.Errorf("%s: problems=%v, want %v", name, got, want)
		}
	}
	if p := graceProblems(map[string]string{"api": "45s", "worker": "46s"}, b); len(p) != 0 {
		t.Errorf("a grace that is long enough was refused: %v", p)
	}
}

// bindsRawSecret reports a line that assigns what a secret file holds to a shell variable. A variable is a
// place the secret lint cannot follow: it finds a secret by the lines that name its path, so every later use of
// the variable is a line it does not see (round 16, admin-r16-21; the Valkey start file had done exactly that,
// with `svc_pw=$(tr ... < /run/secrets/...)` on the list). The one binding the stack makes is of a digest, the
// ClickHouse hash, which is derived and not the secret; a binding is let through only when the substitution
// ends in the digest tool.
func bindsRawSecret(ln string) bool {
	assign := regexp.MustCompile(`^(?:[a-z]+ )?[A-Za-z_][A-Za-z0-9_]*=`)
	return assign.MatchString(ln) && !strings.Contains(ln, "| sha256sum |")
}

// TestAllowedSecretLinesBindNoRawSecretToAVariable holds the list itself to the rule, so that a line added to
// it later cannot be the one that makes a secret invisible.
func TestAllowedSecretLinesBindNoRawSecretToAVariable(t *testing.T) {
	for _, ln := range allowedSecretLines {
		if bindsRawSecret(ln) {
			t.Errorf("the allowed line %q binds a secret to a variable", ln)
		}
	}
	for ln, want := range map[string]bool{
		`svc_pw=$(tr -d '\r\n' < "/run/secrets/valkey_password_$zone")`:                               true,
		`local pw=$(cat /run/secrets/x)`:                                                              true,
		`pw="$(cat /run/secrets/x)"`:                                                                  true,
		`hash_api=$(tr -d '\r\n' < /run/secrets/clickhouse_api_password | sha256sum | cut -d' ' -f1)`: false,
		`if [ -z "$(tr -d '\r\n' < /run/secrets/clickhouse_api_password)" ]; then`:                    false,
		`api) printf 'user api on >%s' "$(tr -d '\r\n' < "/run/secrets/valkey_password_$zone")" ;;`:   false,
	} {
		if bindsRawSecret(ln) != want {
			t.Errorf("bindsRawSecret(%q) = %v, want %v", ln, !want, want)
		}
	}
}

// memTotal adds the memory limits of a profile, each counted once for every service that takes the variable.
func memTotal(t *testing.T, env map[string]string, takers map[string]int) int {
	t.Helper()
	sum := 0
	for k, v := range env {
		if strings.HasPrefix(k, "MEM_") {
			sum += mib(t, v) * takers[k]
		}
	}
	return sum
}

// TestProfileTotalCountsAVariableOnceForEveryServiceThatTakesIt (admin-r16-25): the real profiles fit with room
// to spare, so the test of their total cannot tell a sum that counts a shared variable once from one that does
// not; this one can.
func TestProfileTotalCountsAVariableOnceForEveryServiceThatTakesIt(t *testing.T) {
	env := map[string]string{"MEM_A": "100m", "MEM_B": "1g", "NOT_MEM": "9g"}
	if got := memTotal(t, env, map[string]int{"MEM_A": 2, "MEM_B": 1}); got != 1224 {
		t.Errorf("total %d MiB, want 1224 (100 twice and 1024 once)", got)
	}
	if got := memTotal(t, env, map[string]int{"MEM_A": 1, "MEM_B": 1}); got != 1124 {
		t.Errorf("total %d MiB, want 1124", got)
	}
}
