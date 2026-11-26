package lint_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Rule exposure-is-declared, the Compose half (round 16, admin-r16-4, rebuilt for admin-r16-17).
//
// The invariant: nothing a service can be given by the Compose file is outside a list somebody read. The
// lints of this directory decode the file into a struct of the fields seen so far, and yaml.v3 drops every
// other key, so `volumes`, `privileged`, `pid`, `devices`, `sysctls`, `userns_mode`, `extra_hosts` and a
// `cap_add` outside caddy passed unseen: a later edit that bound ../../secrets into the internet-facing api,
// or mounted the Docker socket, or made valkey privileged, kept every Compose test green. The secrets rule
// (TestComposeKeyFilesFollowTheDomains, TestComposeSecretsAreFiles) reads the `secrets:` list only, which a
// bind mount of the same files does not touch. The first version of this lint then accepted every value of
// `security_opt`, `tmpfs`, `user`, `build`, `ulimits` and `ports` (it knew the key names only) and never looked
// inside the top-level `volumes`, `networks` and `secrets`, so `seccomp:unconfined` on the api, a named volume
// declared as a bind of the Docker socket through `driver_opts`, `driver: host` and `build.context: /` passed.
//
// What it judges: the whole document as generic data (anchors and merges resolved), so nothing is dropped, and
// every key AND value that gives a container more than the image's default, against closed tables:
//
//  1. The top level holds only name, services, networks, volumes, secrets and x-* extension fields. A
//     top-level volume has NO content at all (a named volume; a driver, driver_opts, external or name makes it
//     a bind of something); a top-level network holds only driver (bridge), internal, enable_ipv6 and an ipam
//     of subnet and ip_range; a top-level secret holds only `file`, a name under the secrets directory
//     variable and nothing else.
//  2. A service holds only the keys of composeServiceKeys. Anything else (privileged, pid, ipc, uts, devices,
//     sysctls, userns_mode, extra_hosts, cgroup_parent, group_add, dns, include, extends, configs, a key not
//     yet invented) fails, whatever its value.
//  3. The keys that widen what a container may do take their values from closed tables, exactly: security_opt
//     (one entry), cap_drop (ALL), read_only (true), cap_add, network_mode, user, tmpfs, build, ports, ulimits,
//     shm_size, profiles and volumes (the entries of each service). A service that is not in a table may have
//     none of that key.
//  4. Whatever the tables say, no volume source may be the secrets directory (or hold the word), the Docker
//     socket or a path outside the repository, and every bind mount of a host path is read-only. These hold if
//     someone edits the tables.
//  5. Every named volume, network, secret and dependency a service uses is declared, and every secret entry of
//     a service is a plain name (the long form can name a target path or a mode).
//
// What it does not judge: the values of logging, image, mem_limit, pids_limit and stop_grace_period (the value
// gives no reach, or another lint judges it: environment is composeenv_test.go, and command, entrypoint and
// healthcheck are composecmd_test.go, closed tables since round 17), and a file that is not
// docker-compose.yml. The tables are the review: a new volume, capability or port is a line here with its
// reason. Each clause has its own planted break in TestComposeKeysLintCanFail, named by the words the clause
// puts in its problem, so a clause that is deleted fails the plant of its own even when a table still refuses it.

// composeServiceKeys are the keys a service may have.
var composeServiceKeys = map[string]string{
	"build": "judged by composeTables.Build", "image": "", "command": "", "entrypoint": "", "environment": "",
	"secrets": "plain names only", "volumes": "judged by composeTables.Volumes", "networks": "", "ports": "judged by composeTables.Ports",
	"depends_on": "", "healthcheck": "", "restart": "", "logging": "", "security_opt": "judged exactly", "cap_drop": "judged exactly",
	"cap_add": "judged by composeTables.CapAdd", "read_only": "judged exactly", "pids_limit": "", "mem_limit": "",
	"user": "judged by composeTables.User", "stop_grace_period": "", "profiles": "judged by composeTables.Profiles",
	"network_mode": "judged by composeTables.NetworkMode", "tmpfs": "judged by composeTables.Tmpfs",
	"shm_size": "judged by composeTables.ShmSize", "ulimits": "judged by composeTables.Ulimits",
	"pull_policy": "judged by composeTables.PullPolicy",
}

// composeTables are the closed tables the lint judges against; the real ones are realComposeTables.
type composeTables struct {
	CapAdd      map[string][]string
	NetworkMode map[string]string
	Volumes     map[string][]string
	User        map[string]string
	Tmpfs       map[string][]string
	Build       map[string]map[string]string
	Ports       map[string][]string
	Ulimits     map[string]any
	ShmSize     map[string]string
	Profiles    map[string][]string
	PullPolicy  map[string]string
}

func valkeyZoneVolumes(zone string) []string {
	return []string{
		"valkey_" + zone + "_data:/data",
		"./valkey/valkey.conf:/etc/valkey/valkey.conf:ro",
		"./valkey/start.sh:/etc/valkey/start.sh:ro",
		"./valkey/maintain.sh:/etc/valkey/maintain.sh:ro",
		"./valkey/sweep.lua:/etc/valkey/sweep.lua:ro",
		"../../internal/ratelimit/lua:/etc/valkey/lua:ro",
	}
}

func realComposeTables() composeTables {
	return composeTables{
		// The capability each service adds back after dropping all of them.
		CapAdd: map[string][]string{"caddy": {"NET_BIND_SERVICE"}, "caddy-init": {"CHOWN"}},
		// The service that has no network of its own.
		NetworkMode: map[string]string{"caddy-init": "none"},
		// Every volume entry of every service, exactly. A bind mount is read-only; a named volume is one of the
		// top-level volumes.
		Volumes: map[string][]string{
			"api":        {"api_spool:/spool"},
			"caddy-init": {"caddy_data:/data", "caddy_config:/config"},
			"caddy":      {"./caddy/Caddyfile:/etc/caddy/Caddyfile:ro", "caddy_data:/data", "caddy_config:/config"},
			"postgres": {
				"pgdata:/var/lib/postgresql",
				"./postgres/postgresql.conf:/etc/postgresql/postgresql.conf:ro",
				"./postgres/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro",
				"./postgres/initdb:/docker-entrypoint-initdb.d:ro",
				"../../migrations/postgres/bootstrap:/ctrlz-bootstrap:ro",
				"./postgres/entrypoint.sh:/ctrlz-postgres/entrypoint.sh:ro",
				"./postgres/watchdog.sh:/ctrlz-postgres/watchdog.sh:ro",
			},
			// P4 3.3: the hub writes hub_tls.spki to hub_public, admin reads it; both read the signed bundles and root.json.
			"hub": {"hub_public:/var/lib/ctrlz/hub_public", "../../deploy/bundles:/var/lib/ctrlz/bundles:ro", "artifacts:/var/lib/ctrlz/artifacts:ro"},
			// P4 6.5: the compiler, which runs in the worker, writes the artifact store; the hub reads it.
			"worker":       {"artifacts:/var/lib/ctrlz/artifacts"},
			"admin":        {"hub_public:/var/lib/ctrlz/hub_public:ro", "../../deploy/bundles:/var/lib/ctrlz/bundles:ro"},
			"clickhouse":   {"chdata:/var/lib/clickhouse", "./clickhouse/ctrlz.xml:/etc/clickhouse-server/config.d/ctrlz.xml:ro"},
			"valkey-api":   valkeyZoneVolumes("api"),
			"valkey-admin": valkeyZoneVolumes("admin"),
		},
		// The user a service runs as, where the file sets one (the image's own user otherwise). caddy-init is
		// the one root container, for one chown.
		User: map[string]string{
			"caddy": "65532:65532", "caddy-init": "0:0", "web-panel": "65532:65532", "web-admin": "65532:65532",
			"valkey-api": "999:999", "valkey-admin": "999:999",
		},
		// A tmpfs the container writes to: the Valkey zones' /tmp, which holds the ACL file for the length of one read,
		// and the one scratch directory of each web container (its root is read-only and Next writes nothing else).
		Tmpfs: map[string][]string{
			"web-panel":    {"/tmp"},
			"web-admin":    {"/tmp"},
			"valkey-api":   {"/tmp:size=1m,mode=0700,uid=999,gid=999"},
			"valkey-admin": {"/tmp:size=1m,mode=0700,uid=999,gid=999"},
		},
		// What a build may name: the image of the Go services, from the repository root.
		Build: map[string]map[string]string{"migrate": {"context": "../..", "dockerfile": "deploy/docker/Dockerfile"}},
		// The only published ports of the stack: the front door and the hub's node port (TestComposePublishesNoDatabasePort holds the same fact).
		Ports: map[string][]string{"caddy": {"${CTRLZ_HTTP_PORT:-80}:80", "${CTRLZ_HTTPS_PORT:-443}:443"}, "hub": {"9443:9443"}},
		// clickhouse opens many files; it is the one service that raises a limit.
		Ulimits:  map[string]any{"clickhouse": map[string]any{"nofile": map[string]any{"soft": 262144, "hard": 262144}}},
		ShmSize:  map[string]string{"postgres": "${PG_SHM_SIZE:-512m}"},
		Profiles: map[string][]string{"rekey": {"tools"}, "domain-apply": {"tools"}},
		// The Panel image and the two web images are bare names a registry would resolve (admin-r17-4): every
		// service that runs one is never pulled. imagePullProblems holds the same fact from the image side.
		PullPolicy: map[string]string{
			"api": "never", "admin": "never", "worker": "never", "hub": "never", "migrate": "never", "rekey": "never", "domain-apply": "never",
			"web-panel": "never", "web-admin": "never",
		},
	}
}

// composeAllowedTop are the top-level keys.
var composeAllowedTop = map[string]bool{"name": true, "services": true, "networks": true, "volumes": true, "secrets": true}

// composeSecretFile is the one shape a top-level secret's file may have: a name under the secrets directory.
var composeSecretFile = regexp.MustCompile(`^\$\{CTRLZ_SECRETS_DIR:-\.\./\.\./secrets\}/[a-z0-9_]+$`)

func composeMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func composeStrings(v any) ([]string, bool) {
	l, ok := v.([]any)
	if !ok {
		return nil, v == nil
	}
	var out []string
	for _, x := range l {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func composeSameStrings(a, b []string) bool {
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, "\x00") == strings.Join(b, "\x00")
}

// composeNames returns the names a service lists under `networks` or `depends_on`, which are a list or a map.
func composeNames(v any) []string {
	var out []string
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	case map[string]any:
		for k := range x {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// composeOnlyKeys reports each key of m that is not in allowed.
func composeOnlyKeys(what string, m map[string]any, allowed ...string) []string {
	var out []string
	for k := range m {
		ok := false
		for _, a := range allowed {
			ok = ok || a == k
		}
		if !ok {
			out = append(out, fmt.Sprintf("%s has the key %s, which is not on the list", what, k))
		}
	}
	return out
}

// composeTopLevelProblems judges the top-level volumes, networks and secrets (rule point 1) and returns the names
// each declares.
func composeTopLevelProblems(doc map[string]any) (problems []string, volumes, networks, secrets map[string]bool) {
	volumes, networks, secrets = map[string]bool{}, map[string]bool{}, map[string]bool{}
	for name, raw := range composeMap(doc["volumes"]) {
		volumes[name] = true
		if raw != nil {
			problems = append(problems, fmt.Sprintf("the top-level volume %s has content (%v): a named volume is declared with no options, since a driver or driver_opts makes it a bind of any host path", name, raw))
		}
	}
	for name, raw := range composeMap(doc["networks"]) {
		networks[name] = true
		n := composeMap(raw)
		if raw != nil && n == nil {
			problems = append(problems, "the network "+name+" is not a mapping")
			continue
		}
		problems = append(problems, composeOnlyKeys("the network "+name, n, "driver", "internal", "enable_ipv6", "ipam")...)
		if d, ok := n["driver"]; ok && d != "bridge" {
			problems = append(problems, fmt.Sprintf("the network %s has driver %v: only bridge is allowed", name, d))
		}
		for _, k := range []string{"internal", "enable_ipv6"} {
			if v, ok := n[k]; ok {
				if _, isBool := v.(bool); !isBool {
					problems = append(problems, fmt.Sprintf("the network %s has %s %v, want a boolean", name, k, v))
				}
			}
		}
		if ipam, ok := n["ipam"]; ok {
			m := composeMap(ipam)
			problems = append(problems, composeOnlyKeys("the ipam of "+name, m, "config")...)
			cfg, _ := m["config"].([]any)
			for _, c := range cfg {
				problems = append(problems, composeOnlyKeys("an ipam config of "+name, composeMap(c), "subnet", "ip_range")...)
			}
		}
	}
	for name, raw := range composeMap(doc["secrets"]) {
		secrets[name] = true
		s := composeMap(raw)
		problems = append(problems, composeOnlyKeys("the secret "+name, s, "file")...)
		if f, _ := s["file"].(string); !composeSecretFile.MatchString(f) {
			problems = append(problems, fmt.Sprintf("the secret %s has file %v, want a name under ${CTRLZ_SECRETS_DIR:-../../secrets}", name, s["file"]))
		}
	}
	return problems, volumes, networks, secrets
}

// composeVolumeProblems judges the volume entries of one service: the exact table, then the clauses that hold
// whatever the table says (rule point 4 and the declared-volume half of point 5).
func composeVolumeProblems(name string, vols []string, table []string, named map[string]bool) []string {
	var out []string
	if !composeSameStrings(vols, table) {
		out = append(out, fmt.Sprintf("%s mounts %v, the table allows %v", name, vols, table))
	}
	for _, v := range vols {
		parts := strings.Split(v, ":")
		src := parts[0]
		lower := strings.ToLower(src)
		isBind := strings.HasPrefix(src, ".") || strings.HasPrefix(src, "/") || strings.HasPrefix(src, "~") || strings.Contains(src, "$")
		switch {
		case strings.Contains(lower, "secret") || strings.Contains(lower, "docker.sock") || strings.Contains(lower, "/var/run") || strings.Contains(lower, "/run/"):
			out = append(out, fmt.Sprintf("%s mounts %s: the secrets directory and the Docker socket are never a volume", name, v))
		case !isBind:
			if !named[src] {
				out = append(out, fmt.Sprintf("%s mounts the volume %s, which the file does not declare", name, src))
			}
		default:
			if len(parts) < 3 || parts[len(parts)-1] != "ro" {
				out = append(out, fmt.Sprintf("%s mounts the host path %s writable: a bind mount is read-only", name, v))
			}
			// One of two homes only: the compose directory, or a directory of the repository two levels up.
			if strings.HasPrefix(src, "/") || strings.HasPrefix(src, "~") || strings.Contains(src, "$") || strings.Count(src, "../") > 2 ||
				(strings.HasPrefix(src, "../") && !strings.HasPrefix(src, "../../")) {
				out = append(out, fmt.Sprintf("%s mounts %s, a host path outside the repository", name, src))
			}
		}
	}
	return out
}

// composeKeyProblems judges the text of a Compose file against the real tables.
func composeKeyProblems(text string) []string {
	return composeKeyProblemsWith(text, realComposeTables())
}

// composeKeyProblemsWith is composeKeyProblems against the tables it is given.
func composeKeyProblemsWith(text string, tb composeTables) []string {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return []string{"docker-compose.yml: " + err.Error()}
	}
	var out []string
	for k := range doc {
		if !composeAllowedTop[k] && !strings.HasPrefix(k, "x-") {
			out = append(out, "the top level has the key "+k+", which is not on the list")
		}
	}
	services := composeMap(doc["services"])
	if len(services) == 0 {
		return append(out, "the file has no services")
	}
	top, named, nets, secs := composeTopLevelProblems(doc)
	out = append(out, top...)
	for name, raw := range services {
		s := composeMap(raw)
		for key := range s {
			if _, ok := composeServiceKeys[key]; !ok {
				out = append(out, fmt.Sprintf("%s has the key %s, which is not on the list of service keys", name, key))
			}
		}
		if v, ok := s["security_opt"]; ok {
			if got, plain := composeStrings(v); !plain || !composeSameStrings(got, []string{"no-new-privileges:true"}) {
				out = append(out, fmt.Sprintf("%s has security_opt %v, the only entry allowed is no-new-privileges:true", name, v))
			}
		}
		if v, ok := s["cap_drop"]; ok {
			if got, plain := composeStrings(v); !plain || !composeSameStrings(got, []string{"ALL"}) {
				out = append(out, fmt.Sprintf("%s has cap_drop %v, want [ALL]", name, v))
			}
		}
		if v, ok := s["read_only"]; ok && v != true {
			out = append(out, fmt.Sprintf("%s has read_only %v, want true", name, v))
		}
		if v, ok := s["cap_add"]; ok {
			got, plain := composeStrings(v)
			if !plain || !composeSameStrings(got, tb.CapAdd[name]) {
				out = append(out, fmt.Sprintf("%s adds the capabilities %v, the table allows %v", name, v, tb.CapAdd[name]))
			}
		}
		if v, ok := s["network_mode"]; ok {
			if str, _ := v.(string); str == "" || str != tb.NetworkMode[name] {
				out = append(out, fmt.Sprintf("%s has network_mode %v, the table allows %q", name, v, tb.NetworkMode[name]))
			}
		}
		if v, ok := s["user"]; ok {
			if str, _ := v.(string); str == "" || str != tb.User[name] {
				out = append(out, fmt.Sprintf("%s runs as %v, the table allows %q", name, v, tb.User[name]))
			}
		}
		if v, ok := s["tmpfs"]; ok {
			got, plain := composeStrings(v)
			if !plain || !composeSameStrings(got, tb.Tmpfs[name]) {
				out = append(out, fmt.Sprintf("%s has the tmpfs %v, the table allows %v", name, v, tb.Tmpfs[name]))
			}
		}
		if v, ok := s["build"]; ok {
			got := map[string]string{}
			for k, x := range composeMap(v) {
				got[k], _ = x.(string)
			}
			if !reflect.DeepEqual(got, tb.Build[name]) {
				out = append(out, fmt.Sprintf("%s builds %v, the table allows %v", name, v, tb.Build[name]))
			}
		}
		if v, ok := s["ports"]; ok {
			got, plain := composeStrings(v)
			if !plain || !composeSameStrings(got, tb.Ports[name]) {
				out = append(out, fmt.Sprintf("%s publishes %v, the table allows %v", name, v, tb.Ports[name]))
			}
		}
		if v, ok := s["ulimits"]; ok && !reflect.DeepEqual(v, tb.Ulimits[name]) {
			out = append(out, fmt.Sprintf("%s has ulimits %v, the table allows %v", name, v, tb.Ulimits[name]))
		}
		if v, ok := s["shm_size"]; ok && v != tb.ShmSize[name] {
			out = append(out, fmt.Sprintf("%s has shm_size %v, the table allows %q", name, v, tb.ShmSize[name]))
		}
		if v, ok := s["pull_policy"]; ok {
			if str, _ := v.(string); str == "" || str != tb.PullPolicy[name] {
				out = append(out, fmt.Sprintf("%s has pull_policy %v, the table allows %q", name, v, tb.PullPolicy[name]))
			}
		}
		if v, ok := s["profiles"]; ok {
			got, plain := composeStrings(v)
			if !plain || !composeSameStrings(got, tb.Profiles[name]) {
				out = append(out, fmt.Sprintf("%s has the profiles %v, the table allows %v", name, v, tb.Profiles[name]))
			}
		}
		for _, n := range composeNames(s["networks"]) {
			if !nets[n] {
				out = append(out, fmt.Sprintf("%s joins the network %s, which the file does not declare", name, n))
			}
		}
		for _, d := range composeNames(s["depends_on"]) {
			if _, ok := services[d]; !ok {
				out = append(out, fmt.Sprintf("%s depends on %s, which is not a service", name, d))
			}
		}
		if v, ok := s["secrets"]; ok {
			plainNames, plain := composeStrings(v)
			if !plain {
				out = append(out, name+" lists a secret in the long form, which can name a target path and a mode")
			}
			for _, sec := range plainNames {
				if !secs[sec] {
					out = append(out, fmt.Sprintf("%s uses the secret %s, which the file does not declare", name, sec))
				}
			}
		}
		vols, plain := composeStrings(s["volumes"])
		if !plain {
			out = append(out, name+" lists a volume in the long form; write each as source:target[:ro]")
			continue
		}
		out = append(out, composeVolumeProblems(name, vols, tb.Volumes[name], named)...)
	}
	for name := range tb.Volumes {
		if _, ok := services[name]; !ok {
			out = append(out, "the volume table names the service "+name+", which the file does not have")
		}
	}
	for name := range tb.CapAdd {
		if _, ok := services[name]; !ok {
			out = append(out, "the capability table names the service "+name+", which the file does not have")
		}
	}
	sort.Strings(out)
	return out
}

func TestComposeKeysAreAnAllowList(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "compose", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if p := composeKeyProblems(string(b)); len(p) != 0 {
		t.Fatalf("%s", strings.Join(p, "\n"))
	}
}

// TestComposeKeysLintCanFail plants every kind of break the rule names, each in the document of the real file,
// and requires the problem that the clause of that break writes: a plant that a table also refuses is no proof
// of its clause, so each row names the words of the clause it is aimed at.
func TestComposeKeysLintCanFail(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "compose", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	good := string(b)
	if p := composeKeyProblems(good); len(p) != 0 {
		t.Fatalf("the real file is refused: %v", p)
	}
	// plant adds lines after the name line of a service, as keys of that service (an explicit key wins over a merged one).
	plant := func(service, lines string) func(string) string {
		return func(s string) string {
			i := strings.Index(s, "\n  "+service+":\n")
			if i < 0 {
				t.Fatalf("no service %s", service)
			}
			j := i + len("\n  "+service+":\n")
			return s[:j] + lines + s[j:]
		}
	}
	replace := func(old, new string) func(string) string {
		return func(s string) string {
			if strings.Count(s, old) != 1 {
				t.Fatalf("the text %q occurs %d times in the real file", old, strings.Count(s, old))
			}
			return strings.Replace(s, old, new, 1)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(string) string
		want   string // words of the clause the plant is aimed at
	}{
		// Volumes: the table AND the clauses that hold whatever the table says.
		{"a bind of the secrets directory into the api", replace("      - api_spool:/spool\n", "      - api_spool:/spool\n      - ../../secrets:/keys:ro\n"), "never a volume"},
		{"a bind of kek_root into the api", replace("      - api_spool:/spool\n", "      - api_spool:/spool\n      - ../../secrets/kek_root:/kek_root:ro\n"), "never a volume"},
		{"the Docker socket in the worker", plant("migrate", "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"), "never a volume"},
		{"a writable bind in a valkey zone", replace("./valkey/valkey.conf:/etc/valkey/valkey.conf:ro\n      - ./valkey/start.sh:/etc/valkey/start.sh:ro\n      - ./valkey/maintain.sh:/etc/valkey/maintain.sh:ro\n      - ./valkey/sweep.lua:/etc/valkey/sweep.lua:ro\n      - ../../internal/ratelimit/lua:/etc/valkey/lua:ro\n    networks: [vk_api]",
			"./valkey/valkey.conf:/etc/valkey/valkey.conf\n      - ./valkey/start.sh:/etc/valkey/start.sh:ro\n      - ./valkey/maintain.sh:/etc/valkey/maintain.sh:ro\n      - ./valkey/sweep.lua:/etc/valkey/sweep.lua:ro\n      - ../../internal/ratelimit/lua:/etc/valkey/lua:ro\n    networks: [vk_api]"), "writable"},
		{"an undeclared named volume", plant("migrate", "    volumes:\n      - nowhere:/data\n"), "does not declare"},
		{"a long-form volume", plant("migrate", "    volumes:\n      - {type: bind, source: ../../secrets, target: /s}\n"), "long form"},
		{"a volume added to a service in the table", replace("      - hub_public:/var/lib/ctrlz/hub_public\n", "      - hub_public:/var/lib/ctrlz/hub_public\n      - ../../apps:/apps:ro\n"), "the table allows"},
		{"a host path outside the repository", plant("migrate", "    volumes:\n      - /etc:/www:ro\n"), "outside the repository"},
		{"a host path two levels above the repository", plant("migrate", "    volumes:\n      - ../../../x:/www:ro\n"), "outside the repository"},
		{"a host path one level up", plant("migrate", "    volumes:\n      - ../x:/www:ro\n"), "outside the repository"},
		{"a host path from a variable", plant("migrate", "    volumes:\n      - ${HOME}:/www:ro\n"), "outside the repository"},
		// The top level.
		{"a named volume declared as a bind of the Docker socket", replace("\nvolumes:\n  pgdata:\n", "\nvolumes:\n  pgdata:\n    driver_opts: {type: none, o: bind, device: /var/run/docker.sock}\n"), "has content"},
		{"a named volume with a driver", replace("\nvolumes:\n  pgdata:\n", "\nvolumes:\n  pgdata:\n    driver: local\n"), "has content"},
		{"a top-level network on the host", replace("  egress:\n    driver: bridge", "  egress:\n    driver: host"), "only bridge"},
		{"an external network", replace("  hub_ingress:\n    driver: bridge", "  hub_ingress:\n    driver: bridge\n    external: true"), "which is not on the list"},
		{"a network with driver options", replace("  web:\n    driver: bridge\n    internal: true", "  web:\n    driver: bridge\n    internal: true\n    driver_opts: {com.docker.network.bridge.name: docker0}"), "which is not on the list"},
		{"a network flag that is not a boolean", replace("  web:\n    driver: bridge\n    internal: true", "  web:\n    driver: bridge\n    internal: \"false\""), "want a boolean"},
		{"an ipam key that is not subnet or ip_range", replace("        - subnet: fd00:213:77:1::/64", "        - subnet: fd00:213:77:1::/64\n          gateway: fd00::1"), "an ipam config"},
		{"a secret that is read from the environment", replace("  proof_key:\n    file: ${CTRLZ_SECRETS_DIR:-../../secrets}/proof_key", "  proof_key:\n    environment: HOME"), "the secret proof_key has the key"},
		{"a secret whose file is outside the secrets directory", replace("  proof_key:\n    file: ${CTRLZ_SECRETS_DIR:-../../secrets}/proof_key", "  proof_key:\n    file: /etc/shadow"), "want a name under"},
		{"a top-level include", func(s string) string { return "include:\n  - other.yml\n" + s }, "the top level has the key include"},
		{"a top-level configs", func(s string) string { return "configs:\n  x: {file: ./x}\n" + s }, "the top level has the key configs"},
		// Service keys and the values of the keys that widen a container.
		{"privileged", plant("valkey-api", "    privileged: true\n"), "service keys"},
		{"pid host", plant("api", "    pid: host\n"), "service keys"},
		{"ipc host", plant("api", "    ipc: host\n"), "service keys"},
		{"uts host", plant("api", "    uts: host\n"), "service keys"},
		{"devices", plant("api", "    devices: [\"/dev/mem\"]\n"), "service keys"},
		{"sysctls", plant("api", "    sysctls: {net.ipv4.ip_forward: 1}\n"), "service keys"},
		{"userns_mode", plant("api", "    userns_mode: host\n"), "service keys"},
		{"extra_hosts", plant("api", "    extra_hosts: [\"x:1.2.3.4\"]\n"), "service keys"},
		{"cgroup_parent", plant("api", "    cgroup_parent: x\n"), "service keys"},
		{"group_add", plant("api", "    group_add: [docker]\n"), "service keys"},
		{"extends", plant("api", "    extends: {service: worker}\n"), "service keys"},
		{"a key nobody has invented yet", plant("api", "    brand_new_option: true\n"), "service keys"},
		{"cap_add outside caddy", plant("valkey-api", "    cap_add: [SYS_ADMIN]\n"), "adds the capabilities"},
		{"a second cap for caddy", replace(`cap_add: ["NET_BIND_SERVICE"]`, `cap_add: ["NET_BIND_SERVICE", "SYS_PTRACE"]`), "adds the capabilities"},
		{"network_mode host", plant("valkey-api", "    network_mode: host\n"), "network_mode"},
		{"network_mode on caddy-init changed", replace("network_mode: none", "network_mode: host"), "network_mode"},
		{"a long-form secret", plant("web-panel", "    secrets:\n      - {source: pg_tenant_password, target: /x, mode: 0444}\n"), "long form"},
		{"a secret the file does not declare", plant("web-panel", "    secrets: [ghost_secret]\n"), "uses the secret ghost_secret"},
		{"seccomp unconfined on the api", plant("api", "    security_opt: [\"no-new-privileges:true\", \"seccomp:unconfined\"]\n"), "the only entry allowed"},
		{"no security_opt entry that matters", plant("api", "    security_opt: [\"label:disable\"]\n"), "the only entry allowed"},
		{"a capability left in", plant("api", "    cap_drop: [NET_RAW]\n"), "want [ALL]"},
		{"a writable root", plant("api", "    read_only: false\n"), "want true"},
		{"a tmpfs over the secrets", plant("api", "    tmpfs: [\"/run/secrets\"]\n"), "has the tmpfs"},
		{"another tmpfs in a zone", plant("valkey-api", "    tmpfs: [\"/tmp:size=1m,mode=0700,uid=999,gid=999\", \"/run/secrets\"]\n"), "has the tmpfs"},
		{"root for the api", plant("api", "    user: \"0:0\"\n"), "runs as"},
		{"a user that is no table row", plant("hub", "    user: \"65532:65532\"\n"), "runs as"},
		{"a build of the whole disk", plant("api", "    build: {context: /, dockerfile: x}\n"), "builds"},
		{"the migrate build moved", replace("context: ../..", "context: /"), "builds"},
		{"a published port of the api", plant("api", "    ports: [\"8080:8080\"]\n"), "publishes"},
		{"a third published port of caddy", replace("      - \"${CTRLZ_HTTPS_PORT:-443}:443\"\n", "      - \"${CTRLZ_HTTPS_PORT:-443}:443\"\n      - \"2019:2019\"\n"), "publishes"},
		{"a ulimit on the api", plant("api", "    ulimits: {nproc: 1}\n"), "has ulimits"},
		{"the clickhouse ulimit changed", replace("nofile: {soft: 262144, hard: 262144}", "nofile: {soft: 1, hard: 262144}"), "has ulimits"},
		{"a shm_size on the api", plant("api", "    shm_size: 4g\n"), "shm_size"},
		{"a profile on the api", plant("api", "    profiles: [tools]\n"), "the profiles"},
		{"a pull policy on a third-party image", plant("caddy", "    pull_policy: never\n"), "has pull_policy"},
		{"a pull policy that fetches the Panel image", plant("api", "    pull_policy: always\n"), "has pull_policy"},
		{"a web service that may be pulled", replace("    image: ${CTRLZ_WEB_ADMIN_IMAGE:-ctrlz/web-admin:dev}\n    pull_policy: never\n", "    image: ${CTRLZ_WEB_ADMIN_IMAGE:-ctrlz/web-admin:dev}\n    pull_policy: missing\n"), "has pull_policy"},
		{"a second tmpfs in a web service", func(s string) string {
			return strings.Replace(s, "tmpfs: [\"/tmp\"]", "tmpfs: [\"/tmp\", \"/run/secrets\"]", 1)
		}, "has the tmpfs"},
		{"a mount in a web service", plant("web-panel", "    volumes:\n      - ../../apps:/apps:ro\n"), "the table allows"},
		{"an undeclared network", replace("    networks: [web]\n\n  web-admin:", "    networks: [web, nowhere]\n\n  web-admin:"), "joins the network nowhere"},
		{"a dependency that is no service", plant("web-panel", "    depends_on: [ghost]\n"), "which is not a service"},
	} {
		p := composeKeyProblems(tc.mutate(good))
		if len(p) == 0 {
			t.Errorf("%s: no problem reported", tc.name)
			continue
		}
		// A plant that only made the YAML invalid (a key twice) is a vacuous pass.
		if len(p) == 1 && strings.HasPrefix(p[0], "docker-compose.yml:") {
			t.Errorf("%s: the plant is not valid YAML, so it proves nothing: %s", tc.name, p[0])
			continue
		}
		found := false
		for _, line := range p {
			found = found || strings.Contains(line, tc.want)
		}
		if !found {
			t.Errorf("%s: no problem says %q (a table may have refused it, and not the clause aimed at); got %v", tc.name, tc.want, p)
		}
	}
}

// TestComposeVolumeClausesHoldWhateverTheTableSays gives composeVolumeProblems a table that already names the
// bad entry, so that the exact-table check passes and only the clauses of rule point 4 can refuse it: a table
// edit must not be able to open the hole.
func TestComposeVolumeClausesHoldWhateverTheTableSays(t *testing.T) {
	declared := map[string]bool{"pgdata": true}
	for _, tc := range []struct {
		entry, want string
	}{
		{"../../secrets:/keys:ro", "never a volume"},
		{"./secrets/kek_root:/k:ro", "never a volume"},
		{"/var/run/docker.sock:/s:ro", "never a volume"},
		{"/run/user/1000/podman.sock:/s:ro", "never a volume"},
		{"./a:/b", "writable"},
		{"./a:/b:rw", "writable"},
		{"nowhere:/d", "does not declare"},
		{"/etc:/e:ro", "outside the repository"},
		{"~/x:/e:ro", "outside the repository"},
		{"$HOME/x:/e:ro", "outside the repository"},
		{"../x:/e:ro", "outside the repository"},
		{"../../../x:/e:ro", "outside the repository"},
	} {
		p := composeVolumeProblems("svc", []string{tc.entry}, []string{tc.entry}, declared)
		found := false
		for _, line := range p {
			if strings.Contains(line, "the table allows") {
				t.Errorf("%s: the exact table refused it, so the clause is not what this row tests: %v", tc.entry, p)
			}
			found = found || strings.Contains(line, tc.want)
		}
		if !found {
			t.Errorf("%s: no problem says %q although the table allows it; got %v", tc.entry, tc.want, p)
		}
	}
	for _, ok := range []string{"pgdata:/var/lib/postgresql", "./a/b:/c:ro", "../../migrations/x:/c:ro"} {
		if p := composeVolumeProblems("svc", []string{ok}, []string{ok}, declared); len(p) != 0 {
			t.Errorf("%s is refused: %v", ok, p)
		}
	}
}
