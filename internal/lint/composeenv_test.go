package lint_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Kup1ng/CtrlZ-Panel/deploy"
)

// Rule exposure-is-declared, the Compose environment (round 17, admin-r17-5).
//
// The invariant: what a long-running container has as its process environment is a closed table somebody
// read. The `environment:` map of a service is where a value becomes `docker inspect` output, the
// /proc/1/environ of a long-running process and the environment of every child it starts, which is the one
// place the header of the Compose file says no password may be. Until round 17 the map was judged by a word
// list (a variable whose name held PASSWORD, SECRET, TOKEN or KEY had to be a *_FILE path, except names that
// ended in _ADDR or _USER), the same shape that round 16 retired for the shell files: `CTRLZ_SMS_CRED:
// ${SMS_API_PASS}`, `CTRLZ_DB_PASS: ${PG_PASS}`, `VALKEY_AUTH: ...` and `CTRLZ_VALKEY_PASSWORD_USER: hunter2`
// are credentials that no word of the list names or that an exception waved through.
//
// What it judges, as an allow list that fails closed:
//
//  1. Every service that has an environment has a row in composeEnvTable, and every variable of the service is
//     a key of its row with exactly the value of the row: a literal, or `${VAR:-literal}` with the variable
//     and the literal the row states. A key or a value that is not on the table fails, whatever it is called.
//  2. A value of the row that is composeEnvFile stands for a secret path and is judged by what it is, not by a
//     name: `/run/secrets/<secret>` where the secret is one the service mounts (its `secrets:` list), under a
//     variable that ends in _FILE. A file path of a secret the service does not mount fails.
//  3. A row that names a variable the service does not have fails (a stale row would otherwise let a later
//     edit bring the variable back unseen), and so does a row for a service the file lacks.
//  4. The form is a map. The list form (`- KEY=value`) and a map with a nested value are refused, so a reader
//     of the table never has to wonder what a line means.
//  5. Whatever the table says, every `${...}` or `$VAR` of the whole file (a command, a healthcheck, a
//     limit, a secret path) names a host variable of composeHostVariables, which is the only list of what
//     an .env may feed into this file. A credential that an .env carries has no way in through a name that
//     is not on it. The scan reads every scalar of the decoded YAML (keys and values, quoted strings included),
//     not the lines, and a listed variable that the file no longer expands fails, so the list cannot outlive its
//     cause (round 17 fix gate, admin-r17-19). The command, entrypoint and healthcheck of every service are a
//     closed table of their own (composecmd_test.go, admin-r17-20).
//
// What it does not judge: the contents of a file a *_FILE variable points to (they are secrets, which the
// secret lints and the canary scripts watch), and a variable a container sets for itself at run time (a
// script; the shell lints of this directory judge those).

// composeEnvFile is the value of a table row for a variable whose value is the path of a secret the service
// mounts.
const composeEnvFile = "@file"

// composeEnvGo is the environment every Go service gets from the x-go-env anchor of the file: the database
// address and the key directory. Their passwords are *_FILE variables of the service's own row.
var composeEnvGo = map[string]string{
	"CTRLZ_DB_HOST": "postgres", "CTRLZ_DB_NAME": "ctrlz", "CTRLZ_DB_PORT": "5432", "CTRLZ_DB_SSLMODE": "disable",
	"CTRLZ_ENV": "${CTRLZ_ENV:-production}", "CTRLZ_KEK_DIR": "/run/secrets",
}

// composeEnvGoServices are the services that take composeEnvGo; the table below adds their own variables.
var composeEnvGoServices = []string{"api", "admin", "worker", "hub", "migrate", "rekey"}

// composeEnvTable is the whole environment of every service that has one, apart from composeEnvGo.
var composeEnvTable = map[string]map[string]string{
	"api": {
		"CTRLZ_ARGON2_BUDGET_MIB": "${CTRLZ_API_ARGON2_BUDGET_MIB:-128}", "CTRLZ_ARGON2_CONCURRENCY": "${CTRLZ_API_ARGON2_CONCURRENCY:-2}",
		"CTRLZ_DB_MAX_CONNS": "${CTRLZ_API_DB_MAX_CONNS:-16}", "CTRLZ_DB_PASSWORD_FILE": composeEnvFile,
		"CTRLZ_LISTEN": ":8080", "CTRLZ_PANEL_HOST": "${CTRLZ_PANEL_HOST:-panel.localhost}", "CTRLZ_TRUSTED_PROXY": "10.213.78.200",
		"CTRLZ_VALKEY_ADDR": "valkey-api:6379", "CTRLZ_VALKEY_PASSWORD_FILE": composeEnvFile, "CTRLZ_VALKEY_USER": "api",
		"GOMEMLIMIT": "${GOMEMLIMIT_API:-200MiB}",
	},
	"admin": {
		"CTRLZ_ADMIN_HOST": "${CTRLZ_ADMIN_HOST:-admin.localhost}", "CTRLZ_ARGON2_BUDGET_MIB": "${CTRLZ_ADMIN_ARGON2_BUDGET_MIB:-64}",
		"CTRLZ_ARGON2_CONCURRENCY": "1", "CTRLZ_DB_MAX_CONNS": "${CTRLZ_ADMIN_DB_MAX_CONNS:-5}", "CTRLZ_DB_PASSWORD_FILE": composeEnvFile,
		"CTRLZ_LISTEN": ":8081", "CTRLZ_PANEL_HOST": "${CTRLZ_PANEL_HOST:-panel.localhost}", "CTRLZ_TRUSTED_PROXY": "10.213.78.200",
		"CTRLZ_VALKEY_ADDR": "valkey-admin:6379", "CTRLZ_VALKEY_PASSWORD_FILE": composeEnvFile, "CTRLZ_VALKEY_USER": "admin",
		"GOMEMLIMIT": "${GOMEMLIMIT_ADMIN:-96MiB}",
	},
	"worker": {
		"CTRLZ_DB_COMPILER_PASSWORD_FILE": composeEnvFile, "CTRLZ_DB_MAX_CONNS": "${CTRLZ_WORKER_DB_MAX_CONNS:-4}",
		"CTRLZ_DB_PASSWORD_FILE": composeEnvFile, "CTRLZ_LISTEN": "127.0.0.1:8083",
	},
	"hub": {
		"CTRLZ_DB_MAX_CONNS": "${CTRLZ_HUB_DB_MAX_CONNS:-4}", "CTRLZ_DB_PASSWORD_FILE": composeEnvFile,
		"CTRLZ_LISTEN": "127.0.0.1:7443", "CTRLZ_PROOF_KEY_FILE": composeEnvFile,
	},
	"migrate": {"CTRLZ_DB_PASSWORD_FILE": composeEnvFile},
	"rekey":   {"CTRLZ_DB_PASSWORD_FILE": composeEnvFile},
	"caddy": {
		"CTRLZ_ADMIN_HOST": "${CTRLZ_ADMIN_HOST:-admin.localhost}", "CTRLZ_PANEL_HOST": "${CTRLZ_PANEL_HOST:-panel.localhost}",
	},
	"postgres": {
		"CTRLZ_DB_NAME":       "ctrlz",
		"CTRLZ_PG_CONN_ADMIN": "${CTRLZ_PG_CONN_ADMIN:-8}", "CTRLZ_PG_CONN_COMPILER": "${CTRLZ_PG_CONN_COMPILER:-4}",
		"CTRLZ_PG_CONN_HUB": "${CTRLZ_PG_CONN_HUB:-10}", "CTRLZ_PG_CONN_MIGRATOR": "${CTRLZ_PG_CONN_MIGRATOR:-3}",
		"CTRLZ_PG_CONN_TENANT": "${CTRLZ_PG_CONN_TENANT:-20}", "CTRLZ_PG_CONN_TOOLS": "${CTRLZ_PG_CONN_TOOLS:-4}",
		"CTRLZ_PG_CONN_WORKER": "${CTRLZ_PG_CONN_WORKER:-10}", "CTRLZ_PG_IDLE_TX_TIMEOUT": "${CTRLZ_PG_IDLE_TX_TIMEOUT:-60s}",
		"CTRLZ_PG_LOCK_TIMEOUT": "${CTRLZ_PG_LOCK_TIMEOUT:-5s}", "CTRLZ_PG_STATEMENT_TIMEOUT": "${CTRLZ_PG_STATEMENT_TIMEOUT:-30s}",
		"CTRLZ_PG_TX_TIMEOUT": "${CTRLZ_PG_TX_TIMEOUT:-120s}", "CTRLZ_PG_WATCHDOG_INTERVAL": "${CTRLZ_PG_WATCHDOG_INTERVAL:-2}",
		"CTRLZ_PG_WATCHDOG_MAX_BLOCK": "${CTRLZ_PG_WATCHDOG_MAX_BLOCK:-2}", "CTRLZ_PG_WATCHDOG_MAX_HOLD": "${CTRLZ_PG_WATCHDOG_MAX_HOLD:-150}",
		"CTRLZ_PG_WATCHDOG_MAX_TX": "${CTRLZ_PG_WATCHDOG_MAX_TX:-300}",
		"POSTGRES_DB":              "postgres", "POSTGRES_PASSWORD_FILE": composeEnvFile, "POSTGRES_USER": "postgres",
	},
	"clickhouse": {
		"CH_MAX_SERVER_MEMORY_USAGE": "${CH_MAX_SERVER_MEMORY_USAGE:-2000000000}", "CLICKHOUSE_SKIP_USER_SETUP": "1",
	},
	"valkey-api":   {"VK_MAXMEMORY": "${VALKEY_MAXMEMORY:-64mb}", "VK_ZONE": "api"},
	"valkey-admin": {"VK_MAXMEMORY": "${VALKEY_MAXMEMORY:-64mb}", "VK_ZONE": "admin"},
}

// composeHostVariables is every variable an .env (or the shell that runs compose) may feed into the file. The
// list is the review: a new line is a new way for the host to put a value into a container or a limit, so it
// is read for what the value could carry. None of them is a credential; passwords come from files.
var composeHostVariables = map[string]string{
	"CTRLZ_IMAGE": "the name of the Panel image under test", "CTRLZ_WEB_PANEL_IMAGE": "the name of the web-panel image built on this machine", "CTRLZ_WEB_ADMIN_IMAGE": "the name of the web-admin image built on this machine",
	"CTRLZ_ENV":        "production, or test for the smoke",
	"CTRLZ_PANEL_HOST": "a host name", "CTRLZ_ADMIN_HOST": "a host name", "CTRLZ_HTTP_PORT": "a port", "CTRLZ_HTTPS_PORT": "a port",
	"CTRLZ_SECRETS_DIR":           "the directory of the secret files, a path and no content",
	"CTRLZ_ENV_FORMAT_2":          "the marker of the .env layout",
	"CTRLZ_API_ARGON2_BUDGET_MIB": "a number", "CTRLZ_API_ARGON2_CONCURRENCY": "a number", "CTRLZ_ADMIN_ARGON2_BUDGET_MIB": "a number",
	"CTRLZ_API_DB_MAX_CONNS": "a number", "CTRLZ_ADMIN_DB_MAX_CONNS": "a number", "CTRLZ_WORKER_DB_MAX_CONNS": "a number", "CTRLZ_HUB_DB_MAX_CONNS": "a number",
	"GOMEMLIMIT_API": "a size", "GOMEMLIMIT_ADMIN": "a size",
	"CTRLZ_PG_CONN_ADMIN": "a number", "CTRLZ_PG_CONN_COMPILER": "a number", "CTRLZ_PG_CONN_HUB": "a number", "CTRLZ_PG_CONN_MIGRATOR": "a number",
	"CTRLZ_PG_CONN_TENANT": "a number", "CTRLZ_PG_CONN_TOOLS": "a number", "CTRLZ_PG_CONN_WORKER": "a number",
	"CTRLZ_PG_IDLE_TX_TIMEOUT": "a duration", "CTRLZ_PG_LOCK_TIMEOUT": "a duration", "CTRLZ_PG_STATEMENT_TIMEOUT": "a duration",
	"CTRLZ_PG_TX_TIMEOUT": "a duration", "CTRLZ_PG_WATCHDOG_INTERVAL": "a number", "CTRLZ_PG_WATCHDOG_MAX_BLOCK": "a number",
	"CTRLZ_PG_WATCHDOG_MAX_HOLD": "a number", "CTRLZ_PG_WATCHDOG_MAX_TX": "a number",
	"CH_MAX_SERVER_MEMORY_USAGE": "a number of bytes", "VALKEY_MAXMEMORY": "a size",
	"MEM_WEB": "a size", "MEM_CADDY": "a size", "MEM_API": "a size", "MEM_ADMIN": "a size", "MEM_WORKER": "a size", "MEM_HUB": "a size",
	"MEM_POSTGRES": "a size", "MEM_CLICKHOUSE": "a size", "MEM_VALKEY": "a size",
	"PG_EFFECTIVE_CACHE_SIZE": "a size", "PG_MAINTENANCE_WORK_MEM": "a size", "PG_MAX_CONNECTIONS": "a number", "PG_SHARED_BUFFERS": "a size",
	"PG_SHM_SIZE": "a size", "PG_WORK_MEM": "a size",
}

var composeVarRef = regexp.MustCompile(`\$(?:\{([A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_]*))`)

// composeHostVarProblems reads every scalar of the decoded document, keys and values, for a variable expansion
// that is not on the table, and says which listed variables it saw. It reads the YAML and not the lines: the
// first version cut each line at " #" as a trailing comment, but inside a quoted string (a command, an
// sh -c script) " #" is no comment and Compose still interpolates what follows, so
// `command: ["sh", "-c", "echo ok #${SMS_API_PASS}"]` was never judged (round 17 fix gate, admin-r17-19). A real
// comment is not a node of the document, so it is not read either. `$$` is Compose's own escape for a `$`
// the container's shell expands, and is no host variable.
func composeHostVarProblems(text string, allowed map[string]string) (problems []string, used map[string]bool) {
	used = map[string]bool{}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return []string{"docker-compose.yml: " + err.Error()}, used
	}
	seen := map[string]bool{}
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		if n.Kind == yaml.ScalarNode {
			for _, m := range composeVarRef.FindAllStringSubmatch(strings.ReplaceAll(n.Value, "$$", ""), -1) {
				name := m[1] + m[2]
				used[name] = true
				if _, ok := allowed[name]; !ok && !seen[name] {
					seen[name] = true
					problems = append(problems, "the file expands the host variable "+name+", which is not on composeHostVariables")
				}
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(&doc)
	return problems, used
}

// composeEnvProblems judges the Compose text against the tables it is given.
func composeEnvProblems(text string, goEnv map[string]string, goServices []string, table map[string]map[string]string, hostVars map[string]string) []string {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return []string{"docker-compose.yml: " + err.Error()}
	}
	services := composeMap(doc["services"])
	var out []string
	want := map[string]map[string]string{}
	for n, row := range table {
		want[n] = map[string]string{}
		for k, v := range row {
			want[n][k] = v
		}
	}
	for _, n := range goServices {
		if want[n] == nil {
			want[n] = map[string]string{}
		}
		for k, v := range goEnv {
			want[n][k] = v
		}
	}
	for n := range want {
		if _, ok := services[n]; !ok {
			out = append(out, "the table has a row for the service "+n+", which the file does not have")
		}
	}
	names := make([]string, 0, len(services))
	for n := range services {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s := composeMap(services[n])
		raw, has := s["environment"]
		row, inTable := want[n]
		if !has {
			if inTable && len(row) > 0 {
				out = append(out, n+" has no environment, and its row lists "+fmt.Sprint(len(row))+" variables")
			}
			continue
		}
		vars, isMap := raw.(map[string]any)
		if !isMap {
			out = append(out, n+" writes its environment as a list or a scalar; write a map, so each value is judged")
			continue
		}
		if !inTable {
			out = append(out, n+" has an environment and no row in the table")
			continue
		}
		mounted := map[string]bool{}
		secrets, _ := composeStrings(s["secrets"])
		for _, sec := range secrets {
			mounted[sec] = true
		}
		keys := make([]string, 0, len(vars))
		for k := range vars {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			val, scalar := vars[k].(string)
			if !scalar {
				// A number or a boolean written without quotes is a scalar too; compare its text.
				switch vars[k].(type) {
				case int, int64, float64, bool:
					val, scalar = fmt.Sprint(vars[k]), true
				}
			}
			if !scalar {
				out = append(out, fmt.Sprintf("%s: %s has a value that is not a scalar", n, k))
				continue
			}
			rule, ok := row[k]
			if !ok {
				if rule, ok = goEnvOf(want, goServices, n, k); !ok {
					out = append(out, fmt.Sprintf("%s: %s is not on its row of the environment table", n, k))
					continue
				}
			}
			if rule == composeEnvFile {
				sec := strings.TrimPrefix(val, "/run/secrets/")
				if !strings.HasSuffix(k, "_FILE") || sec == val || !mounted[sec] {
					out = append(out, fmt.Sprintf("%s: %s=%q must be /run/secrets/<a secret %s mounts> under a *_FILE name", n, k, val, n))
				}
				continue
			}
			if val != rule {
				out = append(out, fmt.Sprintf("%s: %s is %q, the table allows %q", n, k, val, rule))
			}
		}
		for k := range row {
			if _, ok := vars[k]; !ok {
				out = append(out, fmt.Sprintf("%s: the table lists %s, which the service does not have (a stale row lets it come back unseen)", n, k))
			}
		}
	}
	hostProblems, used := composeHostVarProblems(text, hostVars)
	out = append(out, hostProblems...)
	// A listed variable the file no longer uses is a way in that nobody reads any more (the list is the review).
	for name := range hostVars {
		if !used[name] {
			out = append(out, "composeHostVariables lists "+name+", which the file no longer expands: remove it")
		}
	}
	sort.Strings(out)
	return out
}

// goEnvOf returns the rule of a variable of the shared Go environment, for a service that takes it.
func goEnvOf(want map[string]map[string]string, goServices []string, svc, key string) (string, bool) {
	for _, g := range goServices {
		if g == svc {
			v, ok := want[svc][key]
			return v, ok
		}
	}
	return "", false
}

func realComposeText(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "compose", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestComposeEnvironmentIsAClosedTable(t *testing.T) {
	if p := composeEnvProblems(realComposeText(t), composeEnvGo, composeEnvGoServices, composeEnvTable, composeHostVariables); len(p) != 0 {
		t.Fatalf("%s", strings.Join(p, "\n"))
	}
}

func TestComposeEnvironmentLintCanFail(t *testing.T) {
	good := realComposeText(t)
	plant := func(old, repl string) string {
		if strings.Count(good, old) < 1 {
			t.Fatalf("the plant's anchor %q is not in the Compose file", old)
		}
		return strings.Replace(good, old, repl, 1)
	}
	cases := map[string]struct {
		text string
		want string
	}{
		"a credential through a name no list holds":     {plant("      CTRLZ_VALKEY_USER: api\n", "      CTRLZ_VALKEY_USER: api\n      CTRLZ_SMS_CRED: ${SMS_API_PASS}\n"), "CTRLZ_SMS_CRED is not on its row"},
		"a password through a short name":               {plant("      CTRLZ_VALKEY_USER: api\n", "      CTRLZ_VALKEY_USER: api\n      CTRLZ_DB_PASS: ${PG_PASS}\n"), "CTRLZ_DB_PASS is not on its row"},
		"a credential named AUTH":                       {plant("      CTRLZ_VALKEY_USER: api\n", "      CTRLZ_VALKEY_USER: api\n      VALKEY_AUTH: x\n"), "VALKEY_AUTH is not on its row"},
		"a literal under an _USER name":                 {plant("      CTRLZ_VALKEY_USER: api\n", "      CTRLZ_VALKEY_USER: hunter2\n"), `CTRLZ_VALKEY_USER is "hunter2"`},
		"a literal where a file belongs":                {plant("      CTRLZ_VALKEY_PASSWORD_FILE: /run/secrets/valkey_password_api\n", "      CTRLZ_VALKEY_PASSWORD_FILE: hunter2\n"), "must be /run/secrets/"},
		"a file of a secret the service does not mount": {plant("      CTRLZ_VALKEY_PASSWORD_FILE: /run/secrets/valkey_password_api\n", "      CTRLZ_VALKEY_PASSWORD_FILE: /run/secrets/valkey_password_admin\n"), "must be /run/secrets/"},
		"a file path outside the secrets directory":     {plant("      CTRLZ_VALKEY_PASSWORD_FILE: /run/secrets/valkey_password_api\n", "      CTRLZ_VALKEY_PASSWORD_FILE: /etc/passwd\n"), "must be /run/secrets/"},
		"a secret path under a name that is not _FILE":  {plant("      CTRLZ_VALKEY_PASSWORD_FILE: /run/secrets/valkey_password_api\n", "      CTRLZ_VALKEY_PASSWORD: /run/secrets/valkey_password_api\n"), "is not on its row"},
		"a changed value":                               {plant("      CTRLZ_VALKEY_ADDR: valkey-api:6379\n", "      CTRLZ_VALKEY_ADDR: valkey-admin:6379\n"), "the table allows"},
		"a changed default":                             {plant("${CTRLZ_API_DB_MAX_CONNS:-16}", "${CTRLZ_API_DB_MAX_CONNS:-160}"), "the table allows"},
		"a host variable swapped for another":           {plant("${CTRLZ_API_DB_MAX_CONNS:-16}", "${PG_PASS:-16}"), "PG_PASS"},
		"a variable the table lists and the file lost":  {plant("      CTRLZ_VALKEY_USER: api\n", ""), "the table lists CTRLZ_VALKEY_USER"},
		"an environment in the list form":               {plant("    environment:\n      VK_ZONE: api\n      VK_MAXMEMORY: ${VALKEY_MAXMEMORY:-64mb}\n", "    environment:\n      - VK_ZONE=api\n      - VK_MAXMEMORY=${VALKEY_MAXMEMORY:-64mb}\n"), "as a list or a scalar"},
		"a nested value":                                {plant("      VK_ZONE: api\n", "      VK_ZONE: {a: b}\n"), "not a scalar"},
		"an environment for a service with no row":      {plant("  web-panel:\n", "  web-panel:\n    environment:\n      A: b\n"), "has an environment and no row"},
		"a host variable in a command":                  {plant(`test: ["CMD", "node", "-e", "fetch(`, `test: ["CMD", "node", "-e", "${SMS_API_PASS}fetch(`), "SMS_API_PASS"},
		"a bare host variable in a limit":               {plant("mem_limit: ${MEM_WEB:-128m}", "mem_limit: $SMS_API_PASS"), "SMS_API_PASS"},
	}
	names := make([]string, 0, len(cases))
	for n := range cases {
		names = append(names, n)
	}
	sort.Strings(names)
	if p := composeEnvProblems(good, composeEnvGo, composeEnvGoServices, composeEnvTable, composeHostVariables); len(p) != 0 {
		t.Fatalf("the real file is refused: %v", p)
	}
	for _, n := range names {
		c := cases[n]
		p := composeEnvProblems(c.text, composeEnvGo, composeEnvGoServices, composeEnvTable, composeHostVariables)
		if !strings.Contains(strings.Join(p, "\n"), c.want) {
			t.Errorf("%s: want a problem with %q, got %v", n, c.want, p)
		}
	}
	// A row for a service the file does not have, and an escaped dollar that is no host variable.
	if p := composeEnvProblems(good, composeEnvGo, composeEnvGoServices, map[string]map[string]string{"ghost": {"A": "b"}}, composeHostVariables); !strings.Contains(strings.Join(p, "\n"), "which the file does not have") {
		t.Errorf("a row for a service the file lacks was accepted: %v", p)
	}
	if p, _ := composeHostVarProblems("command: [\"sh\", \"-c\", \"echo $$HOME ${CTRLZ_ENV:-x}\"]\n", composeHostVariables); len(p) != 0 {
		t.Errorf("an escaped dollar was read as a host variable: %v", p)
	}
	// Round 17 fix gate, admin-r17-19: a reference after " #" inside a quoted string is Compose's to expand; one
	// in a real comment is not.
	if p, _ := composeHostVarProblems("command: [\"sh\", \"-c\", \"echo ok #${SMS_API_PASS}\"]\n", composeHostVariables); !strings.Contains(strings.Join(p, "\n"), "SMS_API_PASS") {
		t.Errorf("a reference after ' #' inside a string was not judged: %v", p)
	}
	if p, _ := composeHostVarProblems("a: b # ${SMS_API_PASS}\n# ${OTHER}\n", composeHostVariables); len(p) != 0 {
		t.Errorf("a real comment was read as a reference: %v", p)
	}
	if p, _ := composeHostVarProblems("\"${SMS_API_PASS}\": x\n", composeHostVariables); !strings.Contains(strings.Join(p, "\n"), "SMS_API_PASS") {
		t.Errorf("a reference in a key was not judged: %v", p)
	}
	// A listed variable the file does not use is reported, and a fixture that lists a ghost shows it.
	if p := composeEnvProblems(realComposeText(t), composeEnvGo, composeEnvGoServices, composeEnvTable, map[string]string{"CTRLZ_GHOST_VARIABLE": "x"}); !strings.Contains(strings.Join(p, "\n"), "lists CTRLZ_GHOST_VARIABLE") {
		t.Errorf("a stale entry of composeHostVariables was accepted: %v", p)
	}
}

// TestComposeRefusesAnEnvFromAnEarlierLayout (admin-r17-6): an .env written before round 16 keeps floating image
// names and a Valkey memory size sized for one server, and Compose lets any variable override what the file
// says. The file carries a marker, `x-env-format: ${CTRLZ_ENV_FORMAT_N:?...}`, which Compose interpolates at
// load, so an .env without the variable of the current layout is refused by every compose command. The static
// half: the marker is there, names a variable that .env.example defines (the one place a fresh .env comes
// from, select-profile.sh included) and is on the host variable list. The live half runs `docker compose
// config` once with the marker and once without.
func TestComposeRefusesAnEnvFromAnEarlierLayout(t *testing.T) {
	text := realComposeText(t)
	m := regexp.MustCompile(`(?m)^x-env-format:\s*"\$\{([A-Z0-9_]+):\?[^}]+\}"\s*$`).FindStringSubmatch(text)
	if m == nil {
		t.Fatal("the Compose file has no x-env-format marker with a required variable: an .env of an earlier layout would be accepted")
	}
	name := m[1]
	if _, ok := composeHostVariables[name]; !ok {
		t.Errorf("the marker %s is not on composeHostVariables", name)
	}
	example, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "compose", ".env.example"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^` + name + `=\S+`).Match(example) {
		t.Fatalf(".env.example does not define %s: a fresh .env would be refused too", name)
	}
	if testing.Short() {
		t.Skip("-short: the live half needs Docker")
	}
	compose := filepath.Join(repoRoot(t), "deploy", "compose", "docker-compose.yml")
	dir := t.TempDir()
	without := filepath.Join(dir, "old.env")
	with := filepath.Join(dir, "new.env")
	if err := os.WriteFile(without, []byte("CTRLZ_IMAGE=ctrlz/panel:dev\nMEM_VALKEY=256m\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(with, []byte(name+"=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	run := func(envFile string) (string, error) {
		cmd := deploy.Docker(ctx, "compose", "config", "--quiet").WithCompose(compose, envFile)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := run(without); err == nil {
		t.Errorf("an .env of the earlier layout was accepted by docker compose:\n%s", out)
	} else if !strings.Contains(string(out), name) {
		t.Errorf("compose refused the old .env without naming the marker:\n%s", out)
	}
	if out, err := run(with); err != nil {
		t.Errorf("an .env with the marker was refused:\n%s", out)
	}
}
