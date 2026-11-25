package lint_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Rule exposure-is-declared, the program a container runs (round 17 fix gate, admin-r17-20).
//
// The invariant: what a service runs, with which arguments, and how its health is asked, is a closed table
// somebody read. The command line of a process is public to every process of the host that can read /proc, and
// `docker inspect` prints it, so a credential in a `command`, an `entrypoint` or a `healthcheck` is the leak the
// Compose header forbids ("no password is a command-line argument"). Round 17 first replaced the word list of
// the environment judgement with the closed table of composeenv_test.go and, with it, deleted the old
// check of the command arguments (a word PASSWORD, SECRET, TOKEN or KEY next to an =), leaving all three keys
// judged by "other lints" that did not exist: `command: ["valkey-server", "--requirepass", "hunter2"]`
// passed. A word list for them would be the shape that was retired; the table is the review instead.
//
// What it judges, as an allow list that fails closed: for every service, the value of each of command,
// entrypoint and healthcheck (the whole map: test, interval, retries, ...) is encoded as JSON, whatever its
// YAML form, and its SHA-256 must be the one on composeCommandTable for that service and key. A service that
// has one of these keys and no row fails, a row for a key the service lacks fails, and so does a row for a
// service the file lacks. Any edit of the text of any of them is therefore a line of this table, and the
// failure prints the new text so that whoever updates the hash has read it: the table is not the review, the
// reading is, and the failure is what forces it.
//
// What it does not judge: what the program does with its arguments, the scripts the commands run (the shell
// lints judge them) and the environment (composeenv_test.go).

type composeCommandRow struct {
	sha256 string
	what   string
}

// composeCommandTable is every command, entrypoint and healthcheck of the Compose file, by "service.key".
var composeCommandTable = map[string]composeCommandRow{
	"admin.command":            {"c65da2d503b825520bce533f73d8ad25587b354e3f23b606f2e3df8b37c7a0a8", `the role name "admin"`},
	"admin.healthcheck":        {"4434da596e079e0e6ea634d3dbed48d7ac74b6050277533b5fab974657d0ae27", "the Go binary asks its own listener"},
	"api.command":              {"69a641e9f97ee422dc24d935c9f43e8f8f0c7ea923f1f04b78af58aa4ab340e7", `the role name "api"`},
	"api.healthcheck":          {"2d482f019e1994ec705b8d492432c19f19f5d97716c8e4a71c076f3906f063c4", "the Go binary asks its own listener"},
	"caddy-init.command":       {"bcb731514f0b4ad92cf19fe154c26221f7b7938994ea12a39fb8b753ba50d741", "chown of the two caddy state directories"},
	"clickhouse.entrypoint":    {"a43fd330ebbd54a0936be425eb530b1268e9fa95f9a2753e0c194a0252c85208", "the wrapper that writes the user file from the secret and starts the server"},
	"clickhouse.healthcheck":   {"11c236931b15870fdea63f710bea773fdca339ddec68eda8b66485966aae3f5e", "a ping of the server"},
	"domain-apply.command":     {"7feaf52df99945b2fc6c526de52d0a1db0580eaf7df30525ae59f68bf494c836", `the role name "domain-apply"`},
	"hub.command":              {"c83a78b2c174a7e283eca6d6714be591ff779bb2bc0c56bcea8f666dd7e71a2f", `the role name "hub"`},
	"hub.healthcheck":          {"e5ff5051a2dc7917567528ea3e6703ea82ce1c3705e25bd3ba22022564b589ed", "the Go binary asks its own listener"},
	"migrate.command":          {"7ebb53c1c877f87b553b96d49dea280b69b49701ae464a9da2eff7cfd6bb61cc", `the role name "migrate"`},
	"postgres.command":         {"ff8976d0a854bd19aac426b6dd3f2ea130ed2cff60bf678678560af39a0c942d", "the server's configuration flags (no password among them)"},
	"postgres.entrypoint":      {"b9d1f0f67732c7d25fd937d7038e7df2e9db915f7e0f79024ba46518b3363915", "the start script of the image"},
	"postgres.healthcheck":     {"c92ff73baaff5aaec2d4bdde10b7cb29f6b5a6e867a04ed87d327511ca4e3157", "pg_isready"},
	"rekey.command":            {"ccef35961dcf19749c4afccf30237393bb3b2431888f7e925e0e6fbf171ea288", `the role name "rekey"`},
	"valkey-admin.command":     {"21b2014a19450f5fbc6970895206dde5e461d138f2f72c35f55d8fb21e6dd236", "the start file, which reads the password from the secret"},
	"valkey-admin.healthcheck": {"a47cebf6fb862cf2deb16b5e330156f59019a952f17f9eba14faceb129d052bf", "the heartbeat file of the maintenance loop"},
	"valkey-api.command":       {"21b2014a19450f5fbc6970895206dde5e461d138f2f72c35f55d8fb21e6dd236", "the start file, which reads the password from the secret"},
	"valkey-api.healthcheck":   {"a47cebf6fb862cf2deb16b5e330156f59019a952f17f9eba14faceb129d052bf", "the heartbeat file of the maintenance loop"},
	"web-admin.healthcheck":    {"2150f598117c6177835bfaefc473d8904e3c02ac090bef97e57e1fd688c17975", "node asks the Next server for /fa/login on loopback"},
	"web-panel.healthcheck":    {"2150f598117c6177835bfaefc473d8904e3c02ac090bef97e57e1fd688c17975", "node asks the Next server for /fa/login on loopback"},
	"worker.command":           {"892fb3f00c2598ceea720fc08111c95e22b60b697205272619be4a94ae829ffa", `the role name "worker"`},
	"worker.healthcheck":       {"e357e4cfe5b71eef98772c3f9a19aecd77085dba0f9db23df3964eb6feac6c39", "the Go binary asks its own listener"},
}

// composeCommandKeys are the keys of a service that decide what runs in it.
var composeCommandKeys = []string{"command", "entrypoint", "healthcheck"}

// composeCommandProblems judges the text against a table.
func composeCommandProblems(text string, table map[string]composeCommandRow) []string {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return []string{"docker-compose.yml: " + err.Error()}
	}
	services := composeMap(doc["services"])
	var out []string
	seen := map[string]bool{}
	names := make([]string, 0, len(services))
	for n := range services {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s := composeMap(services[n])
		for _, k := range composeCommandKeys {
			v, has := s[k]
			if !has {
				continue
			}
			id := n + "." + k
			seen[id] = true
			j, err := json.Marshal(v)
			if err != nil {
				out = append(out, id+": "+err.Error())
				continue
			}
			sum := sha256.Sum256(j)
			row, ok := table[id]
			switch {
			case !ok:
				out = append(out, fmt.Sprintf("%s has no row in composeCommandTable; it runs %s (sha256 %s)", id, j, hex.EncodeToString(sum[:])))
			case row.sha256 != hex.EncodeToString(sum[:]):
				out = append(out, fmt.Sprintf("%s is not the text that was reviewed (%s); it is now %s (sha256 %s): read it for a credential and for what it runs, then update the table", id, row.what, j, hex.EncodeToString(sum[:])))
			}
		}
	}
	rows := make([]string, 0, len(table))
	for id := range table {
		rows = append(rows, id)
	}
	sort.Strings(rows)
	for _, id := range rows {
		if !seen[id] {
			out = append(out, "composeCommandTable lists "+id+", which the file does not have: remove the row, so that it cannot come back unseen")
		}
	}
	return out
}

func TestComposeCommandsAreAClosedTable(t *testing.T) {
	if p := composeCommandProblems(realComposeText(t), composeCommandTable); len(p) != 0 {
		t.Fatalf("%s", strings.Join(p, "\n"))
	}
}

func TestComposeCommandLintCanFail(t *testing.T) {
	good := realComposeText(t)
	plant := func(old, repl string) string {
		if strings.Count(good, old) < 1 {
			t.Fatalf("the plant's anchor %q is not in the Compose file", old)
		}
		return strings.Replace(good, old, repl, 1)
	}
	if p := composeCommandProblems(good, composeCommandTable); len(p) != 0 {
		t.Fatalf("the real file is refused: %v", p)
	}
	for name, c := range map[string]struct{ text, want string }{
		"a credential flag on a command":        {plant(`command: ["sh", "/etc/valkey/start.sh"]`, `command: ["valkey-server", "--requirepass", "hunter2"]`), "valkey-admin.command is not the text that was reviewed"},
		"a credential as an attached flag":      {plant(`command: ["api"]`, `command: ["api", "--password=hunter2"]`), "api.command is not the text that was reviewed"},
		"an entrypoint added to a service":      {plant(`command: ["worker"]`, `command: ["worker"]`+"\n    entrypoint: [\"x\"]"), "worker.entrypoint has no row"},
		"a web healthcheck that asks elsewhere": {plant("http://127.0.0.1:3000/fa/login", "http://example.invalid/fa/login"), "web-panel.healthcheck is not the text that was reviewed"},
		"a service with a new command":          {plant("  web-panel:\n", "  web-panel:\n    entrypoint: [\"sh\", \"-c\", \"echo hunter2\"]\n"), "web-panel.entrypoint has no row"},
	} {
		p := strings.Join(composeCommandProblems(c.text, composeCommandTable), "\n")
		if !strings.Contains(p, c.want) {
			t.Errorf("%s: want a problem with %q, got %q", name, c.want, p)
		}
	}
	// A row for a key a service lacks, and a row for a service the file lacks.
	extra := map[string]composeCommandRow{}
	for k, v := range composeCommandTable {
		extra[k] = v
	}
	extra["api.entrypoint"] = composeCommandRow{"0", "a stale row"}
	extra["ghost.command"] = composeCommandRow{"0", "a service that is gone"}
	p := strings.Join(composeCommandProblems(good, extra), "\n")
	for _, want := range []string{"lists api.entrypoint", "lists ghost.command"} {
		if !strings.Contains(p, want) {
			t.Errorf("a stale row was accepted: want %q in %q", want, p)
		}
	}
}
