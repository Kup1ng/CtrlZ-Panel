package lint_test

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The wiring of the postgres watchdog (P1 auth review round 16, db-r16-4). The watchdog is the one party
// a compromised service role does not control, and every fact that decides whether it RUNS lived in
// three places that nothing compared: the Compose entrypoint, mounts, environment and healthcheck, the
// paths and variable names inside the scripts, and the socket and peer rule of the server configuration.
// A typo in any of them left a healthy-looking container with no watchdog. The facts are read from the
// files and compared with each other; the behaviour is run against the pinned image by
// internal/store/catalogtest TestTheWatchdogRunsInTheContainerTheComposeFileStarts.
//
// Contract: this judges the postgres service of the Compose file and the three files it starts; it does
// not judge the image (a variant without gosu fails the healthcheck, which the container test shows for
// the pinned one).

// watchdogOperatorOnly are the variables the script reads that Compose does not pass, each with the reason.
var watchdogOperatorOnly = map[string]string{
	"CTRLZ_PG_WATCHDOG_ONCE":   "one sweep and exit: the test and an operator at a shell",
	"CTRLZ_PG_WATCHDOG_SQL":    "the test copies the SQL elsewhere; Compose mounts it at the script's own default",
	"CTRLZ_PG_WATCHDOG_SOCKET": "the test; the server's socket directory is the image's default",
	"CTRLZ_PG_WATCHDOG_BEAT":   "the test; the heartbeat file is private to the container",
}

type watchdogCompose struct {
	Services map[string]struct {
		Entrypoint  []string          `yaml:"entrypoint"`
		Volumes     []string          `yaml:"volumes"`
		Environment map[string]string `yaml:"environment"`
		Healthcheck struct {
			Test []string `yaml:"test"`
		} `yaml:"healthcheck"`
	} `yaml:"services"`
}

var (
	reDefault   = regexp.MustCompile(`\$\{([A-Z0-9_]+):-([^}]*)\}`)
	reScriptVar = regexp.MustCompile(`\$\{(CTRLZ_[A-Z0-9_]+):-([^}]*)\}`)
	reShWatch   = regexp.MustCompile(`sh\s+(/[^\s"']+/watchdog\.sh)`)
)

func TestComposeWiresTheWatchdog(t *testing.T) {
	root := repoRoot(t)
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, p := range watchdogWiringProblems(read("deploy/compose/docker-compose.yml"), read("deploy/compose/postgres/entrypoint.sh"),
		read("deploy/compose/postgres/watchdog.sh"), read("deploy/compose/postgres/pg_hba.conf"), read("deploy/compose/postgres/postgresql.conf"),
		func(dir string) []string { return listDir(t, filepath.Join(root, filepath.FromSlash(dir))) }) {
		t.Error(p)
	}
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// watchdogWiringProblems compares the facts. ls lists a directory of the repository relative to deploy/compose
// (the host side of a mount), so the test can plant a tree.
func watchdogWiringProblems(composeYAML, entrypoint, script, hba, conf string, ls func(dir string) []string) []string {
	var out []string
	problem := func(msg string) { out = append(out, "watchdog wiring: "+msg) }

	var c watchdogCompose
	if err := yaml.Unmarshal([]byte(composeYAML), &c); err != nil {
		return []string{"docker-compose.yml: " + err.Error()}
	}
	pg, ok := c.Services["postgres"]
	if !ok {
		return []string{"watchdog wiring: the compose file has no postgres service"}
	}

	// The entrypoint override runs a script that is mounted from this repository.
	if len(pg.Entrypoint) != 2 || pg.Entrypoint[0] != "sh" {
		problem("the postgres entrypoint must be [\"sh\", <script>] so the script runs without an executable bit")
		return out
	}
	mounts := map[string]string{} // container path -> host path
	for _, v := range pg.Volumes {
		parts := strings.Split(v, ":")
		if len(parts) >= 2 && strings.HasPrefix(parts[0], ".") {
			mounts[parts[1]] = parts[0]
		}
	}
	mustMount := func(containerPath, wantHost string) {
		host, ok := mounts[containerPath]
		switch {
		case !ok:
			problem(containerPath + " is not mounted into the postgres container")
		case path.Clean(host) != path.Clean(wantHost):
			problem(containerPath + " is mounted from " + host + ", want " + wantHost)
		}
	}
	mustMount(pg.Entrypoint[1], "./postgres/"+path.Base(pg.Entrypoint[1]))

	// The script the entrypoint starts is the one that is mounted, and every mention agrees.
	watch := map[string]bool{}
	for _, m := range reShWatch.FindAllStringSubmatch(entrypoint, -1) {
		watch[m[1]] = true
	}
	if len(watch) != 1 {
		problem("entrypoint.sh must name exactly one watchdog script path, it names " + strconv.Itoa(len(watch)))
	}
	for p := range watch {
		mustMount(p, "./postgres/watchdog.sh")
		// The healthcheck asks that same script.
		if !strings.Contains(strings.Join(pg.Healthcheck.Test, " "), "sh "+p+" --healthy") {
			problem("the postgres healthcheck does not run `sh " + p + " --healthy`, so a watchdog that does not run is invisible")
		}
	}

	// The SQL the script runs is mounted where the script looks, and exists.
	sqlDefault := ""
	for _, m := range reScriptVar.FindAllStringSubmatch(script, -1) {
		if m[1] == "CTRLZ_PG_WATCHDOG_SQL" {
			sqlDefault = m[2]
		}
	}
	if sqlDefault == "" {
		problem("watchdog.sh has no default for CTRLZ_PG_WATCHDOG_SQL")
	} else {
		dir, file := path.Split(sqlDefault)
		dir = strings.TrimSuffix(dir, "/")
		host, ok := mounts[dir]
		if !ok {
			problem("the directory " + dir + " of the watchdog's SQL is not mounted into the postgres container")
		} else if !contains(ls(path.Join("deploy/compose", host)), file) {
			problem("the watchdog's SQL " + file + " is not in the mounted directory " + host)
		}
	}

	// Every variable the script reads is passed by Compose, with the script's own default, or listed
	// as operator-only with a reason; every number is a whole number of at least one second.
	scriptVars := map[string]string{}
	for _, m := range reScriptVar.FindAllStringSubmatch(script, -1) {
		if strings.HasPrefix(m[1], "CTRLZ_PG_WATCHDOG_") {
			scriptVars[m[1]] = m[2]
		}
	}
	composeDefaults := map[string]string{}
	for name, val := range pg.Environment {
		if !strings.HasPrefix(name, "CTRLZ_PG_WATCHDOG_") {
			continue
		}
		m := reDefault.FindStringSubmatch(val)
		if m == nil || m[1] != name {
			problem(name + " must be passed as ${" + name + ":-default}, it is " + strconv.Quote(val))
			continue
		}
		composeDefaults[name] = m[2]
	}
	names := make([]string, 0, len(scriptVars))
	for n := range scriptVars {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		_, inCompose := composeDefaults[n]
		_, operator := watchdogOperatorOnly[n]
		switch {
		case !inCompose && !operator:
			problem("watchdog.sh reads " + n + ", which Compose does not pass and which is not listed as operator-only")
		case inCompose && composeDefaults[n] != scriptVars[n]:
			problem(n + " defaults to " + composeDefaults[n] + " in Compose and " + scriptVars[n] + " in the script: one decision, one number")
		}
	}
	for n := range composeDefaults {
		if _, read := scriptVars[n]; !read {
			problem("Compose passes " + n + ", which watchdog.sh does not read")
		}
	}
	num := func(name string) int {
		v, err := strconv.Atoi(composeDefaults[name])
		if err != nil || v < 1 {
			problem(name + " must default to a whole number of seconds, at least 1")
			return -1
		}
		return v
	}
	maxTx, block, every := num("CTRLZ_PG_WATCHDOG_MAX_TX"), num("CTRLZ_PG_WATCHDOG_MAX_BLOCK"), num("CTRLZ_PG_WATCHDOG_INTERVAL")
	hold := num("CTRLZ_PG_WATCHDOG_MAX_HOLD")
	// The bounds sit on the right side of the role defaults they back up (spec 2, db-r15-7, db-r16-3).
	secs := func(env string) int {
		m := reDefault.FindStringSubmatch(pg.Environment[env])
		if m == nil {
			problem("the postgres service has no " + env)
			return -1
		}
		v, err := strconv.Atoi(strings.TrimSuffix(m[2], "s"))
		if err != nil {
			problem(env + " must default to whole seconds, it is " + m[2])
			return -1
		}
		return v
	}
	if txTimeout := secs("CTRLZ_PG_TX_TIMEOUT"); txTimeout > 0 && maxTx > 0 && maxTx <= txTimeout {
		problem("the age bound (" + strconv.Itoa(maxTx) + " s) must be above the role's transaction_timeout (" + strconv.Itoa(txTimeout) + " s), or it ends honest transactions the server would have ended cleanly")
	}
	if txTimeout, lock := secs("CTRLZ_PG_TX_TIMEOUT"), secs("CTRLZ_PG_LOCK_TIMEOUT"); txTimeout > 0 && lock > 0 && hold > 0 {
		// An honest holder is as old as its transaction, and the one age it cannot pass is the
		// transaction_timeout that Postgres enforces (db-r17-16). lock_timeout bounds one WAIT, and a transaction
		// takes several and runs statements between them, so a hold bound derived from it (the first form: above
		// lock_timeout) ended honest holders that were making progress. Above the age bound it never fires.
		if hold <= txTimeout || hold <= lock {
			problem("the hold bound (" + strconv.Itoa(hold) + " s) must be above the roles' transaction_timeout (" + strconv.Itoa(txTimeout) + " s) and lock_timeout (" + strconv.Itoa(lock) + " s): an honest holder that makes progress would be ended")
		}
		if maxTx > 0 && hold >= maxTx {
			problem("the hold bound (" + strconv.Itoa(hold) + " s) must be below the age bound (" + strconv.Itoa(maxTx) + " s), or it never fires")
		}
	}
	if lock := secs("CTRLZ_PG_LOCK_TIMEOUT"); lock > 0 && block > 0 && every > 0 {
		if block >= lock {
			problem("the lock bound (" + strconv.Itoa(block) + " s) must be below the roles' lock_timeout (" + strconv.Itoa(lock) + " s): an honest waiter gives up before it counts as having waited")
		} else if block+every >= lock {
			problem("a sweep every " + strconv.Itoa(every) + " s with a lock bound of " + strconv.Itoa(block) + " s can miss a waiter that gives up after " + strconv.Itoa(lock) + " s")
		}
	}

	// The socket the script connects to is the one the server listens on, and peer authentication lets
	// the postgres OS user in as the superuser.
	sock := ""
	for _, m := range reScriptVar.FindAllStringSubmatch(script, -1) {
		if m[1] == "CTRLZ_PG_WATCHDOG_SOCKET" {
			sock = m[2]
		}
	}
	if m := regexp.MustCompile(`(?m)^\s*unix_socket_directories\s*=\s*'?([^'\n#]*)`).FindStringSubmatch(conf); m != nil {
		if !contains(strings.Split(strings.ReplaceAll(strings.TrimSpace(m[1]), " ", ""), ","), sock) {
			problem("postgresql.conf puts the socket in " + strings.TrimSpace(m[1]) + ", the watchdog connects to " + sock)
		}
	} else if sock != "/var/run/postgresql" {
		problem("the watchdog connects to " + sock + " but postgresql.conf leaves the image's default, /var/run/postgresql")
	}
	peer := false
	for _, ln := range strings.Split(hba, "\n") {
		f := strings.Fields(strings.TrimSpace(ln))
		if len(f) < 4 || strings.HasPrefix(f[0], "#") || f[0] != "local" {
			continue
		}
		// The first local line that can match the superuser decides.
		if (f[1] == "all" || f[1] == "postgres") && (f[2] == "postgres" || f[2] == "all") {
			peer = f[len(f)-1] == "peer"
			break
		}
	}
	if !peer {
		problem("pg_hba.conf does not let the postgres OS user in as the superuser by peer authentication over the socket: the first local line that can match it must say peer")
	}
	return out
}
