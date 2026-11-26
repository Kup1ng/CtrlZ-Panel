package lint_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Round 14, admin-r14-8; rebuilt in round 16 (admin-r16-5). The Compose header says no password is an
// environment variable of a long-running process, and round 13 made the valkey start line hand the maintenance
// password to maintain.sh in REDISCLI_AUTH for the life of the container. Nothing compared the claim with the
// file. Round 14 wrote a lint that looked for a credential NAME (AUTH, PASS, PASSWORD, SECRET, TOKEN) in front of
// a command, and round 15 widened that list; `PW=$pw valkey-cli`, `MAINT=$pw sh x.sh &`, `API_KEY=$k curl`,
// `DBCRED=$c psql`, `KEY=$(cat /run/secrets/x) cmd` and `export pw=$x` all passed it. A guess at what a
// credential is called cannot end, so this is the other way round.
//
// The rule is about the shape that puts a value into a process's environment, whatever the variable is called
// and whatever it holds. Every word is unquoted first (`"PW=x"`, `'PW=x'` and `P"W"=x` are one word). In a line
// of any file under deploy/ or scripts/ (comments excepted; *.example, *.conf, *.lua, *.env and *.go are data
// and are not read; any other file is, HTML and XML included), these are problems unless the line is one of
// allowedEnvironmentAssignments, character for character, in its file, with the reason:
//
//  1. a command preceded by an assignment (`NAME=value cmd`);
//  2. an assignment in front of another word of a command, whoever the wrapper is (`command PW=1 cmd`,
//     `nohup env PW=x cmd`, `sudo PW=x cmd`, `xargs PW=x cmd`): the position is judged and not the name of the
//     wrapper, because a list of wrappers cannot be closed. An assignment whose previous word is a flag on
//     assignmentFlags (awk -v, --build-arg, --label) is that flag's value, and one that ends a command is data
//     (`echo X=1`); after any other flag it is an environment (`command -p PW=1 cmd`, `env -i PW=1 cmd`);
//  3. the words `export` and `env` anywhere in a command (`go env` excepted), `declare -x`, `typeset -x`,
//     `local -x`, `readonly -x`, `set -a` and `set -o allexport`;
//  4. the container flags `--env`, `--env-file` (also with an equals sign) in any command, and `-e` (alone or
//     with its value attached) in EVERY command whose first word is not on dashENeutral (test, [, grep, sed,
//     set, echo, printf, awk and the shells, where `-e` means something else), so a runtime reached through a
//     variable, a wrapper or a name nobody listed fails closed (round 17, admin-r17-9), and `sudo -E`;
//  5. the script given to `sh|bash|dash|ash|zsh|ksh -c` and the arguments of `eval`, when they are literals:
//     each is read as shell text of its own, nested as deep as it goes.
//
// A plain `name=value` on a line of its own is a shell variable and not an environment, so it is not examined;
// a command substitution inside a word is examined as a command of its own.
//
// What it judges: the text of those files as shell. What it does not: a script built at run time (`eval "$cmd"`,
// `sh -c "$cmd"`), where the assignment is not in the file; a variable exported by a sourced file; and YAML that is not shell (a Compose `environment:` map is data, judged by the secret lint of
// compose_test.go). The Compose header has to name each file under deploy/ that holds an allowed line.

// envWord is one shell word of a command text, with where it stood.
type envWord struct {
	text string
	sep  bool // a command separator (; & && | || ( ) newline), not a word
}

// shellWords splits text into words and separators. Single and double quotes, `${...}`, `$(...)` and backticks
// keep what they contain inside one word, so a space inside them splits nothing.
func shellWords(text string) []envWord {
	var out []envWord
	var cur strings.Builder
	has := false
	flush := func() {
		if has {
			out = append(out, envWord{text: cur.String()})
			cur.Reset()
			has = false
		}
	}
	rs := []rune(text)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == '\'':
			cur.WriteRune(c)
			has = true
			for i++; i < len(rs) && rs[i] != '\''; i++ {
				cur.WriteRune(rs[i])
			}
			if i < len(rs) {
				cur.WriteRune(rs[i])
			}
		case c == '"':
			cur.WriteRune(c)
			has = true
			depth := 0
			for i++; i < len(rs); i++ {
				if rs[i] == '\\' && i+1 < len(rs) {
					cur.WriteRune(rs[i])
					i++
					cur.WriteRune(rs[i])
					continue
				}
				if rs[i] == '$' && i+1 < len(rs) && rs[i+1] == '(' {
					depth++
				}
				if rs[i] == ')' && depth > 0 {
					depth--
				}
				if rs[i] == '"' && depth == 0 {
					break
				}
				cur.WriteRune(rs[i])
			}
			if i < len(rs) {
				cur.WriteRune(rs[i])
			}
		case c == '\\' && i+1 == len(rs):
			// A backslash that ends the text is a line continuation nobody joined: it is no word, so that a
			// command split over two lines is judged only by the joining of logicalLines.
		case c == '\\' && i+1 < len(rs):
			cur.WriteRune(c)
			i++
			cur.WriteRune(rs[i])
			has = true
		case c == '$' && i+1 < len(rs) && (rs[i+1] == '(' || rs[i+1] == '{'):
			open, shut := rs[i+1], ')'
			if open == '{' {
				shut = '}'
			}
			cur.WriteRune(c)
			has = true
			depth := 0
			for i++; i < len(rs); i++ {
				cur.WriteRune(rs[i])
				if rs[i] == open {
					depth++
				}
				if rs[i] == shut {
					depth--
					if depth == 0 {
						break
					}
				}
			}
		case c == '`':
			cur.WriteRune(c)
			has = true
			for i++; i < len(rs) && rs[i] != '`'; i++ {
				cur.WriteRune(rs[i])
			}
			if i < len(rs) {
				cur.WriteRune(rs[i])
			}
		case c == ' ' || c == '\t' || c == '\r':
			flush()
		case c == '\n' || c == ';' || c == '(' || c == ')':
			flush()
			out = append(out, envWord{sep: true, text: string(c)})
		case c == '&' || c == '|':
			flush()
			// && and || and | and & are all separators.
			for i+1 < len(rs) && (rs[i+1] == '&' || rs[i+1] == '|') {
				i++
			}
			out = append(out, envWord{sep: true, text: string(c)})
		case c == '#' && !has:
			// A comment runs to the end of the line.
			for i < len(rs) && rs[i] != '\n' {
				i++
			}
			i--
		default:
			cur.WriteRune(c)
			has = true
		}
	}
	flush()
	return out
}

var (
	assignmentWord = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\+?=`)
	// beforeCommand are the words after which a command starts.
	beforeCommand = map[string]bool{"{": true, "then": true, "do": true, "else": true, "elif": true, "if": true, "while": true, "until": true, "!": true, "time": true, "exec": true}
	// dashENeutral are the commands whose `-e` is known NOT to be a container's environment: test's file check,
	// grep's and sed's pattern or script, echo and printf's escapes, set and the shells' own flag. Round 17
	// (admin-r17-9) turned the judgement round: the list used to name the container runtimes (docker, podman,
	// nerdctl) and so failed open for a runtime reached through a variable (`"$docker" run -e PW=x`), a wrapper
	// (`exec`, `nohup`, `xargs`) or a tool nobody listed. `-e` now counts in every command that is not on this
	// list, so a command word that is unknown, a variable or new fails closed; a false hit is a line on
	// allowedEnvironmentAssignments with its reason, or a name added here with the reason it is not a runtime.
	dashENeutral = map[string]bool{"test": true, "[": true, "[[": true, "grep": true, "egrep": true, "fgrep": true, "sed": true,
		"set": true, "echo": true, "printf": true, "awk": true, "gawk": true, "sh": true, "bash": true, "dash": true, "ash": true,
		"zsh": true, "ksh": true}
	// assignmentFlags are the flags whose value is a NAME=value that is no environment: awk's variable, a build
	// argument, a label. An assignment after any other flag is an environment for what follows (`command -p
	// PW=1 cmd`, `env -i PW=1 cmd`), which the first version read as that flag's value and passed.
	assignmentFlags = map[string]bool{"-v": true, "--build-arg": true, "--label": true, "-l": true, "--annotation": true, "--set": true,
		"--sysctl": true, "--opt": true, "--driver-opt": true, "-o": true, "-c": true, "-F": true}
	// shellNames are the commands that run a script given as an argument (`sh -c '...'`).
	shellNames = map[string]bool{"sh": true, "bash": true, "dash": true, "ash": true, "zsh": true, "ksh": true}
	// privilegeWrappers are the commands whose `-E` keeps the caller's environment.
	privilegeWrappers = map[string]bool{"sudo": true, "doas": true}
	// attachedEnvName is `-eNAME`, the container flag with the name of a host variable attached. Upper case
	// only: `sh -ec` and `bash -eu` are shell flags.
	attachedEnvName   = regexp.MustCompile(`^-e[A-Z_][A-Z0-9_]*$`)
	attachedEnvAssign = regexp.MustCompile(`^-e[A-Za-z_][A-Za-z0-9_]*=`)
)

// unquote removes the quotes and backslashes of a shell word and keeps what they protect, so `"PW=x"`, `'PW=x'`
// and `P"W"=x` are all the word PW=x. A substitution is kept as written (innerCommands reads it from the raw
// word). It does not expand anything: a variable stays `$x`.
func unquote(w string) string {
	var b strings.Builder
	rs := []rune(w)
	for i := 0; i < len(rs); i++ {
		switch c := rs[i]; {
		case c == '\'':
			for i++; i < len(rs) && rs[i] != '\''; i++ {
				b.WriteRune(rs[i])
			}
		case c == '"':
			for i++; i < len(rs) && rs[i] != '"'; i++ {
				if rs[i] == '\x5c' && i+1 < len(rs) {
					i++
				}
				b.WriteRune(rs[i])
			}
		case c == '\x5c' && i+1 < len(rs):
			i++
			b.WriteRune(rs[i])
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// innerCommands returns the text of every `$(...)` and backtick substitution of a word, outermost only (the
// recursion in environmentProblems finds the rest).
func innerCommands(w string) []string {
	var out []string
	rs := []rune(w)
	for i := 0; i < len(rs); i++ {
		if rs[i] == '\'' {
			for i++; i < len(rs) && rs[i] != '\''; i++ {
			}
			continue
		}
		if rs[i] == '$' && i+1 < len(rs) && rs[i+1] == '(' {
			depth, start := 0, i+2
			for j := i + 1; j < len(rs); j++ {
				if rs[j] == '(' {
					depth++
				}
				if rs[j] == ')' {
					depth--
					if depth == 0 {
						out = append(out, string(rs[start:j]))
						i = j
						break
					}
				}
			}
		} else if rs[i] == '`' {
			j := i + 1
			for ; j < len(rs) && rs[j] != '`'; j++ {
			}
			out = append(out, string(rs[i+1:j]))
			i = j
		}
	}
	return out
}

// baseName is the command a path word names: /usr/bin/docker is docker.
func baseName(w string) string {
	if i := strings.LastIndex(w, "/"); i >= 0 {
		return w[i+1:]
	}
	return w
}

// environmentProblems reports each way a text gives a command an environment of its own.
func environmentProblems(text string) []string {
	words := shellWords(text)
	var out []string
	for i := 0; i < len(words); {
		// At the start of a command: skip the words that only say a command follows.
		for i < len(words) && (words[i].sep || beforeCommand[words[i].text]) {
			i++
		}
		if i >= len(words) {
			break
		}
		start := i
		// The words of this command, unquoted, up to the next separator.
		end := i
		for end < len(words) && !words[end].sep {
			end++
		}
		cmdWords := words[start:end]
		un := make([]string, len(cmdWords))
		for k, w := range cmdWords {
			un[k] = unquote(w.text)
		}
		// An assignment before the command (`NAME=value cmd`) is the environment of that command; a line of
		// assignments and nothing else is the shell's own variables.
		lead := 0
		for lead < len(un) && assignmentWord.MatchString(un[lead]) {
			lead++
		}
		if lead > 0 && lead < len(un) {
			out = append(out, "an assignment before a command ("+un[0][:strings.Index(un[0], "=")]+"=... "+un[lead]+")")
		}
		// An assignment that stands directly in front of another word of the command is an environment for
		// whatever runs next, whoever the wrapper is: `command PW=1 cmd`, `nohup env PW=x cmd`, `sudo PW=x cmd`,
		// `xargs PW=x cmd`. A list of wrappers cannot be closed, so the position is judged and not the name.
		// An assignment whose previous word is a flag is that flag's value (`awk -v n=1 prog`,
		// `docker build --build-arg X=1 .`) and one that ends the command is data (`ARG X=1`, `echo X=1`).
		for k := lead + 1; k < len(un); k++ {
			if !assignmentWord.MatchString(un[k]) {
				continue
			}
			j := k
			for j < len(un) && assignmentWord.MatchString(un[j]) {
				j++
			}
			if j < len(un) && !strings.HasPrefix(un[j], "-") && !assignmentFlags[un[k-1]] {
				out = append(out, "an assignment in front of another word ("+un[k][:strings.Index(un[k], "=")]+"=... "+un[j]+") is an environment for what runs next")
			}
			k = j - 1
		}
		// `-e` counts in every command whose first word is not known to give it another meaning.
		dashE := lead >= len(un) || !dashENeutral[baseName(un[lead])]
		for k, w := range un {
			if k < lead {
				continue
			}
			switch {
			case w == "export" || (w == "env" && !(k > 0 && un[k-1] == "go")):
				// `go env` prints the toolchain's settings and is no environment, so it is the one command
				// the word is read around.
				out = append(out, w+" gives the commands after it an environment")
			case w == "declare" || w == "typeset" || w == "local" || w == "readonly":
				for _, f := range un[k+1:] {
					if strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "--") && strings.Contains(f, "x") {
						out = append(out, w+" -x exports a variable")
					}
				}
			case w == "set":
				for j, f := range un[k+1:] {
					if (strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "--") && strings.Contains(f, "a")) ||
						(f == "-o" && k+j+2 < len(un) && un[k+j+2] == "allexport") {
						out = append(out, "set -a exports every variable that is assigned after it")
					}
				}
			case w == "--env" || w == "--env-file" || strings.HasPrefix(w, "--env=") || strings.HasPrefix(w, "--env-file="):
				out = append(out, w+" puts values in a container's environment")
			case dashE && (w == "-e" || attachedEnvName.MatchString(w) || attachedEnvAssign.MatchString(w)):
				out = append(out, w+" puts a value in a container's environment")
			case (w == "-E" || w == "--preserve-env" || strings.HasPrefix(w, "--preserve-env=")) && anyWord(un, privilegeWrappers):
				out = append(out, w+" keeps the caller's environment through a privilege wrapper")
			case w == "eval":
				// The arguments of eval are shell text of their own.
				out = append(out, environmentProblems(strings.Join(un[k+1:], " "))...)
			case shellNames[baseName(w)]:
				// A script given to a shell is shell text of its own: `sh -c 'PW=$x cmd'`, `bash -ec "..."`.
				for j := k + 1; j+1 < len(un); j++ {
					if un[j] == "-c" || (strings.HasPrefix(un[j], "-") && !strings.HasPrefix(un[j], "--") && strings.HasSuffix(un[j], "c")) {
						out = append(out, environmentProblems(un[j+1])...)
						break
					}
				}
			}
		}
		for _, w := range cmdWords {
			for _, inner := range innerCommands(w.text) {
				out = append(out, environmentProblems(inner)...)
			}
		}
		i = end
	}
	return out
}

func anyWord(words []string, set map[string]bool) bool {
	for _, w := range words {
		if set[baseName(w)] {
			return true
		}
	}
	return false
}

// allowedEnvironmentAssignments maps a file, relative to the repository root, to the lines of it that may give
// a command an environment, each with the reason it is safe. A file under deploy/ that is listed has to be
// named in the Compose header. Scripts under scripts/ run on the host or in CI for the length of one command; they
// are listed too, so a new line is a reviewed line.
var allowedEnvironmentAssignments = map[string]map[string]string{
	"deploy/compose/valkey/maintain.sh": {
		`cli() { REDISCLI_AUTH=$pw valkey-cli -h 127.0.0.1 -p "$port" --user "$user" --no-auth-warning "$@"; }`: "the password is a variable of the " +
			"loop's shell and is never exported; it is in the environment of one valkey-cli for the length of one command, which is no " +
			"long-running process",
	},
	"deploy/compose/valkey/start.sh": {
		`MAINT_USER=maint sh /etc/valkey/maintain.sh &`: "the value is the name of the maintenance user, not a credential; the password " +
			"is handed over in a file that maintain.sh reads once and deletes",
	},
	// The scripts run on the host or in CI, one command at a time. None of these values is a credential: a toolchain
	// switch, a flag for Git Bash, a path, a list of names, or the name of the image under test.
	"scripts/ci.sh": {
		`export PATH="$gobin:$PATH"`:                               "the tool directory of the Go install, a path",
		`GOOS=linux go vet ./...`:                                  "the target of a vet run",
		`export CTRLZ_IMAGE="$image"`:                              "the name of the image under test",
		`export CTRLZ_CI=1`:                                        "a switch for the tests of this run",
		`CTRLZ_IMAGE="$image" sh "$here/scripts/compose-smoke.sh"`: "the name of the image under test",
	},
	// The web gate (P1 web merge): one script on the host or the CI runner that builds the web images, brings the e2e
	// stack up and runs Playwright against it, a command at a time. Nothing here is a long-running process: a toolchain
	// switch, a test flag, a path, or the name of the image. The one credential-like value is the login of the e2e user,
	// which the seed made for a throw-away stack whose SMS driver is `noop` and whose database is removed at the end of
	// the run (ci-web.sh traps it); it reaches the short-lived browser test and no container.
	"scripts/ci-web.sh": {
		`export MSYS_NO_PATHCONV=1`:                                        "a Git Bash path-conversion switch",
		`export NEXT_TELEMETRY_DISABLED=1`:                                 "a switch that turns Next's telemetry off, which the run must not send",
		`export NODE_OPTIONS`:                                              "the heap size of the build, exported under a name set a few lines above; a number",
		`(cd "apps/$app" && E2E_START_SERVER=1 pnpm exec playwright test)`: "a flag for the test run: start `next start` on its own port",
		`(cd "apps/$app" && CTRLZ_VERIFY_ORIGIN='https://*.verify.dns.example.test' E2E_START_SERVER=1 pnpm exec playwright test headers.spec.ts --project=functional)`: "a host pattern " +
			"on a reserved name, for the header spec of the web proxy; no credential",
		`CTRLZ_WEB_DEPS_IMAGE="$deps_image" sh scripts/web-deps-stamp.sh`: "the name of a local image",
		`{ grep -hv '^#' deploy/compose/.env.example deploy/compose/profiles/small.env | grep -v '^$' \`: "the substitution file of the throw-away e2e project: the path " +
			"of its secrets directory, which the line writes into a file and no container's environment",
		`docker compose -p "$project" $files --env-file "$work/env" down -v --remove-orphans >/dev/null 2>&1 || true`: "Compose's own --env-file: the substitution file of the e2e project (names, ports, a path)",
		`docker compose -p "$project" -f deploy/compose/docker-compose.yml -f deploy/compose/e2e.yml -f deploy/compose/e2e-offline.yml --env-file "$work/env" "$@"`: "Compose's own " +
			"--env-file: the substitution file of the e2e project",
		`docker compose -p "$project" $files --env-file "$work/env" "$@"`:                                                                             "Compose's own --env-file: the substitution file of the e2e project",
		`(cd apps/panel && E2E_CTRLZ_VERSION="$web_version" E2E_BASE_URL=https://panel.localhost pnpm exec playwright test --project=w1280-fa-light)`: "the version the image was built with, and the address the browser test opens",
		`(cd "apps/$app" && E2E_CTRLZ_VERSION="$web_version" E2E_BASE_URL="https://$app.localhost" pnpm exec playwright test $projects)`:              "the version the image was built with, and the address the browser test opens",
		`(cd "apps/$app" && E2E_STALLED_POST=1 E2E_BASE_URL="https://$app.localhost" pnpm exec playwright test headers.spec.ts --project=functional -g "never finished")`: "two switches " +
			"of one spec, and the address",
		`(cd "apps/$app" && E2E_UPSTREAM_STOPPED=1 E2E_BASE_URL="https://$app.localhost" pnpm exec playwright test headers.spec.ts --project=functional -g "own 502 or 504")`: "two switches " +
			"of one spec, and the address",
		`CTRLZ_VERIFY_ORIGIN='https://not-a-verify-host.example' web_compose up -d --force-recreate --no-deps web-panel`: "a host name on a reserved domain, set to prove the web healthcheck goes unhealthy",
		`node scripts/e2e-seed.mjs --env-file "$work/env" --out "$work/seed" > /dev/null`: "Compose's --env-file handed to the seed script: " +
			"a file of names, ports and a path",
		`E2E_PHONE=$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).user.phone)' "$E2E_SEED_FILE")`: "node's -e is its eval flag; this reads the " +
			"phone number of the throw-away e2e user from the seed file",
		`E2E_PASSWORD=$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).user.password)' "$E2E_SEED_FILE")`: "node's -e is its eval flag; this reads the " +
			"login password of the throw-away e2e user from the seed file, a value that exists for the length of one run on a stack that is removed at its end",
		`export E2E_SEED_FILE E2E_PHONE E2E_PASSWORD`:                  "hands the e2e user's login to the short-lived browser test (not a container), see the note above",
		`(cd "apps/$app" && E2E_MODE=stack pnpm exec playwright test)`: "a switch for the test run",
	},
	"scripts/web-deps-stamp.sh": {`export MSYS_NO_PATHCONV=1`: "a Git Bash path-conversion switch"},
	"scripts/compose-net-test.sh": {
		`export MSYS_NO_PATHCONV=1`: "a Git Bash path-conversion switch",
		`if [ -n "$envfile" ]; then docker compose -p "$project" -f "$file" --env-file "$envfile" "$@"`: "Compose's own --env-file: the " +
			"substitution file of a throw-away project (image names, ports, a directory path), which sets no container's environment",
		`dc exec -T "$1" node -e "const s=require('net').connect({host:'$2',port:$3,timeout:2000});s.on('connect',()=>process.exit(0));s.on('error',()=>process.exit(1));s.on('timeout',()=>process.exit(1))"`: "node's -e is its eval flag: " +
			"the probe script runs in the web container and sets no environment (the command word is a function, which the lint cannot know)",
	},
	"deploy/docker/web.Dockerfile": {
		`RUN NEXT_PUBLIC_CTRLZ_VERSION="$CTRLZ_VERSION" pnpm --filter "@ctrlz/$APP" build`: "the version string of the build, which a NEXT_PUBLIC name " +
			"puts into the browser bundle on purpose, so it can never be a credential; the build stage is not the image that ships",
	},
	"deploy/docker/Dockerfile": {
		`RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/ctrlz ./cmd/ctrlz \`: "toolchain switches of the build " +
			"stage, no credential, and the stage is not in the image that ships",
	},
	"scripts/compose-smoke.sh": {
		`dc() { docker compose -p "$project" -f deploy/compose/docker-compose.yml -f deploy/compose/ci-placeholder.yml --env-file "$(host_path "$envfile")" "$@"; }`: "Compose's own " +
			"--env-file: the substitution file of the throw-away project, made by this script from image names, ports and a directory path; " +
			"ci-placeholder.yml is a static override of the two web services (no credential), which the file's own header explains",
		`export MSYS_NO_PATHCONV=1`:                                                             "a Git Bash path-conversion switch",
		`export CTRLZ_CANARY_RUNTIME_DIR="$runtime"`:                                            "a directory path read by secret-canary.sh, which holds the values it looks for",
		`export CTRLZ_CANARY_CONSUMERS="$consumers"`:                                            "the path of the list of logs the canary reads",
		`export CTRLZ_CANARY_UNCONSUMED="kek_root kek_cert_wrap policy_key_pub web_intake_key"`: "the names of secrets no container may hold, not their values",
		`export CTRLZ_COMPOSE_ENV="$(host_path "$envfile")"`:                                    "the path of the environment file of the run",
	},
	"scripts/gen-secrets.sh":  {`MSYS_NO_PATHCONV=1 docker run --pull never --rm --network none --read-only --cap-drop ALL \`: "a Git Bash path-conversion switch for one docker run"},
	"scripts/go-pin-check.sh": {`have=$(GOTOOLCHAIN=local go env GOVERSION)`: "asks the host compiler, not a downloaded one"},
	"scripts/image-smoke.sh": {
		`export MSYS_NO_PATHCONV=1   # Git Bash on Windows rewrites /usr/... arguments otherwise`: "a Git Bash path-conversion switch",
		`built=$(GOTOOLCHAIN=local go version "$native" 2>/dev/null | awk '{print $2}')`:          "asks the host compiler, not a downloaded one",
	},
	"scripts/proto-baseline/move.sh": {`export PATH="$(go env GOPATH)/bin:$PATH"`: "the tool directory of the Go install, a path"},
	"scripts/secret-canary.sh": {
		`tr -d '\r' < "$f" | while IFS= read -r line || [ -n "$line" ]; do`: "IFS is emptied for one read, so a line keeps its blanks",
		`while IFS= read -r line; do`:                                       "IFS is emptied for one read, so a line keeps its blanks",
	},
}

// logicalLines joins a line that ends in a backslash with the next one, as the shell does, and returns each
// logical line with the number and the text of its first physical line (what the allow list names).
func logicalLines(text string) (nums []int, firsts, joined []string) {
	phys := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i := 0; i < len(phys); i++ {
		first := strings.TrimSpace(phys[i])
		all := phys[i]
		for strings.HasSuffix(strings.TrimRight(all, " \t"), "\\") && i+1 < len(phys) {
			all = strings.TrimSuffix(strings.TrimRight(all, " \t"), "\\") + " " + phys[i+1]
			i++
		}
		nums = append(nums, i+1)
		firsts = append(firsts, first)
		joined = append(joined, all)
	}
	return nums, firsts, joined
}

// environmentLineProblems returns the lines of one file that give a command an environment and are not allowed.
func environmentLineProblems(rel, text string) []string {
	var out []string
	nums, firsts, joined := logicalLines(text)
	for k := range joined {
		trim := strings.TrimSpace(joined[k])
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		// Compose writes a literal dollar as two.
		probs := environmentProblems(strings.ReplaceAll(trim, "$$", "$"))
		if len(probs) == 0 {
			continue
		}
		if _, ok := allowedEnvironmentAssignments[rel][firsts[k]]; ok {
			continue
		}
		sort.Strings(probs)
		out = append(out, rel+":"+itoa(nums[k])+": "+strings.Join(probs, "; ")+" in a line that is not on the list")
	}
	return out
}

func TestNoPasswordIsAnEnvironmentOfALongRunningProcess(t *testing.T) {
	root := repoRoot(t)
	seen := map[string]map[string]bool{}
	for _, dir := range []string{"deploy", "scripts"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if strings.HasSuffix(p, ".example") || strings.HasSuffix(p, ".conf") || strings.HasSuffix(p, ".lua") || strings.HasSuffix(p, ".env") || strings.HasSuffix(p, ".go") {
				return nil // a template or a file of values is data, not a command
			}
			// A Node script is not shell: its `export` is the ES module keyword (the .d.mts files declare exports in
			// nearly every line) and this lint reads a line as the shell would. What a Node script puts in a child's
			// environment is not judged here.
			if strings.HasSuffix(p, ".mjs") || strings.HasSuffix(p, ".mts") || strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".ts") {
				return nil
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			for _, problem := range environmentLineProblems(rel, string(b)) {
				t.Error(problem)
			}
			for _, ln := range strings.Split(string(b), "\n") {
				if _, ok := allowedEnvironmentAssignments[rel][strings.TrimSpace(ln)]; ok {
					if seen[rel] == nil {
						seen[rel] = map[string]bool{}
					}
					seen[rel][strings.TrimSpace(ln)] = true
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// Every other shell file of the tree (round 17 fix gate, admin-r17-24): the two directories above were a guess
	// at where shell lives, and migrations/postgres/bootstrap/*.sh and .githooks/pre-commit were outside it, so a
	// `PGPASSWORD=$pw psql` added to a repair script that runs in the postgres container was never read. A shell
	// file is one that is named .sh or starts with a shell shebang, found by walking the tree.
	skip := map[string]bool{".git": true, "node_modules": true, "docs": true, "apps": true, "packages": true, ".claude": true, ".codegraph": true, "testdata": true}
	shellFiles := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			// unreadRel is the one list of the places of the tree that are other people's files (gotree_test.go):
			// the published tree carries the CI overlay .github/ci, whose scripts run on the runner with no
			// password in any environment and which the publish gate judges. Reading it here failed the
			// published tree on the runner (run 44855288724) although the workspace tree passed.
			if skip[d.Name()] || unreadRel(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(rel, "deploy/") || strings.HasPrefix(rel, "scripts/") {
			return nil // judged above
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		first, _, _ := strings.Cut(string(b), "\n")
		if !strings.HasSuffix(p, ".sh") && !(strings.HasPrefix(first, "#!") && (strings.Contains(first, "sh") || strings.Contains(first, "bash"))) {
			return nil
		}
		shellFiles++
		for _, problem := range environmentLineProblems(rel, string(b)) {
			t.Error(problem)
		}
		for _, ln := range strings.Split(string(b), "\n") {
			if _, ok := allowedEnvironmentAssignments[rel][strings.TrimSpace(ln)]; ok {
				if seen[rel] == nil {
					seen[rel] = map[string]bool{}
				}
				seen[rel][strings.TrimSpace(ln)] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if shellFiles < 3 {
		t.Fatalf("only %d shell files were found outside deploy/ and scripts/: the walk no longer sees migrations/postgres/bootstrap and .githooks", shellFiles)
	}
	// A listed line that no file has is an exception someone may bring back without the lint noticing.
	for rel, lines := range allowedEnvironmentAssignments {
		for ln := range lines {
			if !seen[rel][ln] {
				t.Errorf("%s: the allowed line %q is not in the file; remove it from the list", rel, ln)
			}
		}
	}
	// Every line of the list has its reason.
	for rel, lines := range allowedEnvironmentAssignments {
		for ln, why := range lines {
			if strings.TrimSpace(why) == "" {
				t.Errorf("%s: the allowed line %q has no reason", rel, ln)
			}
		}
	}
	// The header states the rule and has to name the exception of every file under deploy/.
	b, err := os.ReadFile(filepath.Join(root, "deploy", "compose", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	header, _, _ := strings.Cut(string(b), "\nname: ctrlz")
	for rel := range allowedEnvironmentAssignments {
		if strings.HasPrefix(rel, "deploy/") && !strings.Contains(header, filepath.Base(rel)) {
			t.Errorf("the Compose header does not name %s, which holds an allowed environment assignment", rel)
		}
	}
}

// TestCredentialAssignmentCheckCanFail plants every shape the rule must refuse, whatever the variable is
// called and whatever it holds, and the shapes that are no environment at all.
func TestCredentialAssignmentCheckCanFail(t *testing.T) {
	allowedLine := `cli() { REDISCLI_AUTH=$pw valkey-cli -h 127.0.0.1 -p "$port" --user "$user" --no-auth-warning "$@"; }`
	for _, tc := range []struct {
		name, file, text string
		bad              bool
	}{
		{"the round 13 start line", "deploy/compose/docker-compose.yml", `REDISCLI_AUTH="$$maint_pw" VALKEYCLI_AUTH="$$maint_pw" MAINT_USER=maint sh /etc/valkey/maintain.sh &`, true},
		{"the same line in its file", "deploy/compose/valkey/maintain.sh", allowedLine, false},
		{"the same line in another file", "scripts/x.sh", allowedLine, true},
		{"a line like it with a flag more", "deploy/compose/valkey/maintain.sh", `cli() { REDISCLI_AUTH=$pw valkey-cli -a x "$@"; }`, true},
		{"export of a password", "scripts/x.sh", `export PGPASSWORD=x`, true},
		// The names round 15 still let through: none of them has one of the five words.
		{"PW", "scripts/x.sh", `PW=$maint_pw valkey-cli ping`, true},
		{"MAINT", "scripts/x.sh", `MAINT=$pw sh x.sh &`, true},
		{"API_KEY", "scripts/x.sh", `API_KEY=$k curl -s http://127.0.0.1/x`, true},
		{"DBCRED", "scripts/x.sh", `DBCRED=$c psql`, true},
		{"KEY from a secret file", "scripts/x.sh", `KEY=$(cat /run/secrets/x) cmd`, true},
		{"a lower case export with a value", "scripts/x.sh", `export pw=$x`, true},
		{"a lower case export by name", "scripts/x.sh", `export pw`, true},
		{"a name that says nothing", "scripts/x.sh", `A=$(cat /run/secrets/x) tool &`, true},
		{"a lower case prefix", "scripts/x.sh", `pw=$x valkey-cli ping`, true},
		{"a harmless looking name", "scripts/x.sh", `PORT=8080 app`, true},
		{"several assignments", "scripts/x.sh", `A=1 B=2 C=3 tool`, true},
		{"after a semicolon", "scripts/x.sh", `cd /tmp; X=1 psql`, true},
		{"after &&", "scripts/x.sh", `true && X=1 psql`, true},
		{"after a pipe", "scripts/x.sh", `echo | X=1 cmd`, true},
		{"after then", "scripts/x.sh", `if true; then X=1 cmd; fi`, true},
		{"in a function body", "scripts/x.sh", `f() { X=1 cmd; }`, true},
		{"inside a command substitution", "scripts/x.sh", `out=$(X=1 cmd arg)`, true},
		{"inside a quoted command substitution", "scripts/x.sh", `echo "$(X=1 cmd arg)"`, true},
		{"inside backticks", "scripts/x.sh", "out=`X=1 cmd`", true},
		{"nested substitutions", "scripts/x.sh", `a=$(b=$(X=1 cmd) other)`, true},
		{"env", "scripts/x.sh", `env X=1 cmd`, true},
		{"env with no assignment", "scripts/x.sh", `env -i cmd`, true},
		{"declare -x", "scripts/x.sh", `declare -x X=1`, true},
		{"typeset -x", "scripts/x.sh", `typeset -ix X=1`, true},
		{"docker run -e", "scripts/x.sh", `docker run --rm -e PW=$x img`, true},
		{"docker run --env", "scripts/x.sh", `docker run --env PW=$x img`, true},
		{"docker run --env=", "scripts/x.sh", `docker run --env=PW=$x img`, true},
		{"a quoted value with spaces", "scripts/x.sh", `X="a b c" cmd`, true},
		{"a line continuation does not hide the command", "scripts/x.sh", "X=1 \\\ncmd", true},
		// Not an environment.
		{"a comment", "scripts/x.sh", `# REDISCLI_AUTH=x valkey-cli`, false},
		{"a plain variable", "scripts/x.sh", `pw=$(cat f)`, false},
		{"several plain variables", "scripts/x.sh", `a=1 b=2 c=3`, false},
		{"a substitution result", "scripts/x.sh", `r=$(cli ping 2>&1)`, false},
		{"an assignment in a case arm", "scripts/x.sh", `*[!0-9]*) ok=0; bad="$bad x" ;;`, false},
		// An assignment in front of another word is an environment whoever the wrapper is, so the one position
		// that looks like data (`echo FOO=bar baz`) is judged too: it is `command FOO=bar baz` by another name.
		{"an assignment in front of an argument of echo", "scripts/x.sh", `echo FOO=bar baz`, true},
		{"an assignment that ends the command is data", "scripts/x.sh", `echo FOO=bar`, false},
		// Round 16, admin-r16-16: the shapes the first rebuild still let through.
		{"-e with a quoted assignment", "scripts/x.sh", `docker run -e "PW=x" img`, true},
		{"-e with a single quoted assignment", "scripts/x.sh", `docker run -e 'PW=x' img`, true},
		{"-e with the assignment attached", "scripts/x.sh", `docker run -ePW=x img`, true},
		{"-e that passes a host variable by name", "scripts/x.sh", `docker run -e PW img`, true},
		{"-e attached that passes a host variable", "scripts/x.sh", `docker run -ePW img`, true},
		{"--env-file", "scripts/x.sh", `docker run --env-file /run/secrets/x img`, true},
		{"--env-file with an equals sign", "scripts/x.sh", `docker run --env-file=/x img`, true},
		{"--env with a quoted assignment", "scripts/x.sh", `docker run --env "PW=x" img`, true},
		{"podman -e", "scripts/x.sh", `podman run -e PW=x img`, true},
		{"a runtime by its path", "scripts/x.sh", `/usr/bin/docker run -e PW=x img`, true},
		{"sh -c with an assignment", "scripts/x.sh", `sh -c 'PW=$x valkey-cli ping'`, true},
		{"bash -c in double quotes", "scripts/x.sh", `bash -c "PW=$x cmd"`, true},
		{"bash -ec", "scripts/x.sh", `bash -ec 'PW=x cmd'`, true},
		{"sh -c inside a container command", "scripts/x.sh", `docker run --rm img sh -c 'PW=x valkey-cli ping'`, true},
		{"sh -c with a nested export", "scripts/x.sh", `sh -c 'export PW=x; cmd'`, true},
		{"sh -c with a nested sh -c", "scripts/x.sh", `sh -c "sh -c 'PW=x cmd'"`, true},
		{"eval of a literal", "scripts/x.sh", `eval "PW=x cmd"`, true},
		{"a wrapper before env", "scripts/x.sh", `nohup env PW=x cmd &`, true},
		{"env after a wrapper with no assignment", "scripts/x.sh", `nohup env -i cmd &`, true},
		{"command with an assignment", "scripts/x.sh", `command PW=1 cmd`, true},
		{"sudo with an assignment", "scripts/x.sh", `sudo PW=x cmd`, true},
		{"xargs with an assignment", "scripts/x.sh", `xargs PW=x cmd`, true},
		{"sudo -E", "scripts/x.sh", `sudo -E cmd`, true},
		{"sudo --preserve-env", "scripts/x.sh", `sudo --preserve-env=PW cmd`, true},
		{"set -a", "scripts/x.sh", `set -a`, true},
		{"set -ea", "scripts/x.sh", `set -ea`, true},
		{"set -o allexport", "scripts/x.sh", `set -o allexport`, true},
		{"declare -x in a function", "scripts/x.sh", `f() { declare -x X=1; }`, true},
		{"typeset -x", "scripts/x.sh", `typeset -x X=1`, true},
		// Round 17, admin-r17-9: the shapes the round 16 rebuild still let through.
		{"a runtime reached through a variable", "scripts/x.sh", `"$docker" run -d -e VALKEY_PASSWORD="$(cat secrets/valkey_password_admin)" img`, true},
		{"a runtime reached through a variable, name only", "scripts/x.sh", `$engine run -e PW img`, true},
		{"a runtime nobody listed", "scripts/x.sh", `buildah run -e PW=x ctr cmd`, true},
		{"a runtime behind a wrapper", "scripts/x.sh", `nohup docker run -e PW=x img &`, true},
		{"-e after an assignment prefix of the command", "scripts/x.sh", `DOCKER_HOST=x docker run -e PW=x img`, true},
		{"command -p with an assignment", "scripts/x.sh", `command -p CTRLZ_PW=$pw ctrlz serve`, true},
		{"env -i with an assignment", "scripts/x.sh", `env -i PW=x cmd`, true},
		{"local -x", "scripts/x.sh", `f() { local -x PW=$x; long_running & }`, true},
		{"readonly -x", "scripts/x.sh", `readonly -x PW=$x`, true},
		{"test -e is a file check", "scripts/x.sh", `test -e /tmp/x`, false},
		{"[ -e is a file check", "scripts/x.sh", `if [ -e /tmp/x ]; then echo a; fi`, false},
		{"sed -e is a script", "scripts/x.sh", `sed -e s/a/b/ f`, false},
		{"echo -e is an escape switch", "scripts/x.sh", `echo -e "a\nb"`, false},
		{"sh -e is the shell flag", "scripts/x.sh", `sh -e script.sh`, false},
		{"a backtick substitution", "scripts/x.sh", "out=`PW=x cmd`", true},
		// What the shapes above must not catch.
		{"go env", "scripts/x.sh", `gobin=$(go env GOPATH)/bin`, false},
		{"sh -c with no assignment", "scripts/x.sh", `sh -c 'echo hi'`, false},
		{"sh -ec with no assignment", "scripts/x.sh", `sh -ec 'cd /tmp'`, false},
		{"set -eu", "scripts/x.sh", `set -eu`, false},
		{"grep -E", "scripts/x.sh", `grep -E 'a|b' f`, false},
		{"sudo without -E", "scripts/x.sh", `sudo cmd`, false},
		{"a flag whose value is an assignment", "scripts/x.sh", `awk -v n=1 'prog' f`, false},
		{"a build argument", "scripts/x.sh", `docker build --build-arg X=1 .`, false},
		{"set -o pipefail", "scripts/x.sh", `set -o pipefail`, false},
		{"docker with no environment flag", "scripts/x.sh", `docker run --rm -v a:b img`, false},
		{"a flag with an equals sign", "scripts/x.sh", `cmd --password=x --user=y`, false},
		{"a variable with a default", "scripts/x.sh", `x=${Y:-z}`, false},
		{"grep -e of a word", "scripts/x.sh", `grep -e foo bar`, false},
		{"a Compose line", "deploy/compose/docker-compose.yml", `      CTRLZ_DB_HOST: postgres`, false},
		{"a quoted assignment is no assignment", "scripts/x.sh", `echo "X=1 cmd"`, false},
	} {
		got := environmentLineProblems(tc.file, tc.text)
		if (len(got) > 0) != tc.bad {
			t.Errorf("%s: problems %q, want a problem: %v", tc.name, got, tc.bad)
		}
	}
}
