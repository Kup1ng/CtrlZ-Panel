package lint_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Round 14, admin-r14-8. The Compose header says no password is an environment variable of a long-running
// process, and round 13 made the valkey start line hand the maintenance password to maintain.sh in
// REDISCLI_AUTH for the life of the container. Nothing compared the claim with the file: the secret lint
// (TestComposeSecretsStayOutOfArgumentsAndEnvironments) looks at lines that name a secret path or a
// *PASSWORD* variable, and `maint_pw` is neither.
//
// The rule is the one the header states, as a shape and not a list of spellings: a line of any file under
// deploy/ or scripts/ that assigns a variable whose name says it is a credential (AUTH, PASS, PASSWORD,
// SECRET, TOKEN), as a prefix of a command or with export, is a problem unless it is one of
// allowedCredentialAssignments, character for character, in its file. The list names the reason of each
// line, and the Compose header has to name the exception. A path variable (_FILE, _DIR, _PATH) is no
// credential.
//
// What it does not see: a lower case variable that is exported on a later line (`pw=...`, then `export pw`),
// one built at run time, or a command that puts the value into the environment of a child in a way that is not an
// assignment (`env "$name=$value"`). The first is a shell variable, not an environment, until it is exported,
// and `export` of any name that holds a secret is the case the secret lint above catches by its source.
//
// The keyword may be anywhere in the name, the start included (round 15, admin-r15-5: the first shape needed a
// character before it, so PASSWORD=, TOKEN=, AUTH=, SECRET= and SECRET_KEY= passed, the commonest spellings of
// all, and the test planted prefixed names only). The second alternative is `export` of a name in any case:
// exporting is what puts a value in a child's environment, so `export password=$x` counts and `password=$x`
// alone (a shell variable) does not.
var credentialAssignment = regexp.MustCompile(`(?:^|[\s;&|(])(?:(?:export\s+)?([A-Z0-9_]*(?:AUTH|PASS|PASSWORD|SECRET|TOKEN)[A-Z0-9_]*)|export\s+([A-Za-z0-9_]*(?i:auth|pass|password|secret|token)[A-Za-z0-9_]*))=`)

// allowedCredentialAssignments maps a file, relative to the repository root, to the lines of it that may
// assign a credential variable, each with the reason it is safe.
var allowedCredentialAssignments = map[string]map[string]string{
	"deploy/compose/valkey/maintain.sh": {
		`cli() { REDISCLI_AUTH=$pw valkey-cli -h 127.0.0.1 -p "$port" --user "$user" --no-auth-warning "$@"; }`: "the password is a variable of the " +
			"loop's shell and is never exported; it is in the environment of one valkey-cli for the length of one command, which is no " +
			"long-running process",
	},
}

// credentialAssignmentProblems returns the lines of one file that assign a credential variable and are not
// allowed for that file. A comment line is not a line of the file's code.
func credentialAssignmentProblems(rel, text string) []string {
	var out []string
	for i, ln := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		trim := strings.TrimSpace(ln)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		m := credentialAssignment.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		name := m[1]
		if name == "" {
			name = m[2]
		}
		name = strings.ToUpper(name)
		if strings.HasSuffix(name, "_FILE") || strings.HasSuffix(name, "_DIR") || strings.HasSuffix(name, "_PATH") {
			continue
		}
		if _, ok := allowedCredentialAssignments[rel][trim]; ok {
			continue
		}
		out = append(out, rel+":"+itoa(i+1)+": assigns "+name+" in a line that is not on the list")
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
			if strings.HasSuffix(p, ".example") || strings.HasSuffix(p, ".conf") || strings.HasSuffix(p, ".lua") {
				return nil // a template of values is data, not a command
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			for _, problem := range credentialAssignmentProblems(rel, string(b)) {
				t.Error(problem)
			}
			for _, ln := range strings.Split(string(b), "\n") {
				if _, ok := allowedCredentialAssignments[rel][strings.TrimSpace(ln)]; ok {
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
	// A listed line that no file has is an exception someone may bring back without the lint noticing.
	for rel, lines := range allowedCredentialAssignments {
		for ln := range lines {
			if !seen[rel][ln] {
				t.Errorf("%s: the allowed line %q is not in the file; remove it from the list", rel, ln)
			}
		}
	}
	// The header states the rule and has to name the exception.
	b, err := os.ReadFile(filepath.Join(root, "deploy", "compose", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	header, _, _ := strings.Cut(string(b), "\nname: ctrlz")
	for rel := range allowedCredentialAssignments {
		if !strings.Contains(header, filepath.Base(rel)) {
			t.Errorf("the Compose header does not name %s, which holds an allowed credential assignment", rel)
		}
	}
}

func TestCredentialAssignmentCheckCanFail(t *testing.T) {
	allowedLine := `cli() { REDISCLI_AUTH=$pw valkey-cli -h 127.0.0.1 -p "$port" --user "$user" --no-auth-warning "$@"; }`
	for _, tc := range []struct {
		name, file, text string
		bad              bool
	}{
		{"the round 13 start line", "deploy/compose/docker-compose.yml", `REDISCLI_AUTH="$$maint_pw" VALKEYCLI_AUTH="$$maint_pw" MAINT_USER=maint sh /etc/valkey/maintain.sh &`, true},
		{"export of a password", "scripts/x.sh", `export PGPASSWORD=x`, true},
		{"a token prefix", "scripts/x.sh", `	API_TOKEN="$t" curl -s http://127.0.0.1/x`, true},
		{"a command after a semicolon", "scripts/x.sh", `cd /tmp; DB_PASS=$p psql`, true},
		{"the same line in another file", "scripts/x.sh", allowedLine, true},
		{"the same line in its file", "deploy/compose/valkey/maintain.sh", allowedLine, false},
		{"a line like it with a flag more", "deploy/compose/valkey/maintain.sh", `cli() { REDISCLI_AUTH=$pw valkey-cli -a x "$@"; }`, true},
		{"the same variable exported", "deploy/compose/valkey/maintain.sh", `export REDISCLI_AUTH=$pw`, true},
		{"a comment", "scripts/x.sh", `# REDISCLI_AUTH=x valkey-cli`, false},
		{"a path variable", "scripts/x.sh", `CTRLZ_VALKEY_PASSWORD_FILE=/run/secrets/x app`, false},
		{"a directory variable", "scripts/x.sh", `CTRLZ_SECRETS_DIR=../../secrets docker compose up`, false},
		{"a lower case shell variable", "scripts/x.sh", `pw=$(cat f)`, false},
		// admin-r15-5: a name that starts with the keyword, or holds it anywhere.
		{"PASSWORD alone", "scripts/x.sh", `PASSWORD="$(cat /run/secrets/x)" some-daemon &`, true},
		{"export TOKEN", "scripts/x.sh", `export TOKEN=$t`, true},
		{"AUTH alone", "scripts/x.sh", `AUTH=x cmd`, true},
		{"SECRET alone", "scripts/x.sh", `SECRET=x cmd`, true},
		{"PASSWORD then a word", "scripts/x.sh", `PASSWORD_X=x cmd`, true},
		{"SECRET_KEY", "scripts/x.sh", `SECRET_KEY=x cmd`, true},
		{"TOKEN_FILE_CONTENT", "scripts/x.sh", `TOKEN_FILE_CONTENT=x cmd`, true},
		{"a keyword in the middle", "scripts/x.sh", `MY_PASSWORD_X=x cmd`, true},
		{"after env", "scripts/x.sh", `env TOKEN=x cmd`, true},
		{"after a pipe", "scripts/x.sh", `echo | PASS=x cmd`, true},
		{"a lower case export", "scripts/x.sh", `export password=$x`, true},
		{"a mixed case export", "scripts/x.sh", `export dbToken=$x`, true},
		{"PASSWORD_FILE alone", "scripts/x.sh", `PASSWORD_FILE=/run/secrets/x cmd`, false},
		{"TOKEN_DIR alone", "scripts/x.sh", `TOKEN_DIR=/x cmd`, false},
		{"a word that only contains the letters", "scripts/x.sh", `COMPASS=north cmd`, true},
		{"a flag", "scripts/x.sh", `cmd --password=x`, false},
		{"no credential", "scripts/x.sh", `PORT=8080 app`, false},
	} {
		got := credentialAssignmentProblems(tc.file, tc.text)
		if (len(got) > 0) != tc.bad {
			t.Errorf("%s: problems %q, want a problem: %v", tc.name, got, tc.bad)
		}
	}
}
