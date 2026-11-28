package domainapply

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// The three variables the apply step owns in deploy/compose/.env (10.4). Every other line of the file is kept as it is.
const (
	envPanelHost    = "CTRLZ_PANEL_HOST"
	envAdminHost    = "CTRLZ_ADMIN_HOST"
	envVerifyOrigin = "CTRLZ_VERIFY_ORIGIN"
)

// envPair is one assignment to write.
type envPair struct{ key, value string }

// errEnvFile is the one answer for a file this code will not edit. It names no content.
var errEnvFile = errors.New("the .env file is not a plain KEY=value file this tool edits (a carriage return was found)")

// envLineShape is the one shape of a line this tool and scripts/domain-apply.sh both accept in a .env: a comment, a blank line
// or NAME=value, from the first column. The script checks the printed file with the same expression before it replaces the
// .env, so setEnv refuses, before any file is written, every line the script would refuse afterwards (R34-r1-7).
var envLineShape = regexp.MustCompile(`^(#.*|[A-Za-z_][A-Za-z0-9_]*=.*|)$`)

// envLineKey returns the variable a line assigns, or "" for a comment, a blank line or text that is no assignment. The
// optional `export ` prefix and spaces around the name are the shapes a shell-minded editor writes; Compose reads them too.
func envLineKey(line string) string {
	s := strings.TrimSpace(line)
	if s == "" || s[0] == '#' {
		return ""
	}
	s = strings.TrimSpace(strings.TrimPrefix(s, "export "))
	k, _, ok := strings.Cut(s, "=")
	if !ok {
		return ""
	}
	return strings.TrimSpace(k)
}

// envValue reads the current value of a variable: the last assignment wins, as it does for Compose. A value in quotes is
// unquoted, a trailing comment of an unquoted one is dropped. "" is also the answer for a variable that is not set.
func envValue(content []byte, key string) string {
	var val string
	for _, line := range strings.Split(string(content), "\n") {
		if envLineKey(line) != key {
			continue
		}
		_, v, _ := strings.Cut(line, "=")
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		} else if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		val = v
	}
	return val
}

// setEnv returns content with each pair set. The first assignment of a variable is replaced in place, the later ones
// are dropped (the file would otherwise still hold a value that wins over ours), and a variable the file lacks is
// appended. A value outside the alphabet of hostnames and origins is refused, so a value can never end a line, open a
// quote or start a comment in the file Compose reads.
func setEnv(content []byte, pairs []envPair) ([]byte, error) {
	if strings.ContainsRune(string(content), '\r') {
		return nil, errEnvFile
	}
	for i, line := range strings.Split(strings.TrimSuffix(string(content), "\n"), "\n") {
		if !envLineShape.MatchString(line) {
			return nil, errors.New("line " + strconv.Itoa(i+1) + " of the .env is not a comment, a blank line or NAME=value from the first column; fix it and run the script again")
		}
	}
	for _, p := range pairs {
		if !safeEnvValue(p.value) {
			return nil, errors.New("a value for " + p.key + " has a character a .env value may not have here")
		}
	}
	lines := strings.Split(string(content), "\n")
	// A file that ends in a newline splits into a last empty element; the result ends in one newline either way.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	done := map[string]bool{}
	out := make([]string, 0, len(lines)+len(pairs))
	for _, line := range lines {
		k := envLineKey(line)
		replaced := false
		for _, p := range pairs {
			if p.key != k {
				continue
			}
			replaced = true
			if !done[k] {
				out = append(out, k+"="+p.value)
				done[k] = true
			}
		}
		if !replaced {
			out = append(out, line)
		}
	}
	for _, p := range pairs {
		if !done[p.key] {
			out = append(out, p.key+"="+p.value)
		}
	}
	return []byte(strings.Join(out, "\n") + "\n"), nil
}

// safeEnvValue is the alphabet of what the apply step writes: hostnames, and origins of the form
// https://*.verify.<zone>[,...]. Empty is allowed (no zone yet).
func safeEnvValue(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == ',' || c == '*' || c == ':' || c == '/') {
			return false
		}
	}
	return true
}

// envMarker is the layout marker the script requires in the file it puts in place.
var envMarker = regexp.MustCompile(`(?m)^CTRLZ_ENV_FORMAT_2=`)
