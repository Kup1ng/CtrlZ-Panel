package lint_test

import (
	"go/format"
	"sort"
	"strings"
	"testing"
)

// The format of every Go file (P1 auth review round 18, admin-r18-9). scripts/ci.sh ran gofmt over four
// directories named in the script (cmd, internal, tools, migrations), so the Go that deploy/ and api/ gained
// in rounds 16 and 17 was read by no format gate: the list was a copy of the tree that went stale the day a
// directory was added. The unit here is the tree: realImageSources walks every Go file under the repository
// root (what it skips is a vendor-like set: node_modules, docs, apps, packages, testdata, .git), so a directory
// added later is covered by being there. A line ending written by a Windows checkout is not a format error.

// unformatted returns the files of src that go/format would change, and the files it cannot parse.
func unformatted(src map[string]string) []string {
	var out []string
	for p, text := range src {
		text = strings.ReplaceAll(text, "\r\n", "\n")
		got, err := format.Source([]byte(text))
		if err != nil || string(got) != text {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func TestEveryGoFileIsFormatted(t *testing.T) {
	s := realImageSources(t)
	if len(s.goFiles) < 100 {
		t.Fatalf("only %d Go files were read: the gate would judge nothing", len(s.goFiles))
	}
	if bad := unformatted(s.goFiles); len(bad) > 0 {
		t.Fatalf("not gofmt-formatted (run gofmt -w): %s", strings.Join(bad, ", "))
	}
}

func TestFormatGateCanFail(t *testing.T) {
	got := unformatted(map[string]string{
		"deploy/new.go":  "package deploy\nfunc f( ) {}\n",
		"api/ok.go":      "package api\n\nfunc f() {}\n",
		"x/crlf.go":      "package x\r\n\r\nfunc f() {}\r\n",
		"x/broken.go":    "package x\nfunc (",
		"newdir/deep.go": "package n\nvar  x = 1\n",
	})
	if strings.Join(got, ",") != "deploy/new.go,newdir/deep.go,x/broken.go" {
		t.Fatalf("unformatted = %v", got)
	}
}
