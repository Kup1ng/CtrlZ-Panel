package xrayschema

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
)

// sourceKeys reads testdata/<tag>.keys.json: every json key of every struct of infra/conf at
// that Xray-core tag, extracted from the source (p4b-proxy 15.4, G4). The file is
// regenerated for a new release from its source, and B0 confirms it on the binary.
func sourceKeys(t *testing.T, tag string) map[string]bool {
	t.Helper()
	b, err := os.ReadFile("testdata/" + tag + ".keys.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Items []string `json:"items"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, line := range doc.Items {
		_, k, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("bad line %q", line)
		}
		keys[strings.ToLower(k)] = true
	}
	if len(keys) < 200 {
		t.Fatalf("only %d keys: wrong file?", len(keys))
	}
	return keys
}

// tableKeys walks a table and returns every key it names, with where it is used.
func tableKeys(n *node, depth int, out map[string]string, where string) {
	if depth > 12 {
		return
	}
	add := func(k string) {
		if _, ok := out[k]; !ok {
			out[k] = where
		}
	}
	for k, c := range n.fields {
		add(k)
		tableKeys(c, depth+1, out, where+"."+k)
	}
	for old := range n.alias {
		add(old)
	}
	for _, c := range n.sel {
		tableKeys(c, depth+1, out, where+".<variant>")
	}
	if n.elem != nil {
		tableKeys(n.elem, depth+1, out, where+"[]")
	}
	for _, a := range n.alts {
		tableKeys(a, depth+1, out, where+"|")
	}
}

// Every key of a release table is a key of that release's source, so a typo in the
// table (which would turn an allowed key into an unknown one, or let a misspelt
// rejection pass) fails here and not on a node.
func TestTableKeysAreKeysOfTheSource(t *testing.T) {
	for _, tag := range Releases() {
		src := sourceKeys(t, tag)
		tb, _ := For(tag)
		used := map[string]string{}
		tableKeys(tb.build(), 0, used, "outbound")
		// Keys that links and older configs carry and that are not a key of this release
		// any more: the table lists them only to drop them (7.2).
		goName := map[string]bool{"ota": true, "alterid": true, "tcpnodelay": true}
		var missing []string
		for k, where := range used {
			if !src[strings.ToLower(k)] && !goName[strings.ToLower(k)] {
				missing = append(missing, k+" ("+where+")")
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("%s: keys of the table that the source does not have: %v", tag, missing)
		}
		for k := range globalRejected() {
			// WireGuardConfig.IsClient has the empty tag json:"", so its Go name is the key.
			if !src[k] && k != "isclient" {
				t.Errorf("%s: always-rejected key %q is not a key of the source", tag, k)
			}
		}
	}
}
