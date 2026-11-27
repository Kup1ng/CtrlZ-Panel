package vectors

import (
	"encoding/json"
	"strings"
	"testing"
)

// requiredGroups are the golden vector groups of contract section 15 that
// exist in P0, with the number of cases each must keep. The minimum is the
// count when the group was last reviewed, so removing a case shows up here and
// in the diff of this file, not only in a rehashed CHECKSUMS.
//
// Absent on purpose: grants (the Grant table lives in the node, P4b) and xray and
// sharelink (the packages are P4b). When one of them is written its group is
// added to this list in the same change; until then a file of that name is an
// unlisted file and fails TestGroupFilesAreTheListedOnes.
var requiredGroups = map[string]int{
	"hash": 17, "names": 57, "identity": 68, "tokens": 54, "precedence": 18, "specificity": 19, "merge": 13,
	"schedule": 15, "client-order": 4, "expiry": 7, "geo-order": 10, "dest-geo": 17, "cname": 13,
	"qtype-matrix": 68, "options": 40, "safe-search": 9, "dnssec": 32, "sysnames": 35, "locations": 9,
	"auto-random": 9, "route": 18, "upload": 8, "blob": 37, "gtable": 23, "quarantine": 13, "no-redirect": 36,
	// P4 W1 (SC 8a.10): the zone package. zone-failover is written by
	// sharedtool failover-vectors and nobody edits it.
	"zone-answer": 65, "zone-failover": 119, "pair-table-validate": 67,
	// P4 gate (T-541, T-545): the node's apply rules, run by a reference model here and
	// by the node's table writer there.
	"pair-table-apply": 30,
}

// extraGroups are groups the module has that section 15 does not list by name:
// they pin parts of sections 5, 9, 10, 13 and 11 that need their own files.
var extraGroups = map[string]int{
	"locations-sets": 16, "schedule-zones": 6, "traffic-cat": 5, "manifest": 26,
	// P3 (SC 14 and 15): the Apple DNS profile request, its stored form and its identity.
	"appleprofile": 23,
	// P4 W1b: the activity entry of three forms and the free part of a counters batch.
	"telemetry-validate": 35,
	// P4 W1b (D42, T-524): a Redirect for an Iranian name is a Bypass at every stage.
	"iranian-redirect": 26,
}

func caseCount(t *testing.T, name string) int {
	t.Helper()
	g, err := ReadGroup(name)
	if err != nil {
		t.Fatal(err)
	}
	var cases []json.RawMessage
	if err := json.Unmarshal(g.Cases, &cases); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return len(cases)
}

// Section 17 makes "every group exists" part of done. Run iterates whatever is
// embedded, so deleting a group file and rehashing would otherwise leave every
// test green and the coverage gone.
func TestEveryRequiredGroupExists(t *testing.T) {
	have := map[string]bool{}
	for _, n := range Groups() {
		have[n] = true
	}
	for _, list := range []map[string]int{requiredGroups, extraGroups} {
		for name, min := range list {
			if !have[name] {
				t.Errorf("vector group %q is missing", name)
				continue
			}
			if n := caseCount(t, name); n < min {
				t.Errorf("vector group %q has %d cases, at least %d are required", name, n, min)
			}
		}
	}
}

// A group file that is not in either list is a group nobody has said must
// exist; it is listed here when it is added.
func TestGroupFilesAreTheListedOnes(t *testing.T) {
	var unlisted []string
	for _, n := range Groups() {
		_, a := requiredGroups[n]
		_, b := extraGroups[n]
		if !a && !b {
			unlisted = append(unlisted, n)
		}
	}
	if len(unlisted) > 0 {
		t.Errorf("vector groups not in requiredGroups or extraGroups: %s", strings.Join(unlisted, ", "))
	}
	if len(requiredGroups) != 30 {
		t.Errorf("the written groups are 30 (section 15, the no-redirect group of P2 and pair-table-apply); grants, xray and sharelink are not yet written; the list has %d", len(requiredGroups))
	}
	for n := range requiredGroups {
		if _, dup := extraGroups[n]; dup {
			t.Errorf("%q is in both lists", n)
		}
	}
}

// A negative text vector names the text its error must contain, so it cannot
// pass for a reason other than its own (review A11). Every checked-in negative
// case does.
func TestNegativeTextVectorsNameTheirCause(t *testing.T) {
	checked := 0
	for _, name := range Groups() {
		g, err := ReadGroup(name)
		if err != nil {
			t.Fatal(err)
		}
		if g.Fixture != "" || name == "blob" || name == "gtable" || name == "quarantine" || name == "zone-answer" || name == "zone-failover" || name == "pair-table-validate" || name == "pair-table-apply" || name == "telemetry-validate" {
			continue
		}
		var cases []TextCase
		if err := decodeStrict(g.Cases, &cases); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, c := range cases {
			if c.Error && c.ErrorContains == "" {
				t.Errorf("%s/%s is a negative case without error_contains", name, c.ID)
			}
			if !c.Error && c.ErrorContains != "" {
				t.Errorf("%s/%s has error_contains but is not a negative case", name, c.ID)
			}
			if c.Error {
				checked++
			}
		}
	}
	if checked < 80 {
		t.Errorf("only %d negative cases found; the walk is broken", checked)
	}
}

// The runner itself: a negative case passes only for its own cause, and an
// unknown op never passes.
func TestTextVerdict(t *testing.T) {
	cases := []struct {
		name string
		c    TextCase
		fail string // "" for a pass, else text the failure must contain
	}{
		{"positive", TextCase{Op: "parse_user", Input: "Example.COM", Expect: "example.com"}, ""},
		{"positive, wrong output", TextCase{Op: "parse_user", Input: "example.com", Expect: "other.com"}, "got"},
		{"negative for its own cause", TextCase{Op: "parse_user", Input: "a b.example", Error: true, ErrorContains: "outside [a-z0-9_-]"}, ""},
		{"negative for another cause", TextCase{Op: "parse_user", Input: "a b.example", Error: true, ErrorContains: "empty label"}, "another reason"},
		{"negative that is accepted", TextCase{Op: "parse_user", Input: "example.com", Error: true, ErrorContains: "x"}, "accepted"},
		{"positive that is rejected", TextCase{Op: "parse_user", Input: "a b.example", Expect: "x"}, "rejected"},
		{"unknown op in a negative case", TextCase{Op: "parse_usr", Input: "example.com", Error: true}, "unknown vector op"},
		{"unknown op with a cause named", TextCase{Op: "rules_pars", Input: "x", Error: true, ErrorContains: "unknown"}, "unknown vector op"},
		{"unknown op in a positive case", TextCase{Op: "nope", Input: "x", Expect: "y"}, "unknown vector op"},
		{"unknown location op", TextCase{Op: "loc_nope", Error: true}, "unknown vector op"},
	}
	for _, tc := range cases {
		c := tc.c
		got := textVerdict(&c)
		switch {
		case tc.fail == "" && got != "":
			t.Errorf("%s: failed: %s", tc.name, got)
		case tc.fail != "" && !strings.Contains(got, tc.fail):
			t.Errorf("%s: verdict %q, want it to contain %q", tc.name, got, tc.fail)
		}
	}
}
