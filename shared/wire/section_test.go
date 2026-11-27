package wire

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
)

// hubOnlySections are the section names of validators that run only at the
// hub, on a message a node sent. A node never reports a failure of these, so
// they never travel in QuarantineReport.section and may be longer.
var hubOnlySections = map[string]bool{
	"proof_observation":     true,
	"quarantine_report":     true,
	"block_unblock_request": true,
	"block_key_request":     true,
}

// Every section name a decoder or validator on the node side can put in a
// reason.Error must pass ValidateQuarantineReport. The names are read from the
// source, so a new validator with a long name fails here instead of making the
// hub refuse the report of the failure that most needs an alert.
func TestEverySectionFitsAReport(t *testing.T) {
	re := regexp.MustCompile(`(?:const w = |bad\([^,]+, |reason\.New\([^,]+, )"([A-Za-z_0-9]+)"`)
	dirs := []string{".", "../blob", "../gtable", "../quarantine", "../schedule", "../route"}
	found := map[string]bool{}
	for _, d := range dirs {
		files, err := filepath.Glob(filepath.Join(d, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range re.FindAllStringSubmatch(string(src), -1) {
				found[m[1]] = true
			}
		}
	}
	if len(found) < 20 {
		t.Fatalf("the scan found only %d section names; the pattern is broken", len(found))
	}
	for sec := range found {
		if hubOnlySections[sec] {
			continue
		}
		q := &hubv1.QuarantineReport{Seq: 1, Scope: hubv1.Scope_SCOPE_RECORD, Reason: "bad_section", Section: sec}
		if err := ValidateQuarantineReport(q); err != nil {
			t.Errorf("section %q: %v", sec, err)
		}
	}
	// The allow-list must not hide a name that does fit.
	for sec := range hubOnlySections {
		if len(sec) <= MaxSectionName {
			t.Errorf("%q is exempt but fits; remove it from hubOnlySections", sec)
		}
	}
	// And the bound is still a bound.
	long := &hubv1.QuarantineReport{Seq: 1, Scope: hubv1.Scope_SCOPE_RECORD, Reason: "bad_section", Section: strings.Repeat("s", MaxSectionName+1)}
	if ValidateQuarantineReport(long) == nil {
		t.Error("a section name over the limit was accepted")
	}
}
