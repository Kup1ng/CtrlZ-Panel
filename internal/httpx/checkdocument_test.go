package httpx_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
)

// CheckDocument checks the rules one at a time and stops at 100 problems; for what it answers it must be what
// CheckComponent answers on the whole file, at the same pointers (spec 6.2, finding p2-B3-r2-6).
func TestCheckDocumentAnswersWhatCheckComponentAnswers(t *testing.T) {
	v, err := httpx.NewValidator(api.Tenant())
	if err != nil {
		t.Fatal(err)
	}
	const head = `{"format":"ctrlz-profile","version":1,"kind":"custom",`
	many := strings.Repeat(`{"pattern":"a.example","action":"block"},`, 30) + `{"action":"nope","enabled":3}`
	for name, c := range map[string]struct{ component, doc string }{
		"valid":              {"ProfileDocument", head + `"rules":[{"pattern":"a.example","action":"block"}]}`},
		"bad rule":           {"ProfileDocument", head + `"rules":[{"pattern":"a.example","action":"block"},{"action":"nope","enabled":3}]}`},
		"rule not an object": {"ProfileDocument", head + `"rules":[1,null,"x"]}`},
		"unknown member":     {"ProfileDocument", head + `"rules":[{"pattern":"a","action":"block","zz":1}]}`},
		"rules not array":    {"ProfileDocument", head + `"rules":{}}`},
		"rules null":         {"ProfileDocument", head + `"rules":null}`},
		"no rules":           {"ProfileDocument", head + `"filters":[{}]}`},
		"bad rest":           {"ProfileDocument", head + `"folders":[{}],"rules":[{"pattern":"a"}]}`},
		"many":               {"ProfileDocument", head + `"rules":[` + many + `]}`},
		"rules document":     {"RulesDocument", `{"format":"ctrlz-rules","version":1,"rules":[{"pattern":"a","action":"block","folder":"f1"},{}]}`},
	} {
		want, err1 := v.CheckComponent(c.component, []byte(c.doc))
		got, err2 := v.CheckDocument(c.component, []byte(c.doc))
		if err1 != nil || err2 != nil {
			t.Fatalf("%s: %v, %v", name, err1, err2)
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("%s:\nwhole %+v\nparts %+v", name, want, got)
		}
	}
	// Past maxItems the rules are not looked at: one problem at /rules, whatever the rules are.
	over := head + `"rules":[` + strings.Repeat(`{},`, 10000) + `{}]}`
	got, err := v.CheckDocument("ProfileDocument", []byte(over))
	if err != nil || len(got) != 1 || got[0].Pointer != "/rules" || got[0].Code != "exceeded" {
		t.Errorf("10,001 rules: %+v, %v", got, err)
	}
	// And never more than 100 problems, in document order.
	bad := head + `"rules":[` + strings.Repeat(`{},`, 500) + `{}]}`
	got, _ = v.CheckDocument("ProfileDocument", []byte(bad))
	if len(got) != 100 || got[0].Pointer != "/rules/0" {
		t.Errorf("500 bad rules: %d problems, first %+v", len(got), got[0])
	}
}
