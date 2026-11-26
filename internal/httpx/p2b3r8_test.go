package httpx

import (
	"context"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/api"
)

func repJSON(one string, n int) string {
	return "[" + strings.TrimSuffix(strings.Repeat(one+",", n), ",") + "]"
}

// TestCheckDocumentChecksEveryArrayItemByItem: services, filters and folders of the wrong type built the error tree of the
// whole rest of the document in one call, about 30 MiB for a body of 0.7 MiB (p2-B3-r8-3). Each item is checked on its own
// now, so the heap follows one item and the answer stops at 100 problems.
func TestCheckDocumentChecksEveryArrayItemByItem(t *testing.T) {
	v, err := NewValidator(api.Tenant())
	if err != nil {
		t.Fatal(err)
	}
	doc := `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"x",` +
		`"services":` + repJSON(`{"slug":1,"action":2,"enabled":3,"target":4}`, 5000) +
		`,"filters":` + repJSON(`{"id":1,"enabled":2,"mode":3}`, 1000) +
		`,"folders":` + repJSON(`{"ref":1,"name":2,"kind":3}`, 500) + `,"rules":[]}`
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	got, err := v.CheckDocument(context.Background(), "ProfileDocument", []byte(doc))
	runtime.ReadMemStats(&m1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != documentProblems {
		t.Errorf("the answer has %d problems, want %d", len(got), documentProblems)
	}
	if alloc := m1.TotalAlloc - m0.TotalAlloc; alloc > 16<<20 {
		t.Errorf("the check allocated %d MiB for a body of %d KiB, the bound is 16 MiB", alloc>>20, len(doc)>>10)
	}
}

// TestCheckDocumentGivesWhatCheckComponentGives: the item-wise check answers with the problems of the whole-document
// check, at the same pointers, for documents that have problems in every array and in the rest.
func TestCheckDocumentGivesWhatCheckComponentGives(t *testing.T) {
	v, err := NewValidator(api.Tenant())
	if err != nil {
		t.Fatal(err)
	}
	docs := map[string]string{
		"few": `{"format":"ctrlz-profile","version":1,"kind":"zzz","name":"x","services":[{"slug":"a","action":"block"},{"slug":1},{"action":"zzz"}],` +
			`"filters":[{"id":"a"},{"id":2,"mode":3}],"folders":[{"ref":"f1","name":"n","kind":"standard"},{"ref":"","name":2}],` +
			`"rules":[{"pattern":"a.example","action":"block"},{"pattern":1,"action":"nope","folder":2}],"options":{"dns64":"x"}}`,
		"many": `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"x","services":` + repJSON(`{"slug":1}`, 70) +
			`,"filters":` + repJSON(`{"id":1}`, 30) + `,"folders":` + repJSON(`{"ref":1}`, 20) + `,"rules":` + repJSON(`{"pattern":1}`, 40) + `}`,
		"not arrays": `{"format":"ctrlz-profile","version":1,"kind":"custom","services":5,"filters":"x","folders":{},"rules":null}`,
		"unknown":    `{"format":"ctrlz-profile","version":1,"kind":"custom","zz":1,"services":[{"slug":"a","action":"block","q":1}]}`,
	}
	for name, doc := range docs {
		want, err := v.CheckComponent("ProfileDocument", []byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		got, err := v.CheckDocument(context.Background(), "ProfileDocument", []byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: CheckDocument gave %+v, CheckComponent %+v", name, got, want)
		}
	}
	rules := `{"format":"ctrlz-rules","version":1,"rules":[{"pattern":"a.example","action":"block"},{"pattern":1}]}`
	want, _ := v.CheckComponent("RulesDocument", []byte(rules))
	got, _ := v.CheckDocument(context.Background(), "RulesDocument", []byte(rules))
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rules document: CheckDocument gave %+v, CheckComponent %+v", got, want)
	}
}
