package api

import (
	"fmt"
	"strings"
	"testing"
)

// padDoc is a body just over the default body limit: a heavy request that is no document, so the answer after the work
// starts is 422.
func padDoc() map[string]any {
	return map[string]any{"document": b64(`{"pad":"` + strings.Repeat("a", 80<<10) + `"}`)}
}

// validBulkDoc is a valid profile document whose body is over the default limit: 600 rules with comments of 60 characters.
func validBulkDoc() map[string]any {
	var b strings.Builder
	b.WriteString(`{"format":"ctrlz-profile","version":1,"kind":"custom","name":"x","rules":[`)
	for i := 0; i < 600; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"pattern":"a%d.example","action":"block","comment":"%s"}`, i, strings.Repeat("c", 60))
	}
	b.WriteString(`]}`)
	return map[string]any{"document": b64(b.String())}
}

// bigRuleBody is a rule create whose body is over the default limit of 16 KiB (400 patterns of 200 characters), so it is a
// heavy request (spec 6.5).
func bigRuleBody() map[string]any {
	ps := make([]string, 400)
	for i := range ps {
		ps[i] = fmt.Sprintf("%s%d.example", strings.Repeat("a", 190), i)
	}
	return map[string]any{"patterns": ps, "action": "block"}
}

// TestAnOrdinaryRuleCreateNeverMeetsAPlace: a rule create inside the default limit is an ordinary operation. A tenant whose
// place is taken (by anything heavy) still creates small rules, and its big rule create is the one that is refused (spec 6.5).
func TestAnOrdinaryRuleCreateNeverMeetsAPlace(t *testing.T) {
	f := newFrig(t, frigOpts{})
	adm := f.withAdmission()
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	pa := a.mustProfile("Place", "custom")
	hold, err := adm.Place(A.Tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	defer hold()
	a.post("/profiles/"+pa.ID.String()+"/rules", map[string]any{"patterns": []string{"small.example"}, "action": "block"}).want(201, "")
	a.post("/profiles/"+pa.ID.String()+"/rules", bigRuleBody()).want(503, "server_busy")
}
