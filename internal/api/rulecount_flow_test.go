package api

import (
	"testing"

	"github.com/google/uuid"
)

// GET /profiles counts the rules of a profile only when its version has changed (p2-B3-r14-1). The count must still follow
// every write of rules, since each one steps the version through the guard, and a tenant never reads another's count.
func TestProfileListRuleCountFollowsWrites(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	a := f.makeSession(A.Tenant, A.User)
	b := f.makeSession(B.Tenant, B.User)

	rulesOf := func(c *client, id uuid.UUID) int {
		t.Helper()
		var list struct {
			Items []pProfile `json:"items"`
		}
		c.get("/profiles").want(200, "").json(&list)
		for _, p := range list.Items {
			if p.ID == id {
				return p.Counts.Rules
			}
		}
		t.Fatalf("profile %s is not in the list", id)
		return -1
	}
	p := a.mustProfile("Counted", "custom")
	base := "/profiles/" + p.ID.String()
	if n := rulesOf(a, p.ID); n != 0 {
		t.Fatalf("an empty profile lists %d rules", n)
	}
	a.post(base+"/rules", map[string]any{"patterns": []string{"one.example", "two.example", "three.example"}, "action": "block"}).want(201, "")
	for range 2 { // the second read is served from the cache
		if n := rulesOf(a, p.ID); n != 3 {
			t.Fatalf("after three rules the list says %d", n)
		}
	}
	a.post(base+"/rules", map[string]any{"patterns": []string{"four.example"}, "action": "block"}).want(201, "")
	if n := rulesOf(a, p.ID); n != 4 {
		t.Fatalf("after a fourth rule the list says %d (a stale cached count)", n)
	}
	var rules struct {
		Items []struct {
			ID uuid.UUID `json:"id"`
		} `json:"items"`
	}
	a.get(base+"/rules").want(200, "").json(&rules)
	a.do("POST", base+"/rules:batch", map[string]any{"op": "delete", "ids": []uuid.UUID{rules.Items[0].ID, rules.Items[1].ID}}, idem("rc-del")).want(200, "")
	if n := rulesOf(a, p.ID); n != 2 {
		t.Fatalf("after two deletes the list says %d", n)
	}
	// The single read and the list agree, and tenant B's list does not hold A's profile or its count.
	var one pProfile
	a.get(base).want(200, "").json(&one)
	if one.Counts.Rules != 2 {
		t.Fatalf("the profile read says %d rules, the list says 2", one.Counts.Rules)
	}
	var bl struct {
		Items []pProfile `json:"items"`
	}
	b.get("/profiles").want(200, "").json(&bl)
	for _, q := range bl.Items {
		if q.ID == p.ID {
			t.Fatal("tenant B lists a profile of A")
		}
	}
}
