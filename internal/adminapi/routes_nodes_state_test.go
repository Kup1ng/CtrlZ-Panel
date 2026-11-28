package adminapi

import (
	"reflect"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/adminapi/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// TestNodeViewShowsWhatTheHubWrote covers T-542: the F3 conditions that are unmet, the moment F3 acts and the drain state come
// from node_dns_state, which only the hub writes. A node the hub has written nothing for carries none of the four fields, so the
// page can say "not reported yet" and not "every condition is met".
func TestNodeViewShowsWhatTheHubWrote(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.seedRealNodes(t)
	r.env.Exec(t, `INSERT INTO ctrlz.node_dns_state (node_id, f3_unmet, f3_due_at, drain_state, drain_since)
  VALUES ($1, '{hub_fit,stable_period}', now() + interval '5 minutes', 'draining', now())`, seedNode1)

	var list struct {
		Items []map[string]any `json:"items"`
	}
	b.get("/nodes").want(200, "").json(&list)
	if len(list.Items) != 2 {
		t.Fatalf("list %v", list)
	}
	a, c := list.Items[0], list.Items[1]
	if a["id"] != seedNode1 {
		t.Fatalf("order %v", a["id"])
	}
	if got, _ := a["f3_unmet"].([]any); !reflect.DeepEqual(got, []any{"hub_fit", "stable_period"}) {
		t.Fatalf("f3_unmet = %v", a["f3_unmet"])
	}
	if a["drain_state"] != "draining" || a["f3_due_at"] == nil || a["drain_since"] == nil {
		t.Fatalf("the hub's state of node 1 = %v", a)
	}
	for _, k := range []string{"f3_unmet", "f3_due_at", "drain_state", "drain_since"} {
		if _, ok := c[k]; ok {
			t.Errorf("node 2, for which the hub wrote nothing, shows %s", k)
		}
	}

	// One node, the same fields; and a row of the hub for a node with no conditions is an empty list, not an absent one.
	r.env.Exec(t, `INSERT INTO ctrlz.node_dns_state (node_id) VALUES ($1)`, seedNode2)
	var one map[string]any
	b.get("/nodes/"+seedNode2).want(200, "").json(&one)
	if got, ok := one["f3_unmet"].([]any); !ok || len(got) != 0 || one["drain_state"] != "none" {
		t.Fatalf("a node with a quiet row: %v", one)
	}
}

// hubState adds the four fields together or none of them, from the state of a row.
func TestHubStateFieldsComeTogether(t *testing.T) {
	var v gen.NodeView
	hubState(&v, store.NodeRow{})
	if v.F3Unmet != nil || v.DrainState != nil || v.F3DueAt != nil || v.DrainSince != nil {
		t.Fatalf("a node with no row: %+v", v)
	}
	state := "done"
	hubState(&v, store.NodeRow{DrainState: &state, F3Unmet: []string{"held"}})
	if v.DrainState == nil || *v.DrainState != "done" || v.F3Unmet == nil || len(*v.F3Unmet) != 1 || (*v.F3Unmet)[0] != "held" {
		t.Fatalf("a node with a row: %+v", v)
	}
	var empty gen.NodeView
	hubState(&empty, store.NodeRow{DrainState: &state})
	if empty.F3Unmet == nil || len(*empty.F3Unmet) != 0 {
		t.Fatal("a row with no conditions must say so with an empty list")
	}
}
