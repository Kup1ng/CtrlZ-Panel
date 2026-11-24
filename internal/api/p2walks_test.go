package api

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	apidoc "github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/isolation"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// The structural checks S1, S2, S6 and S7 of spec 10.2, each a walk over the scenario table of p2scenario_test.go, which
// TestTheScenarioTableHoldsEveryOperation holds equal to the document. A new operation joins every walk by joining the table.

// walkRig is a frig whose tenant A may hold as many profiles as the walks make.
type walkRig struct {
	f   *frig
	ops map[string]apispec.Operation
	dig *isolation.Tenants
}

func newWalkRig(t *testing.T) *walkRig {
	t.Helper()
	f := newFrig(t, frigOpts{})
	f.env.Exec(t, `UPDATE ctrlz.tenant_entitlements SET max_profiles = 1000`)
	docOps, err := apispec.Parse(apidoc.Tenant(), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	w := &walkRig{f: f, ops: map[string]apispec.Operation{}}
	for _, op := range docOps {
		w.ops[op.ID] = op
	}
	w.dig = &isolation.Tenants{Env: f.env, T: t, Phones: func(isolation.Who) []string { return nil }}
	return w
}

// scn builds a scenario for tenant A, with the state the case needs.
func (w *walkRig) scn(c p2Case) *scn {
	s := newScn(w.f, w.f.env.A.Tenant, w.f.env.A.User, "A")
	if c.prep != nil {
		c.prep(s)
	}
	return s
}

// digest is the fingerprint of everything tenant A owns in the tables a route writes.
func (w *walkRig) digest() map[string]string { return w.dig.Digest(isolation.A) }

// changed names the tables whose digest differs.
func changed(before, after map[string]string) string {
	var out []string
	for k, v := range before {
		if after[k] != v {
			out = append(out, k)
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// lockRow locks a profile the way a lock leaves it, with no Argon2 run: the walks need the lock, not the route.
func (w *walkRig) lockRow(id string) {
	w.f.t.Helper()
	w.f.env.Exec(w.f.t, `UPDATE ctrlz.profiles SET lock_state = 'locked', lock_password_hash = 'h', locked_at = now() WHERE id = $1`, id)
}

type outboxRow struct {
	Type  string `json:"type"`
	ID    string `json:"id"`
	Batch string `json:"batch"`
}

// outbox reads the policy_outbox rows of tenant A.
func (w *walkRig) outbox() []outboxRow {
	w.f.t.Helper()
	var js string
	w.f.env.Scan(w.f.t, `SELECT coalesce(jsonb_agg(jsonb_build_object('type', aggregate_type, 'id', aggregate_id, 'batch', batch_id) ORDER BY id), '[]'::jsonb)::text
		FROM ctrlz.policy_outbox WHERE tenant_id = $1`, []any{w.f.env.A.Tenant}, &js)
	var rows []outboxRow
	if err := json.Unmarshal([]byte(js), &rows); err != nil {
		w.f.t.Fatal(err)
	}
	return rows
}

// since is what was added to the outbox after before: the rows are never changed, only added.
func since(before, after []outboxRow) []outboxRow {
	var out []outboxRow
	for _, r := range after {
		if !slices.Contains(before, r) {
			out = append(out, r)
		}
	}
	return out
}

func (w *walkRig) version(id string) int {
	w.f.t.Helper()
	return w.f.count(`SELECT version FROM ctrlz.profiles WHERE id = $1`, id)
}

// wantLock is what spec 10.2 S1 says an operation declares: guard for every one that writes an existing profile's content,
// lock and unlock for those two, none for a read and for one that only creates a profile (Duplicate among them).
func wantLock(c p2Case) string {
	switch {
	case c.writes:
		return "guard"
	case c.op == "lockProfile":
		return "lock"
	case c.op == "unlockProfile":
		return "unlock"
	}
	return "none"
}

// TestS1TheLockGuardOnEveryOperation: every operation that writes an existing profile's content declares the guard, and each
// of them on a locked profile answers 423 and changes nothing (spec 10.2 S1, T-140).
func TestS1TheLockGuardOnEveryOperation(t *testing.T) {
	w := newWalkRig(t)
	guarded := 0
	for _, c := range p2Cases() {
		op, ok := w.ops[c.op]
		if !ok {
			t.Fatalf("%s is not in the document", c.op)
		}
		if op.Lock != wantLock(c) {
			t.Errorf("%s declares x-ctrlz-lock %q, spec 8.2 says %q", c.op, op.Lock, wantLock(c))
		}
		if op.Lock != "guard" {
			continue
		}
		guarded++
		t.Run(c.op, func(t *testing.T) {
			s := w.scn(c)
			w.lockRow(s.ids["profile"])
			before := w.digest()
			r := s.send(c.call(s, refs{s: s}))
			r.want(423, "profile_locked")
			if d := changed(before, w.digest()); d != "" {
				t.Errorf("a refused write on a locked profile changed %s", d)
			}
		})
	}
	if guarded < 15 {
		t.Fatalf("only %d operations declare the guard", guarded)
	}
}

// TestS1TheLockOfADestinationAndASource: Copy and Move are judged by the profile each one writes: a locked destination
// refuses both, a locked source refuses a Move only, and a Copy out of a locked source succeeds with the source's digest and
// version unchanged and one outbox row, the destination's (spec 3.1, 7.3, 10.2 S1). Both routes, and above the job threshold.
func TestS1TheLockOfADestinationAndASource(t *testing.T) {
	w := newWalkRig(t)
	type route struct {
		name string
		call func(s *scn, op string) p2Spec
	}
	routes := []route{
		{"transferRule", func(s *scn, op string) p2Spec {
			return p2Spec{method: "POST", path: "/profiles/" + s.ids["profile"] + "/rules/" + s.ids["rule"] + ":transfer",
				body: map[string]any{"op": op, "dest_profile_id": s.ids["profile2"], "dest_root": true}}
		}},
		{"batchRules", func(s *scn, op string) p2Spec {
			return p2Spec{method: "POST", path: "/profiles/" + s.ids["profile"] + "/rules:batch", hdr: s.key(),
				body: map[string]any{"op": op, "ids": []string{s.ids["rule"], s.ids["rule2"]}, "dest_profile_id": s.ids["profile2"], "dest_root": true}}
		}},
	}
	for _, rt := range routes {
		for _, c := range []struct {
			name, op           string
			lockSrc, lockDst   bool
			want               int
			wantCode           string
			sourceMayBeTouched bool
		}{
			{"copy into a locked destination", "copy", false, true, 423, "profile_locked", false},
			{"copy from a locked source", "copy", true, false, 200, "", false},
			{"copy between two locked profiles", "copy", true, true, 423, "profile_locked", false},
			{"move into a locked destination", "move", false, true, 423, "profile_locked", false},
			{"move out of a locked source", "move", true, false, 423, "profile_locked", false},
		} {
			t.Run(rt.name+" "+c.name, func(t *testing.T) {
				s := newScn(w.f, w.f.env.A.Tenant, w.f.env.A.User, "A")
				if c.lockSrc {
					w.lockRow(s.ids["profile"])
				}
				if c.lockDst {
					w.lockRow(s.ids["profile2"])
				}
				before, boxBefore, ver := w.digest(), w.outbox(), w.version(s.ids["profile"])
				r := s.send(rt.call(s, c.op))
				r.want(c.want, c.wantCode)
				if c.want != 200 {
					if d := changed(before, w.digest()); d != "" {
						t.Errorf("a refused request changed %s", d)
					}
					return
				}
				if got := w.version(s.ids["profile"]); got != ver {
					t.Errorf("a copy out of a locked source stepped its version from %d to %d", ver, got)
				}
				added := since(boxBefore, w.outbox())
				if len(added) != 1 || added[0].Type != "profile" || added[0].ID != s.ids["profile2"] {
					t.Errorf("a copy wrote the outbox rows %+v, want one for the destination %s", added, s.ids["profile2"])
				}
			})
		}
	}
	// Above the job threshold the lock is read before a job is queued: 423, no job, nothing changed.
	t.Run("a rules batch above 1,000 items on a locked profile", func(t *testing.T) {
		s := newScn(w.f, w.f.env.A.Tenant, w.f.env.A.User, "A")
		w.f.env.Exec(t, `DELETE FROM ctrlz.batch_jobs WHERE tenant_id = $1`, s.tenant)
		w.lockRow(s.ids["profile"])
		before := w.digest()
		ids := uuids(1001)
		s.send(p2Spec{method: "POST", path: "/profiles/" + s.ids["profile"] + "/rules:batch", hdr: s.key(),
			body: map[string]any{"op": "delete", "ids": ids}}).want(423, "profile_locked")
		if d := changed(before, w.digest()); d != "" {
			t.Errorf("a refused big batch changed %s", d)
		}
	})
}

// wantOutbox is what spec 3.2 says each operation marks, written here once and held against the document: a delete marks the
// profile and the endpoint set, rename, lock and unlock mark nothing, every other write marks its profile once.
func wantOutbox(c p2Case) string {
	switch c.op {
	case "deleteProfile":
		return "profile+endpoint_set"
	case "renameProfile", "lockProfile", "unlockProfile":
		return "none"
	}
	if c.effect == isolation.Shows {
		return "none"
	}
	return "profile"
}

// TestS2TheOutboxOfEveryOperation: the rows an operation writes are the ones it declares, one for each aggregate and never one
// for each rule, a Move between two profiles marks both under one batch id, and a failed request writes none (spec 3.2,
// 10.2 S2, T-387).
func TestS2TheOutboxOfEveryOperation(t *testing.T) {
	w := newWalkRig(t)
	for _, c := range p2Cases() {
		t.Run(c.op, func(t *testing.T) {
			want := wantOutbox(c)
			if got := w.ops[c.op].Outbox; got != want {
				t.Errorf("%s declares x-ctrlz-outbox %q, spec 3.2 says %q", c.op, got, want)
			}
			s := w.scn(c)
			before := w.outbox()
			s.send(c.call(s, refs{s: s})).want(c.status, "")
			added := since(before, w.outbox())
			var types []string
			for _, r := range added {
				types = append(types, r.Type)
			}
			sort.Strings(types)
			wantTypes := map[string][]string{"none": nil, "profile": {"profile"}, "profile+endpoint_set": {"endpoint_set", "profile"}}[want]
			if !slices.Equal(types, wantTypes) {
				t.Errorf("%s wrote the outbox rows %+v, want %v", c.op, added, wantTypes)
			}
		})
	}
	t.Run("a selection is one row, not one for each rule", func(t *testing.T) {
		s := newScn(w.f, w.f.env.A.Tenant, w.f.env.A.User, "A")
		before := w.outbox()
		s.send(p2Spec{method: "POST", path: "/profiles/" + s.ids["profile"] + "/rules:batch", hdr: s.key(),
			body: map[string]any{"op": "disable", "ids": []string{s.ids["rule"], s.ids["rule2"], s.ids["rule3"]}}}).want(200, "")
		if added := since(before, w.outbox()); len(added) != 1 {
			t.Errorf("three rules wrote %d outbox rows: %+v", len(added), added)
		}
	})
	t.Run("a move between two profiles marks both under one batch id", func(t *testing.T) {
		s := newScn(w.f, w.f.env.A.Tenant, w.f.env.A.User, "A")
		before := w.outbox()
		s.send(p2Spec{method: "POST", path: "/profiles/" + s.ids["profile"] + "/rules/" + s.ids["rule"] + ":transfer",
			body: map[string]any{"op": "move", "dest_profile_id": s.ids["profile2"], "dest_root": true}}).want(200, "")
		added := since(before, w.outbox())
		if len(added) != 2 || added[0].Batch != added[1].Batch || added[0].ID == added[1].ID {
			t.Errorf("a move wrote %+v, want two profiles under one batch id", added)
		}
	})
	t.Run("a failed request writes none", func(t *testing.T) {
		s := newScn(w.f, w.f.env.A.Tenant, w.f.env.A.User, "A")
		before := w.outbox()
		s.send(p2Spec{method: "POST", path: "/profiles/" + s.ids["profile"] + "/rules",
			body: map[string]any{"patterns": []string{"ok.example", "bad..name"}, "action": "block"}}).want(422, "validation_failed")
		if added := since(before, w.outbox()); len(added) != 0 {
			t.Errorf("a refused request wrote %+v", added)
		}
	})
}

// sameJSON says two bodies are one document.
func sameJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// TestS6IdempotencyOfEveryKeyedOperation: a replay gives the first answer and no second effect, the same key with another body,
// another path id or another mode is 409, and two concurrent twins have one effect (spec 3.5, 10.2 S6).
func TestS6IdempotencyOfEveryKeyedOperation(t *testing.T) {
	w := newWalkRig(t)
	ops := 0
	for _, c := range p2Cases() {
		if c.alt == nil {
			continue
		}
		ops++
		t.Run(c.op, func(t *testing.T) {
			s := w.scn(c)
			first := c.call(s, refs{s: s})
			if first.hdr == nil {
				t.Fatalf("%s: its call carries no Idempotency-Key", c.op)
			}
			// The header is required: a request with none is the 400 of the pipeline and no effect.
			bare := first
			bare.hdr = nil
			s.send(bare).want(400, "")
			a := s.send(first).want(c.status, "")
			after := w.digest()
			boxAfter := w.outbox()
			b := s.send(first).want(c.status, "")
			if !sameJSON(a.Body, b.Body) {
				t.Errorf("a replay gave another answer:\n%s\n%s", a.Body, b.Body)
			}
			if d := changed(after, w.digest()); d != "" {
				t.Errorf("a replay changed %s", d)
			}
			if added := since(boxAfter, w.outbox()); len(added) != 0 {
				t.Errorf("a replay wrote the outbox rows %+v", added)
			}
			// The same key with another body, or another mode.
			other := c.alt(s)
			other.hdr = first.hdr
			s.send(other).want(409, "idempotency_key_reused")
			// And with another path id.
			if strings.HasPrefix(first.path, "/profiles/"+s.ids["profile"]) {
				moved := first
				moved.path = strings.Replace(first.path, s.ids["profile"], s.ids["profile2"], 1)
				s.send(moved).want(409, "idempotency_key_reused")
			}
			if d := changed(after, w.digest()); d != "" {
				t.Errorf("a refused reuse of a key changed %s", d)
			}
		})
		t.Run(c.op+" twins", func(t *testing.T) {
			s := w.scn(c)
			twin := c.call(s, refs{s: s})
			before := w.outbox()
			var wg sync.WaitGroup
			codes := make([]int, 2)
			clients := []*client{s.take(), s.take()}
			for i := range codes {
				wg.Add(1)
				go func() {
					defer wg.Done()
					codes[i] = clients[i].do(twin.method, twin.path, twin.body, twin.hdr).Code
				}()
			}
			wg.Wait()
			// A twin that meets the other's row lock inside the 200 ms wait answers 503, and its retry is a replay.
			for i, code := range codes {
				if code == 503 {
					codes[i] = clients[i].do(twin.method, twin.path, twin.body, twin.hdr).Code
				}
				if codes[i] != c.status {
					t.Errorf("twin %d answered %d, want %d", i, codes[i], c.status)
				}
			}
			if added := since(before, w.outbox()); len(added) > 1 {
				t.Errorf("two twins wrote %d outbox rows: %+v", len(added), added)
			}
		})
	}
	if ops != 4 {
		t.Fatalf("%d operations take an Idempotency-Key, want the four of spec 8.2 (import, duplicate, upload, rules:batch)", ops)
	}
}

// TestS7AtomicityOfEveryBatch: a batch, an upload, an import and a create with one bad item last write nothing, and lock and
// unlock take no API token (spec 10.2 S7, T-141).
func TestS7AtomicityOfEveryBatch(t *testing.T) {
	w := newWalkRig(t)
	for _, c := range p2Cases() {
		if c.op == "lockProfile" || c.op == "unlockProfile" {
			if tok := w.ops[c.op].Token; tok != "none" {
				t.Errorf("%s declares x-ctrlz-token %q, want none: a token cannot lock or unlock (T-141)", c.op, tok)
			}
		}
	}
	long := func(items ...string) string {
		var rules []string
		for _, p := range items {
			rules = append(rules, fmt.Sprintf(`{"pattern":%q,"action":"block"}`, p))
		}
		return strings.Join(rules, ",")
	}
	s := newScn(w.f, w.f.env.A.Tenant, w.f.env.A.User, "A")
	base := "/profiles/" + s.ids["profile"]
	for name, sp := range map[string]p2Spec{
		"create": {method: "POST", path: base + "/rules", body: map[string]any{"patterns": []string{"ok1.example", "ok2.example", "bad..name"}, "action": "block"}},
		"import": {method: "POST", path: "/profiles:import", hdr: s.key(),
			body: map[string]any{"document": b64(`{"format":"ctrlz-profile","version":1,"kind":"custom","name":"Atomic","rules":[` + long("ok1.example", "ok2.example", "bad..name") + `]}`)}},
		"upload": {method: "POST", path: base + "/folders/" + s.ids["folder"] + ":upload", hdr: s.key(),
			body: map[string]any{"document": b64(`{"format":"ctrlz-rules","version":1,"rules":[` + long("ok1.example", "ok2.example", "bad..name") + `]}`)}},
		"services": {method: "POST", path: base + "/services:batch",
			body: map[string]any{"op": "set", "slugs": []string{"youtube", "netflix", "no-such-service"}, "enabled": true, "action": "block"}},
		"rules batch": {method: "POST", path: base + "/rules:batch", hdr: s.key(),
			body: map[string]any{"op": "delete", "ids": []string{s.ids["rule"], s.ids["rule2"], uuid.NewString()}}},
		"rules batch edit": {method: "POST", path: base + "/rules:batch", hdr: s.key(),
			body: map[string]any{"op": "edit", "ids": []string{s.ids["rule"], s.ids["rule2"], uuid.NewString()}, "set": map[string]any{"comment": "x"}}},
	} {
		t.Run(name, func(t *testing.T) {
			before, box := w.digest(), w.outbox()
			r := s.send(sp)
			if r.Code < 400 || r.Code >= 500 {
				t.Fatalf("a request with one bad item last answered %d %s, want a refusal of the client", r.Code, r.Body)
			}
			if d := changed(before, w.digest()); d != "" {
				t.Errorf("the refused request changed %s", d)
			}
			if added := since(box, w.outbox()); len(added) != 0 {
				t.Errorf("the refused request wrote the outbox rows %+v", added)
			}
		})
	}
}
