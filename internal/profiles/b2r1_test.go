package profiles_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// B2 review round 1: the refusals of spec 3.7 that a batch, a folder edit and the key table owe.

func TestBatchRefusesRepeatedIDsAndBadSelectors(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "dups")
	q := f.newProfile(t, f.A.Tenant, "other")
	var ids []uuid.UUID
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		rs, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{"a.example.com", "b.example.com"}, Act: block()})
		for _, r := range rs {
			ids = append(ids, r.ID)
		}
		return err
	})
	var foreign uuid.UUID
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		row, err := f.env.CreateFolder(tx, q, profiles.FolderIn{Name: "theirs", Kind: "standard"})
		foreign = row.ID
		return err
	})
	box := f.outbox(t, p)
	try := func(in profiles.BatchIn) *profiles.Error {
		return f.refusal(t, f.A.Tenant, func(tx store.Tx) error { _, err := f.env.RulesBatch(tx, p, in); return err })
	}
	for _, op := range []string{"delete", "disable", "enable", "edit"} {
		e := try(profiles.BatchIn{Op: op, IDs: []uuid.UUID{ids[0], ids[1], ids[0]}})
		if !hasField(e, "/ids/2", "duplicate") || len(e.Fields) != 1 {
			t.Errorf("%s with a repeated id: %v", op, e)
		}
	}
	if f.count(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1`, p) != 2 || f.outbox(t, p) != box {
		t.Error("a refused batch changed the profile")
	}

	for name, c := range map[string]struct {
		sel         profiles.Selector
		field, code string
	}{
		"status typo":   {profiles.Selector{Status: "enabeld"}, "/selector/status", "invalid"},
		"folder value":  {profiles.Selector{Folder: "everywhere"}, "/selector/folder", "invalid"},
		"action value":  {profiles.Selector{Action: "allow"}, "/selector/action", "invalid"},
		"folder w/o id": {profiles.Selector{Folder: "folder"}, "/selector/folder_id", "required"},
	} {
		sel := c.sel
		if e := try(profiles.BatchIn{Op: "delete", Selector: &sel}); !hasField(e, c.field, c.code) {
			t.Errorf("%s: %v", name, e)
		}
	}
	// A folder of another profile is not found, and so is one that is nobody's.
	for name, id := range map[string]uuid.UUID{"another profile": foreign, "no folder": uuid.New()} {
		e := try(profiles.BatchIn{Op: "delete", Selector: &profiles.Selector{Folder: "folder", FolderID: id}})
		if e.Kind != profiles.KindNotFound {
			t.Errorf("folder of %s: %v", name, e)
		}
	}
	// Tenant B cannot name A's folder either.
	pb := f.newProfile(t, f.B.Tenant, "b")
	e := f.refusal(t, f.B.Tenant, func(tx store.Tx) error {
		_, err := f.env.RulesBatch(tx, pb, profiles.BatchIn{Op: "delete", Selector: &profiles.Selector{Folder: "folder", FolderID: foreign}})
		return err
	})
	if e.Kind != profiles.KindNotFound {
		t.Errorf("B names A's folder: %v", e)
	}
}

func TestUpdateFolderChecksTheActionSet(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "folders")
	var id uuid.UUID
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		row, err := f.env.CreateFolder(tx, p, profiles.FolderIn{Name: "f", Kind: "standard"})
		id = row.ID
		return err
	})
	for _, a := range []string{"inherit", "foo"} {
		e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
			_, err := f.env.UpdateFolder(tx, p, id, profiles.FolderPatch{Act: &profiles.Act{Action: a}})
			return err
		})
		if !hasField(e, "/action", "invalid") {
			t.Errorf("action %q: %v", a, e)
		}
	}
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.UpdateFolder(tx, p, id, profiles.FolderPatch{Act: &profiles.Act{Action: "block"}})
		return err
	})
}

// TestMaxRulesPerRequestBoundary holds the limit at its edge (spec 3.4, 10.4): 10,000 items pass and 10,001 are
// refused before any work, for a create; a selector answers the same at a lowered limit.
func TestMaxRulesPerRequestBoundary(t *testing.T) {
	f := newFx(t)
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_rules_per_request = NULL, max_rules_per_profile = NULL WHERE tenant_id = $1`, f.A.Tenant)
	names := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("n%d.example.com", i)
		}
		return out
	}
	p := f.newProfile(t, f.A.Tenant, "limit")
	e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: names(10001), Act: block()})
		return err
	})
	if !hasField(e, "max_rules_per_request", "exceeded") {
		t.Errorf("10,001 items: %v", e)
	}
	if f.count(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1`, p) != 0 {
		t.Error("a refused request wrote rules")
	}
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		rs, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: names(10000), Act: block()})
		if err == nil && len(rs) != 10000 {
			t.Errorf("created %d", len(rs))
		}
		return err
	})
	// A selector: matches at the limit pass, one more is refused.
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_rules_per_request = 10000 WHERE tenant_id = $1`, f.A.Tenant)
	if err := f.in(f.A.Tenant, func(tx store.Tx) error {
		r, err := f.env.RulesBatch(tx, p, profiles.BatchIn{Op: "disable", Selector: &profiles.Selector{}})
		if err == nil && r.Updated != 10000 {
			t.Errorf("selector at the limit: %+v", r)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_rules_per_request = 9999 WHERE tenant_id = $1`, f.A.Tenant)
	e = f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.RulesBatch(tx, p, profiles.BatchIn{Op: "enable", Selector: &profiles.Selector{}})
		return err
	})
	if !hasField(e, "max_rules_per_request", "exceeded") {
		t.Errorf("one match over the limit: %v", e)
	}
}

// TestKeyLifeIsTwentyFourHours: a key past its expiry is claimed anew by the next request, which gets a fresh
// effect and not the old answer or a 409, although no sweep has removed the row (spec 3.5).
func TestKeyLifeIsTwentyFourHours(t *testing.T) {
	f := newFx(t)
	req := profiles.Request{Key: "life", Method: "POST", Path: "/api/v1/profiles", Body: []byte(`{"name":"one"}`)}
	next := req
	next.Body = []byte(`{"name":"two"}`)
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		if proceed, _, err := f.env.BeginKey(tx, req); err != nil || !proceed {
			t.Fatalf("first: %v %v", proceed, err)
		}
		return f.env.FinishKey(tx, req, 201, []byte(`{"a":1}`))
	})
	f.now = f.now.Add(23 * time.Hour)
	e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error { _, _, err := f.env.BeginKey(tx, next); return err })
	if e.Kind != profiles.KindKeyReused {
		t.Errorf("inside the day: %v", e)
	}
	f.now = f.now.Add(2 * time.Hour)
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		proceed, _, err := f.env.BeginKey(tx, next)
		if err != nil || !proceed {
			t.Errorf("another body after the day: %v %v", proceed, err)
			return err
		}
		return f.env.FinishKey(tx, next, 201, []byte(`{"b":2}`))
	})
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		proceed, rep, err := f.env.BeginKey(tx, next)
		if err != nil || proceed || rep.Status != 201 {
			t.Errorf("replay of the new claim: %v %+v %v", proceed, rep, err)
		}
		return err
	})
	// Tenant B's row of the same key is its own.
	f.must(t, f.B.Tenant, func(tx store.Tx) error {
		proceed, _, err := f.env.BeginKey(tx, req)
		if err != nil || !proceed {
			t.Errorf("B: %v %v", proceed, err)
		}
		return err
	})
}

// TestProfileWriteDiesWithItsTransaction: a permission taken in one transaction writes nothing in the next, even
// for the same tenant and profile, because no guard ran there.
func TestProfileWriteDiesWithItsTransaction(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "kept")
	var kept store.ProfileWrite
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		w, won, err := tx.ProfileGuard(p)
		if err != nil || !won.Yes() {
			t.Fatalf("guard: %v %v", won, err)
		}
		kept = w
		return tx.ProfileRename(w, "same transaction")
	})
	err := f.in(f.A.Tenant, func(tx store.Tx) error { return tx.ProfileRename(kept, "later") })
	if !errors.Is(err, store.ErrNoProfileWrite) {
		t.Errorf("a kept permission: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.profiles WHERE id = $1 AND name = 'same transaction'`, p); n != 1 {
		t.Error("the later write landed")
	}
}
