package profiles_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// TestGuardRefusesEveryWriteOfALockedProfile walks every write operation of the package on a locked profile: 423,
// the profile unchanged, no outbox row (spec 3.1, 10.2 S1). Unlocked, the same calls pass.
func TestGuardRefusesEveryWriteOfALockedProfile(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "walk")
	// Something to edit, written while the profile is unlocked.
	var rule, folder uuid.UUID
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		fo, err := f.env.CreateFolder(tx, p, profiles.FolderIn{Name: "f", Kind: "standard"})
		if err != nil {
			return err
		}
		folder = fo.ID
		rs, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{"a.example.com"}, Act: block()})
		if err != nil {
			return err
		}
		rule = rs[0].ID
		return nil
	})
	f.lock(t, p)
	before, boxBefore := f.digest(t, p), f.outbox(t, p)
	ops := map[string]func(tx store.Tx) error{
		"rename":  func(tx store.Tx) error { _, err := f.env.RenameProfile(tx, p, "x"); return err },
		"disable": func(tx store.Tx) error { _, err := f.env.Disable(tx, p, "1h", nil); return err },
		"enable":  func(tx store.Tx) error { _, err := f.env.Enable(tx, p); return err },
		"create rules": func(tx store.Tx) error {
			_, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{"b.example.com"}, Act: block()})
			return err
		},
		"update rule": func(tx store.Tx) error {
			c := "c"
			_, err := f.env.UpdateRule(tx, p, rule, profiles.RulePatch{Comment: &c})
			return err
		},
		"delete rule": func(tx store.Tx) error { return f.env.DeleteRule(tx, p, rule) },
		"create folder": func(tx store.Tx) error {
			_, err := f.env.CreateFolder(tx, p, profiles.FolderIn{Name: "g", Kind: "standard"})
			return err
		},
		"update folder": func(tx store.Tx) error {
			n := "h"
			_, err := f.env.UpdateFolder(tx, p, folder, profiles.FolderPatch{Name: &n})
			return err
		},
		"delete folder": func(tx store.Tx) error { return f.env.DeleteFolder(tx, p, folder) },
		"set services": func(tx store.Tx) error {
			_, err := f.env.SetServices(tx, p, []string{"youtube"}, profiles.ServiceState{Enabled: true, Act: block()})
			return err
		},
		"del services": func(tx store.Tx) error { _, err := f.env.DeleteServices(tx, p, []string{"youtube"}); return err },
		"set filter":   func(tx store.Tx) error { _, err := f.env.SetFilter(tx, p, "phishing", true, ""); return err },
		"options": func(tx store.Tx) error {
			b := true
			_, err := f.env.PatchOptions(tx, p, profiles.OptionsPatch{SafeSearch: &b})
			return err
		},
		"batch enable": func(tx store.Tx) error {
			_, err := f.env.RulesBatch(tx, p, profiles.BatchIn{Op: "disable", IDs: []uuid.UUID{rule}})
			return err
		},
		"batch delete": func(tx store.Tx) error {
			_, err := f.env.RulesBatch(tx, p, profiles.BatchIn{Op: "delete", IDs: []uuid.UUID{rule}})
			return err
		},
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			if e := f.refusal(t, f.A.Tenant, op); e.Kind != profiles.KindLocked {
				t.Fatalf("got %v, want profile_locked", e)
			}
			if got := f.digest(t, p); got != before {
				t.Errorf("a refused write changed the profile")
			}
			if f.outbox(t, p) != boxBefore {
				t.Errorf("a refused write wrote an outbox row")
			}
		})
	}
	// Delete opens its own transaction (it retries a deadlock as a whole), so it is walked beside the others.
	err := f.env.Delete(f.ctx, f.st, f.A.Tenant, p, store.TxOpts{})
	if e, ok := err.(*profiles.Error); !ok || e.Kind != profiles.KindLocked {
		t.Errorf("delete: got %v, want profile_locked", err)
	}
	f.unlock(t, p)
	f.must(t, f.A.Tenant, func(tx store.Tx) error { _, err := f.env.RenameProfile(tx, p, "after unlock"); return err })
}

// TestOutboxRowsAreOnePerProfile: a transaction that changes what the profile compiles to marks it once, however
// many rows it wrote; a rename marks nothing; a delete marks the profile and the tenant's endpoint_set (3.2).
func TestOutboxRowsAreOnePerProfile(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "outbox")
	before := f.outbox(t, p)
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{"a.example.com", "b.example.com", "c.example.com"}, Act: block()})
		return err
	})
	if got := f.outbox(t, p) - before; got != 1 {
		t.Errorf("three rules wrote %d outbox rows, want 1", got)
	}
	before = f.outbox(t, p)
	f.must(t, f.A.Tenant, func(tx store.Tx) error { _, err := f.env.RenameProfile(tx, p, "renamed"); return err })
	if f.outbox(t, p) != before {
		t.Error("a rename wrote an outbox row")
	}
	// A failed request writes none.
	e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{"ok.example.com", "not a name"}, Act: block()})
		return err
	})
	if e.Kind != profiles.KindValidation || !hasField(e, "/patterns/1", "pattern_invalid") && len(e.Fields) == 0 {
		t.Errorf("got %v", e)
	}
	if f.outbox(t, p) != before {
		t.Error("a refused create wrote an outbox row")
	}
	if err := f.env.Delete(f.ctx, f.st, f.A.Tenant, p, store.TxOpts{}); err != nil {
		t.Fatal(err)
	}
	if f.count(t, `SELECT count(*) FROM ctrlz.policy_outbox WHERE aggregate_type = 'endpoint_set' AND aggregate_id = $1`, f.A.Tenant) != 1 {
		t.Error("a delete did not mark the tenant's endpoint_set")
	}
}

// TestDeleteInUse: a profile an Endpoint or a window uses is profile_in_use, and a free one is removed.
func TestDeleteInUse(t *testing.T) {
	f := newFx(t)
	err := f.env.Delete(f.ctx, f.st, f.A.Tenant, f.A.Profile, store.TxOpts{})
	if e, ok := err.(*profiles.Error); !ok || e.Kind != profiles.KindInUse {
		t.Fatalf("got %v, want profile_in_use", err)
	}
	free := f.newProfile(t, f.A.Tenant, "free")
	if err := f.env.Delete(f.ctx, f.st, f.A.Tenant, free, store.TxOpts{}); err != nil {
		t.Fatal(err)
	}
	if f.count(t, `SELECT count(*) FROM ctrlz.profiles WHERE id = $1`, free) != 0 {
		t.Error("the profile is still there")
	}
	if err := f.env.Delete(f.ctx, f.st, f.A.Tenant, free, store.TxOpts{}); err == nil {
		t.Error("a second delete succeeded")
	} else if e, ok := err.(*profiles.Error); !ok || e.Kind != profiles.KindNotFound {
		t.Errorf("got %v, want not_found", err)
	}
}

// TestTwoTenants: B's session cannot reach A's profile or any id of A's content, whatever the operation, and A's
// state is unchanged afterwards (spec 10.1, cross ids).
func TestTwoTenants(t *testing.T) {
	f := newFx(t)
	a := f.newProfile(t, f.A.Tenant, "a")
	b := f.newProfile(t, f.B.Tenant, "b")
	var aRule, aFolder uuid.UUID
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		fo, err := f.env.CreateFolder(tx, a, profiles.FolderIn{Name: "f", Kind: "standard"})
		if err != nil {
			return err
		}
		aFolder = fo.ID
		rs, err := f.env.CreateRules(tx, a, profiles.RuleIn{Patterns: []string{"mine.example.com"}, Act: block()})
		aRule = rs[0].ID
		return err
	})
	digestA, digestB := f.digest(t, a), f.digest(t, b)
	notFound := func(name string, fn func(tx store.Tx) error) {
		t.Run(name, func(t *testing.T) {
			if e := f.refusal(t, f.B.Tenant, fn); e.Kind != profiles.KindNotFound {
				t.Errorf("got %v, want not_found", e)
			}
		})
	}
	// A's id from B's session.
	notFound("rename", func(tx store.Tx) error { _, err := f.env.RenameProfile(tx, a, "x"); return err })
	notFound("create rules", func(tx store.Tx) error {
		_, err := f.env.CreateRules(tx, a, profiles.RuleIn{Patterns: []string{"x.example.com"}, Act: block()})
		return err
	})
	notFound("update rule", func(tx store.Tx) error {
		c := "x"
		_, err := f.env.UpdateRule(tx, a, aRule, profiles.RulePatch{Comment: &c})
		return err
	})
	notFound("delete folder", func(tx store.Tx) error { return f.env.DeleteFolder(tx, a, aFolder) })
	notFound("set filter", func(tx store.Tx) error { _, err := f.env.SetFilter(tx, a, "phishing", true, ""); return err })
	// A's rule and folder ids sent under B's own profile are not B's either.
	notFound("update rule under own profile", func(tx store.Tx) error {
		c := "x"
		_, err := f.env.UpdateRule(tx, b, aRule, profiles.RulePatch{Comment: &c})
		return err
	})
	notFound("delete rule under own profile", func(tx store.Tx) error { return f.env.DeleteRule(tx, b, aRule) })
	notFound("rule into A's folder", func(tx store.Tx) error {
		_, err := f.env.CreateRules(tx, b, profiles.RuleIn{Patterns: []string{"x.example.com"}, Act: block(), FolderID: aFolder})
		return err
	})
	notFound("batch with A's id", func(tx store.Tx) error {
		_, err := f.env.RulesBatch(tx, b, profiles.BatchIn{Op: "delete", IDs: []uuid.UUID{aRule}})
		return err
	})
	notFound("batch into A's profile", func(tx store.Tx) error {
		_, err := f.env.RulesBatch(tx, b, profiles.BatchIn{Op: "copy", Selector: &profiles.Selector{}, DestProfile: a, DestRoot: true})
		return err
	})
	if err := f.env.Delete(f.ctx, f.st, f.B.Tenant, a, store.TxOpts{}); err == nil {
		t.Error("B deleted A's profile")
	}
	if f.digest(t, a) != digestA {
		t.Error("A's profile changed")
	}
	if f.digest(t, b) != digestB {
		t.Error("B's profile changed")
	}
}

// TestQuotas: each limit is decided by the statement and answers exceeded with the column; B is unaffected by A's
// limits and an override of B changes nothing for A (T-338).
func TestQuotas(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "quota")
	pb := f.newProfile(t, f.B.Tenant, "quota-b")

	t.Run("rules per profile", func(t *testing.T) {
		f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_rules_per_profile = 3 WHERE tenant_id = $1`, f.A.Tenant)
		f.must(t, f.A.Tenant, func(tx store.Tx) error {
			_, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{"a.example.com", "b.example.com", "c.example.com"}, Act: block()})
			return err
		})
		e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
			_, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{"d.example.com"}, Act: block()})
			return err
		})
		if !hasField(e, "max_rules_per_profile", "exceeded") {
			t.Errorf("got %v", e)
		}
		// B has its own limit and its own rules.
		f.must(t, f.B.Tenant, func(tx store.Tx) error {
			_, err := f.env.CreateRules(tx, pb, profiles.RuleIn{Patterns: []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"}, Act: block()})
			return err
		})
	})
	t.Run("wildcards per profile", func(t *testing.T) {
		q := f.newProfile(t, f.A.Tenant, "wild")
		f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_wildcards_per_profile = 1 WHERE tenant_id = $1`, f.A.Tenant)
		f.must(t, f.A.Tenant, func(tx store.Tx) error {
			_, err := f.env.CreateRules(tx, q, profiles.RuleIn{Patterns: []string{"*.one.example.com"}, Act: block()})
			return err
		})
		e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
			_, err := f.env.CreateRules(tx, q, profiles.RuleIn{Patterns: []string{"*.two.example.com"}, Act: block()})
			return err
		})
		if !hasField(e, "max_wildcards_per_profile", "exceeded") {
			t.Errorf("got %v", e)
		}
		// A plain rule turned into a wildcard is a new wildcard too (PATCH of a pattern).
		var plain uuid.UUID
		f.must(t, f.A.Tenant, func(tx store.Tx) error {
			rs, err := f.env.CreateRules(tx, q, profiles.RuleIn{Patterns: []string{"plain.example.com"}, Act: block()})
			plain = rs[0].ID
			return err
		})
		w := "*.three.example.com"
		e = f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
			_, err := f.env.UpdateRule(tx, q, plain, profiles.RulePatch{Pattern: &w})
			return err
		})
		if !hasField(e, "max_wildcards_per_profile", "exceeded") {
			t.Errorf("got %v", e)
		}
	})
	t.Run("rules per request", func(t *testing.T) {
		q := f.newProfile(t, f.A.Tenant, "request")
		f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_rules_per_request = 2 WHERE tenant_id = $1`, f.A.Tenant)
		e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
			_, err := f.env.CreateRules(tx, q, profiles.RuleIn{Patterns: []string{"a.example.com", "b.example.com", "c.example.com"}, Act: block()})
			return err
		})
		if !hasField(e, "max_rules_per_request", "exceeded") {
			t.Errorf("got %v", e)
		}
	})
	t.Run("profiles", func(t *testing.T) {
		n := f.count(t, `SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1`, f.A.Tenant)
		f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_profiles = $2 WHERE tenant_id = $1`, f.A.Tenant, n)
		e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error { _, err := f.env.CreateProfile(tx, "one too many", "custom"); return err })
		if !hasField(e, "max_profiles", "exceeded") {
			t.Errorf("got %v", e)
		}
		f.must(t, f.B.Tenant, func(tx store.Tx) error { _, err := f.env.CreateProfile(tx, "b is not full", "kids"); return err })
	})
	t.Run("folders per profile", func(t *testing.T) {
		q := f.newProfile(t, f.A.Tenant, "folders")
		f.exec(t, `INSERT INTO ctrlz.rule_folders (tenant_id, profile_id, name) SELECT $1, $2, 'f' || g FROM generate_series(1, 500) g`, f.A.Tenant, q)
		e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
			_, err := f.env.CreateFolder(tx, q, profiles.FolderIn{Name: "x", Kind: "standard"})
			return err
		})
		if !hasField(e, "max_folders_per_profile", "exceeded") {
			t.Errorf("got %v", e)
		}
	})
}

// TestDisableUsesTheApplicationClock: Disable ends at the application time plus the duration (T-138), until a
// moment in the past is refused, and Enable clears it.
func TestDisableUsesTheApplicationClock(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "disable")
	var got store.Profile
	f.must(t, f.A.Tenant, func(tx store.Tx) (err error) { got, err = f.env.Disable(tx, p, "1h", nil); return })
	if got.DisabledUntil == nil || !got.DisabledUntil.Equal(f.now.Add(time.Hour)) {
		t.Errorf("disabled until %v, want %v", got.DisabledUntil, f.now.Add(time.Hour))
	}
	past := f.now.Add(-time.Minute)
	e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error { _, err := f.env.Disable(tx, p, "", &past); return err })
	if !hasField(e, "/until", "in_past") {
		t.Errorf("got %v", e)
	}
	e = f.refusal(t, f.A.Tenant, func(tx store.Tx) error { _, err := f.env.Disable(tx, p, "2h", nil); return err })
	if !hasField(e, "/for", "invalid") {
		t.Errorf("got %v", e)
	}
	f.must(t, f.A.Tenant, func(tx store.Tx) (err error) { got, err = f.env.Enable(tx, p); return })
	if got.DisabledUntil != nil {
		t.Error("Enable did not clear the Disable")
	}
}

// TestDeleteAgainstAClientWriter: the delete of a profile that clients name locks them in id order before it
// deletes, so a writer that locks the same clients in id order cannot deadlock with it (T-530, PS test 27); a
// deadlock that does happen is retried.
func TestDeleteAgainstAClientWriter(t *testing.T) {
	f := newFx(t)
	for round := 0; round < 8; round++ {
		p := f.newProfile(t, f.A.Tenant, "clients")
		for i := 0; i < 6; i++ {
			f.exec(t, `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, profile_id) VALUES ($1, $2, $3, $4)`,
				f.A.Tenant, f.A.Endpoint, fmt.Sprintf("c%d-%d", round, i), p)
		}
		done := make(chan error, 1)
		go func() {
			w, err := f.db.Conn(f.ctx, "ctrlz_hub")
			if err != nil {
				done <- err
				return
			}
			defer w.Close(f.ctx)
			for k := 0; k < 20; k++ {
				tx, err := w.Begin(f.ctx)
				if err != nil {
					done <- err
					return
				}
				if _, err := tx.Exec(f.ctx, `UPDATE ctrlz.clients SET last_seen_at = now() WHERE tenant_id = $1 AND id = ANY (ARRAY(SELECT id FROM ctrlz.clients WHERE tenant_id = $1 AND endpoint_id = $2 ORDER BY id FOR NO KEY UPDATE))`, f.A.Tenant, f.A.Endpoint); err != nil {
					_ = tx.Rollback(f.ctx)
					continue // the profile went away under it: nothing to do
				}
				_ = tx.Commit(f.ctx)
			}
			done <- nil
		}()
		if err := f.env.Delete(f.ctx, f.st, f.A.Tenant, p, store.TxOpts{LockWait: 5 * time.Second}); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

// TestDeleteDoesNotRepeatOnALockTimeout (p2-B3-r13-5): spec 3.3 retries a delete on a deadlock only. A delete that meets a
// held guard is refused at the end of the one lock wait of 3.1, as a 503 the client retries, and does not run again two
// more times on a pooled connection: three waits of 300 ms here would be 900 ms.
func TestDeleteDoesNotRepeatOnALockTimeout(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "held")
	super, err := f.db.Super(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(context.Background()) }()
	holder, err := super.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.Background()) }()
	// A writer of the profile (a job) holds its row.
	if _, err := holder.Exec(f.ctx, `SELECT 1 FROM ctrlz.profiles WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, f.A.Tenant, p); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = f.env.Delete(f.ctx, f.st, f.A.Tenant, p, store.TxOpts{LockWait: 300 * time.Millisecond})
	took := time.Since(start)
	if !errors.Is(err, store.ErrRetry) {
		t.Fatalf("a delete behind a held guard: %v, want the retryable refusal", err)
	}
	if took < 250*time.Millisecond {
		t.Fatalf("the delete gave up after %v, before its lock wait", took)
	}
	if took > 700*time.Millisecond {
		t.Fatalf("the delete ran again after a lock timeout: %v for a wait of 300 ms", took)
	}
}
