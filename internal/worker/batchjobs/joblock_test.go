package batchjobs_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// The lock guard and the outbox of the job runner (spec 3.1, 3.2, 10.2 S1 and S2, 10.4): a job is the code of a route run
// later, so a lock taken after it was queued must refuse it, and what it writes is marked once for each profile.

// lockRow locks a profile the way a lock leaves it, with no Argon2 run: the case needs the lock, not the route.
func (f *fx) lockRow(t *testing.T, profile uuid.UUID) {
	t.Helper()
	f.exec(t, `UPDATE ctrlz.profiles SET lock_state = 'locked', lock_password_hash = 'h', locked_at = now() WHERE id = $1`, profile)
}

// queueTransfer queues a rules_batch that names a destination, as the route does: a copy reads the path profile and writes
// the destination, a move to another profile writes both.
func (f *fx) queueTransfer(t *testing.T, tenant, profile uuid.UUID, in profiles.BatchIn, move bool) uuid.UUID {
	t.Helper()
	input, err := profiles.JobInputJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	if err := f.tenant.WithTenant(f.ctx, tenant, store.TxOpts{}, func(tx store.Tx) (e error) {
		id, e = f.env.QueueJob(tx, profiles.JobRequest{Kind: profiles.JobRulesBatch, Profile: profile, Total: len(in.IDs), Input: input, Dest: in.DestProfile, Move: move})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

type boxRow struct {
	Type  string `json:"type"`
	ID    string `json:"id"`
	Batch string `json:"batch"`
}

// policyBox reads the policy_outbox rows of a tenant in order.
func (f *fx) policyBox(t *testing.T, tenant uuid.UUID) []boxRow {
	t.Helper()
	var js string
	f.scan(t, `SELECT coalesce(jsonb_agg(jsonb_build_object('type', aggregate_type, 'id', aggregate_id, 'batch', batch_id) ORDER BY id), '[]'::jsonb)::text
		FROM ctrlz.policy_outbox WHERE tenant_id = $1`, []any{tenant}, &js)
	var rows []boxRow
	if err := json.Unmarshal([]byte(js), &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

// contentDigest fingerprints the rules and folders of a tenant: a refused job must leave both as they were.
func (f *fx) contentDigest(t *testing.T, tenant uuid.UUID) string {
	t.Helper()
	var s string
	f.scan(t, `SELECT (SELECT coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') FROM ctrlz.rules x WHERE tenant_id = $1) || '/' ||
		(SELECT coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') FROM ctrlz.rule_folders x WHERE tenant_id = $1) || '/' ||
		(SELECT coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') FROM ctrlz.profiles x WHERE tenant_id = $1)`, []any{tenant}, &s)
	return s
}

func (f *fx) untilEnded(t *testing.T, id uuid.UUID) (state, errJSON string) {
	t.Helper()
	testwait.Until(t, 90*time.Second, "the job to end", func() bool { s, _ := f.state(t, id); return s == "done" || s == "failed" })
	return f.state(t, id)
}

// TestAJobSeesALockTakenAfterItWasQueued: each job kind that writes an existing profile, queued while the profile is free
// and run after it is locked, fails with profile_locked and writes nothing: no rule, no folder, no version step, no outbox
// row. Copy and Move are judged by the profile each one writes (spec 3.1, 7.3, 10.2 S1, 10.4).
func TestAJobSeesALockTakenAfterItWasQueued(t *testing.T) {
	// Each case has a fixture of its own: the runner starts only after the lock, or it would run the job at once, and a
	// tenant holds one active job at a time.
	type kase struct {
		name  string
		lock  func(src, dst uuid.UUID) uuid.UUID // the profile locked after the queue
		queue func(f *fx, t *testing.T, src, dst, folder uuid.UUID, ids []uuid.UUID) uuid.UUID
	}
	cases := []kase{
		{"rules batch disable", func(src, _ uuid.UUID) uuid.UUID { return src },
			func(f *fx, t *testing.T, src, _, _ uuid.UUID, ids []uuid.UUID) uuid.UUID {
				return f.queue(t, f.A.Tenant, profiles.JobRulesBatch, src, len(ids), profiles.BatchIn{Op: "disable", IDs: ids})
			}},
		{"rules batch delete", func(src, _ uuid.UUID) uuid.UUID { return src },
			func(f *fx, t *testing.T, src, _, _ uuid.UUID, ids []uuid.UUID) uuid.UUID {
				return f.queue(t, f.A.Tenant, profiles.JobRulesBatch, src, len(ids), profiles.BatchIn{Op: "delete", IDs: ids})
			}},
		{"rules batch copy into a destination locked later", func(_, dst uuid.UUID) uuid.UUID { return dst },
			func(f *fx, t *testing.T, src, dst, _ uuid.UUID, ids []uuid.UUID) uuid.UUID {
				return f.queueTransfer(t, f.A.Tenant, src, profiles.BatchIn{Op: "copy", IDs: ids, DestProfile: dst, DestRoot: true}, false)
			}},
		{"rules batch move into a destination locked later", func(_, dst uuid.UUID) uuid.UUID { return dst },
			func(f *fx, t *testing.T, src, dst, _ uuid.UUID, ids []uuid.UUID) uuid.UUID {
				return f.queueTransfer(t, f.A.Tenant, src, profiles.BatchIn{Op: "move", IDs: ids, DestProfile: dst, DestRoot: true}, true)
			}},
		{"rules batch move out of a source locked later", func(src, _ uuid.UUID) uuid.UUID { return src },
			func(f *fx, t *testing.T, src, dst, _ uuid.UUID, ids []uuid.UUID) uuid.UUID {
				return f.queueTransfer(t, f.A.Tenant, src, profiles.BatchIn{Op: "move", IDs: ids, DestProfile: dst, DestRoot: true}, true)
			}},
		{"upload", func(src, _ uuid.UUID) uuid.UUID { return src },
			func(f *fx, t *testing.T, src, _, folder uuid.UUID, _ []uuid.UUID) uuid.UUID {
				return f.queue(t, f.A.Tenant, profiles.JobUpload, src, 1, profiles.UploadInput{FolderID: folder, Mode: "new_only", Doc: rulesDoc("late.example")})
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFx(t)
			src := f.seedProfile(t, f.A.Tenant, "Src", "a.example", "b.example")
			dst := f.seedProfile(t, f.A.Tenant, "Dst")
			folder := f.queueFolder(t, f.A.Tenant, src, "Folder")
			ids := f.ruleIDs(t, f.A.Tenant, src)
			id := c.queue(f, t, src, dst, folder, ids)
			f.lockRow(t, c.lock(src, dst))
			digest, box := f.contentDigest(t, f.A.Tenant), f.policyBox(t, f.A.Tenant)
			f.start(t)
			state, e := f.untilEnded(t, id)
			var got struct {
				Code string `json:"code"`
			}
			if state != "failed" || json.Unmarshal([]byte(e), &got) != nil || got.Code != "profile_locked" {
				t.Errorf("the job is %s with %s, want failed with profile_locked", state, e)
			}
			if f.contentDigest(t, f.A.Tenant) != digest {
				t.Errorf("a refused job changed the content of the tenant")
			}
			if after := f.policyBox(t, f.A.Tenant); len(after) != len(box) {
				t.Errorf("a refused job wrote the outbox rows %+v", after[len(box):])
			}
		})
	}
}

// TestAJobDoneMarksEachProfileOnce: a job that ends done writes one policy_outbox row for each profile it wrote, never one for
// each rule, and a move to another profile writes two under one batch id. The aggregate is the profile (spec 3.2, 10.2 S2).
func TestAJobDoneMarksEachProfileOnce(t *testing.T) {
	f := newFx(t)
	f.start(t)
	src := f.seedProfile(t, f.A.Tenant, "Src", "a.example", "b.example", "c.example")
	dst := f.seedProfile(t, f.A.Tenant, "Dst")
	dst2 := f.seedProfile(t, f.A.Tenant, "Dst two")
	folder := f.queueFolder(t, f.A.Tenant, src, "Uploaded")
	ids := f.ruleIDs(t, f.A.Tenant, src)

	for _, c := range []struct {
		name   string
		queue  func() uuid.UUID
		wrote  []uuid.UUID // the profiles the job wrote
		oneRow bool        // all rows share one batch id
	}{
		{"disable three rules", func() uuid.UUID {
			return f.queue(t, f.A.Tenant, profiles.JobRulesBatch, src, 3, profiles.BatchIn{Op: "disable", IDs: ids})
		}, []uuid.UUID{src}, false},
		{"upload three rules", func() uuid.UUID {
			return f.queue(t, f.A.Tenant, profiles.JobUpload, src, 3, profiles.UploadInput{FolderID: folder, Mode: "new_only", Doc: rulesDoc("u1.example", "u2.example", "u3.example")})
		}, []uuid.UUID{src}, false},
		{"copy three rules to another profile", func() uuid.UUID {
			return f.queueTransfer(t, f.A.Tenant, src, profiles.BatchIn{Op: "copy", IDs: ids, DestProfile: dst, DestRoot: true}, false)
		}, []uuid.UUID{dst}, false},
		{"move three rules to another profile", func() uuid.UUID {
			return f.queueTransfer(t, f.A.Tenant, src, profiles.BatchIn{Op: "move", IDs: ids, DestProfile: dst2, DestRoot: true}, true)
		}, []uuid.UUID{src, dst2}, true},
	} {
		before := f.policyBox(t, f.A.Tenant)
		f.runToDone(t, c.queue())
		added := f.policyBox(t, f.A.Tenant)[len(before):]
		if len(added) != len(c.wrote) {
			t.Errorf("%s: wrote %d outbox rows %+v, want %d", c.name, len(added), added, len(c.wrote))
			continue
		}
		seen := map[string]bool{}
		for _, r := range added {
			seen[r.ID] = true
			if r.Type != "profile" {
				t.Errorf("%s: the aggregate is %q, want profile", c.name, r.Type)
			}
			if c.oneRow && r.Batch != added[0].Batch {
				t.Errorf("%s: the rows of one move carry two batch ids: %+v", c.name, added)
			}
		}
		for _, p := range c.wrote {
			if !seen[p.String()] {
				t.Errorf("%s: no outbox row names profile %s: %+v", c.name, p, added)
			}
		}
	}
}

// TestAJobEndedBeforeItsWorkWritesNothing: a job that ended between its claim and its work (the sweep or a mark-failed came
// in) applies nothing and keeps the end the other one gave it, whether the work is stopped by the gate or by the finish that
// finds no running row (spec 3.5). A trigger ends the row in the claim statement, which is the one point a test cannot
// otherwise reach.
func TestAJobEndedBeforeItsWorkWritesNothing(t *testing.T) {
	f := newFx(t)
	src := f.seedProfile(t, f.A.Tenant, "Src", "a.example", "b.example")
	ids := f.ruleIDs(t, f.A.Tenant, src)
	id := f.queue(t, f.A.Tenant, profiles.JobRulesBatch, src, len(ids), profiles.BatchIn{Op: "delete", IDs: ids})
	f.exec(t, `CREATE FUNCTION public.test_end_claimed_job() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE ctrlz.batch_jobs SET state = 'failed', error = '{"code": "job_attempts_exhausted"}'::jsonb, input = NULL WHERE id = NEW.id;
  RETURN NULL;
END $$`)
	f.exec(t, `CREATE TRIGGER test_end_claimed_job AFTER UPDATE ON ctrlz.batch_jobs FOR EACH ROW
WHEN (OLD.state = 'queued' AND NEW.state = 'running') EXECUTE FUNCTION public.test_end_claimed_job()`)
	digest, box := f.contentDigest(t, f.A.Tenant), f.policyBox(t, f.A.Tenant)
	f.start(t)
	testwait.Until(t, 90*time.Second, "River to finish its delivery", func() bool {
		var n int
		f.scan(t, `SELECT count(*) FROM river.river_job WHERE state = 'completed'`, nil, &n)
		return n == 1
	})
	s, e := f.state(t, id)
	if s != "failed" || e != `{"code": "job_attempts_exhausted"}` {
		t.Fatalf("the job is %s with %s, want the end the trigger gave it", s, e)
	}
	if f.contentDigest(t, f.A.Tenant) != digest || f.ruleCount(t, src) != len(ids) {
		t.Fatal("a job that ended before its work applied the work")
	}
	if after := f.policyBox(t, f.A.Tenant); len(after) != len(box) {
		t.Fatalf("a job that ended before its work wrote the outbox rows %+v", after[len(box):])
	}
	var attempts int
	f.scan(t, `SELECT coalesce(max(attempt), 0) FROM river.river_job`, nil, &attempts)
	if attempts != 1 {
		t.Fatalf("the job took %d deliveries, want 1: it is not an error to retry", attempts)
	}
}
