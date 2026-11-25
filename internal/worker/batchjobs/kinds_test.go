package batchjobs_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/batchjobs"
)

// Review round 3 of package B3: one worker test per job kind the first tests did not run, and the branches of the
// handler a real queue meets only after failures (p2-B3-r3-2, p2-B3-r3-4).

// queue records a job of any kind as tenant and returns its id.
func (f *fx) queue(t *testing.T, tenant uuid.UUID, kind string, profile uuid.UUID, total int, input any) uuid.UUID {
	t.Helper()
	in, err := profiles.JobInputJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	if err := f.tenant.WithTenant(f.ctx, tenant, store.TxOpts{}, func(tx store.Tx) (e error) {
		id, e = f.env.QueueJob(tx, profiles.JobRequest{Kind: kind, Profile: profile, Total: total, Input: in})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// runToDone waits for the job to end and requires it done.
func (f *fx) runToDone(t *testing.T, id uuid.UUID) {
	t.Helper()
	testwait.Until(t, 90*time.Second, "the job to end", func() bool { s, _ := f.state(t, id); return s == "done" || s == "failed" })
	if s, e := f.state(t, id); s != "done" {
		t.Fatalf("state %s, error %s", s, e)
	}
}

// seedProfile makes a profile of a tenant with the rules (patterns) at its top level and returns its id.
func (f *fx) seedProfile(t *testing.T, tenant uuid.UUID, name string, patterns ...string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.tenant.WithTenant(f.ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
		p, err := f.env.CreateProfile(tx, name, "custom")
		if err != nil {
			return err
		}
		id = p.ID
		if len(patterns) == 0 {
			return nil
		}
		_, err = f.env.CreateRules(tx, id, profiles.RuleIn{Patterns: patterns, Act: profiles.Act{Action: "block"}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *fx) ruleCount(t *testing.T, profile uuid.UUID) int {
	t.Helper()
	var n int
	f.scan(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1`, []any{profile}, &n)
	return n
}

func (f *fx) ruleIDs(t *testing.T, tenant, profile uuid.UUID) []uuid.UUID {
	t.Helper()
	var ids []uuid.UUID
	if err := f.tenant.WithTenant(f.ctx, tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		rows, err := tx.RulesAll(profile)
		for _, r := range rows {
			ids = append(ids, r.ID)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return ids
}

// TestARulesBatchJobRunsOnTheWorker: the input of a rules_batch job survives the batch_jobs.input round trip, and the
// worker role's grants reach everything copy, move and edit write (spec 3.5).
func TestARulesBatchJobRunsOnTheWorker(t *testing.T) {
	f := newFx(t)
	src := f.seedProfile(t, f.A.Tenant, "Src", "a.example", "b.example", "c.example")
	dst := f.seedProfile(t, f.A.Tenant, "Dst")
	ids := f.ruleIDs(t, f.A.Tenant, src)
	if len(ids) != 3 {
		t.Fatalf("seeded %d rules", len(ids))
	}
	f.start(t)

	// Copy two to the destination: the source keeps them.
	f.runToDone(t, f.queue(t, f.A.Tenant, profiles.JobRulesBatch, src, 2, profiles.BatchIn{Op: "copy", IDs: ids[:2], DestProfile: dst, DestRoot: true}))
	if f.ruleCount(t, dst) != 2 || f.ruleCount(t, src) != 3 {
		t.Fatalf("after the copy: dst %d, src %d", f.ruleCount(t, dst), f.ruleCount(t, src))
	}
	// Move the third: the source loses it.
	f.runToDone(t, f.queue(t, f.A.Tenant, profiles.JobRulesBatch, src, 1, profiles.BatchIn{Op: "move", IDs: ids[2:], DestProfile: dst, DestRoot: true}))
	if f.ruleCount(t, dst) != 3 || f.ruleCount(t, src) != 2 {
		t.Fatalf("after the move: dst %d, src %d", f.ruleCount(t, dst), f.ruleCount(t, src))
	}
	// Edit with a Set.
	comment := "set by the worker"
	last := f.queue(t, f.A.Tenant, profiles.JobRulesBatch, src, 2, profiles.BatchIn{Op: "edit", IDs: ids[:2], Set: &profiles.EditSet{Comment: &comment}})
	f.runToDone(t, last)
	var n int
	f.scan(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1 AND comment = $2`, []any{src, comment}, &n)
	if n != 2 {
		t.Fatalf("%d rules carry the comment, want 2", n)
	}
	var res *string
	f.scan(t, `SELECT result::text FROM ctrlz.batch_jobs WHERE id = $1`, []any{last}, &res)
	if res == nil {
		t.Fatal("a finished job has no result")
	}
	// Tenant B has none of it.
	f.scan(t, `SELECT count(*) FROM ctrlz.rules WHERE tenant_id = $1 AND comment = $2`, []any{f.B.Tenant, comment}, &n)
	if n != 0 {
		t.Fatalf("tenant B has %d rules with A's comment", n)
	}
}

// TestAnUploadJobRunsOnTheWorker: the UploadInput round trip and the grants an upload writes through.
func TestAnUploadJobRunsOnTheWorker(t *testing.T) {
	f := newFx(t)
	p := f.seedProfile(t, f.A.Tenant, "Up", "old.example")
	var folder uuid.UUID
	if err := f.tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		row, err := f.env.CreateFolder(tx, p, profiles.FolderIn{Name: "Uploaded", Kind: "standard"})
		folder = row.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	doc := profiles.RulesDocument{Format: profiles.RulesFormat, Version: profiles.DocVersion}
	for _, h := range []string{"u1.example", "u2.example", "u3.example"} {
		doc.Rules = append(doc.Rules, profiles.DocRule{Pattern: h, Action: "block"})
	}
	f.start(t)
	f.runToDone(t, f.queue(t, f.A.Tenant, profiles.JobUpload, p, len(doc.Rules), profiles.UploadInput{FolderID: folder, Mode: "new_only", Doc: doc}))
	var n int
	f.scan(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1 AND folder_id = $2`, []any{p, folder}, &n)
	if n != 3 || f.ruleCount(t, p) != 4 {
		t.Fatalf("uploaded %d rules into the folder, %d in the profile; want 3 and 4", n, f.ruleCount(t, p))
	}
}

// TestADuplicateJobRunsOnTheWorker: the source is read again at run time and the copy is the job's profile.
func TestADuplicateJobRunsOnTheWorker(t *testing.T) {
	f := newFx(t)
	src := f.seedProfile(t, f.A.Tenant, "Original", "d1.example", "d2.example")
	f.start(t)
	id := f.queue(t, f.A.Tenant, profiles.JobDuplicate, uuid.Nil, 2, profiles.DuplicateInput{Source: src, Name: "Original copy"})
	f.runToDone(t, id)
	var jobProfile uuid.UUID
	f.scan(t, `SELECT profile_id FROM ctrlz.batch_jobs WHERE id = $1`, []any{id}, &jobProfile)
	if jobProfile == src || jobProfile == uuid.Nil || f.ruleCount(t, jobProfile) != 2 || f.ruleCount(t, src) != 2 {
		t.Fatalf("the copy is %s with %d rules, the source has %d", jobProfile, f.ruleCount(t, jobProfile), f.ruleCount(t, src))
	}
}

// TestTheFourthDeliveryOnlyMarksTheJobFailed: attempts 1 to 3 run the work, and a fourth ends the job with
// job_attempts_exhausted without running it (spec 3.5). A transient error of a run is retried, never ended.
func TestTheFourthDeliveryOnlyMarksTheJobFailed(t *testing.T) {
	f := newFx(t)
	id := f.queueImport(t, f.A.Tenant, "Never made", 2)
	// A run that cannot reach the database fails in a way a later attempt may mend: not a cancel.
	gone, cancel := context.WithCancel(f.ctx)
	cancel()
	if err := f.runner.WorkDelivery(gone, f.A.Tenant.String(), id.String(), 1); err == nil || batchjobs.IsCancel(err) {
		t.Fatalf("a transient failure gave %v, want an error River retries", err)
	}
	if s, _ := f.state(t, id); s != "queued" {
		t.Fatalf("a transient failure left the job %s", s)
	}
	// The fourth delivery fails the job and runs none of it.
	if err := f.runner.WorkDelivery(f.ctx, f.A.Tenant.String(), id.String(), profiles.JobAttempts+1); !batchjobs.IsCancel(err) {
		t.Fatalf("the fourth delivery gave %v, want a cancel", err)
	}
	s, e := f.state(t, id)
	if s != "failed" || e != `{"code": "job_attempts_exhausted"}` {
		t.Fatalf("state %s error %s", s, e)
	}
	var n int
	f.scan(t, `SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1 AND name = 'Never made'`, []any{f.A.Tenant}, &n)
	if n != 0 {
		t.Fatal("the fourth delivery ran the work")
	}
}

// TestTheDrainLeavesRowsOfOtherKinds: job_outbox is the general outbox; the batch drain takes its own kind only.
func TestTheDrainLeavesRowsOfOtherKinds(t *testing.T) {
	f := newFx(t)
	f.exec(t, `INSERT INTO ctrlz.job_outbox (tenant_id, kind, args) VALUES ($1, 'welcome', '{}'::jsonb)`, f.A.Tenant)
	id := f.queueImport(t, f.A.Tenant, "Drained", 1)
	f.start(t)
	f.runToDone(t, id)
	var kind string
	f.scan(t, `SELECT kind FROM ctrlz.job_outbox`, nil, &kind)
	if kind != "welcome" {
		t.Fatalf("the outbox holds %q after the drain, want the welcome row", kind)
	}
}
