package batchjobs_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestADuplicateJobReadsItsSourceInOneSnapshot: the racing case of spec 10.3. The job reads the folders of the source and then
// its rules. The test holds the rules table locked, so the job stops at that second read, and while it waits, a move of the
// rules from their folder into a new one commits. A read of two statements in two snapshots takes the old folder list with the
// new rules, and the writer of the document puts a rule whose folder it does not hold at the top level, so the copy would have
// its rules outside the folder. In one RepeatableRead snapshot the read is the state before the move (spec 6.1; p2-B8-r2-5).
func TestADuplicateJobReadsItsSourceInOneSnapshot(t *testing.T) {
	f := newFx(t)
	src := f.seedProfile(t, f.A.Tenant, "Racing source", "r1.example", "r2.example")
	// The rules start in a folder, so a torn read shows: the document writer puts a rule whose folder it does not hold at the
	// top level, so the copy of a read of two snapshots has its rules outside the folder.
	var before uuid.UUID
	f.scan(t, `INSERT INTO ctrlz.rule_folders (tenant_id, profile_id, name) VALUES ($1, $2, 'Before') RETURNING id`, []any{f.A.Tenant, src}, &before)
	f.exec(t, `UPDATE ctrlz.rules SET folder_id = $2 WHERE profile_id = $1`, src, before)
	id := f.queue(t, f.A.Tenant, profiles.JobDuplicate, uuid.Nil, 2, profiles.DuplicateInput{Source: src, Name: "Racing copy"})

	super, err := f.db.Super(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(context.Background()) }()
	tx, err := super.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(f.ctx, `LOCK TABLE ctrlz.rules IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	count := func(ctx context.Context, sql string) (int, error) {
		var n int
		err := f.db.Scan(ctx, sql, nil, &n)
		return n, err
	}
	if err := testpg.AwaitLockWaiters(f.ctx, count, 1); err != nil {
		t.Fatal(err)
	}
	var folder uuid.UUID
	if err := tx.QueryRow(f.ctx, `INSERT INTO ctrlz.rule_folders (tenant_id, profile_id, name) VALUES ($1, $2, 'Moved into') RETURNING id`, f.A.Tenant, src).Scan(&folder); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, `UPDATE ctrlz.rules SET folder_id = $2 WHERE profile_id = $1`, src, folder); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.runToDone(t, id)
	var copyID uuid.UUID
	f.scan(t, `SELECT profile_id FROM ctrlz.batch_jobs WHERE id = $1`, []any{id}, &copyID)
	var inFolder int
	f.scan(t, `SELECT count(*) FROM ctrlz.rules r JOIN ctrlz.rule_folders d ON d.tenant_id = r.tenant_id AND d.profile_id = r.profile_id AND d.id = r.folder_id
	  WHERE r.profile_id = $1 AND d.name = 'Before'`, []any{copyID}, &inFolder)
	if n := f.ruleCount(t, copyID); n != 2 || inFolder != 2 {
		t.Fatalf("the copy has %d rules, %d of them in the folder Before, want 2 and 2", n, inFolder)
	}
}
