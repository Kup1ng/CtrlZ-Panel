package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestExportReadsOneSnapshotWhileARuleMovesIntoANewFolder: the racing case of spec 10.3 through GET /profiles/{id}/export. The
// export reads the folders of the profile and then its rules. The test holds the rules table locked so the export stops at
// the second read, and while it waits, a move of the rules into a new folder commits. A read of two statements in two
// snapshots takes the old folder list with the new rules, a document that names a folder it lacks and that no import
// accepts; one RepeatableRead snapshot gives the state before the move, a document that is whole (p2-B8-r2-5).
func TestExportReadsOneSnapshotWhileARuleMovesIntoANewFolder(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	p := f.fresh(A.Tenant, A.User).mustProfile("Racing export", "custom")
	base := "/profiles/" + p.ID.String()
	f.fresh(A.Tenant, A.User).post(base+"/rules", map[string]any{"patterns": []string{"r1.example", "r2.example"}, "action": "block"}).want(201, "")

	super, err := f.env.DB.Super(f.env.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(context.Background()) }()
	tx, err := super.Begin(f.env.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(f.env.Ctx, `LOCK TABLE ctrlz.rules IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	// The session is made before the request goroutine starts, so a failure of it ends the test from this goroutine.
	c := f.fresh(A.Tenant, A.User)
	done := make(chan *resp, 1)
	go func() { done <- c.get(base + "/export") }()
	count := func(ctx context.Context, sql string) (int, error) {
		var n int
		err := f.env.DB.Scan(ctx, sql, nil, &n)
		return n, err
	}
	if err := testpg.AwaitLockWaiters(f.env.Ctx, count, 1); err != nil {
		t.Fatal(err)
	}
	var folder uuid.UUID
	if err := tx.QueryRow(f.env.Ctx, `INSERT INTO ctrlz.rule_folders (tenant_id, profile_id, name) VALUES ($1, $2, 'Moved into') RETURNING id`, A.Tenant, p.ID).Scan(&folder); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.env.Ctx, `UPDATE ctrlz.rules SET folder_id = $2 WHERE profile_id = $1`, p.ID, folder); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.env.Ctx); err != nil {
		t.Fatal(err)
	}
	r := <-done
	r.want(200, "")
	var doc struct {
		Folders []struct {
			Ref string `json:"ref"`
		} `json:"folders"`
		Rules []struct {
			Pattern string `json:"pattern"`
			Folder  string `json:"folder"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(r.Body, &doc); err != nil {
		t.Fatal(err)
	}
	refs := map[string]bool{}
	for _, fo := range doc.Folders {
		refs[fo.Ref] = true
	}
	if len(doc.Rules) != 2 {
		t.Fatalf("the export holds %d rules, want 2", len(doc.Rules))
	}
	for _, ru := range doc.Rules {
		if ru.Folder != "" && !refs[ru.Folder] {
			t.Fatalf("the rule %q names the folder %q, which the document lacks: the export read two snapshots", ru.Pattern, ru.Folder)
		}
	}
}
