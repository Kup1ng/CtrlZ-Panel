package catalogtest_test

import (
	"context"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/migrate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestMigration0060RevokesTheInvitesThatCannotBeOpened is D67: an invite is a signed link now, so a row made
// for the old short code can never be opened, and it must not stay in the admin's list as pending. The migration
// revokes every invite that was open and leaves a used one and an already revoked one exactly as they were
// (their timestamps are history), and it lets the admin role insert the id, because the id is inside the token.
func TestMigration0060RevokesTheInvitesThatCannotBeOpened(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	d := c.NewEmptyDB(ctx, t)
	db, err := d.MigratorDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	super, err := d.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(context.Background())

	if _, err := migrate.UpTo(ctx, db, 59); err != nil {
		t.Fatal(err)
	}
	// One of each state, with hashes that stand for codes of the old form.
	for i, row := range []struct{ phone, state string }{
		{"+989125550001", "open"}, {"+989125550002", "expired"}, {"+989125550003", "used"}, {"+989125550004", "revoked"},
	} {
		used, revoked, expires := "NULL", "NULL", "now() + interval '1 day'"
		switch row.state {
		case "expired":
			expires = "now() - interval '1 day'"
		case "used":
			used = "now() - interval '2 hours'"
		case "revoked":
			revoked = "now() - interval '3 hours'"
		}
		if _, err := super.Exec(ctx, `INSERT INTO ctrlz.invites (token_hash, phone_e164, expires_at, used_at, revoked_at) VALUES (sha256($1::bytea), $2, `+expires+`, `+used+`, `+revoked+`)`,
			[]byte{byte(i + 1)}, row.phone); err != nil {
			t.Fatal(err)
		}
	}
	type state struct{ usedSet, revokedSet bool }
	read := func() map[string]state {
		t.Helper()
		rows, err := super.Query(ctx, `SELECT phone_e164, used_at IS NOT NULL, revoked_at IS NOT NULL FROM ctrlz.invites`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]state{}
		for rows.Next() {
			var p string
			var s state
			if err := rows.Scan(&p, &s.usedSet, &s.revokedSet); err != nil {
				t.Fatal(err)
			}
			out[p] = s
		}
		return out
	}
	var usedAt, revokedAt time.Time
	if err := super.QueryRow(ctx, `SELECT used_at FROM ctrlz.invites WHERE phone_e164 = '+989125550003'`).Scan(&usedAt); err != nil {
		t.Fatal(err)
	}
	if err := super.QueryRow(ctx, `SELECT revoked_at FROM ctrlz.invites WHERE phone_e164 = '+989125550004'`).Scan(&revokedAt); err != nil {
		t.Fatal(err)
	}

	if _, err := migrate.UpTo(ctx, db, 60); err != nil {
		t.Fatalf("0060: %v", err)
	}
	got := read()
	if len(got) != 4 {
		t.Fatalf("%d invites after the migration, want the same four", len(got))
	}
	for _, p := range []string{"+989125550001", "+989125550002"} {
		if !got[p].revokedSet || got[p].usedSet {
			t.Errorf("%s: %+v, want revoked and not used", p, got[p])
		}
	}
	if s := got["+989125550003"]; !s.usedSet || s.revokedSet {
		t.Errorf("the used invite changed: %+v", s)
	}
	var usedAfter, revokedAfter time.Time
	if err := super.QueryRow(ctx, `SELECT used_at FROM ctrlz.invites WHERE phone_e164 = '+989125550003'`).Scan(&usedAfter); err != nil {
		t.Fatal(err)
	}
	if err := super.QueryRow(ctx, `SELECT revoked_at FROM ctrlz.invites WHERE phone_e164 = '+989125550004'`).Scan(&revokedAfter); err != nil {
		t.Fatal(err)
	}
	if !usedAfter.Equal(usedAt) || !revokedAfter.Equal(revokedAt) {
		t.Error("a used or an already revoked invite had its timestamp rewritten")
	}

	// The admin role may insert the id, and may not set the other columns it had no grant on.
	var granted, other bool
	if err := super.QueryRow(ctx, `SELECT has_column_privilege('ctrlz_admin', 'ctrlz.invites', 'id', 'INSERT'),
	  has_column_privilege('ctrlz_admin', 'ctrlz.invites', 'used_at', 'INSERT')`).Scan(&granted, &other); err != nil {
		t.Fatal(err)
	}
	if !granted || other {
		t.Errorf("ctrlz_admin INSERT on invites.id = %v, on used_at = %v, want true and false", granted, other)
	}
}
