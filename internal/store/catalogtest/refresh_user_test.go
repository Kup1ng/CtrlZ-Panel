package catalogtest_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Review round 5, db-r5-5. A refresh token was tied to its session and to its user by two
// separate keys, so nothing said the two name the same person. Today a tenant has one
// owner and no writer can produce a mismatch; the day members arrive (D32) a bug, or a
// statement of the tenant role, could insert a refresh row for user A on a session of
// member B, and a rotation would then act on B's session under A's name (the key share,
// the new refresh row and the audit event all name the refresh row's user). The key is now
// (tenant_id, user_id, session_id) -> sessions (tenant_id, user_id, id).
//
// The rolled-back transaction makes a second user in the tenant by dropping the one-owner
// index, which is the situation the key is for.
func TestRefreshTokenAndItsSessionNameOneUser(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	tx, err := h.super.Begin(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	exec := func(sql string, args ...any) error {
		_, err := tx.Exec(h.ctx, sql, args...)
		return err
	}
	if err := exec(`DROP INDEX ctrlz.users_one_owner_uq`); err != nil {
		t.Fatal(err)
	}
	member, session := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	if err := exec(`INSERT INTO ctrlz.users (tenant_id, id, phone_e164, password_hash) VALUES ($1, $2, '+989000000099', 'argon2id$member')`, h.A.Tenant, member); err != nil {
		t.Fatal(err)
	}
	if err := exec(`INSERT INTO ctrlz.sessions (tenant_id, id, user_id, token_hash, idle_expires_at, absolute_expires_at, last_seen_at)
		VALUES ($1, $2, $3, '\x0a0b', now() + interval '1 hour', now() + interval '8 hours', now())`, h.A.Tenant, session, member); err != nil {
		t.Fatal(err)
	}
	insert := func(user uuid.UUID, hash string) error {
		if err := exec(`SAVEPOINT r`); err != nil {
			t.Fatal(err)
		}
		err := exec(`INSERT INTO ctrlz.refresh_tokens (tenant_id, user_id, session_id, family_id, token_hash, expires_at)
			VALUES ($1, $2, $3, gen_random_uuid(), convert_to($4, 'UTF8'), now() + interval '1 day')`, h.A.Tenant, user, session, hash)
		if err != nil {
			if e := exec(`ROLLBACK TO SAVEPOINT r`); e != nil {
				t.Fatal(e)
			}
		}
		return err
	}
	if err := insert(member, "member-refresh"); err != nil {
		t.Fatalf("a refresh token for the session's own user was refused: %v", err)
	}
	err = insert(h.A.User, "wrong-user-refresh")
	if pe := pgErr(err); pe == nil || pe.Code != "23503" {
		t.Fatalf("a refresh token for user A on member B's session: %v, want a foreign key violation", err)
	}
}
