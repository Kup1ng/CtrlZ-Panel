package store_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// The last_used_at of an API token is written by a short transaction of its own, never by the one a handler runs
// (docs/specs/p3-endpoints.md 6.3 step 7; review round 1 of D5, p3-D5-r1-5): at most once in ten minutes, only for the tenant of
// the token, and never waiting for a row that another transaction holds.
func TestTokenTouchIsBestEffortAndNeverWaits(t *testing.T) {
	e := newRaceEnv(t)
	var token uuid.UUID
	if err := e.super.QueryRow(e.ctx, `INSERT INTO ctrlz.api_tokens (tenant_id, user_id, name, kind, token_hash, token_prefix, expires_at)
		VALUES ($1, $2, 'touch', 'write', '\x7a77'::bytea, 'abcdef', now() + interval '1 day') RETURNING id`, e.A.Tenant, e.A.User).Scan(&token); err != nil {
		t.Fatal(err)
	}
	lastUsed := func() (at time.Time, null bool) {
		var p *time.Time
		if err := e.super.QueryRow(e.ctx, `SELECT last_used_at FROM ctrlz.api_tokens WHERE id = $1`, token).Scan(&p); err != nil {
			t.Fatal(err)
		}
		if p == nil {
			return time.Time{}, true
		}
		return *p, false
	}
	base := time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)

	if err := e.tenant.TouchAPIToken(e.ctx, e.A.Tenant, token, base); err != nil {
		t.Fatal(err)
	}
	if at, null := lastUsed(); null || !at.Equal(base) {
		t.Fatalf("after the first touch: %v null %v, want %v", at, null, base)
	}
	// Inside ten minutes nothing moves; past them the time of the request is written.
	if err := e.tenant.TouchAPIToken(e.ctx, e.A.Tenant, token, base.Add(9*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if at, _ := lastUsed(); !at.Equal(base) {
		t.Errorf("a touch inside ten minutes moved last_used_at to %v", at)
	}
	later := base.Add(11 * time.Minute)
	if err := e.tenant.TouchAPIToken(e.ctx, e.A.Tenant, token, later); err != nil {
		t.Fatal(err)
	}
	if at, _ := lastUsed(); !at.Equal(later) {
		t.Errorf("a touch past ten minutes left last_used_at at %v, want %v", at, later)
	}

	// Another tenant's transaction cannot see the row, so it writes nothing: a token of A names nothing of B's.
	if err := e.tenant.TouchAPIToken(e.ctx, e.B.Tenant, token, later.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if at, _ := lastUsed(); !at.Equal(later) {
		t.Errorf("a transaction of tenant B moved the token of tenant A to %v", at)
	}

	// A row that another transaction holds is skipped at once: the touch neither waits for it nor fails. This is the
	// request of a token that arrives while a long write of the same token is open.
	holder, err := e.super.Begin(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(e.ctx) }()
	if _, err := holder.Exec(e.ctx, `SELECT 1 FROM ctrlz.api_tokens WHERE id = $1 FOR NO KEY UPDATE`, token); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	held := later.Add(2 * time.Hour)
	if err := e.tenant.TouchAPIToken(e.ctx, e.A.Tenant, token, held); err != nil {
		t.Fatalf("a touch of a held row: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("a touch of a held row waited %v", d)
	}
	if at, _ := lastUsed(); at.Equal(held) {
		t.Error("a touch wrote through a row that was held")
	}
}
