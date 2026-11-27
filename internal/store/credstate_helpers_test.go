package store_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// expiresIn runs a query that returns one interval (an expiry minus now()) as the owner
// and returns it as a Duration. The store no longer hands the expiry to Go (rule
// one-time-state), so the tests that pin a lifetime ask the database.
func (f *fixture) expiresIn(t *testing.T, query string, args ...any) time.Duration {
	t.Helper()
	var secs float64
	if err := f.superConn(t).QueryRow(f.ctx, "SELECT EXTRACT(EPOCH FROM v)::float8 FROM ("+query+") AS s(v)", args...).Scan(&secs); err != nil {
		t.Fatal(err)
	}
	return time.Duration(secs * float64(time.Second))
}

// hasExpiry says whether the row still carries a password expiry.
func (f *fixture) hasExpiry(t *testing.T, table string, id uuid.UUID) bool {
	t.Helper()
	var has bool
	if err := f.superConn(t).QueryRow(f.ctx, "SELECT password_expires_at IS NOT NULL FROM ctrlz."+table+" WHERE id = $1", id).Scan(&has); err != nil {
		t.Fatal(err)
	}
	return has
}
