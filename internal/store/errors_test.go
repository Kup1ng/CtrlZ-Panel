package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestSanitizeDropsEveryDriverText is the unit test of review L2-F15. The
// driver errors below carry a canary the way pgx does: its encode error prints
// the argument it could not encode with %#v, and a parse error prints the text.
// None of it may survive sanitize, whatever the shape of the error.
func TestSanitizeDropsEveryDriverText(t *testing.T) {
	const canary = "CANARY-123456"
	encode := fmt.Errorf("failed to encode args[0]: unable to encode map[string]string{\"otp\":%q} into text format for text (OID 25)", canary)
	cases := map[string]error{
		"encode error":        encode,
		"wrapped encode":      fmt.Errorf("batch item 3: %w", encode),
		"parse error":         fmt.Errorf("can't scan into dest[0]: strconv.ParseInt: parsing %q: invalid syntax", canary),
		"plain error":         errors.New("could not use " + canary),
		"joined":              errors.Join(errors.New("first"), encode),
		"connect error text":  &net.OpError{Op: "dial", Net: "tcp", Err: errors.New(canary)},
		"unexpected eof text": fmt.Errorf("%s: %w", canary, io.ErrUnexpectedEOF),
	}
	for name, in := range cases {
		out := sanitize(in)
		if out == nil {
			t.Errorf("%s: sanitize returned nil", name)
			continue
		}
		if strings.Contains(out.Error(), canary) {
			t.Errorf("%s: the canary survived: %q", name, out)
		}
		if !errors.Is(out, ErrDriver) && !errors.Is(out, ErrConnection) {
			t.Errorf("%s: %q is neither ErrDriver nor ErrConnection", name, out)
		}
	}
	if !errors.Is(sanitize(encode), ErrDriver) {
		t.Error("an encode error is a driver error")
	}
	if !errors.Is(sanitize(fmt.Errorf("%s: %w", canary, io.ErrUnexpectedEOF)), ErrConnection) {
		t.Error("a cut connection is ErrConnection")
	}
	if !errors.Is(sanitize(&net.OpError{Op: "read", Err: errors.New("reset")}), ErrConnection) {
		t.Error("a network error is ErrConnection")
	}

	// What stays: nothing, context errors and the one sentinel without text.
	if sanitize(nil) != nil {
		t.Error("nil became an error")
	}
	if got := sanitize(fmt.Errorf("%s: %w", canary, context.DeadlineExceeded)); got != context.DeadlineExceeded {
		t.Errorf("a deadline: %v", got)
	}
	if got := sanitize(fmt.Errorf("%s: %w", canary, context.Canceled)); got != context.Canceled {
		t.Errorf("a cancellation: %v", got)
	}
	if got := sanitize(fmt.Errorf("%s: %w", canary, pgx.ErrNoRows)); got != pgx.ErrNoRows {
		t.Errorf("no rows: %v", got)
	}

	// A database error keeps only its SQLSTATE and class.
	pg := &pgconn.PgError{Code: "23505", Message: "duplicate key value violates " + canary, Detail: "Key (k)=(" + canary + ") already exists"}
	out := sanitize(fmt.Errorf("exec: %w", pg))
	if strings.Contains(out.Error(), canary) || !errors.Is(out, ErrConflict) {
		t.Errorf("a unique violation: %q", out)
	}
	if !errors.Is(sanitize(&pgconn.PgError{Code: "57P01", Message: "terminating connection"}), ErrConnection) {
		t.Error("an admin shutdown is ErrConnection")
	}
	if !errors.Is(sanitize(&pgconn.PgError{Code: "08006"}), ErrConnection) {
		t.Error("a connection failure is ErrConnection")
	}
}

// TestSafeRowsHaveNoConnection: the wrapper is what DBTX.Query returns, and it
// must not give the raw connection back (review L1-F09). It is checked here on
// the type itself so the test needs no database; a database test below checks
// the value DB() really returns.
func TestSafeRowsHaveNoConnection(t *testing.T) {
	var rows pgx.Rows = safeRows{}
	if rows.Conn() != nil {
		t.Fatal("safeRows.Conn() returned a connection")
	}
}

// TestSuspendedClaimRefusalIsAConflict: the trigger that keeps a suspended
// claim from being erased raises its own SQLSTATE. A route answers it like the
// zero rows the delete policy gives a pinned Endpoint, so it must classify as a
// conflict and keep the code, without the message or detail.
func TestSuspendedClaimRefusalIsAConflict(t *testing.T) {
	const canary = "CANARY-claim-detail"
	out := sanitize(fmt.Errorf("exec: %w", &pgconn.PgError{Code: "CZ001", Message: "a suspended claim is not deleted " + canary, Detail: canary}))
	var se *Error
	if !errors.As(out, &se) || se.SQLState() != "CZ001" {
		t.Fatalf("the refusal is %v, want an *Error with SQLSTATE CZ001", out)
	}
	if !errors.Is(out, ErrConflict) {
		t.Error("the refusal to delete a suspended claim is not a conflict")
	}
	if errors.Is(out, ErrConstraint) || errors.Is(out, ErrPermission) || strings.Contains(out.Error(), canary) {
		t.Errorf("the refusal is misclassified or leaks: %q", out)
	}
}

// A lock timeout is a lost race, not a bug: it must read as ErrRetry, which the
// HTTP layer answers with 503 and the workers retry (spec 18.3).
func TestLockTimeoutIsRetryable(t *testing.T) {
	err := sanitize(&pgconn.PgError{Code: "55P03", Message: "canceling statement due to lock timeout"})
	if !errors.Is(err, ErrRetry) {
		t.Fatalf("55P03 became %v", err)
	}
	if strings.Contains(err.Error(), "canceling") {
		t.Fatalf("the driver text survived: %q", err)
	}
}

// A statement that hits the role's statement_timeout is the same kind of pressure as
// a lock timeout: 503 and a retry hint, not a 500 with a WARN (db-r5-3).
func TestStatementTimeoutIsRetryable(t *testing.T) {
	err := sanitize(&pgconn.PgError{Code: "57014", Message: "canceling statement due to statement timeout"})
	if !errors.Is(err, ErrRetry) {
		t.Fatalf("57014 became %v", err)
	}
	if strings.Contains(err.Error(), "canceling") {
		t.Fatalf("the driver text survived: %q", err)
	}
}

// TestSQLStateClassesAreDecidedByClass is the enforcement of rule sqlstate-class: the
// operating conditions of the server are classified by SQLSTATE class, and every code of the
// classes below, listed from the PostgreSQL documentation (appendix A) and not from what the
// code happens to handle, gets the class of its family. A code that a later round finds
// answered as a 500 is a missing row of THIS table or a wrong class, never a new case in
// sanitize.
func TestSQLStateClassesAreDecidedByClass(t *testing.T) {
	retry := []string{
		"40000", "40001", "40002", "40003", "40P01", // transaction rollback
		"53000", "53100", "53200", "53300", "53400", // insufficient resources
		"55P03", "57014", // lock not available, query canceled (statement_timeout)
	}
	connection := []string{
		"08000", "08001", "08003", "08004", "08006", "08007", "08P01", // connection exception
		"57000", "57P01", "57P02", "57P03", "57P04", "57P05", // operator intervention
		"25P03", "25P04", // idle in transaction and transaction timeouts: FATAL, the connection is closed (db-r6-1)
	}
	unclassified := []string{
		"22012", "42601", "42703", "42883", "XX000", "0A000", "P0001", "25006", "25001", "58030", "55006",
	}
	kind := func(code string) error {
		e, _ := sanitize(&pgconn.PgError{Code: code, Message: "canceling " + code}).(*Error)
		if e == nil {
			t.Fatalf("%s: sanitize did not return a database error", code)
		}
		return e.kind
	}
	for _, c := range retry {
		if kind(c) != ErrRetry {
			t.Errorf("SQLSTATE %s is not ErrRetry", c)
		}
	}
	for _, c := range connection {
		if kind(c) != ErrConnection {
			t.Errorf("SQLSTATE %s is not ErrConnection", c)
		}
	}
	for _, c := range unclassified {
		if kind(c) != nil {
			t.Errorf("SQLSTATE %s describes the request or the program and must stay unclassified, got %v", c, kind(c))
		}
	}
	// A code of the families that other cases own is not captured by the class.
	if kind("23505") != ErrConflict || kind("42501") != ErrPermission || kind("23503") != ErrConstraint {
		t.Error("an integrity or access code lost its own class")
	}
}
