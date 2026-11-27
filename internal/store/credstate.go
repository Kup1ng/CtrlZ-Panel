package store

// The SQL fragments that turn the columns of the one-time credential state into the word
// of ctrlz.credential_state (migration 0024; rule one-time-state, internal/auth/credstate).
//
// They are the only text of this package that names must_reset, must_change_password or
// password_expires_at: internal/lint TestOneTimeStateRule fails for any other SQL constant
// that does, so a statement cannot read the state any other way, and cannot write it
// (every change of the state is a ctrlz_fn function, the edges of credstate.Edges). The
// shape of the arguments is checked by the same lint, so a user cannot be asked with the
// admin's arguments or the other way round.
//
// Use a fragment in a statement that names no application-clock column: the function
// reads the database clock inside (clockrule treats a call of it as such a read).
const (
	// userStateSQL is the state of a row of ctrlz.users.
	userStateSQL = `ctrlz.credential_state(must_reset, password_expires_at, false)`
	// adminStateSQL is the state of a row of ctrlz.admin_users: an admin is ready only with
	// an authenticator (D12).
	adminStateSQL = `ctrlz.credential_state(must_change_password, password_expires_at, totp_enabled_at IS NULL)`
	// adminStateAliasedSQL is adminStateSQL for a statement that joins, where the row is "a".
	adminStateAliasedSQL = `ctrlz.credential_state(a.must_change_password, a.password_expires_at, a.totp_enabled_at IS NULL)`
)
