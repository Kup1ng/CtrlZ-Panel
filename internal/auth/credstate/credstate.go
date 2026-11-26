// Package credstate is the Go side of the one-time credential state (P1 auth review,
// round 5, rule one-time-state; spec 4.4, 4.5, 10.1, 10.3, 10.7).
//
// What a user or an admin may do with their password depends on one question: is it a
// one-time password that is still good, one that has expired, a password the admin chose
// before a second factor exists, or an account that is ready. That used to be answered by
// every route with its own boolean expression over must_reset, must_change_password,
// password_expires_at, totp_enabled_at and the session's auth_method, and changed by
// separate UPDATEs, and rounds 1 to 3 each found a route that read one field fewer than
// the next. Now:
//
//   - The answer is ctrlz.credential_state (migration 0024), one SQL function on the
//     database clock. Go receives one of four words, parsed here into State; any other
//     word is an error and the zero State refuses everything.
//   - Go never reads the columns. internal/lint TestOneTimeStateRule fails for a Go field,
//     a selector or a SQL constant that does.
//   - What each state may do is the table of this package, one row per operation class
//     and a few rows per named operation. Every gate of the request pipeline and of the
//     handlers asks the table. TestEveryOperationHasARow lists the operations of both
//     OpenAPI documents and of ctrlz-admin against all four states, and fails for an
//     operation without a row, so a route added tomorrow is covered by its class or fails
//     until someone decides.
//   - What may change a state is the edge table (Edges). Each edge is one SECURITY
//     DEFINER function of ctrlz_fn that checks it (migration 0024), and
//     internal/store TestCredentialStateEdges drives every function from every state.
package credstate

import (
	"errors"
	"fmt"
	"sync"

	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
)

// State is the one-time credential state of a user or an admin. The zero value is not
// a state: it is what a missing or malformed answer parses to, and every gate refuses it.
type State uint8

const (
	// Unknown is the zero value: no answer yet, or an answer this code does not know.
	Unknown State = iota
	// OneTimeLive: the password is one-time (set by an admin, or by the console for an
	// admin) and its expiry has not passed.
	OneTimeLive
	// OneTimeExpired: the password carries an expiry that has passed. It covers the
	// one-time password of a user or of the console, and the hour an admin's chosen
	// password lives while no authenticator is enrolled. It proves nothing and opens no
	// login; the way back is a re-issue, a console reset or Forgot Password.
	OneTimeExpired
	// ChosenNoSecondFactor: an admin chose a password and has not enrolled TOTP yet,
	// inside the hour that password lives (10.3). Users never have this state.
	ChosenNoSecondFactor
	// Ready: the password is the account's own and, for an admin, TOTP is enrolled.
	Ready

	numStates = int(Ready) + 1
)

// The words ctrlz.credential_state returns.
const (
	wordLive    = "one_time_live"
	wordExpired = "one_time_expired"
	wordChosen  = "chosen_no_second_factor"
	wordReady   = "ready"
)

// ErrUnknown is returned for a word that is not one of the four. A caller treats it as
// a failure of the database call: it never guesses a state.
var ErrUnknown = errors.New("credstate: unknown credential state")

// Parse reads the word the database returned. Anything else, an empty word included,
// is ErrUnknown with the zero State, so a caller that ignores the error still holds a
// state every gate refuses.
func Parse(word string) (State, error) {
	switch word {
	case wordLive:
		return OneTimeLive, nil
	case wordExpired:
		return OneTimeExpired, nil
	case wordChosen:
		return ChosenNoSecondFactor, nil
	case wordReady:
		return Ready, nil
	}
	return Unknown, ErrUnknown
}

// String is the word of the database, or "unknown".
func (s State) String() string {
	switch s {
	case OneTimeLive:
		return wordLive
	case OneTimeExpired:
		return wordExpired
	case ChosenNoSecondFactor:
		return wordChosen
	case Ready:
		return wordReady
	}
	return "unknown"
}

// States are the four real states, in the order of the table.
func States() []State { return []State{OneTimeLive, OneTimeExpired, ChosenNoSecondFactor, Ready} }

// OneTime says the password is one-time, live or not. It is what a session record is
// made from (a session opened under a one-time password is "restricted" in the sessions
// table); no gate reads that record, the gates ask the table with the live state.
func (s State) OneTime() bool { return s == OneTimeLive || s == OneTimeExpired }

// Realm is who asks: a tenant user, an admin, or the operator at the console.
type Realm uint8

const (
	Tenant Realm = iota + 1
	Admin
	CLI
)

func (r Realm) String() string {
	switch r {
	case Tenant:
		return "tenant"
	case Admin:
		return "admin"
	case CLI:
		return "cli"
	}
	return "unknown"
}

// Verdict is what a row of the table says.
type Verdict uint8

const (
	// Refuse is the zero value, so a cell nobody wrote refuses.
	Refuse Verdict = iota
	// Allow: the operation runs.
	Allow
	// Fresh: the operation runs inside the realm's fresh window (the reauth window of
	// a tenant session, the five minutes after an admin's TOTP check).
	Fresh
	// FreshUnlessPassword: Fresh, waived for a session that opened with the one-time
	// password itself, the one proof it carries (4.4). A session opened by an SMS code or
	// a passkey proved nothing about the password and is not waived.
	FreshUnlessPassword
	// WithSecondFactor: the operation runs when the request carries the account's second
	// factor as well as the password (10.3).
	WithSecondFactor
)

func (v Verdict) String() string {
	switch v {
	case Allow:
		return "allow"
	case Fresh:
		return "fresh"
	case FreshUnlessPassword:
		return "fresh-unless-password"
	case WithSecondFactor:
		return "with-second-factor"
	}
	return "refuse"
}

// Permits says the operation may go on, possibly after the extra proof the verdict names.
func (v Verdict) Permits() bool { return v != Refuse }

// row is one line of the table: a verdict for each state, indexed by State.
type row [numStates]Verdict

// all is a row that gives every real state the same verdict.
func all(v Verdict) row {
	return row{OneTimeLive: v, OneTimeExpired: v, ChosenNoSecondFactor: v, Ready: v}
}

// classes are the rows of an x-ctrlz-auth class. An operation with no named row below
// takes its class's row, so a new route is covered the day it is written, by the class
// the OpenAPI document must give it (internal/apispec).
//
// Tenant: a user is never ChosenNoSecondFactor, so that cell refuses.
var classes = sync.OnceValue(func() map[Realm]map[apispec.Auth]row {
	return map[Realm]map[apispec.Auth]row{
		Tenant: {
			// No session; the state is not known and not asked.
			apispec.None: all(Allow),
			// A restricted session (a one-time password, live or not) reaches only the setup
			// routes (3.5).
			apispec.Session:      {OneTimeLive: Refuse, OneTimeExpired: Refuse, Ready: Allow},
			apispec.SessionSetup: {OneTimeLive: Allow, OneTimeExpired: Allow, Ready: Allow},
			apispec.Reauth:       {OneTimeLive: Refuse, OneTimeExpired: Refuse, Ready: Fresh},
		},
		Admin: {
			apispec.None: all(Allow),
			// An account in setup (10.3) reaches the setup routes and nothing else.
			apispec.AdminSetup: all(Allow),
			apispec.Admin:      {Ready: Allow},
			apispec.AdminFresh: {Ready: Fresh},
		},
	}
})

// named are the operations whose answer differs from their class by state. The key is
// an operationId of the OpenAPI document of the realm, or "operationId/aspect" for a
// second decision inside one operation, or a command of ctrlz-admin. A name that no
// document or command carries fails TestEveryOperationHasARow.
type namedRow struct {
	class apispec.Auth // the class the OpenAPI document gives the operation; empty for a command
	row   row
}

var named = sync.OnceValue(func() map[Realm]map[string]namedRow {
	return map[Realm]map[string]namedRow{
		Tenant: {
			// A one-time password that has expired is a wrong password (4.5): the stored hash
			// is not used, and the dummy hash is verified instead.
			"loginPassword": {apispec.None, row{OneTimeLive: Allow, OneTimeExpired: Refuse, Ready: Allow}},
			"reauth":        {apispec.SessionSetup, row{OneTimeLive: Allow, OneTimeExpired: Refuse, Ready: Allow}},
			// POST /account/password: the reauth window is waived for a password session
			// while the one-time password is live and for nothing else (4.4, round 1
			// tenant-r1-3, round 2 tenant-r2-6).
			"changePassword": {apispec.SessionSetup, row{OneTimeLive: FreshUnlessPassword, OneTimeExpired: Fresh, Ready: Fresh}},
		},
		Admin: {
			// 10.2: a one-time password past its expiry is a wrong password.
			"adminLogin": {apispec.None, row{OneTimeLive: Allow, OneTimeExpired: Refuse, ChosenNoSecondFactor: Allow, Ready: Allow}},
			// The one request let through a spent admin_login_user scope (10.2): the right
			// console one-time password of an account that still has one.
			"adminLogin/past-spent-scope": {apispec.None, row{OneTimeLive: Allow}},
			// 10.3: the current password is verified in every state but an expired one; once
			// the account is ready a code is needed too.
			"changeAdminPassword": {apispec.AdminSetup, row{OneTimeLive: Allow, ChosenNoSecondFactor: Allow, Ready: WithSecondFactor}},
		},
		CLI: {
			// Refuses in every state because an admin exists in one of them.
			"bootstrap":      {"", row{}},
			"reset-password": {"", all(Allow)},
			"reset-totp":     {"", all(Allow)},
			"unlock":         {"", all(Allow)},
			"keys":           {"", all(Allow)},
			"rekey":          {"", all(Allow)},
			"audit-note":     {"", all(Allow)},
			"sms":            {"", all(Allow)},
			"audit":          {"", all(Allow)},
		},
	}
})

// Class is the row of an x-ctrlz-auth class. An unknown realm, class or state refuses.
func Class(r Realm, c apispec.Auth, s State) Verdict {
	row, ok := classes()[r][c]
	if !ok || int(s) >= numStates {
		return Refuse
	}
	return row[s]
}

// Named is the row of a named operation of the realm, and false when there is none. A
// handler that has a row of its own asks for it; the pipeline asks Class.
func Named(r Realm, id string, s State) Verdict {
	n, ok := named()[r][id]
	if !ok || int(s) >= numStates {
		return Refuse
	}
	return n.row[s]
}

// Resolve is the verdict the table gives an operation: its own row when it has one,
// otherwise its class's. found is false when neither exists, which is the "no row" the
// coverage test fails on.
func Resolve(r Realm, id string, c apispec.Auth, s State) (v Verdict, found bool) {
	if n, ok := named()[r][id]; ok {
		return Named(r, id, s), n.class == c
	}
	if _, ok := classes()[r][c]; ok {
		return Class(r, c, s), true
	}
	return Refuse, false
}

// NamedOperations lists the names of the named rows of a realm with the class each says
// the operation has, for the coverage test.
func NamedOperations(r Realm) map[string]apispec.Auth {
	out := map[string]apispec.Auth{}
	for id, n := range named()[r] {
		out[id] = n.class
	}
	return out
}

// Classes lists the classes that have a row in a realm.
func Classes(r Realm) []apispec.Auth {
	var out []apispec.Auth
	for c := range classes()[r] {
		out = append(out, c)
	}
	return out
}

// Transition names a change of state. Each is one SECURITY DEFINER function of ctrlz_fn
// (migration 0024, functions.yaml) that checks the edge, and no other statement changes
// the columns the state is made of.
type Transition string

const (
	// UserCreate: POST /users makes a user with a one-time password. It has no source
	// state, so it has no edge row.
	UserReissue     Transition = "user_reissue"      // ctrlz_fn.admin_reissue_one_time_password
	UserSetPassword Transition = "user_set_password" // ctrlz_fn.tenant_set_password
	AdminBootstrap  Transition = "admin_bootstrap"   // ctrlz_fn.admin_account_bootstrap
	AdminReset      Transition = "admin_reset"       // ctrlz_fn.admin_account_reset, keeping the authenticator
	AdminResetTOTP  Transition = "admin_reset_totp"  // ctrlz_fn.admin_account_reset, forgetting it
	AdminSetPass    Transition = "admin_set_password"
	AdminTOTPEnable Transition = "admin_totp_enable"
)

// Edge says, for each source state, whether the transition runs and the states it may
// end in. It is a set because the end state also depends on a fact the four words do not
// carry (whether an authenticator is enrolled).
type Edge struct {
	From [numStates]bool
	To   [numStates][]State
}

func edge(pairs map[State][]State) Edge {
	var e Edge
	for from, to := range pairs {
		e.From[from] = true
		e.To[from] = to
	}
	return e
}

// edges is the table behind Edges.
var edges = sync.OnceValue(func() map[Transition]Edge {
	return map[Transition]Edge{
		// 10.7: a re-issue replaces a one-time password that is still the account's password,
		// live or expired, and never one the user chose.
		UserReissue: edge(map[State][]State{OneTimeLive: {OneTimeLive}, OneTimeExpired: {OneTimeLive}}),
		// 4.4: any state ends in a password the user chose.
		UserSetPassword: edge(map[State][]State{OneTimeLive: {Ready}, OneTimeExpired: {Ready}, Ready: {Ready}}),
		// 10.1: the first admin exists only if none does, so there is no source state.
		AdminBootstrap: edge(nil),
		// 10.1: the console may reset any admin, whatever state it is in.
		AdminReset:     edge(map[State][]State{OneTimeLive: {OneTimeLive}, OneTimeExpired: {OneTimeLive}, ChosenNoSecondFactor: {OneTimeLive}, Ready: {OneTimeLive}}),
		AdminResetTOTP: edge(map[State][]State{OneTimeLive: {OneTimeLive}, OneTimeExpired: {OneTimeLive}, ChosenNoSecondFactor: {OneTimeLive}, Ready: {OneTimeLive}}),
		// 10.3: a password is chosen from every state but an expired one (it is a wrong
		// password there). With an authenticator it ends Ready, without one it opens the hour.
		AdminSetPass: edge(map[State][]State{OneTimeLive: {ChosenNoSecondFactor, Ready}, ChosenNoSecondFactor: {ChosenNoSecondFactor}, Ready: {Ready}}),
		// 10.3: enrolment keeps the 24 hour expiry of a console one-time password, and ends the
		// hour of a chosen one. From Ready there is nothing to enrol.
		AdminTOTPEnable: edge(map[State][]State{
			OneTimeLive: {OneTimeLive}, OneTimeExpired: {OneTimeExpired, Ready}, ChosenNoSecondFactor: {Ready},
		}),
	}
})

// Edges is the edge table: what each transition may do from each state.
func Edges() map[Transition]Edge { return edges() }

// Describe names a state and verdict pair for a test message.
func Describe(r Realm, op string, s State, v Verdict) string {
	return fmt.Sprintf("%s %s in %s: %s", r, op, s, v)
}
