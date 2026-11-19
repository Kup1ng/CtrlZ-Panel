package budget

// Bound says what stops a guess at a secret on a route that verifies one.
type Bound int

const (
	// BoundScope is a throttle scope of the registry whose source is a subject or a
	// proof, never the network: the budget follows the account or the proof, so a
	// caller that moves networks does not get a fresh one.
	BoundScope Bound = iota + 1
	// BoundRow is a counter on the row of the thing being proved (an OTP challenge
	// has five tries, a ticket five reads or a single take). The row is the subject.
	BoundRow
	// BoundEntropy is a secret too long to guess (at least 128 bits of a random
	// token), so no budget is needed to keep guesses out; the cheap check in front
	// of it is for cost and not for security.
	BoundEntropy
	// BoundNone is a route that checks no secret.
	BoundNone
)

// Verify classifies one operation of an OpenAPI document by how a guess at its
// secret is bounded. The test in this package fails for an operation with
// `x-ctrlz-auth: none` that is not listed, so a new public route cannot go live
// with a network key as its only bound by omission.
type Verify struct {
	Service Service
	// Op is the operationId.
	Op    string
	Bound Bound
	// Scope is the throttle scope for BoundScope.
	Scope string
	// Why names the row or the secret for the other kinds.
	Why string
}

// Verifies returns the classification. Public operations are all listed; of the
// signed-in ones, those that check a secret are.
func Verifies() []Verify {
	otpRow := "otp_challenges.attempts: five tries a challenge, whatever the network"
	ticketRow := "auth_tickets: taken before the proof is checked, so one try a ticket"
	return []Verify{
		// ---- tenant, public ----
		{Service: Tenant, Op: "getAuthConfig", Bound: BoundNone, Why: "reads a public document"},
		{Service: Tenant, Op: "loginPassword", Bound: BoundScope, Scope: "login_phone"},
		{Service: Tenant, Op: "requestOtp", Bound: BoundNone, Why: "sends a code and checks none; the sms_counters caps bound it"},
		{Service: Tenant, Op: "loginOtp", Bound: BoundRow, Why: otpRow},
		{Service: Tenant, Op: "loginTotp", Bound: BoundScope, Scope: "totp_user"},
		{Service: Tenant, Op: "passkeyLoginBegin", Bound: BoundNone, Why: "checks nothing; the assertion is checked by the finish"},
		{Service: Tenant, Op: "passkeyLoginFinish", Bound: BoundRow, Why: ticketRow},
		{Service: Tenant, Op: "refreshSession", Bound: BoundEntropy, Why: "a 192-bit random refresh token"},
		{Service: Tenant, Op: "register", Bound: BoundRow, Why: otpRow},
		{Service: Tenant, Op: "lookupInvite", Bound: BoundScope, Scope: "invite_use"},
		{Service: Tenant, Op: "resetVerify", Bound: BoundRow, Why: otpRow},
		{Service: Tenant, Op: "resetPasskeyBegin", Bound: BoundRow, Why: "auth_tickets.attempts: five reads a ticket"},
		{Service: Tenant, Op: "resetPasskeyFinish", Bound: BoundScope, Scope: "reset_passkey_user"},
		// A reset with a second factor counts its code on totp_sms (an SMS code opened its ticket, round 9); one with none is bounded by the five reads of its
		// ticket (the ticketRow), and the passkey finish of a reset by reset_passkey_user. The behavioural test of the rows
		// (internal/api TestEveryBoundScopeIsChargedByItsRoute) drives the TOTP case and fails if the scope is another.
		{Service: Tenant, Op: "resetComplete", Bound: BoundScope, Scope: "totp_sms"},
		// ---- tenant, signed in, that check a secret ----
		{Service: Tenant, Op: "reauth", Bound: BoundScope, Scope: "reauth_session"},
		{Service: Tenant, Op: "reauthPasskeyFinish", Bound: BoundScope, Scope: "reauth_passkey_session"},
		{Service: Tenant, Op: "changePassword", Bound: BoundScope, Scope: "totp_session"},
		{Service: Tenant, Op: "confirmPhoneChange", Bound: BoundScope, Scope: "reauth_session"},
		{Service: Tenant, Op: "totpConfirm", Bound: BoundScope, Scope: "totp_session"},
		// ---- admin ----
		{Service: Admin, Op: "adminLogin", Bound: BoundScope, Scope: "admin_login_user"},
		{Service: Admin, Op: "adminTotpFresh", Bound: BoundScope, Scope: "admin_totp_session"},
		{Service: Admin, Op: "changeAdminPassword", Bound: BoundScope, Scope: "admin_reauth"},
		{Service: Admin, Op: "adminTotpConfirm", Bound: BoundScope, Scope: "admin_totp_session"},
	}
}
