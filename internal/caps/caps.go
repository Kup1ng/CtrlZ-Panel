// Package caps is the one registry of every cap, single use and row ending of P1
// (P1 auth review, round 5, rule caps-and-endings; spec 9.5, 9.6, 14.2, 18.3).
//
// The rule. A cap, a single use or the end of a row is decided by ONE conditional
// SQL statement, and the row it returns is the only permission to act (send, refund,
// charge, create, run). Go never counts and then writes. The answer of such a
// statement is a store.Won, which must reach a condition. Every cap is compared by
// one shared expression, ctrlz.cap_reached (migration 0023).
//
// Why a registry. Five of the fifteen findings behind the rule were a cap that nobody
// had raced, and every new cap would be the next one. This package lists them with the
// store methods that decide them. Three tests read it:
//
//   - internal/lint TestCapsAndEndingsRule: every method named here exists in
//     internal/store and returns store.Won, every store method that returns a
//     Won is named here, every Go constant named max* is a cap here or a bound with a
//     reason, and no SQL constant of the module reads a limit outside ctrlz.cap_reached
//     unless it is a LimitStatement, and no Go statement over a limit table reads a whole row
//     (WholeRowOfLimitTable: every select and RETURNING list is plain columns, literals and
//     parameters, and any other item fails, so a spelling nobody listed fails too).
//   - internal/store TestCapsRaceHarness: every entry has a driver that runs N spenders
//     on a barrier against the real database and checks the cap and at most one refund
//     or charge per row. An entry with no driver, or a driver with no entry, fails.
//   - internal/store/catalogtest CheckCaps (check 26): the limits are found by what the
//     database says, with no spelling in it. Every numeric column of the tables of
//     LimitTables (system_settings and the two entitlement tables) is a Settings or
//     Entitlements column of an entry, a PendingLimit or a NotLimit with the reason it limits
//     nothing, and every function of ctrlz and ctrlz_fn that names a limit column outside a call of
//     ctrlz.cap_reached is a LimitFunction.
//
// The package imports only the standard library (crypto/sha256, encoding/hex, regexp, strings, unicode), so
// the store, the api and the tests can all read it.
package caps

// Kind says what an entry limits.
type Kind string

// The kinds.
const (
	// Cap is a count or an amount that may not pass a limit.
	Cap Kind = "cap"
	// SingleUse is something that may be taken once: a code, a ticket, a step, a claim.
	SingleUse Kind = "single-use"
	// Ending is the end of a row that several actors may try to finish (send, expire,
	// sweep): only the one that ends it may refund or charge.
	Ending Kind = "ending"
	// Step is a counter that moves one step per round, not one per racer.
	Step Kind = "step"
	// Invariant is a rule across two tables that several writers can each break by writing one of
	// them: it is checked by one store method that takes a row lock every such writer takes first,
	// so the second writer reads the first's commit (Read Committed shows each only its own write).
	Invariant Kind = "invariant"
)

// MaxPasskeys is how many credentials one user holds. It is a cap and not an input
// bound: Tx.PasskeyAdd compares it inside the INSERT, under the user's row lock.
const MaxPasskeys = 20

// MaxSessions is how many live sessions one account holds (tenant-r18-2, D64 session-cap). A login past it ends the
// oldest ones in the same transaction (store.Tx.SessionsTrim), under the user row lock. Without it every login left a
// live row for ever, and the session list and the pool paid for a loop of logins.
const MaxSessions = 50

// MaxNoticeSMS is how many SMS of ONE kind of security notice one account may queue in 24 hours (question 19, D31 numbers are
// provisional). It is a cap and not an input bound: ctrlz_fn.tenant_notice_sms compares it with ctrlz.cap_reached over
// the audit rows of the action of that notice and of that user, so a thief cannot spend the messages of one kind to silence the other
// (review dec-c-r1-6) and one member of a tenant cannot spend another member's messages (dec-c-r2-5), under the user row lock the two routes already hold, so two changes at once cannot
// both take the last message. The notice is still written past it; only the SMS is not queued.
const MaxNoticeSMS = 3

// Entry is one cap, single use or ending.
type Entry struct {
	// Name is the stable id of the entry; the race harness keys its drivers on it.
	Name string
	Kind Kind
	// Settings are the numeric columns of system_settings that set the limit, whatever they are
	// called (otp_cooldown_s is one); the catalog check finds them by column type, not by name.
	Settings []string
	// Entitlements are the columns of entitlement_defaults and tenant_entitlements that set a per-tenant
	// limit this entry enforces today (sms-r16-28).
	Entitlements []string
	// Consts are the Go constants named max* that set the limit.
	Consts []string
	// Wins are the store methods ("Type.Method") that return a store.Won: the
	// conditional statement is the method, and the caller acts only on a win.
	Wins []string
	// Rows are the store methods ("Type.Method") whose statement returns the rows it
	// won (a claim, an ending of a batch). The rows are the permission.
	Rows []string
	// SQL names the SQL function that decides it, when no Go method does.
	SQL string
	// Slack, when set, says why the limit is not exact and what bounds the excess.
	Slack string
}

// Bound is a Go constant named max* that is not a cap: it limits the size of one
// input or one page, or is a lifetime, and shares no state between actors. The reason
// says why no race can make it wrong.
type Bound struct {
	Const  string
	Reason string
}

// Entries lists every cap, single use and ending.
func Entries() []Entry {
	return []Entry{
		{Name: "otp.phone", Kind: Cap, Settings: []string{"otp_cap_phone"}, SQL: "ctrlz_fn.auth_otp_issue"},
		{Name: "otp.phone_net", Kind: Cap, Settings: []string{"otp_cap_phone_net"}, SQL: "ctrlz_fn.auth_otp_issue"},
		{Name: "otp.phone_trusted", Kind: Cap, Settings: []string{"otp_cap_phone_trusted"}, SQL: "ctrlz_fn.auth_otp_issue"},
		{Name: "otp.ip", Kind: Cap, Settings: []string{"otp_cap_ip"}, SQL: "ctrlz_fn.auth_otp_issue"},
		{Name: "otp.net24", Kind: Cap, Settings: []string{"otp_cap_net24"}, SQL: "ctrlz_fn.auth_otp_issue"},
		{Name: "otp.net48", Kind: Cap, Settings: []string{"otp_cap_net48"}, SQL: "ctrlz_fn.auth_otp_issue"},
		{
			Name: "otp.global", Kind: Cap, Settings: []string{"otp_cap_global"}, SQL: "ctrlz_fn.auth_otp_issue",
			// The count is sixteen shard rows, one of them chosen at random by every request, so that a flood of decoys
			// does not queue every real request behind one row lock (db-r18-2, D64 otp-global-row-serialisation). The
			// sum is read without a lock.
			Slack: "the count the cap and the soft cap compare with is the sum of sixteen shard rows read without a lock, so requests that all read the sum below the cap before the first commits each add one: at most the requests in flight over, which the connection limit of the caller (ctrlz_tenant, 60) bounds; the per-key caps stay exact",
		},
		// The cooldown is a limit of one code per phone and purpose per window that racing issue calls can
		// spend, so it has a driver like the counters beside it (sms-r16-28); it used to be declared as a
		// window that only compares a timestamp, and nothing but the locking of auth_otp_issue held it.
		{Name: "otp.cooldown", Kind: Cap, Settings: []string{"otp_cooldown_s"}, SQL: "ctrlz_fn.auth_otp_issue"},
		// The per-tenant claim quota is compared by hand in ctrlz_fn.ip_claim_request, as a count of rows under
		// the tenant's advisory lock; it is registered so that it has a driver that races it (sms-r16-28).
		{Name: "ip_claims.per_tenant", Kind: Cap, Entitlements: []string{"max_ip_claims"}, SQL: "ctrlz_fn.ip_claim_request"},
		{Name: "outbox.daily", Kind: Cap, Settings: []string{"sms_outbox_cap_daily"}, Wins: []string{"GlobalTx.OutboxFirstGate"}},
		{
			Name: "cost.daily", Kind: Cap, Settings: []string{"sms_cost_cap_daily"},
			Wins: []string{"GlobalTx.OutboxFirstGate", "GlobalTx.OutboxRetryGate"}, SQL: "ctrlz_fn.auth_otp_issue",
			// The claim of a queued OTP is a gate of this cap too (sms-r16-9): without it a burst of real
			// requests that all passed the issue before the first price landed was sent and billed in full. It is
			// named here so that the registry check asks of its statement what it asks of the other gates.
			Rows:  []string{"GlobalTx.OTPClaim"},
			Slack: "the price is added when the provider accepts, after the gate (the outbox gates and the claim of a queued OTP), so the messages in flight when the cap is reached still add theirs: at most Concurrency prices over",
		},
		{
			Name: "cost.needs_price", Kind: Invariant, Settings: []string{"sms_cost_cap_daily"},
			SQL: "GlobalTx.SMSPriceMissingUnderCap (under GlobalTx.SMSSettingsLock)",
		},
		{Name: "passkeys.per_user", Kind: Cap, Consts: []string{"MaxPasskeys"}, Wins: []string{"Tx.PasskeyAdd"}},
		{Name: "sessions.per_user", Kind: Cap, Consts: []string{"MaxSessions"}, Rows: []string{"Tx.SessionsTrim"}},
		{
			Name: "notice.sms", Kind: Cap, Consts: []string{"MaxNoticeSMS"}, SQL: "ctrlz_fn.tenant_notice_sms",
			// The count is of the audit rows of the user the message is for (migration 0064), and the lock that makes it
			// exact is that user's row lock, which both routes hold, so the cap is exact: no other account's change can
			// spend it or race it.
		},
		{Name: "totp.step.user", Kind: SingleUse, Wins: []string{"Tx.TOTPStepAccept"}},
		{Name: "totp.step.admin", Kind: SingleUse, Wins: []string{"GlobalTx.AdminTOTPStepAccept"}},
		{Name: "recovery.code", Kind: SingleUse, Wins: []string{"Tx.RecoveryCodeUse"}},
		{Name: "ticket.take", Kind: SingleUse, Wins: []string{"AuthLookups.TicketTake", "Tx.TicketTake"}},
		{Name: "ticket.spend", Kind: SingleUse, Wins: []string{"AuthLookups.TicketSpend"}},
		{Name: "otp.consume", Kind: SingleUse, SQL: "ctrlz_fn.auth_otp_consume"},
		{Name: "otp.claim", Kind: SingleUse, Rows: []string{"GlobalTx.OTPClaim"}},
		{Name: "outbox.claim", Kind: SingleUse, Consts: []string{"OutboxMaxAttempts"}, Rows: []string{"GlobalTx.OutboxClaim"}},
		{
			Name: "otp.ending", Kind: Ending, Wins: []string{"GlobalTx.OTPDeliveryClear"},
			Rows: []string{"GlobalTx.OTPExpireUndeliveredBatch", "GlobalTx.OTPEndExhausted"},
		},
		{Name: "outbox.ending", Kind: Ending, Wins: []string{"GlobalTx.OutboxFinish"}, Rows: []string{"GlobalTx.OutboxFailStaleBatch"}},
		{Name: "breaker.step", Kind: Step, Wins: []string{"GlobalTx.GatewayFailed"}},
		// The hold of a refused login (sms-r12-3): of the calls in flight that all met the refusal one puts the
		// hold, and of the workers that all saw an accepted test send one lifts it.
		{Name: "gateway.hold", Kind: SingleUse, Wins: []string{"GlobalTx.GatewayHold", "GlobalTx.GatewayRelease"}},
		// The worker's judgement that no sender can be built (sms-r15-1, sms-r15-4): of the workers that all
		// judged the same credentials one writes it, and of those that all built them one takes it back.
		{Name: "gateway.unusable", Kind: SingleUse, Wins: []string{"GlobalTx.GatewayUnusable", "GlobalTx.GatewayUsable"}},
		{Name: "admin_job.run", Kind: Ending, Wins: []string{"GlobalTx.AdminJobStart", "GlobalTx.AdminJobFinish"}},
	}
}

// Bounds lists every constant named max* that is not a cap.
func Bounds() []Bound {
	return []Bound{
		{"maxLimit", "page size of a list route; reads only"},
		{"MaxOTPUnitsFA", "length of one OTP template body in billed units, checked on the value in hand (sms.CheckBodyLength)"},
		{"MaxOTPUnitsEN", "length of one OTP template body in billed units, checked on the value in hand (sms.CheckBodyLength)"},
		{"maxInviteHours", "range of one request field"},
		{"maxBootstrapRetries", "retry count of a single command-line process"},
		{"cursorMaxMicro", "range of a decoded cursor value"},
		{"maxHomeCountries", "length of one request field, written whole under the user's own row"},
		{"maxNotices", "trim of one column, read and written under the admin row locks (qAdminNoticeRows)"},
		{"maxTransports", "length of one request field"},
		{"MaxJitter", "random delay bound"},
		{"MaxLength", "length of one request field"},
		{"MaxBytes", "length of one request field"},
		{"maxRawBytes", "length of one request field"},
		{"maxStoredMemKiB", "ceiling on a stored Argon2 parameter, read once per hash"},
		{"maxStoredTime", "ceiling on a stored Argon2 parameter, read once per hash"},
		{"maxStoredThread", "ceiling on a stored Argon2 parameter, read once per hash"},
		{"maxInput", "length of one request field"},
		{"MaxTypedBytes", "length of one typed code before the fold, checked on the value in hand (digits.Typed callers)"},
		{"nearMaxChanged", "scoring threshold of one password"},
		{"maxScore", "scale of one password score"},
		{"DeviceMaxAge", "cookie lifetime"},
		{"AdminDeviceMaxAge", "cookie lifetime"},
		{"maxPlain", "length of one plaintext"},
		{"maxEntries", "size of the book of one request (internal/reqledger): in memory, one request, nothing shared that racing actors could spend"},
		{"maxKept", "size of the noop driver's in-memory log in a test double"},
		{"MaxProviderField", "length of one provider field"},
		{"MaxBody", "length of one provider response"},
		{"maxValue", "length of one provider parameter"},
		{"maxUserAgent", "length of one stored header"},
		{"maxSessionData", "length of the WebAuthn session data one sealed ceremony ticket carries; checked on the value in hand"},
		{"maxSealedText", "length of a sealed ceremony ticket the api is willing to decode; checked on the value in hand"},
		{"scriptMaxSlots", "slots of one limiter call, as the Valkey scripts bound them (admin-r14-4); a size of one request, not an amount that racing actors spend"},
		{"scriptMaxCap", "largest capacity of a limiter bucket, as the Valkey scripts bound it (admin-r14-4); a range of one request field"},
		{"scriptMaxPerMs", "longest refill period of a limiter bucket, as the Valkey scripts bound it (admin-r14-4); a range of one request field"},
		{"sweepMaxBatches", "batches one admin session sweep pass may run (rule bounded-sweeps); a work limit, not an amount that racing actors spend"},
		{"maxContext", "length of one sealed-value context (keyring.RowContext): built in memory from the ids and parts in hand, nothing shared that racing actors could spend"},
		{"persianMaxWord", "longest piece of a password looked up in the Persian word list (pwstrength): the work of one scan of one value in hand, nothing shared"},
		{"finglishMaxCluster", "longest run of consonants in a Finglish spelling (pwstrength): a shape test on one piece of one password in hand, nothing shared that racing actors could spend"},
		{"maxFrames", "frames kept in the log line of one panic (logattr.Stack); built in memory per call, nothing shared that racing actors could spend"},
	}
}
