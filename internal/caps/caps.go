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
//     LimitTables (system_settings, plans and tenant_entitlements) is a Settings or
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

// MaxFoldersPerProfile is how many rule folders one profile holds (D31, spec 3.4). It is the maxItems of the
// folders list of the profile document too, and a Bounds check compares them. A cap and not an input bound:
// Tx.FolderInsert compares it inside the INSERT, under the guard's row lock.
const MaxFoldersPerProfile = 500

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
	// Entitlements are the columns of plans and tenant_entitlements that set a per-tenant
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

		// P2, the profile write path (docs/specs/p2-profiles.md 3.1, 3.4, 3.5). The per-profile caps are compared inside
		// the statement that adds the row, under the guard's row lock; max_profiles under the tenant's creation lock
		// (ctrlz_fn.profile_tenant_lock).
		{Name: "max_profiles", Kind: Cap, Entitlements: []string{"max_profiles"}, Wins: []string{"Tx.ProfileCreate"}},
		{Name: "max_rules_per_profile", Kind: Cap, Entitlements: []string{"max_rules_per_profile"}, Wins: []string{"Tx.RulesInsert"}},
		{Name: "max_wildcards_per_profile", Kind: Cap, Entitlements: []string{"max_wildcards_per_profile"}, Wins: []string{"Tx.RuleUpdate"},
			Slack: "RulesInsert decides the wildcard cap of a batch in its own statement beside the rule cap; RuleUpdate is the one that moves a rule into the wildcard kinds"},
		{Name: "max_folders_per_profile", Kind: Cap, Consts: []string{"MaxFoldersPerProfile"}, Wins: []string{"Tx.FolderInsert"}},
		// The guard steps the profile's version once per writer, and its row lock is what orders them.
		{Name: "profile.guard", Kind: Step, Wins: []string{"Tx.ProfileGuard"}},
		{Name: "profile.delete", Kind: Ending, Wins: []string{"Tx.ProfileDelete"}},
		// A lock needs an unlocked profile and one statement decides it; the unlock clears the five columns only where the hash that
		// was verified is still the lock, so a relock between the read and the clear clears nothing (spec 7.1, 7.2).
		{Name: "profile.lock", Kind: SingleUse, Wins: []string{"Tx.ProfileLock"}},
		{Name: "profile.unlock", Kind: Ending, Wins: []string{"Tx.ProfileUnlock"}},
		{Name: "batch_job.claim", Kind: Ending, Wins: []string{"Tx.JobClaim"}},
		{Name: "batch_job.finish", Kind: Ending, Wins: []string{"Tx.JobFinish", "Tx.JobFail"}},
		{Name: "idempotency.key", Kind: SingleUse, Wins: []string{"Tx.IdempotencyBegin"}},

		// P3, the Endpoint write path (docs/specs/p3-endpoints.md 3.5, 3.6). max_endpoints is decided by the statement that adds all
		// the Endpoints of a request, under the tenant quota lock; max_clients_per_endpoint by the statement that adds a manual
		// client, under the Endpoint's row; the group cap under the quota lock. A delete is one statement and the Endpoints it
		// returns are the ones that went (an Endpoint a hold pins is not returned).
		{Name: "max_endpoints", Kind: Cap, Entitlements: []string{"max_endpoints"}, Wins: []string{"Tx.EndpointsInsert"}},
		{Name: "max_clients_per_endpoint", Kind: Cap, Entitlements: []string{"max_clients_per_endpoint"}, Wins: []string{"Tx.ClientInsert"}},
		{Name: "endpoint_group.create", Kind: Cap, Consts: []string{"MaxGroupsPerTenant"}, Wins: []string{"Tx.GroupInsert"}},
		{Name: "endpoint.delete", Kind: Ending, Wins: []string{"Tx.EndpointsDelete"}},
		// The access list (spec 3.5, 5). max_authorized_ips counts the tenant's manual rows under the quota lock; a DDNS host is
		// counted under its Endpoint's row; the last row of an Endpoint that requires authorized IPs is one statement that ends
		// with the rows it was given or none, whoever deletes.
		{Name: "max_authorized_ips", Kind: Cap, Entitlements: []string{"max_authorized_ips"}, Wins: []string{"Tx.AuthorizedInsert"}},
		{Name: "ddns_host.create", Kind: Cap, Consts: []string{"MaxDDNSHostsPerEndpoint"}, Wins: []string{"Tx.DDNSHostInsert"}},
		{Name: "authorized_ip.last", Kind: Ending, Wins: []string{"Tx.AuthorizedDelete"}},

		// P3, the links without a session (docs/specs/p3-endpoints.md 3.5, 7.1). The caps count live rows only and are decided by the statement
		// that adds the row, under the Endpoint's row (share links) or the tenant quota lock (download links); a use is spent by one
		// statement that also holds the limit, the expiry and the revocation, so two requests cannot both have the last one.
		{Name: "share_link.create", Kind: Cap, Consts: []string{"MaxShareLinksPerEndpoint"}, Wins: []string{"Tx.ShareLinkInsert"}},
		{Name: "download_link.create", Kind: Cap, Consts: []string{"MaxDownloadLinksPerTenant"}, Wins: []string{"Tx.DownloadLinkInsert"}},
		// API tokens (6.4): the tenant's count of tokens is decided by the INSERT, under the tenant quota lock.
		{Name: "max_api_tokens", Kind: Cap, Entitlements: []string{"max_api_tokens"}, Wins: []string{"Tx.APITokenInsert"}},
		{Name: "share_link.use", Kind: SingleUse, Wins: []string{"Tx.ShareLinkConsume"}},
		{Name: "download_link.use", Kind: SingleUse, Wins: []string{"Tx.DownloadLinkConsume"}},
	}
}

// Bounds lists every constant named max* that is not a cap.
func Bounds() []Bound {
	return []Bound{
		{"maxLimit", "page size of a list route; reads only"},
		{"maxProofMembers", "how many top-level members of one request body the proof reader looks at: in process, one request, nothing shared that racing actors could spend"},
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
		{"ruleCountCacheMax", "size of one process's memory cache of rule counts (internal/api rulecount_cache.go): a full cache is emptied and costs a recount, nothing in the database that racing actors could spend"},
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
		{"maxNameRunes", "length of one value shown on a device, checked on the value in hand (internal/mobileconfig); a size of one request, nothing shared that racing actors could spend"},
		{"maxHostLen", "longest hostname DNS allows, checked on the one value in hand (internal/setup); a format limit, nothing shared that racing actors could spend"},
		{"MaxNamesPerCreate", "names in one Endpoint create (D31): the items of one request, checked on the value in hand; nothing is shared between requests that racing actors could spend (max_endpoints is the cap)"},
		{"MaxIDsPerBatch", "ids in one batch operation (D31): the items of one request, checked on the value in hand"},
		{"MaxWindowsPerEndpoint", "windows in one schedule PUT (the grid holds one byte per cell): the items of one request; the PUT replaces the whole set under the Endpoint's row, so nothing accumulates"},
		{"MaxLockPasswords", "lock passwords in one request (D31): the items of one request, checked before any charge"},
		{"MaxPrefixesPerAdd", "prefixes in one authorized-IP add (D31): the items of one request, checked on the value in hand; max_authorized_ips is the cap"},
		{"MaxHostnameBytes", "longest DDNS hostname DNS allows, checked on the one value in hand; a format limit, nothing shared that racing actors could spend"},
		{"MaxShareHours", "range of one request field (ttl_hours of a share link, 1 to 168): checked on the value in hand; nothing is shared between requests that racing actors could spend (the live links of an Endpoint are capped by MaxShareLinksPerEndpoint)"},
		{"MaxAllowed", "addresses in one token's allowed list (D31, 32): the items of one request, checked on the value in hand; nothing is shared that racing actors could spend (the number of tokens is capped by max_api_tokens)"},
		{"MaxAPITokenListed", "rows one list of a user's tokens returns; reads only, and far above any plan's max_api_tokens"},
		{"MaxConnsPerNode", "connections one node holds open, counted in the hub's process, decided under the limiter's own mutex before any database read (p4-nodes 5.1, 5.7); no statement of a transaction decides it, so no racing actors overspend it"},
		{"MaxHandshakes", "TLS handshakes in progress hub-wide, counted in the hub's process, decided under the limiter's own mutex before any database read (p4-nodes 5.1, 5.7); no statement of a transaction decides it, so no racing actors overspend it"},
		{"MaxNoCertConns", "connections that carry no node certificate, counted in the hub's process, decided under the limiter's own mutex before any database read (p4-nodes 5.1, 5.7); no statement of a transaction decides it, so no racing actors overspend it"},
		{"MaxOpenPerSource", "connections one source holds open before TLS, counted in the hub's process, decided under the limiter's own mutex before any database read (p4-nodes 5.1, 5.7); no statement of a transaction decides it, so no racing actors overspend it"},
		{"MaxOpenRPCs", "RPCs one node holds open, counted in the hub's process, decided under the limiter's own mutex before any database read (p4-nodes 5.1, 5.7); no statement of a transaction decides it, so no racing actors overspend it"},
		{"MaxTransfers", "transfer RPCs one node holds open (SC 12), counted in the hub's process, decided under the limiter's own mutex before any database read (p4-nodes 5.1, 5.7); no statement of a transaction decides it, so no racing actors overspend it"},
		{"MaxRequestsPerConn", "requests that are not a node's call in progress on one connection, counted in the hub's process, decided under the limiter's own mutex before any database read (p4-nodes 5.1, 5.7); no statement of a transaction decides it, so no racing actors overspend it"},
		{"MaxUnreadBytes", "bytes of one request body read and not yet taken by a handler, counted in the hub's process, decided under the limiter's own mutex before any database read (p4-nodes 5.1, 5.7); no statement of a transaction decides it, so no racing actors overspend it"},
		{"MaxHandshakeBytes", "bytes one peer may send before its TLS handshake is done, counted on that one connection by its own read loop (p4-nodes 5.1); a bound of one connection, nothing shared that racing actors could spend"},
		{"maxPeerCerts", "certificates read from one client's handshake, checked on the value in hand in the listener (p4-nodes 5.1); a format limit, nothing shared that racing actors could spend"},
		{"MaxCSR", "length of one CSR in a request, checked on the value in hand (hubnodes)"},
		{"MaxHostname", "length of one hostname field of an enrolment, checked on the value in hand (hubenroll)"},
		{"MaxFreeText", "length of one free text field of an enrolment, checked on the value in hand (hubenroll)"},
		{"BundleMaxTime", "longest time one bundle download may take; a time bound of one response, nothing shared that racing actors could spend"},
		{"StaticMaxTime", "longest time one static install file may take; a time bound of one response, nothing shared that racing actors could spend"},
		{"maxCached", "bundles the install handler keeps in memory, one process, a cache bound and not an amount racing actors spend"},
		{"maxEnvelope", "length of one manifest envelope the install handler reads, checked on the value in hand"},
		{"maxRoot", "length of root.json the install handler reads, checked on the value in hand"},
		{"maxKeys", "keys of one limiter table in the hub's process; a full table drops its oldest key (hublimit), so it bounds memory and decides nothing a racing actor could win"},
		{"maxSeen", "node addresses the hub remembers (hub.addrSet): one per node, a guard on memory in one process"},
		{"MaxFixture", "size of the one fixture file the lab command reads (ctrlz catalog load-fixture): checked on the file in hand; nothing is shared between requests that racing actors could spend"},
		{"MaxEntries", "entries one FetchEntries call returns (hubxfer, p4-nodes 5.2): the size of one read of the log; nothing is spent and nothing is shared that racing actors could spend"},
		{"MaxFetchBytes", "payload bytes one FetchEntries call chooses (hubxfer): the size of one read of the log; the hub-wide memory is counted by FetchBudget in the hub's process under a semaphore, which decides nothing in a transaction"},
		{"MaxBlobBytes", "largest file FetchBlob serves (hubxfer): checked on the file in hand, before any byte is read"},
		{"MaxSnapshotBytes", "largest snapshot file GetSnapshot serves (hubxfer): checked on the file in hand, before any byte is read"},
		{"VerifiedMax", "files the hub remembers as hashed against their name (hubxfer, p4-nodes 5.2): a memo in one process, held to the bound under the service's own mutex (the oldest entry goes first), so it bounds memory and decides nothing in a transaction that racing actors could win; a full memo only costs a re-hash"},
		{"MaxLearnedPerEndpoint", "secure_dns rows one Endpoint holds (D31): counted and decided inside HubLearnIP under the Endpoint's own row lock (the row lock qHubLearnEndpoint takes), so learners of one Endpoint are ordered and none overspends it; the hub's own write, with no tenant request and no Won to return"},
		{"maxBody", "bytes of one probe response the hub's prober reads (hubprobe): a bound of one response in hand, nothing shared that racing actors could spend"},
		{"maxCarriers", "pair tables the hub's view keeps in memory (hubview): one process, a guard on memory against a runaway log, nothing in the database that racing actors could spend"},
		{"maxHealthItems", "health items of one Heartbeat kept in version_info (hubtel): the items of one message in hand, nothing shared that racing actors could spend"},
		{"MaxClientsPerSelector", "clients one selector write resolves (spec 9.3): the write applies to the rows it locked and says whether more remain, so the caller repeats; a size of one request, not an amount racing actors spend"},
	}
}
