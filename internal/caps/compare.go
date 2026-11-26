package caps

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// Digest is what a LimitStatement or a LimitFunction pins: the first 8 bytes of the SHA-256 of the
// text with its white space collapsed, so a re-indented statement is the same one and an edited one is
// not. It is a review pin against an honest edit, not a secret; eight bytes keep it short enough
// not to read as a key to the secret scanner of the commit hook.
func Digest(text string) string {
	sum := sha256.Sum256([]byte(strings.Join(strings.Fields(text), " ")))
	return hex.EncodeToString(sum[:8])
}

// Shared is the one expression every cap is compared with (migration 0023):
//
//	ctrlz.cap_reached(spent, cap)  =  cap IS NOT NULL AND (cap = 'NaN' OR COALESCE(spent, 0) >= cap)
//
// A NULL cap is no cap, a missing counter is 0, and a cap of 0 is reached before the
// first spend. A NaN cap is reached too (migration 0044: nothing can be compared with it,
// and failing open would leave the money cap silently off). The Go statements of the store
// and the plpgsql of the OTP issue both call it, and UnsharedCompare is how the lint and the
// catalog check prove that nothing compares a cap another way.
const Shared = "ctrlz.cap_reached("

// compare finds an ordering operator next to a name that holds a cap. Only orderings: a
// cap is reached when spent >= cap, and "x = $1" next to a cap column is an assignment.
var compare = regexp.MustCompile(`(?i)(<=|>=|<|>)\s*(\(\s*SELECT\s+)?[\w.\[\]()]*(_cap|\bcap\b)|(\w*_cap\w*|\bcap\b)(\[[^\]]*\])?(::\w+)?(\s*[*+/-]\s*[\w.]+(::\w+)?)*\s*(<=|>=|<|>)|\(\s*SELECT\s+[\w.]*_cap\w*\s+FROM[^()]*\)\s*(<=|>=|<|>)`)

// UnsharedCompare returns the first comparison of a *_cap* value in a SQL text that is
// not an argument of ctrlz.cap_reached, or "" when there is none. A text that names no
// cap is clean. Assignments (:=) are not comparisons.
func UnsharedCompare(sql string) string {
	if !strings.Contains(strings.ToLower(sql), "cap") {
		return ""
	}
	s := strings.ReplaceAll(stripShared(sql), ":=", " ASSIGN ")
	return compare.FindString(s)
}

// stripShared cuts every call of ctrlz.cap_reached(...), with its balanced
// arguments, out of a SQL text.
func stripShared(src string) string {
	for {
		i := strings.Index(src, Shared)
		if i < 0 {
			return src
		}
		depth, j := 1, i+len(Shared)
		for j < len(src) && depth > 0 {
			switch src[j] {
			case '(':
				depth++
			case ')':
				depth--
			}
			j++
		}
		src = src[:i] + " TRUE " + src[j:]
	}
}

// The limit columns and who may mention them (sms-r16-4, sms-r16-17).
//
// UnsharedCompare above is a net of spellings: an ordering operator next to a name that contains
// "_cap". It misses a cap read through an alias, a CTE, a variable or BETWEEN, and a limit that is
// not named *_cap* at all, which is the whole class of guard that rounds 11 to 15 kept finding. The
// rule is now an allow list read from what the database says, with no spelling in it:
//
//  1. Every numeric column of system_settings is either a Settings column of an Entry (so the race
//     harness has a driver that spends it) or a NotLimit with the reason it limits nothing. A column
//     added tomorrow, whatever it is called, is neither until a person decides which.
//  2. A statement or a function that names a Settings column, in any form (aliased, in a CTE, in a
//     variable, in a select list) must call ctrlz.cap_reached, or be listed in LimitStatements or
//     LimitFunctions with the reason it only reads or writes the value.
//
// Round 17 (sms-r17-10) made the second question limit by limit: see ReadsLimit. A text that calls
// cap_reached for one limit and names another outside the call is refused, so no statement is left to a
// race driver that never runs it.

// NotLimit is a numeric column of system_settings that limits no spend, with the reason.
type NotLimit struct {
	Column string
	Reason string
}

// NotLimits lists the numeric columns of system_settings that are not a limit.
func NotLimits() []NotLimit {
	return []NotLimit{
		{"open_grace_days", "days a registration mode stays open before it closes itself; compared with a date, spends nothing"},
		{"takeover_idle_days", "days after which an idle admin account may be taken over; compared with a date, spends nothing"},
		{"otp_soft_pct", "percent of otp_cap_global at which a stranger's request is refused; it only scales the global cap inside the call of ctrlz.cap_reached"},
	}
}

// LimitTables are the tables whose numeric columns are discovered from the catalog (sms-r16-28). The
// first discovery asked system_settings only, so the per-tenant entitlement limits (a count of tokens,
// profiles, endpoints, a rate of publishes) were in no registry, no race driver and no lint; every
// numeric column of these tables is now a Settings column of an Entry, a NotLimit, or a PendingLimit.
func LimitTables() []string {
	return []string{"system_settings", "plans", "tenant_entitlements"}
}

// PendingTables are the LimitTables that hold the entitlement columns of PendingLimits.
func PendingTables() []string { return []string{"plans", "tenant_entitlements"} }

// PendingLimit is a numeric column of the entitlement tables: a limit on what a tenant may hold or do,
// with the phase whose code enforces it. No statement spends it in P1 (the objects it counts, profiles,
// endpoints, tokens, rules, realtime sessions and publishes, do not exist yet), so there is nothing to
// race today. It is named here so that it is discovered, so that NamesLimit refuses any statement that
// compares it without ctrlz.cap_reached (the phase that enforces it writes the comparison with the
// shared expression and adds a race driver, by this registry), and so that a column added to these
// tables cannot be a limit nobody decided about.
type PendingLimit struct {
	Column string
	Phase  string
	Reason string
}

// PendingLimits lists the entitlement columns, the same ten in both tables.
func PendingLimits() []PendingLimit {
	const r = "a per-tenant ceiling whose objects do not exist in P1; the default and the override are read for the account page only"
	return []PendingLimit{
		// Enforced in P2 on the items of one request, in memory: no state is shared between requests, so there is
		// nothing for racing actors to spend (spec 3.4). A boundary test at 10,000 and 10,001 items holds it.
		{"max_rules_per_request", "P2", "a bound on the items of one request, compared in Go against the request in hand; nothing is shared, so nothing to race"},
		{"max_realtime_sessions", "P3", r},
		{"max_publishes_per_hour", "P3", r},
	}
}

// LimitStatement is one SQL constant that names a limit column and does not call ctrlz.cap_reached.
// It is identified by the package that declares it (a path under the module) AND the digest of its
// text, not by its name alone (sms-r16-29): a constant of another package with the same name is not
// this one, and a listed constant edited into one that compares a limit by hand is no longer listed,
// so it fails until somebody reads the new text. Digest is the hex SHA-256 of the constant's string
// value, white space collapsed.
type LimitStatement struct {
	Const  string
	Pkg    string
	Digest string
	Reason string
}

// LimitStatements are the SQL constants that name a limit column and do not call ctrlz.cap_reached,
// each with why. A statement that is not here fails.
func LimitStatements() []LimitStatement {
	return []LimitStatement{
		{"qSMSLimitsGet", "internal/store", "a577d8afab889f48", "reads every limit for the SMS page; compares nothing"},
		{"qSMSLimitsLock", "internal/store", "9c2bbda6c400382d", "the same read, with the settings row locked, for the writer that audits what it changes"},
		{"qSMSLimitsSet", "internal/store", "c4f7bd28e36a53b1", "writes every limit from the SMS page; the table's CHECKs judge the values"},
		{"qSMSPriceMissingUnderCap", "internal/store", "5b6c775ad1d6f3be", "asks whether a money cap is set at all (IS NOT NULL), never how much is spent"},
		{"qPublicConfig", "internal/store", "fd5c01fd314aacc0", "reads the public configuration for the login page (the cooldown is shown to the client); compares nothing"},
		{"qCompilerTenant", "internal/store", "dac278b07b043f35", "reads the client cap of the tenant (its override, else its plan's value) to write it into the Endpoint records; compares nothing"},
		{"qLimits", "internal/store", "df5727c3f0103ebf", "reads the effective limits (the tenant override, else the value of its plan) for the account page; enforces nothing"},
		{"qCompilerTenant", "internal/store", "dac278b07b043f35", "reads the effective per-Endpoint client cap (the tenant override, else its plan's value) for the compiler to write into each record (P4 6.2); enforces nothing, the cap is spent by Tx.ClientInsert"},
	}
}

// LimitFunction is a database function (schema.name) that names a limit column and does not call
// ctrlz.cap_reached. Like a LimitStatement it is pinned to the text it was reviewed for: Digest is
// caps.Digest of its source as the catalog holds it, so a function edited after the review is no
// longer listed (sms-r16-29).
type LimitFunction struct {
	Name   string
	Digest string
	Reason string
}

// LimitFunctions are the functions that name a limit column outside every call of ctrlz.cap_reached, each
// with why. The one that spends a limit of the settings calls it; the ones here read the value for
// the login page, gather the limits of one request into an array that is compared only through the shared
// expression (auth_otp_issue), or count rows under a lock and are raced by their own driver.
func LimitFunctions() []LimitFunction {
	return []LimitFunction{
		{"ctrlz_fn.auth_public_config", "c627e76e02ed27c7", "reads the cooldown for the login page; compares nothing (since round 18 the public flag is configuration alone, 0057: it names no limit but the cooldown)"},
		{"ctrlz_fn.auth_otp_issue", "da5bbfda50f18da5", "gathers the limits of the request into one array (the address, the network, the phone and the global cap) and compares each element only through ctrlz.cap_reached, in one loop under the row locks (the global count is read as the sum of its shards without a lock, and compared through ctrlz.cap_reached too, db-r18-2); every otp.* limit has a race driver that spends it through this function. Reviewed in sms-r17-10: a limit named here outside the shared call is an element of that array and nothing else"},
		{"ctrlz_fn.ip_claim_request", "03d2dec354bc9e9e", "compares the count of the tenant's claims with max_ip_claims (the tenant's override, else its plan's value) by hand, under the tenant's advisory lock; raced by the ip_claims.per_tenant driver. Since P3 D1 an overlap with the tenant's own active or grace claim answers own before the count, and one with another tenant's is a pending_proof row in every mode (wide_requires_approval for a /28 to /31); neither changes what is counted"},
		// Round 18 (sms-r18-6): a function that names a limit TABLE is pinned too, because a body that returns the
		// whole row names no column. These three name one for a value that is not a limit.
		{"ctrlz_fn.admin_create_user", "380bcb0a4c2c7714", "puts the new tenant on the default plan by id and inserts its entitlement row with every column at its default; reads no limit value"},
		{"ctrlz_fn.auth_register_user", "525b773f25472d9c", "reads registration_mode, a mode and not a limit, and the id of the default plan; compares nothing"},
		{"ctrlz_fn.ip_claim_take", "676589eb15e845c9", "reads takeover_idle_days as a number of days compared with a date, which spends nothing (the same column NotLimits lists); P3 D1 adds a read of the claiming Endpoint's resolver_id, for the identity an encrypted observation must match, and drops the width condition of the displacement; and answers own, before any evidence is read, when the tenant's own active or grace claim overlaps the claim"},
		{"ctrlz_fn.ip_claim_open_challenge", "8865b8ce59792e44", "bounds the open challenges of a tenant by a multiple of the larger of max_ip_claims and the claims it holds, by hand, under the same tenant advisory lock as ip_claim_request; a derived bound, not a count that racing claimants spend"},
		{"ctrlz_fn.tenant_plan", "85ea5eb05eaccc3f", "returns the effective limits of the caller's own tenant (its override in tenant_entitlements, else its plan's value, by COALESCE) for the statements that compare them through ctrlz.cap_reached (Limits, the profile and rule statements); compares nothing itself"},
		{"ctrlz.plans_one_default", "45e78982bada10df", "counts the rows with is_default at commit, to keep exactly one default plan; names no limit value and compares nothing"},
	}
}

// NamesLimit returns the first limit column the SQL text names, whole word and any case, or "".
func NamesLimit(sql string) string {
	low := strings.ToLower(sql)
	var names []string
	for _, e := range Entries() {
		names = append(names, e.Settings...)
	}
	for _, e := range Entries() {
		names = append(names, e.Entitlements...)
	}
	for _, p := range PendingLimits() {
		names = append(names, p.Column)
	}
	for _, s := range names {
		// The first occurrence may be a prefix of a longer name, so every one is looked at.
		for from := 0; ; {
			j := strings.Index(low[from:], s)
			if j < 0 {
				break
			}
			if wholeWord(low, from+j, len(s)) {
				return s
			}
			from += j + len(s)
		}
	}
	return ""
}

func wholeWord(s string, at, n int) bool {
	isWord := func(b byte) bool {
		return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
	}
	return (at == 0 || !isWord(s[at-1])) && (at+n >= len(s) || !isWord(s[at+n]))
}

// ReadsLimit says what in a SQL text reads a limit outside the shared compare, or returns "" (sms-r17-10).
//
// The first form of the guard asked "does the text name a limit column and call cap_reached anywhere?", so
// a text that called cap_reached for limit A and compared limit B by hand passed, on the argument that B's
// own race driver would catch it; no driver runs a statement its entry does not name, so a NEW statement
// was never run by any. The question is now asked limit by limit: after every call of ctrlz.cap_reached(...)
// is cut out with its arguments, the text must name NO limit column. A limit a text must name outside the
// shared compare (a read for a page, a write from a page) is a LimitStatement or a LimitFunction, pinned by
// its digest. The columns are the registry's (Entries, PendingLimits), which the catalog check holds equal
// to the live columns, so a limit added tomorrow is judged with no new line here.
//
// Contract. It judges the text of one statement or one function body as written. It does not see a limit
// reached through a name the text never holds (a dynamically built column name, EXECUTE of a built query);
// a whole row read by a Go statement is refused by WholeRowOfLimitTable.
func ReadsLimit(sql string) string { return NamesLimit(stripShared(sql)) }
