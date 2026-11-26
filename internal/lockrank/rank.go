// Package lockrank is the one global order in which a write transaction takes
// row locks (P1 auth review, round 5, rule lock-order; spec 4.4).
//
// Why it exists: the order used to be prose. Each transaction took its locks
// implicitly through whatever statements it ran (a foreign key's key share on
// insert, a multi-row UPDATE in heap order, the audit advisory lock, FOR
// UPDATE on users), and every round found another pair of transactions that
// took two rows in opposite orders. Here the order is data, every statement is
// classified by reading its text (Analyze), and a transaction that asks for a
// lock below one it already holds is refused (State.Acquire) instead of
// waiting for a deadlock to show it.
//
// The order is over tables, ascending. A table that is not listed fails the
// catalog test, so a new table cannot be written to without a place in the
// order. Tables of the same band share one number when the code claims no order
// between them; the P0 tenant tables do (their own functions order themselves,
// and gate tests pin that).
package lockrank

import (
	"sort"
	"sync"
)

// Rank is a position in the order. A lock may be taken only at a rank that is
// not below the highest one the transaction holds.
type Rank int

// Named ranks. The numbers leave room between neighbours, so a table that
// proves to need a slot is one new line and not a renumbering.
const (
	// RankJob: admin_jobs. The tenant transactions of a job hold the job's row
	// with FOR SHARE before anything else (AdminJobHold); the row is written
	// only by transactions that touch nothing else.
	RankJob Rank = 5

	// RankTenant is the tenants row. Every tenant table has a foreign key to
	// it, so every insert takes FOR KEY SHARE on it, and nothing takes a
	// conflicting lock on it (see Inert).
	RankTenant Rank = 10

	// RankUser: users, first among the rows that hang together, because every
	// other credential row points at one: a session or a refresh token takes FOR
	// KEY SHARE on its user through the foreign key, so a transaction that holds
	// a session and then wants the user waits behind a writer that holds the user
	// and wants the session. Explicit locks on it are FOR NO KEY UPDATE or FOR
	// KEY SHARE, never FOR UPDATE.
	RankUser      Rank = 100
	RankAdminUser Rank = 110

	RankSession      Rank = 200
	RankAdminSession Rank = 210

	RankRefresh Rank = 300

	// 400 to 470: the other per-user rows.
	// 480 to 490: the rows of a login code and of the outbox, which the worker
	// claims before it counts them.

	// RankCounters: sms_counters. Inside the rank the rows are ordered by the
	// store (a refund locks at most one shard row of the day's global count, without waiting, days in order).
	RankCounters Rank = 500

	// RankIdempotency is where the tenant's profile-creation lock and the idempotency keys sit,
	// before users: a Create or an Import takes the lock first and a profile insert key-shares users
	// afterwards. The key row is inserted by the first statement of a request and updated by its
	// last, and the insert makes the row this transaction's own, so the late update waits for
	// nobody (spec 3.1).
	RankIdempotency Rank = 50

	// RankClients and RankProfile: the profile and its content tables are one rank, because a
	// profile write locks the profile row and then writes its content, and a delete cascades into
	// all of them. clients come first: the delete of a profile locks the clients that name it before
	// the DELETE, since the foreign keys write them through ON DELETE SET NULL (spec 3.3). Both sit
	// before tenant_audit_log, which lock and unlock write after the profile.
	RankClients Rank = 430
	RankProfile Rank = 435

	// RankConfig is the band of every table whose order inside the band is the
	// business of its own functions (P0 tenant configuration, the catalog, the
	// nodes): the code claims no order between them, so they share a number.
	RankConfig Rank = 700

	// RankOutbox: policy_outbox and batch_jobs, one above the band. A delete of a profile cascades
	// into batch_jobs and key-shares endpoints and schedule_windows (the band) before it marks the
	// outboxes, and a job marks before its finishing UPDATE of its row.
	RankOutbox Rank = 710
	// RankJobOutbox: job_outbox, below the audit log.
	RankJobOutbox Rank = 720

	// RankAudit is last: the audit log and its advisory lock are taken at the
	// end of a transaction by every admin write, so they can be taken after
	// anything else and never before.
	RankAudit Rank = 900
)

func buildRanks() map[string]Rank {
	m := map[string]Rank{
		"admin_jobs": RankJob,
		"tenants":    RankTenant,

		"users":       RankUser,
		"admin_users": RankAdminUser,

		"sessions":       RankSession,
		"admin_sessions": RankAdminSession,

		"refresh_tokens": RankRefresh,

		// Credential rows are written by the same routes that then end or rotate
		// sessions (enable or disable the authenticator, regenerate recovery codes,
		// add a passkey): user first, credential rows second, sessions after. So they
		// sit between users and sessions.
		"recovery_codes": 160,

		// A ticket belongs to a user and is spent or revoked by the same routes that go on to
		// write credential rows and sessions: a login with a second factor (code, ticket, then
		// the session), a password reset, a password change, disabling the authenticator and
		// the admin re-issue. The ticket is taken inside the transaction since the request
		// holds one connection (rule one-connection-per-request), and the revoke every
		// credential change makes closes the very ticket being spent, so the take comes first
		// and the revoke is the first thing the session event does. So the tickets sit after
		// the recovery codes a second factor spends and before the sessions the event ends.
		"auth_tickets":         165,
		"webauthn_credentials": 170,
		"api_tokens":           420,
		// The request is locked by the same function that locks its user, and the
		// session work of that transaction follows (confirming a phone change ends the
		// other sessions), so it sits right after users and before sessions.
		"phone_change_requests": 150,
		"notifications":         440,
		"announcement_reads":    450,
		"tenant_audit_log":      460,
		"tenant_entitlements":   470,

		"idempotency_keys": RankIdempotency,
		"clients":          RankClients,

		// The profile and its content (spec 3.1).
		"profiles": RankProfile, "profile_options": RankProfile, "profile_filters": RankProfile,
		"profile_services": RankProfile, "rule_folders": RankProfile, "rules": RankProfile, "block_pages": RankProfile,

		"policy_outbox": RankOutbox, "batch_jobs": RankOutbox, "job_outbox": RankJobOutbox,

		// A login code is locked, then the invite it spends (auth_register_user);
		// the worker claims codes and outbox messages and only then counts them.
		"otp_challenges": 480,
		"invites":        485,
		"sms_outbox":     490,

		// The gateways come before the counters, not after as the sketch had it: the
		// worker settles a failed send by writing the gateway rows (the breakers) and
		// then refunds the counters, and the refund depends on the breaker state this
		// transaction has just written (sms-r4-5), so the counters cannot be written
		// first. Nothing writes the counters and then a gateway.
		"sms_gateways": 495,

		"sms_counters": RankCounters,

		"auth_throttle": 520,

		// The settings rows, then what hangs off a gateway (a delivery
		// record and a provider template take FOR KEY SHARE on it, held by then) and
		// the alerts a failed send raises, last of them.
		"system_settings":        600,
		"webauthn_config":        610,
		"sms_templates":          620,
		"sms_provider_templates": 640,
		"sms_deliveries":         650,
		"alerts":                 660,

		"audit_log": RankAudit,
	}
	for _, t := range configBand() {
		m[t] = RankConfig
	}
	return m
}

// rankTable is computed once and never written again.
var rankTable = sync.OnceValue(buildRanks)

// configBand lists the RankConfig tables.
func configBand() []string {
	return []string{
		"analytics_read_floors", "announcements", "authorized_ips",
		"bundles", "catalog_common_domains", "catalog_filter", "catalog_filter_mode", "catalog_filter_table",
		"catalog_infra_denylist", "catalog_no_redirect_domain", "catalog_protected_domains", "catalog_rewrites", "catalog_service",
		"catalog_service_alias", "catalog_service_category", "catalog_service_domain", "catalog_versions",
		"certificates", "config_log", "config_snapshot", "domain_settings", "endpoint_ddns_hosts",
		"endpoint_groups", "endpoint_types", "endpoints", "feedback_items",
		"filter_preview_jobs", "free_dns_counter_batches", "free_dns_counters", "free_dns_settings", "geoip_versions", "ip_claims", "ip_proof_challenges",
		"leases", "location_availability", "locations", "node_certs", "node_dns_requests", "node_dns_state", "node_enrollments",
		"node_location_configs", "node_pairs", "node_quarantine", "node_resolver_rules", "node_spki_retired", "node_upstreams",
		"nodes", "pair_event_state", "plans", "policy_artifacts", "profile_download_tokens",
		"profile_presets", "public_settings",
		"schedule_windows", "schema_migrations", "setup_share_tokens",
		"tenant_assets", "unblock_requests", "update_status",
	}
}

// Of returns the rank of a table of schema ctrlz.
func Of(table string) (Rank, bool) {
	r, ok := rankTable()[table]
	return r, ok
}

// Tables lists every ranked table, sorted.
func Tables() []string {
	out := make([]string, 0, len(rankTable()))
	for t := range rankTable() {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Inert reports whether a key share on the table is ignored: no statement of
// the system takes a lock on it that conflicts with FOR KEY SHARE, so a key
// share on it cannot take part in a wait cycle. tenants is locked above NO KEY
// UPDATE only by the purge of a deleting tenant (a job of its own, P2, which
// runs when nothing inserts for that tenant any more); admin_users is never
// locked FOR UPDATE and never deleted. An UPDATE of a unique-index column, and a
// DELETE, take a FOR UPDATE strength lock too, so "no unique column changes" is
// not a fact about today's statements: catalog check 21 (checkInertKeyReach)
// reads it from the grants and fails for any login role that can UPDATE such a
// column of either table or DELETE from it (db-r8-1). TestLockOrderRule and
// catalog check 21 also fail for a FOR UPDATE or FOR SHARE on either, in a
// statement or a database function.
func Inert(table string) bool { return InertByRoles(table) || InertByWriters(table) }

// InertByRoles are the inert tables whose premise is read from the roles: no login role updates a
// column of a unique index or deletes (catalog check 21, db-r8-1).
func InertByRoles(table string) bool { return table == "tenants" || table == "admin_users" }

// InertByWriters are the global tables a tenant transaction only key-shares through foreign keys
// (a rule's target location, a profile's filter, mode and service). They are inert for a different
// reason: their writers are the seed, the catalog importer (P6) and the location admin (P4b), and
// none of those touches a tenant table, so a wait on a row of one of these tables can never close a
// cycle with a tenant transaction. Their roles do hold UPDATE and the importers do upsert, so the
// grant premise of InertByRoles does not hold for them and is not asked; what check 21 and
// TestLockOrderRule still refuse is a FOR UPDATE or FOR SHARE on them, as on tenants (spec 3.1).
func InertByWriters(table string) bool {
	switch table {
	case "locations", "catalog_filter", "catalog_filter_mode", "catalog_service":
		return true
	}
	return false
}
