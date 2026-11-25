package compiler

import (
	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/closed"
)

// Reason is why the compiler raises an alert. A closed set, because an alert's params reach the admin page and a
// log line carries them: no text of a rule, a name or an error is in either.
type Reason string

// The reasons.
const (
	ReasonProfile       Reason = "profile_failed"     // a profile did not compile, or a tenant could not be read or compiled; its Endpoints keep the stacks they had, and the tenant is tried again
	ReasonSchedule      Reason = "schedule_failed"    // an Endpoint's zone is unknown; it keeps the schedule it had
	ReasonClientsCut    Reason = "clients_cut"        // an Endpoint has more clients than one record may carry
	ReasonAuthorizedCut Reason = "authorized_cut"     // an Endpoint has more authorized prefixes than one record may carry
	ReasonPrefix        Reason = "prefix_refused"     // a stored prefix could not be written to the wire
	ReasonClaim         Reason = "claim_refused"      // a stored claim could not be written to the wire
	ReasonPairTable     Reason = "pair_table_refused" // the membership gave a table the validator refuses; the last table stands
	ReasonMajorGate     Reason = "major_gate"         // an entry would carry a format major a node has not reported it can apply
	ReasonRecordCap     Reason = "record_cap"         // one batch is larger than an entry may be and was cut
	ReasonLoad          Reason = "load_failed"        // the log or an artifact could not be read when the lease was taken
	ReasonCatalog       Reason = "catalog_refused"    // the current catalog reference does not validate; the one in force stands
	ReasonChain         Reason = "chain_broken"       // the log read at the lease does not chain
	ReasonCommit        Reason = "commit_failed"      // an entry could not be written
	ReasonOrphanSweep   Reason = "orphan_sweep"       // records of no tenant were taken out of the log
	ReasonGCStuck       Reason = "blob_gc_held"       // a blob waits for a node that has not applied a later entry
	ReasonEntryTooLarge Reason = "entry_too_large"    // a single record batch does not fit one entry
	ReasonRecordInvalid Reason = "record_invalid"     // a record the validator refuses was left out of an entry
	ReasonFreeDNS       Reason = "free_dns_refused"   // the free DNS settings do not validate; the value in force stands
)

// logUnit names the unit that kept a panic: a closed type so a log line can carry it.
type logUnit string

const (
	unitPass   logUnit = "pass"
	unitTenant logUnit = "tenant"
)

// Valid reports membership.
func (u logUnit) Valid() bool { return u == unitPass || u == unitTenant }

// Valid reports membership.
func (r Reason) Valid() bool {
	switch r {
	case ReasonProfile, ReasonSchedule, ReasonClientsCut, ReasonAuthorizedCut, ReasonPrefix, ReasonClaim, ReasonPairTable, ReasonMajorGate,
		ReasonRecordCap, ReasonLoad, ReasonCatalog, ReasonChain, ReasonCommit, ReasonOrphanSweep, ReasonGCStuck, ReasonEntryTooLarge, ReasonRecordInvalid, ReasonFreeDNS:
		return true
	}
	return false
}

// String is the text of the reason.
func (r Reason) String() string { return string(r) }

// AlertKind is the kind of every alert of the compiler.
const AlertKind = "compiler"

// alertParams is the params of an alert: the reason only.
type alertParams struct {
	Reason Reason `json:"reason"`
}

// Alert is one alert a pass wants raised. Tenant is Nil for one that is about the log and not a tenant.
type Alert struct {
	Reason Reason
	Tenant uuid.UUID
}

// key is the dedupe key of the alert: one open alert for a reason and a tenant.
func (a Alert) key() closed.Key {
	if a.Tenant == uuid.Nil {
		return closed.NewKey(a.Reason)
	}
	return closed.NewKey(a.Reason, closed.ID(a.Tenant))
}

func (a Alert) params() closed.Params {
	p, err := closed.NewParams(alertParams{Reason: a.Reason})
	if err != nil {
		return closed.Params{}
	}
	return p
}
