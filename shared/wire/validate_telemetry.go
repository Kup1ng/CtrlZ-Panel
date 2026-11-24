package wire

import (
	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
)

// Limits of the telemetry streams (UploadLogs, UploadCounters, ReportActivity).
// The sizes are provisional until the P5 load test (D31).
const (
	// MaxSpoolAge is how far behind the receiver's clock a telemetry time may
	// be. The contract names no spool lifetime, and a node that was cut off
	// flushes its spool when it reconnects, so the bound must not be shorter
	// than the time a node can be offline with data worth keeping. The longest
	// period the plan names for keeping raw rows is the 30-day retention option
	// (T-290), and a row older than that is expired the moment it arrives, so
	// 30 days is the longest age anyone could want. A shorter bound would drop
	// real data after an outage; a longer one only admits rows no tenant can
	// see. Future times keep the five-minute skew of the other observations.
	MaxSpoolAge = 30 * 24 * 3600

	MaxLogRowsPerBatch   = 100_000
	MaxSealedLogBatch    = 8 << 20
	MaxCountersPerBatch  = 1 << 20
	MaxCounterValue      = 1 << 40
	MaxActivityPerBatch  = 1 << 20
	logEphemeralKeyBytes = 32 // X25519 public key

	// MaxDecisionRefBytes bounds decision_ref by its text form: a kind name and a
	// short id (rule: plus a 16-byte id in hex is the longest, 37 bytes), or
	// degraded. It is text, not an id, so it has no fixed width.
	MaxDecisionRefBytes = 64

	// MaxCNAMEChain bounds cname_chain: the qname and the CNAME walk's 32 hops
	// (contract 5.10). A test in the vectors package ties it to the evaluator.
	MaxCNAMEChain = 33
)

// saneSpooledAt reports whether t is a plausible time for a record that may
// have waited in a node's spool: not before now-MaxSpoolAge, not after the
// usual skew ahead of now. Negative values are below the lower bound.
func saneSpooledAt(w, field string, t, now int64) error {
	if t < now-MaxSpoolAge || t > now+MaxObservationSkew {
		return bad(reason.BadEnum, w, "%s %d against the receiver's %d", field, t, now)
	}
	return nil
}

// ValidateLogBatch checks the header of a log batch. Its rows are sealed to the
// hub key, so they can be checked only after the hub opens them (ValidateLogRow
// on each); what can be refused before that is a malformed envelope.
func ValidateLogBatch(b *telemetryv1.LogBatch) error {
	const w = "log_batch"
	if b == nil {
		return bad(reason.BadSection, w, "missing")
	}
	if b.Count == 0 || b.Count > MaxLogRowsPerBatch {
		return bad(reason.SizeCap, w, "count %d", b.Count)
	}
	if err := lenIs(w, "ephemeral_pub", b.EphemeralPub, logEphemeralKeyBytes); err != nil {
		return err
	}
	// The AEAD is not fixed by the contract; 12 and 24 are the nonce sizes of
	// the standard ones (AES-GCM and ChaCha20-Poly1305, XChaCha20-Poly1305).
	if n := len(b.Nonce); n != 12 && n != 24 {
		return bad(reason.BadSection, w, "nonce is %d bytes, want 12 or 24", n)
	}
	if len(b.Sealed) == 0 || len(b.Sealed) > MaxSealedLogBatch {
		return bad(reason.SizeCap, w, "sealed is %d bytes", len(b.Sealed))
	}
	return nil
}

// ValidateLogRow checks one telemetry row at the hub, after the batch it came
// in was opened. now is the hub's clock in Unix seconds.
func ValidateLogRow(r *telemetryv1.LogRow, now int64) error {
	const w = "log_row"
	if r == nil {
		return bad(reason.BadSection, w, "missing")
	}
	if err := saneSpooledAt(w, "ts", r.Ts, now); err != nil {
		return err
	}
	if err := lenIs(w, "endpoint_id", r.EndpointId, 16); err != nil {
		return err
	}
	// Absent is allowed: an Endpoint in degraded mode has no profile, a query
	// names no client, and a row outside any window has no window id. A present
	// id has one width, so a fixed-width column never meets a value it cannot
	// hold or a join cannot match.
	for _, f := range []struct {
		name string
		b    []byte
	}{{"client_id", r.ClientId}, {"profile_id", r.ProfileId}, {"profile2_id", r.Profile2Id}, {"schedule_window_id", r.ScheduleWindowId}} {
		if len(f.b) != 0 {
			if err := lenIs(w, f.name, f.b, 16); err != nil {
				return err
			}
		}
	}
	if len(r.DecisionRef) > MaxDecisionRefBytes {
		return bad(reason.SizeCap, w, "decision_ref is %d bytes, at most %d", len(r.DecisionRef), MaxDecisionRefBytes)
	}
	if r.Location > 0xFFFF {
		return bad(reason.BadEnum, w, "location %d", r.Location)
	}
	if _, err := names.FromCanonicalWire(r.QnameWire); err != nil {
		return bad(reason.BadName, w, "qname_wire: %v", err)
	}
	if r.Qtype > 0xFFFF || r.Rcode > 0xFFFF {
		return bad(reason.BadEnum, w, "qtype or rcode out of range")
	}
	if !validProtocol(r.Protocol) {
		return bad(reason.BadEnum, w, "protocol %d", r.Protocol)
	}
	if r.Action < commonv1.Action_ACTION_BLOCK || r.Action > commonv1.Action_ACTION_REDIRECT {
		return bad(reason.BadEnum, w, "action %d", r.Action)
	}
	if r.DecisionStage < commonv1.Stage_STAGE_RULE || r.DecisionStage > commonv1.Stage_STAGE_SOFT_DISABLED {
		return bad(reason.BadEnum, w, "decision_stage %d", r.DecisionStage)
	}
	if len(r.SourceIp) != 0 && !validIP(r.SourceIp) {
		return bad(reason.BadSection, w, "source_ip length")
	}
	for _, c := range []string{r.SourceCountry, r.AnswerCountry} {
		if len(c) != 0 && !twoASCIILetters(c) {
			return bad(reason.BadSection, w, "country must be two letters")
		}
	}
	if len(r.CnameChain) > MaxCNAMEChain {
		return bad(reason.SizeCap, w, "cname_chain has %d names, at most %d", len(r.CnameChain), MaxCNAMEChain)
	}
	for _, c := range r.CnameChain {
		if _, err := names.FromCanonicalWire(c); err != nil {
			return bad(reason.BadName, w, "cname_chain: %v", err)
		}
	}
	return nil
}

// twoASCIILetters is the shape of a country code. Length alone would let
// control bytes and invalid UTF-8 into a text column.
func twoASCIILetters(c string) bool {
	if len(c) != 2 {
		return false
	}
	for i := 0; i < 2; i++ {
		if b := c[i] | 0x20; b < 'a' || b > 'z' {
			return false
		}
	}
	return true
}

// ValidateCountersBatch checks a counters batch: the bucket time, and every
// counter's endpoint, enums and count.
func ValidateCountersBatch(b *telemetryv1.CountersBatch, now int64) error {
	const w = "counters_batch"
	if b == nil {
		return bad(reason.BadSection, w, "missing")
	}
	if err := saneSpooledAt(w, "bucket_start", b.BucketStart, now); err != nil {
		return err
	}
	if len(b.Counters) == 0 || len(b.Counters) > MaxCountersPerBatch {
		return bad(reason.SizeCap, w, "%d counters", len(b.Counters))
	}
	for _, c := range b.Counters {
		if err := lenIs(w, "endpoint_id", c.GetEndpointId(), 16); err != nil {
			return err
		}
		if !validProtocol(c.Protocol) {
			return bad(reason.BadEnum, w, "protocol %d", c.Protocol)
		}
		if c.Action < commonv1.Action_ACTION_BLOCK || c.Action > commonv1.Action_ACTION_REDIRECT {
			return bad(reason.BadEnum, w, "action %d", c.Action)
		}
		if c.Count == 0 || c.Count > MaxCounterValue {
			return bad(reason.BadEnum, w, "count %d", c.Count)
		}
	}
	return nil
}

// ValidateActivityBatch checks an activity heartbeat. It must never carry a
// name, and the only free text, client_label, is held to the client grammar.
//
// An entry names its source by exactly one of claim_id (the query came from an
// address with an IP claim) and source_ip_hash (it did not), so one entry
// never carries two identities and a query from a claimed address, which has
// no hash to send, is not refused. A query that names no client sends the
// label "default" (the schema's default client row); an empty label stays
// refused (review L2-F16). now bounds both buckets against the receiver's
// clock: the hub keeps the maximum last_seen over nodes, so a bucket far in
// the future would keep a claim from ever going idle.
func ValidateActivityBatch(b *telemetryv1.ActivityBatch, now int64) error {
	const w = "activity"
	if b == nil {
		return bad(reason.BadSection, w, "missing")
	}
	if len(b.Entries) > MaxActivityPerBatch {
		return bad(reason.SizeCap, w, "%d entries", len(b.Entries))
	}
	for _, a := range b.Entries {
		if err := lenIs(w, "endpoint_id", a.GetEndpointId(), 16); err != nil {
			return err
		}
		switch hasClaim, hasHash := len(a.ClaimId) != 0, len(a.SourceIpHash) != 0; {
		case hasClaim && hasHash:
			return bad(reason.BadSection, w, "both claim_id and source_ip_hash are set; send exactly one")
		case hasClaim:
			if err := lenIs(w, "claim_id", a.ClaimId, 16); err != nil {
				return err
			}
		default:
			if err := lenIs(w, "source_ip_hash", a.SourceIpHash, 16); err != nil {
				return err
			}
		}
		// The label becomes a clients row and part of a hostname, so it is the
		// client grammar exactly, and an empty one is refused (review L2-F16).
		if !names.ValidClientLabel(a.ClientLabel) {
			return bad(reason.BadSection, w, "client_label is not a client label")
		}
		if !validProtocol(a.Protocol) {
			return bad(reason.BadEnum, w, "protocol %d", a.Protocol)
		}
		// 5-minute buckets (13).
		if a.FirstSeenBucket%300 != 0 || a.LastSeenBucket%300 != 0 || a.LastSeenBucket < a.FirstSeenBucket {
			return bad(reason.BadEnum, w, "buckets not on 5-minute boundaries or reversed")
		}
		if err := saneSpooledAt(w, "first_seen_bucket", a.FirstSeenBucket, now); err != nil {
			return err
		}
		if err := saneSpooledAt(w, "last_seen_bucket", a.LastSeenBucket, now); err != nil {
			return err
		}
	}
	return nil
}

// ValidateTelemetryMessage is the door for the upload streams (UploadLogs,
// UploadCounters, ReportActivity), as ValidateNodeMessage is for Control. A
// test lists the client-streaming methods of NodeHub from the descriptor and
// fails on errUnhandledBody, so a new stream without a validator breaks the
// build. LogRows inside a LogBatch are checked with ValidateLogRow after the
// hub opens the batch.
func ValidateTelemetryMessage(m proto.Message, now int64) error {
	switch b := m.(type) {
	case *telemetryv1.LogBatch:
		return ValidateLogBatch(b)
	case *telemetryv1.CountersBatch:
		return ValidateCountersBatch(b, now)
	case *telemetryv1.ActivityBatch:
		return ValidateActivityBatch(b, now)
	}
	return errUnhandledBody
}
