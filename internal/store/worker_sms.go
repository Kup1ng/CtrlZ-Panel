package store

import (
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Kup1ng/CtrlZ-Panel/internal/closed"
)

// The worker's side of P1: draining OTP deliveries and the SMS outbox, keeping
// the gateway bookkeeping, running the sweeps, and the jobs the admin queues.
// Everything here runs as ctrlz_worker; the grants of migration 0011 give it
// exactly the columns these statements use, and no more. The send itself
// (opening the sealed payload, calling the provider) happens outside any
// transaction, in internal/worker/smssend, and the results come back through
// these methods.

// OTPDelivery is an OTP the worker must send.
type OTPDelivery struct {
	ID         uuid.UUID
	Phone      string
	Purpose    string
	DeliveryCT []byte // sealed under otp_delivery; aad = phone \0 purpose
	Attempts   int    // including this one
	// CreatedAt is the instant the code was counted, which names the Tehran day of the
	// counter an unsent ending gives back. The worker no longer reads the address or the
	// known-device flag the challenge was issued with: the refund is the global key alone,
	// so nothing needs them (sms-r6-2).
	CreatedAt time.Time
}

// RecordBudget is the longest the record of an accepted send may run while the worker is running
// (sms-r6-6): above the lock waits of the statements of one record, and with the retries of
// smssend.recordTx inside it. It is here, and not in the worker, because the statements that end a
// row on the ground that its claim lapsed wait this long past the lapse (sms-r10-5): a record
// that meets a lock timeout rolls back and pauses, and for the pause nothing locks the row, so a
// lapsed lease alone would let the exhausted pass or the expiry refund the global slot of a code
// the provider had accepted, or the stale-outbox sweep fail an invite it had delivered. A lease
// that lapsed more than RecordBudget ago has no record still running (the record starts before
// the lease ends, and a stop only shortens it).
const RecordBudget = 40 * time.Second

// OTPClaimLease is how long a claim keeps other workers and the sweeps away from a row. A
// send is bounded below it by the worker (smssend.sendBudget), so a claim outlasts the send
// it was taken for, and the record that follows has what is left (sms-r6-7).
const OTPClaimLease = 20 * time.Second

// The lease starts at the instant the UPDATE runs (clock_timestamp), not at the start of
// the claim transaction (now): that transaction first ends the exhausted rows and can wait
// on counter rows for lock_timeout, and the wait would otherwise come out of the send's
// time (sms-r6-7). The window it opens is $3 seconds.
const qOTPClaim = `UPDATE ctrlz.otp_challenges o
SET delivery_claimed_until = clock_timestamp() + make_interval(secs => $3), delivery_attempts = o.delivery_attempts + 1
WHERE o.id IN (
  SELECT c.id FROM ctrlz.otp_challenges c
  WHERE c.delivery_ct IS NOT NULL AND c.expires_at > now() AND c.consumed_at IS NULL
    AND c.delivery_attempts < $2
    AND (c.delivery_claimed_until IS NULL OR c.delivery_claimed_until < now())
  ORDER BY c.created_at LIMIT $1` + lockUpdateSkipLocked + `)
RETURNING o.id, o.phone_e164, o.purpose, o.delivery_ct, o.delivery_attempts, o.created_at`

// OTPClaim takes up to limit undelivered OTPs for 20 seconds. SKIP LOCKED and
// the claim column make several workers safe. A consumed code is never taken: the
// user already has it, so a second send would cost money and tell the phone's
// holder about a login (a worker that died after the provider accepted, before
// OTPDeliveryClear, leaves exactly such a row). A decoy has no delivery_ct and is
// never selected, so nothing is sent for an unknown phone. A worker that
// crashes mid-send leaves a claim that lapses, and another pass sends again: a
// provider may get two, which is accepted over a lost OTP.
//
// maxAttempts is the ceiling on claims: a row that reached it is never taken
// again, however its claim lapsed. Without it, a record transaction that fails
// on every pass (a gateway row deleted under the snapshot, a lock that never
// frees) would let the provider accept the same code every 20 seconds until the
// row expires. OTPEndExhausted closes such a row without a provider call.
func (g GlobalTx) OTPClaim(limit, maxAttempts int) ([]OTPDelivery, error) {
	rows, err := g.tx.Query(g.ctx, qOTPClaim, int32(limit), int32(maxAttempts), OTPClaimLease.Seconds())
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []OTPDelivery
	for rows.Next() {
		var d OTPDelivery
		if err := rows.Scan(&d.ID, &d.Phone, &d.Purpose, &d.DeliveryCT, &d.Attempts, &d.CreatedAt); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, d)
	}
	return out, sanitize(rows.Err())
}

const qOTPDeliveryClear = `WITH c AS (
  UPDATE ctrlz.otp_challenges SET delivery_ct = NULL WHERE id = $1 AND delivery_ct IS NOT NULL
  RETURNING consumed_at)
SELECT consumed_at IS NULL FROM c`

// OTPDeliveryClear drops the sealed code after the gateway accepted it, or
// after the last failed attempt, so the row holds nothing to send. It returns a
// Won that is Yes only when this call was the one that cleared it and the row was
// not consumed. The worker and the sweep can
// both finish a row (a claim that lapsed, an expiry during a slow send), and
// only the one that cleared it may refund its counters: the other would give
// the same slot back a second time, and the shared network and global counters
// would then open a slot per duplicate.
//
// A row the user has already consumed is cleared too but reported as false: the
// code reached them (an earlier attempt was delivered whatever the worker
// recorded), so a refund would open a slot for a message that was sent. The
// sweep makes the same call (db-r1-5, sms-r2-8).
func (g GlobalTx) OTPDeliveryClear(id uuid.UUID) (Won, error) {
	var refundable bool
	err := g.tx.QueryRow(g.ctx, qOTPDeliveryClear, id).Scan(&refundable)
	if ok, err := notFound(err); err != nil || !ok {
		return Won{}, err // no row: another call already cleared it
	}
	return won(refundable), nil
}

// What an OTP row that ends without a message reaching the user gives back is the
// world-wide counter and nothing else, and the statement says so in its text: scope and key
// are literals, and the store has no type, argument or method that names another row
// (rule known-unknown-oracle, review round 6, sms-r6-1 and sms-r6-5).
//
// Why a literal and not a rule about who builds the key list. auth_otp_issue bumps ip,
// phone_net and phone for every request, a decoy included, and global for a real code only;
// a decoy is never ended. Any refund of the other keys leaves a real row's counters below a
// decoy's, and the 429 of the next request tells a phone with an account from one without
// (spec 5.3). Rounds 3 to 6 each found a new way to build the wrong list (a condition, a
// second ending, an elided literal the lint did not read), so the list is gone: a refund
// that could name a key would be one more place to get it wrong. internal/lint
// TestRefundIsTheGlobalKeyOnly fails for any other statement that writes sms_counters, and
// for a store that takes a key again.
//
// One primary-key UPDATE per message, in day order, so two refunds that meet on a day
// boundary lock the two rows in the same order.
const qCountersRefund = `UPDATE ctrlz.sms_counters SET count = GREATEST(count - 1, 0)
WHERE day = ($1::timestamptz AT TIME ZONE 'Asia/Tehran')::date AND scope = 'global' AND key = 'all'`

// CountersRefundAll gives back the world-wide slot of each message counted at the given
// instants, in one transaction. A batch of expired OTPs is refunded here as a whole because
// the lock of the first message is held while the last one is refunded; sorting by instant
// keeps two batches from taking two days' rows in opposite orders. The count never goes
// below zero.
func (g GlobalTx) CountersRefundAll(createdAt []time.Time) error {
	if len(createdAt) == 0 {
		return nil
	}
	at := append([]time.Time(nil), createdAt...)
	sort.Slice(at, func(i, j int) bool { return at[i].Before(at[j]) })
	for _, t := range at {
		if _, err := g.tx.Exec(g.ctx, qCountersRefund, t); err != nil {
			return sanitize(err)
		}
	}
	return nil
}

// CountersRefund gives back the world-wide slot of one message counted at createdAt (the
// Tehran day of that instant). The caps count messages sent but are bumped at issue, so a
// message that was never delivered must not cost the world a slot (9.5).
func (g GlobalTx) CountersRefund(createdAt time.Time) error {
	return g.CountersRefundAll([]time.Time{createdAt})
}

const qCountersAddCost = `INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count, cost)
VALUES ((now() AT TIME ZONE 'Asia/Tehran')::date, 'global', 'all', 0, $1::numeric)
ON CONFLICT (day, scope, key) DO UPDATE SET cost = LEAST(c.cost + EXCLUDED.cost, ` + CostSaturation + `::numeric)`

// CostSaturation is the largest value of sms_counters.cost, which is numeric(14, 4). The spend
// SATURATES here instead of overflowing: the add runs after the provider has accepted a message,
// and an add that raises 22003 rolls the whole record back, so the claim lapses and the provider is
// asked again and bills again, for every later send of the day, because nothing lowers a spend
// (db-r13-1). A spend parked at its maximum is a money cap that is reached (the cap column has the
// same type, so every cap is at or below it) and, with no cap, a number nobody reads, which is the
// right failure for a price that was typed wrong. TestTheSpendSaturatesAtTheColumnMax ties this
// constant to the column's declared precision and scale.
const CostSaturation = "9999999999.9999"

// CountersAddCost adds the configured price of an accepted message to the day's
// money counter, which both the OTP issue and the outbox compare with the cap.
// The price is text (Rial), so no float rounds it. The sum never raises an overflow (see
// CostSaturation): once the provider has accepted a message, recording it cannot fail on arithmetic.
func (g GlobalTx) CountersAddCost(price string) error {
	_, err := g.tx.Exec(g.ctx, qCountersAddCost, price)
	return sanitize(err)
}

// A row whose claim is live belongs to a worker that is sending it, so the sweep
// leaves it alone and the worker alone decides between a refund and a delivery.
// The claim lapses OTPClaimLease after it is taken, longer than the send budget the worker
// holds itself to (smssend.sendBudget). A statement here takes a row only RecordBudget after
// that, not at the lapse: a record of an accepted send that met a lock timeout is between two
// runs and holds no lock, and the lapse alone would let a sweep refund or fail a row whose
// accept is about to be recorded (sms-r10-5). The claim itself still takes a row at the
// lapse, so a worker that died is replaced after 20 seconds, and the duplicate that costs is
// the documented one.
//
// A consumed row has its code cleared too but is not refunded: the message reached the user,
// whatever the worker recorded, and a refund would open a slot on the global key for a
// message that was sent (db-r1-5).
//
// The statements return the id and the creation instant only. The sweeps never read the
// address or the known-device flag the challenge was issued with, because the refund is the
// global key alone (sms-r6-2).
//
// At most OTPEndBatch rows end per call. After a long worker outage thousands of
// rows may wait, and refunding them in one transaction would hold row locks on
// the shared global/all counter for as long as it takes, so that
// auth_otp_issue waits up to lock_timeout and answers 503 (sms-r2-4). A call
// with `more` set means the batch was full and the caller asks again, each call
// in its own transaction.
const qOTPExpireUndelivered = `WITH ended AS (
  UPDATE ctrlz.otp_challenges SET delivery_ct = NULL
  WHERE id IN (
    SELECT id FROM ctrlz.otp_challenges
    WHERE delivery_ct IS NOT NULL AND expires_at <= now()
      AND (delivery_claimed_until IS NULL OR delivery_claimed_until < now() - make_interval(secs => $2))
    ORDER BY created_at LIMIT $1` + lockUpdateSkipLocked + `)
  RETURNING created_at, consumed_at)
SELECT created_at, consumed_at IS NOT NULL FROM ended`

// OTPEndBatch is the most rows one OTPExpireUndelivered or OTPEndExhausted call
// ends.
const OTPEndBatch = 200

// OTPExpireUndelivered clears the sealed code of OTPs that expired without
// being sent, and gives back the world-wide slot each spent, in the same transaction, so a
// worker outage costs no cap. It returns how many rows it refunded.
func (g GlobalTx) OTPExpireUndelivered() (int, error) {
	n, _, err := g.OTPExpireUndeliveredBatch()
	return n, err
}

// OTPExpireUndeliveredBatch is OTPExpireUndelivered that also says whether the
// batch was full.
func (g GlobalTx) OTPExpireUndeliveredBatch() (refunded int, more bool, err error) {
	rows, err := g.tx.Query(g.ctx, qOTPExpireUndelivered, int32(OTPEndBatch), RecordBudget.Seconds())
	return g.refundEnded(rows, err)
}

const qOTPEndExhausted = `WITH ended AS (
  UPDATE ctrlz.otp_challenges SET delivery_ct = NULL
  WHERE id IN (
    SELECT id FROM ctrlz.otp_challenges
    WHERE delivery_ct IS NOT NULL AND delivery_attempts >= $1
      AND (delivery_claimed_until IS NULL OR delivery_claimed_until < now() - make_interval(secs => $3))
    ORDER BY created_at LIMIT $2` + lockUpdateSkipLocked + `)
  RETURNING created_at, consumed_at)
SELECT created_at, consumed_at IS NOT NULL FROM ended`

// OTPEndExhausted closes the rows that used all their claims without a terminal
// record and gives their world-wide slot back, as an expiry does. OTPClaim never takes such
// a row again, so this is what ends it before its five minutes are up. At most
// OTPEndBatch rows per call; the worker's next pass takes the rest.
func (g GlobalTx) OTPEndExhausted(maxAttempts int) (int, error) {
	rows, err := g.tx.Query(g.ctx, qOTPEndExhausted, int32(maxAttempts), int32(OTPEndBatch), RecordBudget.Seconds())
	n, _, rerr := g.refundEnded(rows, err)
	return n, rerr
}

// refundEnded reads the rows a statement that clears delivery_ct returned, then
// refunds each that was not consumed. Both happen in this transaction. The statements stay constants
// in their callers: the SQL lint allows no query built at run time.
func (g GlobalTx) refundEnded(rows pgx.Rows, err error) (refunded int, more bool, _ error) {
	if err != nil {
		return 0, false, sanitize(err)
	}
	var unsent []time.Time
	total := 0
	for rows.Next() {
		var created time.Time
		var consumed bool
		if err := rows.Scan(&created, &consumed); err != nil {
			rows.Close()
			return 0, false, sanitize(err)
		}
		total++
		if consumed {
			continue // cleared, not refunded
		}
		unsent = append(unsent, created)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, false, sanitize(err)
	}
	// One call for the whole batch: the rows stay locked to the end of this
	// transaction, so the days are taken in one order across all of the messages (db-r4-5).
	if err := g.CountersRefundAll(unsent); err != nil {
		return 0, false, err
	}
	return len(unsent), total >= OTPEndBatch, nil
}

// SMSDelivery is one provider attempt. It holds no phone number and no text, by
// design: the table is the evidence that a message went, not a copy of it.
type SMSDelivery struct {
	Source        string // otp or outbox
	SourceID      uuid.UUID
	GatewayID     uuid.UUID
	Provider      string
	TemplateKey   string
	Outcome       string      // accepted, rejected or unreachable
	ProviderState closed.Text // a member of a closed set (sms.Code); nil for none
	ProviderMsgID string
	CostRaw       string
	LatencyMS     int
}

const qDeliveryRecord = `INSERT INTO ctrlz.sms_deliveries
  (source, source_id, gateway_id, provider, template_key, outcome, provider_status, provider_msg_id, cost_raw, latency_ms)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

// DeliveryRecord logs an attempt.
func (g GlobalTx) DeliveryRecord(d SMSDelivery) error {
	state, err := textArg(d.ProviderState)
	if err != nil {
		return err
	}
	_, err = g.tx.Exec(g.ctx, qDeliveryRecord, d.Source, d.SourceID, nilUUID(d.GatewayID), d.Provider, d.TemplateKey, d.Outcome,
		state, emptyNull(d.ProviderMsgID), emptyNull(d.CostRaw), d.LatencyMS)
	return sanitize(err)
}

// OutboxItem is a queued message that is not an OTP.
type OutboxItem struct {
	ID          uuid.UUID
	Kind        string
	GatewayID   uuid.UUID // the nil uuid when the router chooses
	Phone       string
	TemplateKey string
	Locale      string
	ParamsCT    []byte // sealed under sms_cred; aad = id \0 phone
	Attempts    int
	CreatedAt   time.Time
}

// The lease starts at the statement's own instant, like the OTP claim's (sms-r6-7): the claim transaction
// has already ended exhausted OTP rows and may have waited on counter rows.
const qOutboxClaim = `UPDATE ctrlz.sms_outbox o
SET claimed_until = clock_timestamp() + interval '20 seconds', attempts = o.attempts + 1
WHERE o.id IN (
  SELECT c.id FROM ctrlz.sms_outbox c
  WHERE c.state = 'pending' AND (c.claimed_until IS NULL OR c.claimed_until < now())
    AND c.attempts < $2
    AND c.created_at >= now() - interval '1 hour'
  ORDER BY c.created_at LIMIT $1` + lockUpdateSkipLocked + `)
RETURNING o.id, o.kind, o.gateway_id, o.phone_e164, o.template_key, o.locale, o.params_ct, o.attempts, o.created_at`

// OutboxMaxAttempts is the ceiling on claims of one outbox message. With the
// backoff of the worker (30 seconds doubling to 5 minutes) an hour of honest
// retries is about 15 attempts. A message past the ceiling is a record
// transaction that keeps failing after the provider accepted, and OutboxFailStaleBatch
// ends it so the provider is not asked again every 20 seconds.
const OutboxMaxAttempts = 20

// OutboxClaim takes up to limit pending messages for 20 seconds. A message that
// used OutboxMaxAttempts claims, or is older than the hour OutboxFailStaleBatch ends it
// at, is not taken again: OutboxFailStaleBatch waits for a lapsed claim (review round 3,
// db-r3-2), so a message that kept being claimed past the hour would never be ended.
func (g GlobalTx) OutboxClaim(limit int) ([]OutboxItem, error) {
	rows, err := g.tx.Query(g.ctx, qOutboxClaim, int32(limit), int32(OutboxMaxAttempts))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []OutboxItem
	for rows.Next() {
		var o OutboxItem
		var gw *uuid.UUID
		if err := rows.Scan(&o.ID, &o.Kind, &gw, &o.Phone, &o.TemplateKey, &o.Locale, &o.ParamsCT, &o.Attempts, &o.CreatedAt); err != nil {
			return nil, sanitize(err)
		}
		if gw != nil {
			o.GatewayID = *gw
		}
		out = append(out, o)
	}
	return out, sanitize(rows.Err())
}

// The lease a claim still has, measured by the database at the moment of the question (the same
// clock that stamped it). The claim transaction goes on after the two claim statements (the
// outbox gates wait on the shared counter row, an alert insert waits on another worker's), and
// every wait comes out of the lease; the worker asks this as the LAST statement of the
// transaction, so what it hears is what is left when the send can start, and bounds the send by
// it instead of by a number that was only true when the statement ran (sms-r7-3, sms-r7-8).
// A row that is no longer there or no longer claimed counts as no lease at all.
const qClaimLeaseLeft = `SELECT COALESCE(MIN(extract(epoch FROM (s.until - clock_timestamp()))), 0)::float8
FROM (
  SELECT delivery_claimed_until AS until FROM ctrlz.otp_challenges WHERE id = ANY($1)
  UNION ALL
  SELECT claimed_until FROM ctrlz.sms_outbox WHERE id = ANY($2)
) s`

// ClaimLeaseLeft returns the shortest time any of the given claimed rows still has before
// another worker may claim it. It takes no lock: the claim transaction holds the rows. Call it
// last in the claim transaction, so nothing can wait between this answer and the commit.
func (g GlobalTx) ClaimLeaseLeft(otpIDs, outboxIDs []uuid.UUID) (time.Duration, error) {
	if otpIDs == nil {
		otpIDs = []uuid.UUID{}
	}
	if outboxIDs == nil {
		outboxIDs = []uuid.UUID{}
	}
	var secs float64
	if err := g.tx.QueryRow(g.ctx, qClaimLeaseLeft, otpIDs, outboxIDs).Scan(&secs); err != nil {
		return 0, sanitize(err)
	}
	return time.Duration(secs * float64(time.Second)), nil
}

const qOutboxFinish = `UPDATE ctrlz.sms_outbox
SET state = $2, last_error = $3, params_ct = NULL, claimed_until = NULL, sent_at = CASE WHEN $2 = 'sent' THEN now() ELSE sent_at END
WHERE id = $1 AND state = 'pending'`

// OutboxFinish ends a message as sent or failed. Either way params_ct goes to
// NULL: a compromised worker holds the sms_cred key and must not be able to open
// past invite codes (9.5). lastError is a short code, never provider text.
func (g GlobalTx) OutboxFinish(id uuid.UUID, state string, lastError closed.Text) (Won, error) {
	arg, err := textArg(lastError)
	if err != nil {
		return Won{}, err
	}
	tag, err := g.tx.Exec(g.ctx, qOutboxFinish, id, state, arg)
	if err != nil {
		return Won{}, sanitize(err)
	}
	return wonRows(tag), nil
}

// The stale-outbox sweep ends a bounded batch by primary key, like every sweep (rule
// bounded-sweeps). The outer WHERE repeats the pending and unclaimed tests: the subselect
// is read first, and a message claimed between the two must not be ended under the worker
// that is sending it.
const qOutboxFailStale = `UPDATE ctrlz.sms_outbox
SET state = 'failed', params_ct = NULL, claimed_until = NULL,
    last_error = CASE WHEN created_at < now() - interval '1 hour' THEN 'timeout' ELSE 'attempts' END
WHERE id IN (
    SELECT id FROM ctrlz.sms_outbox
    WHERE state = 'pending'
      AND (claimed_until IS NULL OR claimed_until < now() - make_interval(secs => $3))
      AND (created_at < now() - interval '1 hour' OR attempts >= $1)
    LIMIT $2)
  AND state = 'pending'
  AND (claimed_until IS NULL OR claimed_until < now() - make_interval(secs => $3))
  AND (created_at < now() - interval '1 hour' OR attempts >= $1)`

// OutboxFailStaleBatch ends at most limit messages that have been retried for an hour,
// and ones that used all their claims (OutboxMaxAttempts) without ending. It returns how
// many; fewer than limit means none are left. The caller runs it in its own transaction
// through sweepbatch.Drain.
func (g GlobalTx) OutboxFailStaleBatch(limit int) (int, error) {
	if limit < 1 {
		return 0, errors.New("store: sweep batch size must be positive")
	}
	tag, err := g.tx.Exec(g.ctx, qOutboxFailStale, int32(OutboxMaxAttempts), int32(limit), RecordBudget.Seconds())
	if err != nil {
		return 0, sanitize(err)
	}
	return int(tag.RowsAffected()), nil
}

// The outbox has no OTP row to pass through auth_otp_issue, so the worker is its gate
// (9.5, 9.6). Both gates are ONE conditional statement whose returned row is the leave
// to send: the daily count and the money cap are compared in the statement, with
// ctrlz.cap_reached like every other cap, and Go never reads a count and then writes.
// The day is the Tehran day on the database clock.
const (
	// qSpentToday is the day's money counter, 0 when the day has no row yet, so a cap of
	// 0 (stop all spending) refuses the first message of the day (sms-r2-6).
	qSpentToday = `(SELECT k.cost FROM ctrlz.sms_counters k
   WHERE k.day = (now() AT TIME ZONE 'Asia/Tehran')::date AND k.scope = 'global' AND k.key = 'all')`

	qOutboxFirstGate = `WITH money AS (
  SELECT NOT ctrlz.cap_reached(` + qSpentToday + `, s.sms_cost_cap_daily) AS room FROM ctrlz.system_settings s)
INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count)
SELECT (now() AT TIME ZONE 'Asia/Tehran')::date, 'global', 'outbox', 1
FROM money
WHERE money.room AND NOT ctrlz.cap_reached(0, (SELECT s.sms_outbox_cap_daily FROM ctrlz.system_settings s))
ON CONFLICT (day, scope, key) DO UPDATE SET count = c.count + 1
  WHERE (SELECT m.room FROM money m)
    AND NOT ctrlz.cap_reached(c.count, (SELECT s.sms_outbox_cap_daily FROM ctrlz.system_settings s))
RETURNING c.count`

	qOutboxRetryGate = `SELECT true FROM ctrlz.system_settings s
WHERE NOT ctrlz.cap_reached(` + qSpentToday + `, s.sms_cost_cap_daily)`
)

// OutboxFirstGate is the leave to send an outbox message on its first claim: it counts
// the message against sms_outbox_cap_daily and checks the money cap, in one statement.
// A loss means one of the two is used up, and the message ends as failed with
// last_error 'cap'. The count and the claim commit together (the caller runs it in the
// claim transaction), so a crash cannot leave a message sent without being counted.
func (g GlobalTx) OutboxFirstGate() (Won, error) {
	var n int
	return wonRow(g.tx.QueryRow(g.ctx, qOutboxFirstGate).Scan(&n))
}

// OutboxRetryGate is the leave to send a message that is being retried: its count was
// taken when it was first claimed, so only the money cap is compared, against the
// day's spending as it stands now.
func (g GlobalTx) OutboxRetryGate() (Won, error) {
	var ok bool
	return wonRow(g.tx.QueryRow(g.ctx, qOutboxRetryGate).Scan(&ok))
}

// WorkerGateway is a gateway as the router needs it.
type WorkerGateway struct {
	ID             uuid.UUID
	Provider       string
	Role           string
	CredentialsCT  []byte // sealed under sms_cred; aad = id \0 provider
	CostPerMessage *string
	// BreakerOpenFor is how much longer the breaker stays open, measured by the
	// database that opened it; zero when it is closed. A length of time crosses the
	// two clocks safely where an instant does not: the caller adds it to its own
	// clock (clocks.yaml, sms_gateways.breaker_open_until is db).
	BreakerOpenFor time.Duration
	// HeldCTSum and HeldCode are the hold of a gateway whose login the provider refused
	// (sms-r12-3): the SHA-256 of the sealed credentials the refusal was made against, and the
	// code of the answer. Both are nil for a gateway that is not held. The hold counts only while
	// it names the credentials the row has now, so saving other credentials ends it with no write.
	HeldCTSum []byte
	HeldCode  *string
	// UnusableCTSum is the worker's own judgement that no sender can be built for the credentials
	// with this sum (sms-r15-1, sms-r15-4): the SHA-256 of credentials_ct, of the empty string when
	// there is none. The database reads it, with the hold and the missing credentials, as
	// blocked_now, so sms_available does not turn true again for a gateway nothing can send through.
	UnusableCTSum []byte
}

const qWorkerGateways = `SELECT id, provider, role, credentials_ct, cost_per_message::text,
  COALESCE(GREATEST(extract(epoch FROM breaker_open_until - now()), 0), 0)::float8,
  held_ct_sum, held_code, unusable_ct_sum
FROM ctrlz.sms_gateways WHERE role IN ('primary', 'fallback') OR credentials_ct IS NOT NULL OR provider = 'noop' ORDER BY role`

// WorkerGateways returns the gateways that hold a role, and any other gateway
// that has credentials or needs none (a test send can pin one that is not routed yet), with
// their sealed credentials. The router reloads them every 30 seconds and only
// routes ordinary messages through the two that hold a role.
func (g GlobalTx) WorkerGateways() ([]WorkerGateway, error) {
	rows, err := g.tx.Query(g.ctx, qWorkerGateways)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []WorkerGateway
	for rows.Next() {
		var w WorkerGateway
		var open float64
		if err := rows.Scan(&w.ID, &w.Provider, &w.Role, &w.CredentialsCT, &w.CostPerMessage, &open, &w.HeldCTSum, &w.HeldCode, &w.UnusableCTSum); err != nil {
			return nil, sanitize(err)
		}
		w.BreakerOpenFor = time.Duration(open * float64(time.Second))
		out = append(out, w)
	}
	return out, sanitize(rows.Err())
}

// The hold of a gateway whose login the provider refused lives in the row, so every worker reads
// one state (sms-r12-3). It used to be a field of one process's Source: a test send lifted it only
// in the worker that ran the send, and a second worker kept passing the gateway over and kept
// stepping its shared breaker, which the first worker's accepted send closed again, so
// sms_available flapped. Now the hold is two columns of sms_gateways, set by the worker that met
// the refusal and cleared by the worker whose pinned send was accepted.
//
// held_ct_sum is the SHA-256 of credentials_ct as it was when the call was made. The statement
// sets the hold only WHERE the row still has those credentials, so a hold for a call that used
// credentials saved since is ignored (the admin PUT replaced credentials_ct while the call was
// in flight), and a hold that names old credentials stops counting by itself the moment the PUT
// writes new ones: the admin path writes nothing here. The sum is of the ciphertext, not secret,
// and is never logged.
const qGatewayHold = `UPDATE ctrlz.sms_gateways SET held_ct_sum = $2, held_code = $3
WHERE id = $1 AND credentials_ct IS NOT NULL AND sha256(credentials_ct) = $2
  AND held_ct_sum IS DISTINCT FROM $2
RETURNING true`

// GatewayHold puts the gateway on hold for the credentials with the given sum. A loss means the
// credentials changed or the row is gone, and nothing was held. A loss also means the gateway is
// already held for these credentials, so of several calls in flight that all met the refusal exactly one
// wins and logs it. code is the refusal's closed code.
func (g GlobalTx) GatewayHold(id uuid.UUID, ctSum []byte, code closed.Text) (Won, error) {
	arg, err := textArg(code)
	if err != nil {
		return Won{}, err
	}
	if arg == nil || len(ctSum) != 32 {
		return Won{}, ErrConstraint
	}
	var ok bool
	return wonRow(g.tx.QueryRow(g.ctx, qGatewayHold, id, ctSum, arg).Scan(&ok))
}

const qGatewayRelease = `UPDATE ctrlz.sms_gateways SET held_ct_sum = NULL, held_code = NULL
WHERE id = $1 AND held_ct_sum = $2
RETURNING true`

// GatewayRelease lifts the hold that was made for the credentials with the given sum: a test send
// through them was accepted. A hold for other credentials is not this call's to lift.
func (g GlobalTx) GatewayRelease(id uuid.UUID, ctSum []byte) (Won, error) {
	if len(ctSum) != 32 {
		return Won{}, ErrConstraint
	}
	var ok bool
	return wonRow(g.tx.QueryRow(g.ctx, qGatewayRelease, id, ctSum).Scan(&ok))
}

// The worker's judgement that a gateway cannot be built is a column of the row too (sms-r15-1,
// sms-r15-4, migration 0048), for the reason the hold is: the router passes such a gateway over
// without a call, so nothing a user's send does ever opens or closes anything the login page can
// read, and the breaker alone turned sms_available true again after every pause. The sum is of the
// sealed credentials the judgement was made for (of the empty string when there are none), and the
// statement lands only WHERE the row still has them, so a judgement about credentials the admin has
// replaced since is dropped, and one that names old credentials stops counting the moment new ones
// are stored. The sum is a digest of ciphertext, never logged.
const qGatewayUnusable = `UPDATE ctrlz.sms_gateways SET unusable_ct_sum = $2
WHERE id = $1 AND sha256(COALESCE(credentials_ct, ''::bytea)) = $2
  AND unusable_ct_sum IS DISTINCT FROM $2
RETURNING true`

// GatewayUnusable records that no sender can be built for the credentials with the given sum. A
// loss means the credentials changed since, the row is gone, or it already says so.
func (g GlobalTx) GatewayUnusable(id uuid.UUID, ctSum []byte) (Won, error) {
	if len(ctSum) != 32 {
		return Won{}, ErrConstraint
	}
	var ok bool
	return wonRow(g.tx.QueryRow(g.ctx, qGatewayUnusable, id, ctSum).Scan(&ok))
}

const qGatewayUsable = `UPDATE ctrlz.sms_gateways SET unusable_ct_sum = NULL
WHERE id = $1 AND unusable_ct_sum IS NOT NULL
RETURNING true`

// GatewayUsable takes the judgement back: a sender was built for the gateway (a key that opens
// again, a noop row outside production). A loss means it said nothing.
func (g GlobalTx) GatewayUsable(id uuid.UUID) (Won, error) {
	var ok bool
	return wonRow(g.tx.QueryRow(g.ctx, qGatewayUsable, id).Scan(&ok))
}

const qGatewayOK = `UPDATE ctrlz.sms_gateways SET last_ok_at = now(), consecutive_failures = 0, breaker_open_until = NULL WHERE id = $1`

// GatewayOK records a send that the provider accepted: the breaker closes.
func (g GlobalTx) GatewayOK(id uuid.UUID) error {
	_, err := g.tx.Exec(g.ctx, qGatewayOK, id)
	return sanitize(err)
}

const qGatewayFailed = `UPDATE ctrlz.sms_gateways
SET last_error_at = now(), last_error_code = $2,
    consecutive_failures = CASE WHEN $3 AND NOT COALESCE(breaker_open_until > now(), false)
      THEN consecutive_failures + 1 ELSE consecutive_failures END,
    breaker_open_until = CASE WHEN $3 AND NOT COALESCE(breaker_open_until > now(), false) AND consecutive_failures + 1 >= 3
      THEN now() + make_interval(secs => LEAST(900, 60 * power(2, LEAST(consecutive_failures + 1 - 3, 4))))
      ELSE breaker_open_until END
WHERE id = $1
RETURNING $3 AND NOT COALESCE(old.breaker_open_until > now(), false)`

// GatewayFailed records a failure. code is the short class and code of
// sms.Error. countsTowardBreaker is the verdict of classify.CountsTowardBreaker
// (the store does not decide it, and no other caller may: rule
// sms-failure-classification). It is true for a failure that says the gateway
// as a whole cannot send: a transient one, a refused key or an empty account.
// Three of them in a row open the breaker for 60 seconds, doubling up to 15
// minutes (9.1), which is what turns sms_available off when both gateways are
// out of credit. A failure that belongs to one message or one template (a
// refused number, a missing mapping) does not count.
//
// A failure that arrives while the breaker is already open changes neither the
// counter nor the pause. The router checks the breaker against its snapshot
// before the call, so when a pause ends several rows of one pass reach the
// gateway together; if each failure escalated, one probe round would jump the
// pause from 60 seconds to 15 minutes. One round is one step (sms-r2-1).
//
// The Won is Yes when this failure was the step: it counted toward a breaker that was
// not open when the statement read the row. The statement decides it against the
// locked row (OLD is the row it updated), so of N racing failures exactly one steps.
func (g GlobalTx) GatewayFailed(id uuid.UUID, code closed.Text, countsTowardBreaker bool) (Won, error) {
	arg, err := textArg(code)
	if err != nil {
		return Won{}, err
	}
	var stepped bool
	w, err := wonRow(g.tx.QueryRow(g.ctx, qGatewayFailed, id, arg, countsTowardBreaker).Scan(&stepped))
	if err != nil || !w.Yes() {
		return Won{}, err
	}
	return won(stepped), nil
}

const qAlertOnce = `INSERT INTO ctrlz.alerts (severity, kind, params)
VALUES ($1, $2, jsonb_set($4::jsonb, '{key}', to_jsonb($3::text)))
ON CONFLICT DO NOTHING`

// AlertOnce raises an alert unless one with the same kind and key is still
// open (alerts_open_key_uq). The worker holds INSERT only on alerts, so it cannot
// look for an earlier alert; the unique index does it. An operator's ack closes
// the alert and the next failure opens a new one. params is a JSON object with
// no secret in it; the key is added to it.
func (g GlobalTx) AlertOnce(severity, kind string, key closed.Key, params closed.Params) (bool, error) {
	if key.String() == "" {
		return false, ErrConstraint // a key part was off its closed list
	}
	tag, err := g.tx.Exec(g.ctx, qAlertOnce, severity, kind, key.String(), params.JSON())
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

// SweepCounts says what a global sweep deleted.
type SweepCounts struct {
	OTP, Tickets, Throttle, Deliveries, Outbox, Counters, Invites int
}

// SweepStep names one table of the global sweep. Each step runs in its own
// transaction and in batches (SweepGlobalBatch), so a table with a backlog
// cannot starve the others and no statement outruns the worker's
// statement_timeout.
type SweepStep int

// The steps, in the order the sweeper runs them. The raw phone and network
// counters come before the large history tables because they hold who was asked
// about (9.5) and so are the ones that must never be held back.
const (
	SweepCounters SweepStep = iota
	SweepOTP
	SweepTickets
	SweepThrottle
	SweepDeliveries
	SweepOutbox
	SweepInvites
)

// SweepSteps lists every step.
func SweepSteps() []SweepStep {
	return []SweepStep{SweepCounters, SweepOTP, SweepTickets, SweepThrottle, SweepDeliveries, SweepOutbox, SweepInvites}
}

// The batch statements, one constant per step (the SQL lint allows no query
// built at run time). Each deletes by primary key from a LIMIT-ed subselect: the
// subselect is what bounds a single DELETE. ctid would do for any table, but
// reading a system column needs table-level SELECT, which the worker's column
// grants do not give. Every predicate and key column is one the worker has a
// grant for.
const (
	// Every challenge, decoys included, 24 hours after creation. The worker cannot see the decoy rows
	// (row-level security shows it the ones that carry a sealed code, migration 0039), so the sweep
	// is a function (db-r9-3).
	qSweepBatchOTP = `SELECT ctrlz_fn.worker_sweep_otp_challenges($1)`
	// The tickets and the throttle windows are swept by functions that delete only
	// what these statements always did (expired tickets, windows over a day old).
	// The worker holds no grant on either table: with one it could empty the admin
	// login throttle between guesses or delete live tickets (db-r4-8).
	qSweepBatchTickets  = `SELECT ctrlz_fn.worker_sweep_tickets($1)`
	qSweepBatchThrottle = `SELECT ctrlz_fn.worker_sweep_throttle($1)`
	// sms_deliveries is the record of what was sent and what it cost; the worker
	// appends to it and holds no DELETE, so the 90 day sweep is a function.
	qSweepBatchDeliveries = `SELECT ctrlz_fn.worker_sweep_sms_deliveries($1)`
	qSweepBatchOutbox     = `DELETE FROM ctrlz.sms_outbox WHERE id IN
  (SELECT id FROM ctrlz.sms_outbox WHERE created_at < now() - interval '30 days' LIMIT $1)
  AND created_at < now() - interval '30 days'`
	// The per-phone, per-network and per-address keys hold raw numbers and
	// networks, decoys included, so they must not build up into a history of who
	// was asked about. The global rows stay for /sms/stats. The worker cannot see
	// those rows (row-level security shows it the global ones, migration 0035), so
	// the sweep is a function (sms-r8-3, sms-r8-7).
	qSweepBatchCounters = `SELECT ctrlz_fn.worker_sweep_sms_counters($1)`
	qSweepBatchInvites  = `DELETE FROM ctrlz.invites WHERE id IN
  (SELECT id FROM ctrlz.invites WHERE expires_at < now() - interval '90 days' LIMIT $1)
  AND expires_at < now() - interval '90 days'`
)

// String is the step's short name, for a log line.
func (s SweepStep) String() string {
	switch s {
	case SweepOTP:
		return "otp"
	case SweepTickets:
		return "tickets"
	case SweepThrottle:
		return "throttle"
	case SweepDeliveries:
		return "deliveries"
	case SweepOutbox:
		return "outbox"
	case SweepCounters:
		return "counters"
	case SweepInvites:
		return "invites"
	}
	return "unknown"
}

// SweepGlobalBatch deletes at most limit expired rows of one step and returns
// how many it deleted; fewer than limit means the step is drained (9.5, 11.3).
// The caller runs it in its own transaction, in a loop, so one slow table or
// one lock wait fails that batch only.
func (g GlobalTx) SweepGlobalBatch(step SweepStep, limit int) (int, error) {
	if limit < 1 {
		return 0, errors.New("store: sweep batch size must be positive")
	}
	var n int64
	var err error
	switch step {
	case SweepOTP:
		n, err = g.sweepOTP(limit)
	case SweepTickets:
		n, err = g.sweepTickets(limit)
	case SweepThrottle:
		n, err = g.sweepThrottle(limit)
	case SweepDeliveries:
		n, err = g.sweepDeliveries(limit)
	case SweepOutbox:
		n, err = g.rows(g.tx.Exec(g.ctx, qSweepBatchOutbox, int32(limit)))
	case SweepCounters:
		n, err = g.sweepCounters(limit)
	case SweepInvites:
		n, err = g.rows(g.tx.Exec(g.ctx, qSweepBatchInvites, int32(limit)))
	default:
		return 0, errors.New("store: unknown sweep step")
	}
	return int(n), err
}

// rows turns the result of an Exec into a count and a sanitized error.
func (GlobalTx) rows(tag pgconn.CommandTag, err error) (int64, error) {
	if err != nil {
		return 0, sanitize(err)
	}
	return tag.RowsAffected(), nil
}

const qTenantIDs = `SELECT id FROM ctrlz.tenants WHERE ($1::uuid IS NULL OR id > $1) ORDER BY id LIMIT $2`

// TenantIDs pages through the tenants in id order, for the jobs that do one
// WithTenant per tenant. Pass the nil uuid for the first page and the last id of
// a page for the next.
func (g GlobalTx) TenantIDs(after uuid.UUID, limit int) ([]uuid.UUID, error) {
	rows, err := g.tx.Query(g.ctx, qTenantIDs, nilUUID(after), int32(limit))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, id)
	}
	return out, sanitize(rows.Err())
}

const qAdminJobsActive = `SELECT id, kind, params, state, progress, created_at, started_at, finished_at
FROM ctrlz.admin_jobs WHERE state IN ('queued', 'running') ORDER BY created_at`

// AdminJobsActive lists the jobs that are queued or running. A running job is
// listed too: a worker that died leaves one, and every job is safe to run again.
func (g GlobalTx) AdminJobsActive() ([]AdminJob, error) {
	rows, err := g.tx.Query(g.ctx, qAdminJobsActive)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []AdminJob
	for rows.Next() {
		var j AdminJob
		if err := rows.Scan(&j.ID, &j.Kind, &j.Params, &j.State, &j.Progress, &j.CreatedAt, &j.StartedAt, &j.FinishedAt); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, j)
	}
	return out, sanitize(rows.Err())
}

const qAdminJobStart = `UPDATE ctrlz.admin_jobs SET state = 'running', started_at = COALESCE(started_at, now()) WHERE id = $1 AND state IN ('queued', 'running')`

// AdminJobStart marks a job running. It says whether the job was still queued or
// running: false means another worker already finished it, and running it again
// from a job list read earlier would act on parameters that may be out of date
// (sms-r2-12).
func (g GlobalTx) AdminJobStart(id uuid.UUID) (Won, error) {
	tag, err := g.tx.Exec(g.ctx, qAdminJobStart, id)
	if err != nil {
		return Won{}, sanitize(err)
	}
	return wonRows(tag), nil
}

const qAdminJobProgress = `UPDATE ctrlz.admin_jobs SET progress = $2 WHERE id = $1 AND state = 'running'`

// AdminJobProgress records JSON progress.
func (g GlobalTx) AdminJobProgress(id uuid.UUID, progress []byte) error {
	_, err := g.tx.Exec(g.ctx, qAdminJobProgress, id, progress)
	return sanitize(err)
}

const qAdminJobFinish = `UPDATE ctrlz.admin_jobs SET state = $2, progress = COALESCE($3::jsonb, progress), finished_at = now()
WHERE id = $1 AND state IN ('queued', 'running')`

// AdminJobFinish ends a job as done or failed, with final progress (JSON, nil
// to keep). The Won says whether this call ended the job; a job that another worker
// finished first keeps the state that worker gave it.
func (g GlobalTx) AdminJobFinish(id uuid.UUID, state string, progress []byte) (Won, error) {
	tag, err := g.tx.Exec(g.ctx, qAdminJobFinish, id, state, progress)
	if err != nil {
		return Won{}, sanitize(err)
	}
	return wonRows(tag), nil
}

// ---------------------------------------------------------------------------
// Per tenant (WithTenant as ctrlz_worker)

// TenantSweepCounts says what a tenant sweep did.
type TenantSweepCounts struct {
	Sessions, Refresh, PhoneChanges, Audit, PendingTOTP int
}

// TenantSweepStep names one statement of the per-tenant sweep. Like the global
// steps, each runs in its own transaction and in batches, so a tenant with a
// backlog (a sweeper that was down for months, a large audit log after its first
// year) cannot make one DELETE hit statement_timeout and roll back the others,
// the clear of a pending TOTP secret among them (sms-r2-4).
type TenantSweepStep int

// The tenant steps, in the order the sweeper runs them.
const (
	TenantSweepSessions TenantSweepStep = iota
	TenantSweepRefresh
	TenantSweepPhone
	TenantSweepAudit
	TenantSweepPendingTOTP
)

// TenantSweepSteps lists every tenant step. The pending TOTP secret goes first:
// it is the one that holds key material, however small.
func TenantSweepSteps() []TenantSweepStep {
	return []TenantSweepStep{TenantSweepPendingTOTP, TenantSweepSessions, TenantSweepRefresh, TenantSweepPhone, TenantSweepAudit}
}

// String is the step's short name, for a log line.
func (s TenantSweepStep) String() string {
	switch s {
	case TenantSweepSessions:
		return "sessions"
	case TenantSweepRefresh:
		return "refresh"
	case TenantSweepPhone:
		return "phone_changes"
	case TenantSweepAudit:
		return "audit"
	case TenantSweepPendingTOTP:
		return "pending_totp"
	}
	return "unknown"
}

// Each delete takes its rows from a LIMIT-ed subselect on the primary key, as
// the global batches do. The worker has SELECT on tenant_id, id and the
// predicate column of each table (0011) and nothing wider.
const (
	qSweepSessions = `DELETE FROM ctrlz.sessions WHERE tenant_id = $1 AND id IN
  (SELECT id FROM ctrlz.sessions WHERE tenant_id = $1 AND absolute_expires_at < $3::timestamptz - interval '1 day' LIMIT $2)
  AND absolute_expires_at < $3::timestamptz - interval '1 day'`
	qSweepRefresh = `DELETE FROM ctrlz.refresh_tokens WHERE tenant_id = $1 AND id IN
  (SELECT id FROM ctrlz.refresh_tokens WHERE tenant_id = $1 AND expires_at < $3::timestamptz - interval '1 day' LIMIT $2)
  AND expires_at < $3::timestamptz - interval '1 day'`
	qSweepPhone = `DELETE FROM ctrlz.phone_change_requests WHERE tenant_id = $1 AND id IN
  (SELECT id FROM ctrlz.phone_change_requests WHERE tenant_id = $1 AND expires_at < now() - interval '1 day' LIMIT $2)
  AND expires_at < now() - interval '1 day'`
	qSweepAudit = `DELETE FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND id IN
  (SELECT id FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND at < now() - interval '365 days' LIMIT $2)
  AND at < now() - interval '365 days'`
	// A pending secret lives 15 minutes (6.4). Clearing it here keeps a secret
	// the user never confirmed from sitting in the table. The worker holds no
	// grant on users.totp_secret_ct: with one it could clear the seed of an enabled
	// user as well, and it reads every login code (role-reach). The function clears
	// only a setup that was never confirmed, for the tenant of the transaction, and
	// at most the limit it is given: no sweep is exempt from the bound for being
	// small (rule bounded-sweeps).
	qSweepPendingTOTP = `SELECT ctrlz_fn.worker_sweep_pending_totp($1)`
)

// SweepTenantBatch runs one step of the tenant sweep for at most limit rows and
// returns how many it handled; fewer than limit means the step is drained. The
// caller runs it in its own transaction, in a loop. Sessions delete their
// refresh tokens with them (ON DELETE CASCADE), so the refresh step finds only
// tokens whose session is still live.
//
// now is the application clock: the session and refresh expiries it is measured
// against are application-clock columns (clocks.yaml).
func (t Tx) SweepTenantBatch(step TenantSweepStep, limit int, now time.Time) (int, error) {
	if limit < 1 {
		return 0, errors.New("store: sweep batch size must be positive")
	}
	var n int64
	var err error
	switch step {
	case TenantSweepSessions:
		n, err = t.rows(t.tx.Exec(t.ctx, qSweepSessions, t.tenant, int32(limit), now))
	case TenantSweepRefresh:
		n, err = t.rows(t.tx.Exec(t.ctx, qSweepRefresh, t.tenant, int32(limit), now))
	case TenantSweepPhone:
		n, err = t.rows(t.tx.Exec(t.ctx, qSweepPhone, t.tenant, int32(limit)))
	case TenantSweepAudit:
		n, err = t.rows(t.tx.Exec(t.ctx, qSweepAudit, t.tenant, int32(limit)))
	case TenantSweepPendingTOTP:
		var cleared int32
		err = sanitize(t.tx.QueryRow(t.ctx, qSweepPendingTOTP, int32(limit)).Scan(&cleared))
		n = int64(cleared)
	default:
		return 0, errors.New("store: unknown tenant sweep step")
	}
	return int(n), err
}

// rows turns the result of an Exec into a count and a sanitized error.
func (Tx) rows(tag pgconn.CommandTag, err error) (int64, error) {
	if err != nil {
		return 0, sanitize(err)
	}
	return tag.RowsAffected(), nil
}

// A retry of the RP ID job is safe: only rows that were live change, so the
// notification of the caller fires once per credential (7.4 step 4).
// ctrlz_fn.worker_passkeys_mark_stale acts only while rpID is the RP ID in force
// (webauthn_config) and for the tenant of the transaction. The worker has no grant
// on webauthn_credentials: with an UPDATE on stale_at it could end every passkey of
// a tenant, and Enforce Passkey with it (db-r4-7).
const qPasskeysMarkStale = `SELECT user_id FROM ctrlz_fn.worker_passkeys_mark_stale($1)`

// PasskeysMarkStale marks the tenant's credentials of another RP ID stale and
// returns the distinct users who lost one.
func (t Tx) PasskeysMarkStale(rpID string) ([]uuid.UUID, error) {
	rows, err := t.tx.Query(t.ctx, qPasskeysMarkStale, rpID)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	seen := map[uuid.UUID]bool{}
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, sanitize(err)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, sanitize(rows.Err())
}

// ctrlz_fn.worker_enforce_clear_without_live clears the flag only for users with no
// live credential for the RP ID in force, and leaves a notice and an audit row. A
// plain UPDATE grant on enforce_passkey could not limit the rows or the value, so
// the worker, which reads login codes, could have switched Enforce Passkey off for
// any user and logged in with a code (db-r4-7).
const qEnforceClearWithoutLive = `SELECT ctrlz_fn.worker_enforce_clear_without_live($1)`

// EnforceClearWithoutLive turns Enforce Passkey off for users who have no live
// credential left for rpID, so nobody is locked out after an RP ID change.
func (t Tx) EnforceClearWithoutLive(rpID string) (int64, error) {
	var n int32
	if err := t.tx.QueryRow(t.ctx, qEnforceClearWithoutLive, rpID).Scan(&n); err != nil {
		return 0, sanitize(err)
	}
	return int64(n), nil
}

// TOTPSecret is a sealed seed with its owner, for key rotation.
type TOTPSecret struct {
	User uuid.UUID
	CT   []byte
}

const qTOTPSecrets = `SELECT id, totp_secret_ct FROM ctrlz.users WHERE tenant_id = $1 AND totp_secret_ct IS NOT NULL ORDER BY id`

// TOTPSecrets returns the tenant's sealed TOTP seeds. Only the one-shot rekey
// tool uses it; it holds the ciphertext rights and the user_totp key (8.4).
func (t Tx) TOTPSecrets() ([]TOTPSecret, error) {
	rows, err := t.tx.Query(t.ctx, qTOTPSecrets, t.tenant)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []TOTPSecret
	for rows.Next() {
		var s TOTPSecret
		if err := rows.Scan(&s.User, &s.CT); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, s)
	}
	return out, sanitize(rows.Err())
}

// The swap is a function: a column grant on totp_secret_ct could also write NULL
// and switch a user's second factor off (role-reach).
const qTOTPSecretReplace = `SELECT ctrlz_fn.keytool_totp_replace($1, $2, $3)`

// TOTPSecretReplace swaps a sealed seed for its re-encryption. The old value is
// compared, so a seed the user changed in the meantime is not overwritten; false
// means it changed.
func (t Tx) TOTPSecretReplace(user uuid.UUID, old, replacement []byte) (bool, error) {
	var ok bool
	if err := t.tx.QueryRow(t.ctx, qTOTPSecretReplace, user, old, replacement).Scan(&ok); err != nil {
		return false, sanitize(err)
	}
	return ok, nil
}

const qTOTPDeclareLost = `SELECT ctrlz_fn.keytool_totp_declare_lost($1, $2, $3)`

// declareLostBatch is the most seeds one call names. The function refuses more, and a tenant with
// more users is cleared in several calls. Each call writes one notice and one audit row, so a
// declaration is ONE record for any tenant up to this size (db-r15-5); the limit was 500 while the
// function matched the list with array_position, which is quadratic, and is 20000 since it joins.
const declareLostBatch = 20000

// TOTPDeclareLost is `ctrlz declare-lost user_totp` for one tenant (8.5): TOTP is cleared for the
// users whose seeds the caller has proved cannot be opened. It returns how many users it cleared.
// The recovery codes stay: they are hashes that need no key, and with TOTP off they open nothing;
// enrolling again replaces them.
//
// The decision is per seed and never per key number (round 13, admin-r13-3). After a total loss the
// regenerated key starts again at number 1, the number of the lost seeds, so a number cannot tell a
// lost seed from one enrolled after the recovery. The caller passes the seeds it read (TOTPSecrets)
// and could not open; the function clears a row only while it still holds exactly that ciphertext
// and still names keyNumber, so a seed that was enrolled or re-sealed meanwhile is kept.
//
// Only the key tool role (ctrlz_keytool, migration 0017) may call the function. It
// was the admin role's until 0015 and then the worker's, and code running as either
// could name any tenant and leave its users single-factor, the worker's with the
// login codes in reach and the means to delete the notice and audit row the
// function writes (db-r4-3, db-r4-6). The one-shot container that calls this holds
// the only copy of that role's password and the user_totp key ring. The function
// writes the tenant's totp_lost notice and audit row itself, so no caller can clear a
// seed silently. It leaves totp_pending_at alone: an unconfirmed secret that cannot be
// opened is cleared by the pending sweep within 15 minutes.
func (t Tx) TOTPDeclareLost(keyNumber int, lost []TOTPSecret) (int, error) {
	return t.declareLost(keyNumber, lost, declareLostBatch)
}

// declareLost is TOTPDeclareLost with the size of a call as an argument, so a test can show what a
// declaration larger than one call leaves behind (one accurate record per call) without planting
// twenty thousand users. The whole declaration runs in the caller's one transaction, so it cannot
// stop half way: either every call's clear and record commit, or none does.
func (t Tx) declareLost(keyNumber int, lost []TOTPSecret, batch int) (int, error) {
	total := 0
	for len(lost) > 0 {
		chunk := lost
		if len(chunk) > batch {
			chunk = chunk[:batch]
		}
		lost = lost[len(chunk):]
		ids := make([]uuid.UUID, len(chunk))
		cts := make([][]byte, len(chunk))
		for i, s := range chunk {
			ids[i], cts[i] = s.User, s.CT
		}
		var n int
		if err := t.tx.QueryRow(t.ctx, qTOTPDeclareLost, int32(keyNumber), ids, cts).Scan(&n); err != nil {
			return total, sanitize(err)
		}
		total += n
	}
	return total, nil
}

const qWorkerProviderTemplates = `SELECT gateway_id, key, locale, provider_template_id, param_names FROM ctrlz.sms_provider_templates`

// WorkerProviderTemplate is one mapping of our template to a provider's approved
// copy, as the router needs it.
type WorkerProviderTemplate struct {
	GatewayID          uuid.UUID
	Key                string
	Locale             string
	ProviderTemplateID string
	ParamNames         []string
}

// WorkerProviderTemplates reads every mapping. The worker holds SELECT on the
// table (0011) and nothing more.
func (g GlobalTx) WorkerProviderTemplates() ([]WorkerProviderTemplate, error) {
	rows, err := g.tx.Query(g.ctx, qWorkerProviderTemplates)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []WorkerProviderTemplate
	for rows.Next() {
		var r WorkerProviderTemplate
		if err := rows.Scan(&r.GatewayID, &r.Key, &r.Locale, &r.ProviderTemplateID, &r.ParamNames); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

const qOutboxRetryLater = `UPDATE ctrlz.sms_outbox SET claimed_until = now() + make_interval(secs => $2)
WHERE id = $1 AND state = 'pending'`

// OutboxRetryLater holds a pending message back for a while after a failed
// attempt, by pushing its claim forward. The hour of retries of 9.5 then costs a
// few dozen attempts and not one every twenty seconds.
func (g GlobalTx) OutboxRetryLater(id uuid.UUID, wait time.Duration) error {
	_, err := g.tx.Exec(g.ctx, qOutboxRetryLater, id, wait.Seconds())
	return sanitize(err)
}

const qUnprovenClaims = `SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1 AND state = 'active' AND proven_at IS NULL`

// UnprovenClaims counts the tenant's active claims that were never proven. It is
// the impact of moving registration to open (11.4), which the P1 job reports and
// P3's sweep acts on.
func (t Tx) UnprovenClaims() (int, error) {
	var n int
	if err := t.tx.QueryRow(t.ctx, qUnprovenClaims, t.tenant).Scan(&n); err != nil {
		return 0, sanitize(err)
	}
	return n, nil
}

// sweepTickets and sweepThrottle run the sweep functions of migration 0017 and
// return how many rows they deleted. Two methods and not one that takes the
// statement, because the SQL lint allows constants only.
func (g GlobalTx) sweepTickets(limit int) (int64, error) {
	var n int32
	if err := g.tx.QueryRow(g.ctx, qSweepBatchTickets, int32(limit)).Scan(&n); err != nil {
		return 0, sanitize(err)
	}
	return int64(n), nil
}

func (g GlobalTx) sweepThrottle(limit int) (int64, error) {
	var n int32
	if err := g.tx.QueryRow(g.ctx, qSweepBatchThrottle, int32(limit)).Scan(&n); err != nil {
		return 0, sanitize(err)
	}
	return int64(n), nil
}

// sweepDeliveries runs ctrlz_fn.worker_sweep_sms_deliveries (migration 0020) and
// returns how many rows it deleted, as sweepTickets and sweepThrottle do.
func (g GlobalTx) sweepDeliveries(limit int) (int64, error) {
	var n int32
	if err := g.tx.QueryRow(g.ctx, qSweepBatchDeliveries, int32(limit)).Scan(&n); err != nil {
		return 0, sanitize(err)
	}
	return int64(n), nil
}

// textArg is the SQL argument for a status column: NULL for none, the text for a
// member of its closed set, and ErrConstraint for anything else. A column that names
// a failure takes closed.Text and not a string, so a driver's reply text cannot reach
// it (review round 5, rule closed-values-in-logs).
func textArg(t closed.Text) (any, error) {
	if t == nil {
		return nil, nil
	}
	if !t.Valid() {
		return nil, ErrConstraint
	}
	return emptyNull(t.String()), nil
}

// sweepCounters runs ctrlz_fn.worker_sweep_sms_counters (migration 0035) and returns how many
// raw per-subject rows it deleted. The worker cannot see those rows, so the sweep is a function.
func (g GlobalTx) sweepCounters(limit int) (int64, error) {
	var n int32
	if err := g.tx.QueryRow(g.ctx, qSweepBatchCounters, int32(limit)).Scan(&n); err != nil {
		return 0, sanitize(err)
	}
	return int64(n), nil
}

// sweepOTP runs ctrlz_fn.worker_sweep_otp_challenges (migration 0039) and returns how many
// challenges it deleted. The worker cannot see the decoy rows, so the sweep is a function.
func (g GlobalTx) sweepOTP(limit int) (int64, error) {
	var n int32
	if err := g.tx.QueryRow(g.ctx, qSweepBatchOTP, int32(limit)).Scan(&n); err != nil {
		return 0, sanitize(err)
	}
	return int64(n), nil
}
