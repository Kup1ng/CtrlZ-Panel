// Package smssend is the worker that sends SMS (spec 9.5). The queue is the
// database: it drains otp_challenges (the codes that auth_otp_issue stored for
// delivery) and sms_outbox (invites and the SMS page's test send), through the
// sms.Router, and writes the outcome back.
//
// What makes it safe to run, restart and crash:
//
//   - A row is claimed for store.OTPClaimLease with FOR UPDATE SKIP LOCKED, so several
//     workers share the queue, and a worker that dies mid-send leaves a claim
//     that lapses. The next pass sends again: a provider may get two messages,
//     and that is accepted over a lost code (18.3).
//   - The send itself runs outside any transaction. A pool connection is never
//     held while a gateway hangs for 6 seconds. The whole send, the wait for the
//     gateway snapshot included, has a budget below the claim (Config.SendBudget), and
//     the budget is cut to what the claim has left when its transaction ends (the database
//     measures it, the last statement of the claim), so a claim always outlasts the send it
//     was taken for even when the transaction waited on another worker (sms-r6-7, sms-r7-8).
//   - At most Concurrency rows are claimed at a time. Each takes at most two
//     gateway calls of 6 seconds, so a claim is never spent waiting for a free
//     goroutine.
//   - There is no wake-up. The worker polls the outbox every Config.Poll (500 ms), because a
//     notification can fail the commit that sends it (db-r15-1), so none is sent or heard.
//
// Nothing here logs a phone number, a code, a credential or a provider reply.
// A log line carries a row id, a provider name, a class and a fixed code.
package smssend

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/closed"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// logSource says which queue a row came from: the value of sms_deliveries.source and
// a log attribute. It is a closed type so a log line can carry it.
type logSource string

const (
	srcOTP    logSource = "otp"
	srcOutbox logSource = "outbox"
)

// Valid reports membership.
func (s logSource) Valid() bool { return s == srcOTP || s == srcOutbox }

const (
	// DefaultSendBudget is the longest one send may take, snapshot wait included: two provider
	// calls of the router's call timeout (6.5 seconds each). A call is started only with CallNeed
	// (6.6 seconds) left, so two CallNeeds are 13.2 seconds and leave 0.8 seconds of the 14, and a
	// budget below 13.2 seconds cannot reach the fallback behind a hanging primary. The claim lease
	// is 20 seconds, so the record that follows has the rest of the lease before another worker may
	// claim the row (sms-r6-7, sms-r9-10).
	DefaultSendBudget = 14 * time.Second

	// recordBudget bounds the transaction that records an accepted send while the worker is
	// running. It is above lock_timeout (5 s in production, 10 s on the roles) so a wait on the
	// global counter row that every issue holds cannot take the accept with it: a record that
	// times out leaves the code sealed, the claim lapses and the code is sent again and billed
	// again without its price reaching the money counter (sms-r6-6).
	recordBudget = store.RecordBudget

	// shutdownRecordBudget is all the time the record of an accepted send gets once the worker
	// was told to stop: the process is leaving, and a long wait would only hold the stop. A
	// record that does not fit is the documented duplicate (18.3).
	shutdownRecordBudget = 3 * time.Second

	// leaseMargin is what a send leaves of the claim lease for the record that follows it. A send
	// is bounded by the lease the database says is left, minus this, and never by more than the
	// configured budget: the claim transaction keeps going after the lease is stamped (gates,
	// alerts, each of which can wait on another worker), and the budget alone was only right when
	// nothing waited (sms-r7-3, sms-r7-8).
	leaseMargin = store.OTPClaimLease - DefaultSendBudget
)

// errLeaseSpent says the claim has so little lease left that a send could end after another
// worker may claim the row. Nothing is sent: the lease lapses and the next claim does it (the
// attempt is used, and a row that uses all its claims is ended and refunded as usual).
var errLeaseSpent = errors.New("smssend: the claim lease is spent")

// sendBudgetWithin is the time one send may take when the claim has left of its lease: the
// configured budget, or less when the claim transaction used lease time. It is zero or negative
// when no send fits.
func sendBudgetWithin(budget, left time.Duration) time.Duration {
	if room := left - leaseMargin; room < budget {
		return room
	}
	return budget
}

// Config builds a Worker.
type Config struct {
	Store  *store.Store // opened as ctrlz_worker
	Router *sms.Router
	Keys   *keyring.Ring // must hold otp_delivery and sms_cred
	Log    *slog.Logger

	Concurrency int           // goroutines, and rows claimed per pass; default 4
	Poll        time.Duration // how often the outbox is looked at; default 500 ms (there is no wake-up, see Run)
	MaxAttempts int           // OTP attempts before the row is given up; default 3
	Now         func() time.Time

	// SendBudget bounds one send from the moment the worker asks the router: the wait for the
	// gateway snapshot and every provider call. Default DefaultSendBudget; it must stay under
	// store.OTPClaimLease, or another worker could claim a row that is still being sent.
	SendBudget time.Duration

	// BeforeRecord, when set, runs after a gateway accepted a message and before the
	// transaction that records it. It exists for tests, which cancel the worker's
	// context from here to prove that recording an accepted send does not depend on it
	// (sms-r5-3). Production leaves it nil.
	BeforeRecord func()

	// OnSendBudget, when set, is told the budget each send was given after the lease the claim had
	// left was taken into account. It exists for tests of sms-r7-8. Production leaves it nil.
	OnSendBudget func(time.Duration)

	// RecordRetryPause is the pause before the first retry of a record transaction that met a
	// condition a repeat can cure; it doubles each time. Default 100 ms. It exists for tests.
	RecordRetryPause time.Duration
}

// Worker drains the SMS queue.
type Worker struct {
	db         *store.Store
	router     *sms.Router
	keys       *keyring.Ring
	log        *slog.Logger
	conc       int
	poll       time.Duration
	maxTry     int
	now        func() time.Time
	budget     time.Duration
	retryPause time.Duration // the pause before the first retry of a record; see recordTx

	// holds writes the hold or the lifting an attempt asks for, in the record transaction. It is the
	// router's source when that source can keep holds (Source does), and nil when it cannot, which
	// is the behaviour before the hold existed: every send asks again.
	holds holdRecorder

	beforeRecord func()              // Config.BeforeRecord; may be nil
	onSendBudget func(time.Duration) // Config.OnSendBudget; may be nil
}

// holdRecorder is what a source implements to keep the holds of the attempts it is given (Source).
type holdRecorder interface {
	RecordHold(g store.GlobalTx, a sms.Attempt) error
}

// New returns a Worker. The key ring must hold both domains the worker uses.
func New(c Config) (*Worker, error) {
	if c.Store == nil || c.Router == nil || c.Keys == nil || c.Log == nil {
		return nil, errors.New("smssend: store, router, keys and log are required")
	}
	if err := c.Keys.Require(keyring.DomainOTPDelivery, keyring.DomainSMSCred); err != nil {
		return nil, err
	}
	w := &Worker{db: c.Store, router: c.Router, keys: c.Keys, log: c.Log, conc: c.Concurrency, poll: c.Poll, maxTry: c.MaxAttempts, now: c.Now, beforeRecord: c.BeforeRecord, onSendBudget: c.OnSendBudget, retryPause: c.RecordRetryPause}
	w.holds, _ = c.Router.Source().(holdRecorder)
	if w.conc < 1 {
		w.conc = 4
	}
	if w.poll <= 0 {
		w.poll = 500 * time.Millisecond
	}
	if w.maxTry < 1 {
		w.maxTry = 3
	}
	if w.retryPause <= 0 {
		w.retryPause = defaultRecordRetryPause
	}
	if w.now == nil {
		w.now = time.Now
	}
	w.budget = c.SendBudget
	if w.budget <= 0 {
		w.budget = DefaultSendBudget
	}
	if w.budget >= store.OTPClaimLease {
		return nil, errors.New("smssend: the send budget must be shorter than the claim lease")
	}
	return w, nil
}

// Run drains the queue until ctx ends, once at start and then every poll interval. It is a poll and
// nothing else: the worker does not LISTEN, and nothing sends it a NOTIFY, because Postgres has no
// privilege for either and one session that stops reading fills the cluster's notification queue and
// fails every transaction that notified, the issue of an OTP among them (db-r15-1, db-r15-6). The
// interval is the added latency of an OTP; a pass with nothing waiting is one indexed claim query.
func (w *Worker) Run(ctx context.Context) error {
	w.checkGateways(ctx)
	w.drainLogged(ctx)
	tick := time.NewTicker(w.poll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		w.drainLogged(ctx)
	}
}

func (w *Worker) drainLogged(ctx context.Context) {
	n, err := w.Drain(ctx)
	if err != nil && ctx.Err() == nil {
		w.log.Warn("sms drain failed", logattr.Enum("error_class", errClass(err)))
	}
	if n > 0 {
		w.log.Info("sms drained", logattr.Int("rows", n))
	}
}

// errClass names the kind of a store error for a log line, never its text.
func errClass(err error) logattr.ErrClass {
	switch {
	case errors.Is(err, store.ErrConnection):
		return logattr.ErrConnection
	case errors.Is(err, store.ErrRetry):
		return logattr.ErrRetry
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		// A record shortened by a stop ends Canceled, one that used its budget DeadlineExceeded;
		// both say it ran out of time (sms-r8-1).
		return logattr.ErrTimeout
	}
	return logattr.ErrOther
}

// Drain sends what is waiting and returns how many rows it handled. A row that
// fails but may be retried counts too: it was handled once.
func (w *Worker) Drain(ctx context.Context) (int, error) {
	total := 0
	for ctx.Err() == nil {
		otps, outs, ended, leaseEnd, err := w.claim(ctx)
		if err != nil {
			return total, err
		}
		// Rows the claim itself ended (over a cap, out of attempts) count as
		// handled, and a pass that only ended rows looks again: more may wait.
		total += ended
		if len(otps)+len(outs) == 0 {
			if ended == 0 {
				return total, nil
			}
			continue
		}
		var wg sync.WaitGroup
		for _, d := range otps {
			wg.Add(1)
			go func() {
				defer wg.Done()
				w.otp(ctx, d, leaseEnd)
			}()
		}
		for _, o := range outs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				w.outbox(ctx, o, leaseEnd)
			}()
		}
		wg.Wait()
		total += len(otps) + len(outs)
	}
	return total, nil
}

// claim takes up to Concurrency rows in one transaction, leaving at least one
// slot for the outbox so invites are not starved by a stream of codes. ended
// counts the rows the transaction itself finished.
//
// Three things happen here and not later, because each must commit together
// with the claim:
//   - OTPs that used all their claims are closed and refunded, so a row whose
//     record transaction keeps failing is not sent again (OTPClaim skips it).
//   - An outbox message on its first claim is counted against the daily cap. The
//     count and the attempt number are one commit, so a crash between "claimed"
//     and "counted" cannot leave a message that is sent without ever counting.
//   - A first-attempt message over the count or the money cap is ended here.
func (w *Worker) claim(ctx context.Context) (otps []store.OTPDelivery, outs []store.OutboxItem, ended int, leaseEnd time.Time, err error) {
	var exhausted int
	err = w.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		// Store.run runs the function once and never again, so nothing here retries the claim: a
		// failed claim is simply the next poll. The reset below is for the day a caller retries it.
		otps, outs, ended, exhausted = nil, nil, 0, 0
		var err error
		if exhausted, err = g.OTPEndExhausted(w.maxTry); err != nil {
			return err
		}
		ended = exhausted
		otpLimit := w.conc - 1
		if otpLimit < 1 {
			otpLimit = 1
		}
		if otps, err = g.OTPClaim(otpLimit, w.maxTry); err != nil {
			return err
		}
		room := w.conc - len(otps)
		if room < 1 {
			room = 1
		}
		claimed, err := g.OutboxClaim(room)
		if err != nil {
			return err
		}
		for _, it := range claimed {
			// The gate is one conditional statement and its row is the leave to send
			// (rule caps-and-endings). A first claim counts the message against the
			// daily count and the money cap; a retry was counted when it was first
			// claimed, so only the money cap is compared again, against what the day
			// has spent by now.
			gate, err := w.gate(g, it)
			if err != nil {
				return err
			}
			if gate.Yes() {
				outs = append(outs, it)
				continue
			}
			ending, err := g.OutboxFinish(it.ID, "failed", sms.CodeCap)
			if err != nil {
				return err
			}
			if !ending.Yes() {
				continue // another actor ended it first; the count and the alert are theirs
			}
			if _, err := g.AlertOnce("warning", "sms_outbox_cap", w.hourKey(), sms.ReasonParams(sms.CodeCap)); err != nil {
				return err
			}
			ended++
		}
		// The last statement of the transaction (sms-r7-3, sms-r7-8): the gates and the alerts above
		// can each wait on another worker's claim, and the lease the two claim statements stamped
		// has been running all that time. Ask the database what is left now, so that the send is
		// bounded by that and nothing can wait between this answer and the commit. The instant is
		// taken before the question, so the round trip counts against the send, not for it.
		leaseEnd = time.Time{}
		if len(otps)+len(outs) == 0 {
			return nil
		}
		var otpIDs, outIDs []uuid.UUID
		for _, d := range otps {
			otpIDs = append(otpIDs, d.ID)
		}
		for _, o := range outs {
			outIDs = append(outIDs, o.ID)
		}
		asked := time.Now()
		left, err := g.ClaimLeaseLeft(otpIDs, outIDs)
		if err != nil {
			return err
		}
		leaseEnd = asked.Add(left)
		return nil
	})
	if err != nil {
		return nil, nil, 0, time.Time{}, err
	}
	if exhausted > 0 {
		// A count, never a phone or a code: it shows an operator a record
		// transaction that keeps failing.
		w.log.Warn("sms otp rows ended after their last claim", logattr.Int("rows", exhausted))
	}
	return otps, outs, ended, leaseEnd, nil
}

// gate asks the database for the leave to send one outbox message.
func (w *Worker) gate(g store.GlobalTx, it store.OutboxItem) (store.Won, error) {
	if it.Attempts > 1 {
		return g.OutboxRetryGate()
	}
	return g.OutboxFirstGate()
}

// ---------------------------------------------------------------------------
// OTP

// otp sends one code.
func (w *Worker) otp(ctx context.Context, d store.OTPDelivery, leaseEnd time.Time) {
	del, err := sms.OpenOTP(w.keys, d.Phone, d.Purpose, d.DeliveryCT)
	if err != nil {
		// A key that no longer opens the row, or a payload of the wrong shape. No
		// gateway can do anything about it, so the row ends here and gives its
		// caps back. Nothing of the ciphertext or the phone is logged.
		w.log.Error("otp delivery unreadable", logattr.ID("challenge", d.ID))
		w.endOTPUnsent(ctx, d, sms.CodeUnreadable)
		return
	}
	out, spent, err := w.send(ctx, leaseEnd, sms.Request{To: d.Phone, Template: del.Template, Locale: del.Locale, Value: del.Code})
	if _, ok := out.Accepted(); ok {
		// A gateway accepted the code, so it is recorded whatever ctx says, now or a
		// millisecond from now: the provider has billed it, and a record lost to a
		// shutdown that arrives after any check of ctx makes the next worker send the
		// same code again (sms-r5-3). The decision depends on the outcome alone and
		// never on ctx, so there is no window between a check and the transaction.
		if w.beforeRecord != nil {
			w.beforeRecord()
		}
		rctx, cancel := detached(ctx)
		defer cancel()
		w.finishOTP(rctx, d, del.Template, out)
		return
	}
	switch {
	case errors.Is(err, errLeaseSpent):
		w.log.Warn("sms claim lease spent before the send", logattr.ID("challenge", d.ID))
		return
	case ctx.Err() != nil:
		// Shutting down, and nothing was accepted: the claim lapses and the next
		// worker tries again.
		return
	case errors.Is(err, sms.ErrBadRequest):
		w.log.Error("otp payload not sendable", logattr.ID("challenge", d.ID))
		w.endOTPUnsent(ctx, d, sms.CodeBadPayload)
		return
	case spent:
		// The budget ran out. What was attempted is recorded as it was, and the gateway
		// that was cut off counts as one that was not asked (a refused number answered by
		// the primary alone is not yet a verdict of every route).
	case err != nil:
		// The gateways have never loaded. It is a failed attempt like any other
		// that sent nothing: counted by the claim, retried until the third.
		out = sms.Outcome{}
	}
	w.finishOTP(ctx, d, del.Template, out)
}

// finishOTP records the attempts and, when the row is finished, clears the code.
//
// A row is finished when a gateway accepted it, when the number itself was
// refused (no other gateway would change that: Recipient, or Blacklisted by
// every gateway asked), or on the third attempt (9.5).
// An unfinished row is simply left: its claim lapses in 20 seconds and the next
// pass tries again.
func (w *Worker) finishOTP(ctx context.Context, d store.OTPDelivery, template string, out sms.Outcome) {
	accepted, ok := out.Accepted()
	refused := classify.NumberRefused(out)
	terminal := ok || refused || d.Attempts >= w.maxTry

	err := w.recordTx(ctx, func(g store.GlobalTx) error {
		// The order of the statements is the lock order of internal/lockrank, and
		// not the order of the story: the code row, the gateway rows, the counters,
		// then the delivery log and the alerts. A transaction that logged first and
		// cleared after would hold a gateway row while it waited for a code row
		// (spec 4.4). The refund no longer reads the breakers (it is the global key and
		// nothing else), so the order is the rank's and no longer the refund's.
		var cleared store.Won
		if terminal {
			var err error
			if cleared, err = g.OTPDeliveryClear(d.ID); err != nil {
				return err
			}
		}
		if err := w.recordGateways(g, out); err != nil {
			return err
		}
		unsent, err := w.settleOTP(g, d, accepted, ok, refused, terminal, cleared)
		if err != nil {
			return err
		}
		if err := w.recordLog(g, srcOTP, d.ID, template, out); err != nil {
			return err
		}
		if unsent {
			// A row that ended unsent after only transient failures is an outage.
			if down, ok := classify.Down(out); ok {
				return w.raise(g, down)
			}
		}
		return nil
	})
	w.afterRecord(ctx, srcOTP, d.ID, out, err)
}

// settleOTP settles the counters of a finished row whose code is cleared. It
// reports whether this call ended the row unsent for a reason that is an outage (not a
// refused number) and refunded it, so that the caller can raise the sms_down alert that
// goes with that, which is last.
func (w *Worker) settleOTP(g store.GlobalTx, d store.OTPDelivery, accepted sms.Attempt, ok, refused, terminal bool, cleared store.Won) (unsent bool, err error) {
	if !terminal {
		return false, nil
	}
	if ok {
		// The provider charged for it whoever finished the row, so the money
		// counter always gets the price.
		return false, w.addCost(g, accepted)
	}
	if !cleared.Yes() {
		// The sweep (or a worker whose claim lapsed) already ended this row and
		// gave its key back. A second refund would open a slot on the shared
		// global counter for nothing.
		return false, nil
	}
	// Nothing was delivered. refundOTP gives back the global key whatever ended the
	// row, a refused number included: the per-phone caps stay spent and are what stops
	// a refused number from being tried without limit, and the global key is the one
	// counter a decoy never moves, so leaving it spent for this ending alone would
	// tell a phone with an account from one without (sms-r5-2, spec 18.5).
	if err := w.refundOTP(g, d); err != nil {
		return false, err
	}
	// A refused number is the user's, not an outage: no sms_down for it.
	return !refused, nil
}

// endOTPUnsent finishes a row that could not be sent at all: clear the code,
// give the caps back, say why in the delivery log and raise an alert.
func (w *Worker) endOTPUnsent(ctx context.Context, d store.OTPDelivery, reason sms.Code) {
	err := w.recordTx(ctx, func(g store.GlobalTx) error {
		cleared, err := g.OTPDeliveryClear(d.ID)
		if err != nil {
			return err
		}
		// The delivery log before the counters: its gateway column shares the gateway
		// row, which ranks below the counters (internal/lockrank).
		if err := g.DeliveryRecord(store.SMSDelivery{
			Source: string(srcOTP), SourceID: d.ID, Provider: sms.ProviderNone.String(), TemplateKey: sms.TemplateUnknown.String(), Outcome: "unreachable", ProviderState: reason,
		}); err != nil {
			return err
		}
		if cleared.Yes() { // only the call that ended the row refunds it
			if err := w.refundOTP(g, d); err != nil {
				return err
			}
		}
		_, err = g.AlertOnce("critical", "sms_payload", closed.NewKey(sms.KeyOTP, reason), sms.ReasonParams(reason))
		return err
	})
	if err != nil && ctx.Err() == nil {
		w.log.Warn("sms record failed", logattr.Enum("source", srcOTP), logattr.ID("challenge", d.ID), logattr.Enum("error_class", errClass(err)))
	}
}

// ---------------------------------------------------------------------------
// Outbox

// outbox sends one queued message (an invite, or a test).
func (w *Worker) outbox(ctx context.Context, it store.OutboxItem, leaseEnd time.Time) {
	// The daily count and the money cap were applied by the gate in the claim (claim): a
	// retry is the same message, and counting it again would let an hour of outage use
	// up the day's allowance, while its money cap is compared again on every claim,
	// since the day's spending moves. Nothing is checked here: a message that reaches
	// this point holds the gate's leave.
	value, err := sms.OpenOutbox(w.keys, it.ID, it.Phone, it.ParamsCT)
	if err != nil {
		w.log.Error("sms outbox params unreadable", logattr.ID("outbox", it.ID))
		w.endOutbox(ctx, it, sms.CodeUnreadable)
		return
	}
	out, spent, err := w.send(ctx, leaseEnd, sms.Request{To: it.Phone, Template: it.TemplateKey, Locale: it.Locale, Value: value, Gateway: it.GatewayID})
	if _, ok := out.Accepted(); ok { // see otp()
		if w.beforeRecord != nil {
			w.beforeRecord()
		}
		rctx, cancel := detached(ctx)
		defer cancel()
		w.finishOutbox(rctx, it, out)
		return
	}
	switch {
	case errors.Is(err, errLeaseSpent):
		w.log.Warn("sms claim lease spent before the send", logattr.ID("outbox", it.ID))
		return
	case ctx.Err() != nil:
		return
	case errors.Is(err, sms.ErrBadRequest):
		w.endOutbox(ctx, it, sms.CodeBadPayload)
		return
	case spent: // see otp()
	case err != nil:
		out = sms.Outcome{}
	}
	w.finishOutbox(ctx, it, out)
}

// send runs one send inside the worker's budget. The budget covers everything the router
// does, the wait for a snapshot after an Invalidate included (a reload may take its own
// 10 seconds and the router waits for it without a limit), so the lease of the claim
// outlasts the send whatever the database does (sms-r6-7). spent says the budget, and not
// the worker's context, ended the send: the attempts made before it are the outcome, and
// the one that was cut off is counted as a gateway that was not asked.
func (w *Worker) send(ctx context.Context, leaseEnd time.Time, req sms.Request) (out sms.Outcome, spent bool, err error) {
	// The budget is what the claim has left of its lease, as the database measured it at the end
	// of the claim transaction (sms-r7-3, sms-r7-8), and never more than the configured one.
	budget := sendBudgetWithin(w.budget, time.Until(leaseEnd))
	if w.onSendBudget != nil {
		w.onSendBudget(budget)
	}
	// A budget that cannot finish one provider call sends nothing: a call the budget cut would
	// leave an accepted message unrecorded or a hanging gateway uncounted (sms-r8-5). The lease
	// lapses and the next claim does it; the claim already used one attempt, so a row that keeps
	// meeting this is ended and refunded like any other that uses all its claims.
	if budget < w.router.CallNeed() {
		return sms.Outcome{}, false, errLeaseSpent
	}
	sctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	out, err = w.router.Send(sctx, req)
	switch {
	case err != nil && ctx.Err() == nil && errors.Is(err, sms.ErrNoTime):
		// The router stopped for lack of time and counted the gateways it did not ask.
		return out, true, err
	case err != nil && ctx.Err() == nil && sctx.Err() != nil:
		// The budget ended while the send waited for the gateway snapshot.
		out.Skipped++
		return out, true, err
	}
	return out, false, err
}

func (w *Worker) finishOutbox(ctx context.Context, it store.OutboxItem, out sms.Outcome) {
	accepted, ok := out.Accepted()
	// A test send answers once: the operator is waiting for it, and a retry for
	// an hour would only hide the result. An invite is retried until the sweep
	// ends it at the hour (9.5).
	pinned := it.GatewayID != uuid.Nil
	terminal := ok || classify.NumberRefused(out) || pinned

	err := w.recordTx(ctx, func(g store.GlobalTx) error {
		// Outbox row, gateway rows, counters, then the delivery log and the alerts:
		// the lock order of internal/lockrank, which the story order (log first) is
		// not.
		switch {
		case ok || terminal:
			state := "sent"
			var lastError closed.Text // nil for a sent message
			if !ok {
				state, lastError = "failed", out.Last().Status()
			}
			ending, err := g.OutboxFinish(it.ID, state, lastError)
			if err != nil {
				return err
			}
			if !ending.Yes() {
				// The stale sweep (or an earlier finish) ended the row first and its state
				// stands. What the provider did is still recorded below, and an accepted
				// message is still charged: the provider billed it whoever ended the row.
				w.log.Warn("sms outbox row was already ended", logattr.ID("outbox", it.ID))
			}
		default:
			if err := g.OutboxRetryLater(it.ID, backoff(it.Attempts)); err != nil {
				return err
			}
		}
		if err := w.recordGateways(g, out); err != nil {
			return err
		}
		if ok {
			if err := w.addCost(g, accepted); err != nil {
				return err
			}
		}
		return w.recordLog(g, srcOutbox, it.ID, it.TemplateKey, out)
	})
	w.afterRecord(ctx, srcOutbox, it.ID, out, err)
}

// endOutbox finishes a message that was not sent at all.
func (w *Worker) endOutbox(ctx context.Context, it store.OutboxItem, reason sms.Code) {
	err := w.recordTx(ctx, func(g store.GlobalTx) error {
		ending, err := g.OutboxFinish(it.ID, "failed", sms.StatusOf(reason))
		if err != nil {
			return err
		}
		if !ending.Yes() {
			return nil // another actor ended it first; the alert is the ender's
		}
		_, err = g.AlertOnce("warning", "sms_payload", closed.NewKey(sms.KeyOutbox, reason), sms.ReasonParams(reason))
		return err
	})
	if err != nil && ctx.Err() == nil {
		w.log.Warn("sms record failed", logattr.Enum("source", srcOutbox), logattr.ID("outbox", it.ID), logattr.Enum("error_class", errClass(err)))
	}
}

// backoff is the pause after a failed attempt of an outbox message: 30 seconds,
// doubling to 5 minutes.
func backoff(attempts int) time.Duration {
	d := 30 * time.Second
	for i := 1; i < attempts && d < 5*time.Minute; i++ {
		d *= 2
	}
	if d > 5*time.Minute {
		d = 5 * time.Minute
	}
	return d
}

// hourKey makes the alert key of a capped message change every hour, so the
// unique index on open alerts lets one through per hour and no more (9.5).
func (w *Worker) hourKey() closed.Key {
	return closed.NewKey(sms.KeyCap, closed.HourOf(w.now()))
}

// ---------------------------------------------------------------------------
// Shared bookkeeping

// recordGateways writes what the attempts of one send mean for the gateway rows:
// a success closes a breaker, a failure counts toward opening it. recordLog does
// the delivery log and the alerts. Both run in the transaction that also finishes
// the row, so a delivery cannot be logged without its outcome or the reverse.
func (w *Worker) recordGateways(g store.GlobalTx, out sms.Outcome) error {
	// The gateway rows in id order, not attempt by attempt: a worker that failed
	// over from gateway A to B locked A and then B, while another worker that went
	// B then A did the opposite (internal/lockrank, spec 4.4).
	byGateway := append([]sms.Attempt(nil), out.Attempts...)
	sort.SliceStable(byGateway, func(i, j int) bool {
		return bytes.Compare(byGateway[i].Gateway[:], byGateway[j].Gateway[:]) < 0
	})
	for _, a := range byGateway {
		if a.Accepted() {
			if err := g.GatewayOK(a.Gateway); err != nil {
				return err
			}
		} else {
			stepped, err := g.GatewayFailed(a.Gateway, a.Err.Status(), classify.CountsTowardBreaker(a))
			if err != nil {
				return err
			}
			if stepped.Yes() {
				w.log.Info("sms gateway breaker moved one step", logattr.ID("gateway", a.Gateway))
			}
		}
		// The hold of a refused login, or its lifting by an accepted test send, is written here, on
		// the row this transaction has just locked, and not by the router between two gateways
		// (sms-r13-2, sms-r13-5).
		if w.holds != nil {
			if err := w.holds.RecordHold(g, a); err != nil {
				return err
			}
		}
	}
	return nil
}

// recordLog writes the delivery log and raises the alerts of the attempts. It
// runs after recordGateways and the counters (the delivery rows only share the
// gateway row, and the alerts rank last).
func (w *Worker) recordLog(g store.GlobalTx, source logSource, id uuid.UUID, template string, out sms.Outcome) error {
	for _, a := range out.Attempts {
		if a.Accepted() {
			if err := g.DeliveryRecord(store.SMSDelivery{
				Source: string(source), SourceID: id, GatewayID: a.Gateway, Provider: a.Provider, TemplateKey: template,
				Outcome: "accepted", ProviderState: sms.CodeOK, ProviderMsgID: a.Result.ProviderID.String(), CostRaw: a.Result.CostRaw.String(),
				LatencyMS: int(a.Latency / time.Millisecond),
			}); err != nil {
				return err
			}
			continue
		}
		if !a.Local {
			if err := g.DeliveryRecord(store.SMSDelivery{
				Source: string(source), SourceID: id, GatewayID: a.Gateway, Provider: a.Provider, TemplateKey: template,
				Outcome: classify.DeliveryOutcome(a), ProviderState: a.Err.Code, LatencyMS: int(a.Latency / time.Millisecond),
			}); err != nil {
				return err
			}
		}
	}
	// The alerts the failures raise, severity and key included, are classify's: one open
	// alert per key (alerts_open_key_uq); an operator's ack closes it and the next
	// failure opens a new one.
	for _, al := range classify.Alerts(out, sms.ParseTemplate(template)) {
		if err := w.raise(g, al); err != nil {
			return err
		}
	}
	return nil
}

// raise writes one alert the classification decided on.
func (w *Worker) raise(g store.GlobalTx, a classify.Alert) error {
	_, err := g.AlertOnce(a.Severity, a.Kind, a.Key, a.Params)
	return err
}

// addCost adds the accepted gateway's configured price to the day's money
// counter, which the cap of 9.6 reads. Without a price nothing is added: the
// provider's own cost field has an unconfirmed unit and is not summed.
func (w *Worker) addCost(g store.GlobalTx, a sms.Attempt) error {
	if a.Price == nil {
		return nil
	}
	return g.CountersAddCost(*a.Price)
}

// afterRecord logs the result of a record transaction and tells the router to
// look at the gateways again, because the transaction may have opened a breaker.
func (w *Worker) afterRecord(ctx context.Context, source logSource, id uuid.UUID, out sms.Outcome, err error) {
	if err != nil {
		// An accepted send whose record failed is the one failure these paths exist to prevent:
		// the provider has the message, the claim lapses and the row is sent and billed again, with
		// its price never added to the money counter. It is logged whatever the context says. The
		// context that reaches here is the record's own (detached), and a record that ran out of
		// its budget, the shortened one after a stop included, has an ended context, so a check of
		// it would hide exactly the failure to trace (sms-r8-1). Only a record that carried no
		// accept is quiet when the worker's own shutdown cancelled it: nothing was sent, and the
		// next claim does it.
		if _, accepted := out.Accepted(); accepted {
			w.log.Warn("sms accepted send was not recorded", logattr.Enum("source", source), logattr.ID("id", id), logattr.Enum("error_class", errClass(err)))
		} else if ctx.Err() == nil {
			// Nothing was accepted: the claim lapses and the row is tried again, which is the
			// ordinary path of a failed record (18.3).
			w.log.Warn("sms record failed", logattr.Enum("source", source), logattr.ID("id", id), logattr.Enum("error_class", errClass(err)))
		}
		return
	}
	// A pinned send ignores the breaker, so even an accepted one can have closed
	// the breaker of a gateway whose snapshot still says "open" (GatewayOK). Routed
	// traffic would keep skipping it until the next reload, while sms_available
	// already reads true (sms-r4-1).
	if out.Pinned {
		w.router.Invalidate()
	}
	for _, a := range out.Attempts {
		if !a.Accepted() {
			w.router.Invalidate()
			break
		}
	}
	for _, a := range out.Attempts {
		if a.Accepted() {
			w.log.Info("sms sent", logattr.Enum("source", source), logattr.ID("id", id), logattr.Enum("provider", sms.ParseProvider(a.Provider)))
		} else {
			w.log.Info("sms attempt failed", logattr.Enum("source", source), logattr.ID("id", id), logattr.Enum("provider", a.Err.Provider),
				logattr.Enum("scope", classify.ScopeOf(a.Err).Name()), logattr.Enum("code", a.Err.Code))
		}
	}
}

// refundOTP gives back the counter of a row that ended without a message. It is the
// only place the worker refunds an unsent OTP, and it asks nothing: not the answer that
// ended the row, not the attempts, not sms_available.
//
// What goes back is the world-wide slot, and the store's statement says which row in its own
// text. auth_otp_issue bumps ip, phone_net and phone for every request, a decoy included, and
// global for a real code only, and a decoy is never delivered and so never refunded. Any
// refund of the other keys, under any condition, leaves a real phone's counters below an
// unknown phone's and the 429 of spec 5.3 tells them apart. Rounds 3 to 6 each found one more
// way to get the list wrong, so the worker has no list to build (rule known-unknown-oracle).
func (w *Worker) refundOTP(g store.GlobalTx, d store.OTPDelivery) error {
	return g.CountersRefund(d.CreatedAt)
}

// detached gives a context that survives the cancellation of ctx, for recording a send that
// a gateway has already accepted. While the worker runs it has recordBudget, longer than any
// lock wait the record can meet; once the worker was told to stop it has a few seconds, so a
// stop is not held up. While the worker runs, the record of an accept is not bounded by
// something shorter than the lock_timeout of the database, which is what made a busy counter
// row turn an accepted send into a second send (sms-r6-6). A stop that arrives during the record
// shortens it too (sms-r7-9).
func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordBudget)
	// The stop can arrive while the record is already waiting, and a budget chosen once at the
	// start would hold the process for the whole of recordBudget: the container is killed after
	// its own grace period and the record rolls back with it, which is the duplicate the short
	// budget exists to avoid (sms-r7-9). So the stop shortens the record to the shutdown budget,
	// counted from the moment it is seen (at once when ctx is already stopped).
	var (
		mu    sync.Mutex
		timer *time.Timer
		done  bool
	)
	stop := context.AfterFunc(ctx, func() {
		mu.Lock()
		defer mu.Unlock()
		if !done {
			timer = time.AfterFunc(shutdownRecordBudget, cancel)
		}
	})
	return rctx, func() {
		stop()
		mu.Lock()
		done = true
		if timer != nil {
			timer.Stop()
		}
		mu.Unlock()
		cancel()
	}
}

// checkGateways raises the alert for a routed gateway that cannot be used (a
// noop row left in production, credentials that no longer open) at start, and
// not on the first user's request. It is the same alert, with the same key, that
// a failed attempt raises, so the two never double. A snapshot that cannot be
// loaded is not an error here: the first send tries again.
func (w *Worker) checkGateways(ctx context.Context) {
	gws, err := w.router.Gateways(ctx)
	if err != nil {
		if ctx.Err() == nil {
			w.log.Warn("sms gateways not loaded at start", logattr.Enum("error_class", errClass(err)))
		}
		return
	}
	for _, gw := range gws {
		if (gw.Role != "primary" && gw.Role != "fallback") || gw.Sender != nil {
			continue
		}
		// The attempt a send would have made through this gateway, so that the breaker
		// step and the alert are the ones a real failure would produce, from the same
		// classification.
		attempt := gw.ProblemAttempt()
		e := attempt.Err
		out := sms.Outcome{Attempts: []sms.Attempt{attempt}}
		w.log.Warn("sms gateway with a role cannot be used", logattr.ID("gateway", gw.ID), logattr.Enum("provider", e.Provider), logattr.Enum("problem", e.Code))
		err := w.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			// Nothing can be sent through this gateway, so its breaker opens at
			// once (the third failure; later ones change nothing while it is
			// open). Otherwise sms_available stays true after a bad key restore
			// until some user has asked for three codes that never arrive
			// (sms-r2-2). A fixed key closes it again on the first accepted send
			// after the pause. The breaker alone is not what keeps the login page
			// off, though: it lapses, and nothing re-steps it for a gateway that
			// cannot build a sender. Source.Load writes that judgement into the row
			// (unusable_ct_sum, read as blocked_now by auth_public_config), so the
			// flag stays false through every pause (sms-r15-1, sms-r15-4).
			counts := classify.CountsTowardBreaker(attempt)
			for i := 0; i < 3; i++ {
				stepped, err := g.GatewayFailed(gw.ID, e.Status(), counts)
				if err != nil {
					return err
				}
				if !stepped.Yes() {
					break // the breaker is already open: more failures change nothing
				}
			}
			for _, al := range classify.Alerts(out, sms.TemplateUnknown) {
				if err := w.raise(g, al); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil && ctx.Err() == nil {
			w.log.Warn("sms alert failed", logattr.Enum("error_class", errClass(err)))
		}
	}
}
