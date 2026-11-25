package smssend_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/senders"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/smssend"
)

// Review round 16 of the SMS layer and the worker loops (sms-r16-2, sms-r16-7, sms-r16-8,
// sms-r16-9, and sms-r16-13 as far as it is not the owner's).

// sms-r16-8: the snapshot (and with it the unusable judgement Source.Load writes) used to reload
// only when a send or the start of the worker asked for it, so after the admin saved credentials
// the worker could not open, the flag stayed true until a REAL OTP row made the worker load. Only a
// phone with an account leaves such a row, which made the flag a way to tell a known phone from an
// unknown one. The poll now keeps the snapshot fresh with no row waiting.
func TestTheJudgementOfUnreadableCredentialsIsWrittenByThePollWithNoRowWaiting(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithCancel(r.env.Ctx)
	defer cancel()
	log := slog.New(slog.NewJSONHandler(r.logs, nil))
	src := smssend.NewSource(r.worker, r.ring, senderEnv(r.noopFile), log)
	src.Build = r.build
	router := sms.NewRouter(src, classify.Routing{}, sms.WithRefresh(100*time.Millisecond))
	w, err := smssend.New(smssend.Config{Store: r.worker, Router: router, Keys: r.ring, Log: log, Poll: 30 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = w.Run(ctx) }()
	defer func() { cancel(); <-done }()

	if !r.available() {
		t.Fatal("two working routed gateways read as unavailable")
	}
	// What an admin save of credentials sealed under a key this worker does not hold looks like.
	// No OTP is requested: nothing waits in the queue.
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET credentials_ct = '\x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff' WHERE role IN ('primary', 'fallback')`)
	deadline := time.Now().Add(10 * time.Second)
	for r.available() && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if r.available() {
		t.Fatal("credentials the worker cannot open were not judged while nothing waited in the queue; the flag moves only for a request that leaves a real row")
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.otp_challenges`); n != 0 {
		t.Fatalf("the test made %d challenges, so it proves nothing about an idle queue", n)
	}
}

// sms-r16-2: a judgement is taken back only against the credentials it is about. The row says it
// is unusable for credentials B (written by a worker that cannot open them); a worker that built
// the gateway from OTHER credentials, or a snapshot read before the admin saved B, must not erase
// it.
func TestABuildForOtherCredentialsDoesNotTakeBackAJudgement(t *testing.T) {
	r := newRig(t)
	ctx := r.env.Ctx
	// The row holds credentials whose judgement is "unusable", written for them.
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET unusable_ct_sum = sha256(credentials_ct) WHERE id = $1`, r.priID)
	if r.count(`SELECT count(*) FROM ctrlz.sms_gateways WHERE unusable_ct_sum IS NOT NULL`) != 1 {
		t.Fatal("the judgement was not planted")
	}
	// A worker whose build WORKS for these very credentials takes it back (a key that opens again).
	good := r.newSource(senders.Env{Name: "test"}, r.ring)
	good.Build = r.build
	// The judgement names credentials the row no longer has: the admin saved new ones after it was
	// written. It is inert in the database, and a working build of the NEW credentials leaves it
	// alone (before the fix this write cleared it, and so could erase a judgement written for other
	// credentials a moment later).
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET unusable_ct_sum = sha256('\xdeadbeef'::bytea) WHERE id = $1`, r.priID)
	if _, err := good.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if r.count(`SELECT count(*) FROM ctrlz.sms_gateways WHERE id = $1 AND unusable_ct_sum = sha256('\xdeadbeef'::bytea)`, r.priID) != 1 {
		t.Fatal("a build for credentials the judgement does not name took it back")
	}
	// The judgement for the credentials the build was made from is taken back.
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET unusable_ct_sum = sha256(credentials_ct) WHERE id = $1`, r.priID)
	if _, err := good.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if r.count(`SELECT count(*) FROM ctrlz.sms_gateways WHERE unusable_ct_sum IS NOT NULL`) != 0 {
		t.Fatal("a working build did not take back the judgement of its own credentials")
	}
}

// sms-r16-7: the usable marks are written in gateway id order, the order the record transaction of
// a send takes the same rows in. Load lists the rows by role (fallback before primary) and the
// fallback's id is the larger one, so the two writers used to take the rows in opposite orders. The
// test holds the lock the OTHER order would take first and asks which row the write has already
// locked while it waits: in id order it waits on the smaller id before touching the larger one.
func TestTheUsableMarksTakeTheGatewayRowsInIdOrder(t *testing.T) {
	r := newRig(t)
	ctx := r.env.Ctx
	if r.priID.String() >= r.fbID.String() {
		t.Skip("ids of the two gateways are not in the order the test needs (primary smaller)")
	}
	bad := r.newSource(senders.Env{Name: "test"}, r.ring)
	bad.Build = func(string, secret.Bytes) (sms.Sender, error) {
		return nil, &senders.ErrUnusable{Problem: sms.CodeUnusable}
	}
	super, err := r.env.DB.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(ctx)
	lock, err := super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			_ = lock.Commit(ctx)
		}
	}
	defer release()
	if _, err := lock.Exec(ctx, `SELECT 1 FROM ctrlz.sms_gateways WHERE id = $1 FOR UPDATE`, r.priID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := bad.Load(ctx); done <- err }()

	// Wait until the write is blocked on the primary's row.
	deadline := time.Now().Add(8 * time.Second)
	for r.count(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()`) == 0 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if r.count(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()`) == 0 {
		t.Fatal("the write never waited for the locked row, so the test did not lock what it writes")
	}
	// A writer that has taken the fallback first (role order) holds it now, and this fails.
	probe, err := super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = probe.Exec(ctx, `SELECT 1 FROM ctrlz.sms_gateways WHERE id = $1 FOR UPDATE NOWAIT`, r.fbID)
	_ = probe.Rollback(ctx)
	if err != nil && strings.Contains(err.Error(), "55P03") { // lock_not_available
		t.Error("the write took the fallback's row (the larger id) before the primary's: the order of Load, not the id order of a record transaction")
	} else if err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the load did not finish after the row was released")
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.sms_gateways WHERE unusable_ct_sum IS NOT NULL`); n != 2 {
		t.Fatalf("%d gateways judged unusable, want both", n)
	}
}

// sms-r16-9: an OTP that passed the issue before the day had spent its money cap is not sent once
// it has. The price is added only when a provider accepts, so without the gate in the claim every
// real request of a burst that all passed the issue first was sent and billed, however long the
// queue.
func TestAnOTPQueuedBeforeTheMoneyCapWasReachedIsNotSentAfterIt(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `UPDATE ctrlz.system_settings SET otp_cap_phone = 100, otp_cap_phone_net = 100`)
	a := r.request(r.env.A.Phone)
	b := r.request(r.env.B.Phone)
	// The day has spent the cap before the first of them is claimed: a burst of other messages
	// whose prices landed after these two passed the issue.
	r.env.Exec(t, `UPDATE ctrlz.system_settings SET sms_cost_cap_daily = 5`)
	r.ensureGlobalRow()
	r.env.Exec(t, `UPDATE ctrlz.sms_counters SET cost = 5 WHERE scope = 'global' AND key = 'all'`)
	if n := r.drain(); n != 0 {
		t.Fatalf("a drain handled %d rows with the money cap spent", n)
	}
	if r.pri.count()+r.fb.count() != 0 {
		t.Fatalf("a provider was called %d times with the money cap spent", r.pri.count()+r.fb.count())
	}
	if !r.deliveryCT(a.ID) || !r.deliveryCT(b.ID) {
		t.Fatal("a queued code was cleared although nothing was sent")
	}
	// The cap lifted (the owner raised it): the same rows are sent.
	r.env.Exec(t, `UPDATE ctrlz.system_settings SET sms_cost_cap_daily = NULL`)
	if n := r.drain(); n != 2 {
		t.Fatalf("with room again a drain handled %d rows, want 2", n)
	}
}

// hangingSource never answers a load: the database is out, or a reload is stuck.
type hangingSource struct{}

func (hangingSource) Load(ctx context.Context) (sms.Snapshot, error) {
	<-ctx.Done()
	return sms.Snapshot{}, ctx.Err()
}

// sms-r16-8, failure path: the pass now asks the router for its snapshot, so a snapshot that never
// loads must not keep the worker from stopping (the container is killed after its grace period) and
// the wait is the caller's own context. What the failure says, and how long one pass waits, are
// TestAFailingSnapshotReloadIsSaidOnceWithFixedWords and
// TestAColdSnapshotLoadThatHangsHoldsOnePassForOneSecondOnly.
func TestAHangingSnapshotLoadDoesNotKeepTheWorkerFromStopping(t *testing.T) {
	r := newRig(t)
	router := sms.NewRouter(hangingSource{}, classify.Routing{}, sms.WithRefresh(50*time.Millisecond))
	log := slog.New(slog.NewJSONHandler(r.logs, nil))
	w, err := smssend.New(smssend.Config{Store: r.worker, Router: router, Keys: r.ring, Log: log, Poll: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(r.env.Ctx, 400*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the worker did not stop while its snapshot load was hanging")
	}
}

// failingSource answers every load with an error at once: the database is up but refuses the read.
type failingSource struct{}

func (failingSource) Load(context.Context) (sms.Snapshot, error) {
	return sms.Snapshot{}, errors.New("database refused")
}

// sms-r16-25: a reload that fails is said, by the loader the router is built on, as fixed words
// and at most once a minute. The Warn the worker used to keep for it could never run (the router
// returns only the caller's context error or ErrNoSnapshot), so a snapshot that stopped loading
// was invisible. The line names the cache and the class, never the error text.
func TestAFailingSnapshotReloadIsSaidOnceWithFixedWords(t *testing.T) {
	r := newRig(t)
	log := slog.New(slog.NewJSONHandler(r.logs, nil))
	router := sms.NewRouter(failingSource{}, classify.Routing{}, sms.WithRefresh(10*time.Millisecond), sms.WithLog(log))
	w, err := smssend.New(smssend.Config{Store: r.worker, Router: router, Keys: r.ring, Log: log, Poll: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		smssend.KeepSnapshotFresh(r.env.Ctx, w)
		time.Sleep(20 * time.Millisecond)
	}
	out := r.logs.String()
	if n := strings.Count(out, `"cache refresh failed"`); n != 1 {
		t.Fatalf("a failing reload was said %d times, want once: %s", n, out)
	}
	if !strings.Contains(out, `"cache":"sms_router"`) {
		t.Fatalf("the line does not name the cache: %s", out)
	}
	if strings.Contains(out, "database refused") {
		t.Fatal("the text of the error reached the log")
	}
}

// sms-r16-25: a cold router with a database that hangs makes its first caller wait for the whole
// load (the loader's 10 s timeout). One pass of the poll must not: it waits snapshotPollWait and
// goes on, and the load carries on in the loader for the next pass.
func TestAColdSnapshotLoadThatHangsHoldsOnePassForOneSecondOnly(t *testing.T) {
	r := newRig(t)
	router := sms.NewRouter(hangingSource{}, classify.Routing{})
	w, err := smssend.New(smssend.Config{Store: r.worker, Router: router, Keys: r.ring, Log: slog.New(slog.NewJSONHandler(r.logs, nil)), Poll: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	smssend.KeepSnapshotFresh(r.env.Ctx, w)
	if d := time.Since(start); d > smssend.SnapshotPollWait()+2*time.Second {
		t.Fatalf("one pass waited %v for a cold snapshot load that hangs; the bound is %v", d, smssend.SnapshotPollWait())
	}
}

// sms-r16-18: two live workers with different sms_cred key rings (the overlap of a rolling
// rotation) are each right about their own ring. Before, the one that cannot open the credentials
// wrote the judgement and the one that can took it back on every reload, and since the poll
// reloads with no traffic the public flag flipped on a fixed cadence for the whole overlap. Now the
// worker that finds its write taken back leaves the row to the other.
func TestTwoKeyRingsDoNotWriteAndTakeBackTheJudgementOnEveryReload(t *testing.T) {
	r := newRig(t)
	ctx := r.env.Ctx
	wrong, err := keyring.NewEphemeral(keyring.DomainOTPDelivery, keyring.DomainSMSCred)
	if err != nil {
		t.Fatal(err)
	}
	old := r.newSource(senders.Env{Name: "test"}, wrong)
	old.Build = r.build
	cur := r.newSource(senders.Env{Name: "test"}, r.ring)
	cur.Build = r.build

	judged := func() int {
		return r.count(`SELECT count(*) FROM ctrlz.sms_gateways WHERE unusable_ct_sum IS NOT NULL`)
	}
	load := func(s *smssend.Source) {
		t.Helper()
		if _, err := s.Load(ctx); err != nil {
			t.Fatal(err)
		}
	}
	load(old)
	if judged() != 2 {
		t.Fatalf("the worker that cannot open the credentials judged %d gateways, want both", judged())
	}
	load(cur)
	if judged() != 0 {
		t.Fatal("the worker that opens the credentials did not take the judgement back")
	}
	// Ten more reloads of each, the old one first, as the poll does. The old worker has now seen
	// its write taken back and writes no more; the flap would show as a judgement on the row after
	// any of its loads.
	for i := 0; i < 10; i++ {
		load(old)
		if judged() != 0 {
			t.Fatalf("reload %d: the worker whose ring cannot open the credentials wrote its judgement again after the other took it back", i)
		}
		load(cur)
	}
	if !r.available() {
		t.Fatal("the gateways read as unavailable although a worker can send through them")
	}
	if !strings.Contains(r.logs.String(), "judgement left to a worker whose key ring opens the credentials") {
		t.Fatal("the yield was not said")
	}
	// New credentials are a new judgement: the yield belongs to the old ciphertext only, so an
	// admin save that nobody can open is judged again by the worker that sees it first.
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET credentials_ct = '\x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff' WHERE role IN ('primary', 'fallback')`)
	load(old)
	if judged() != 2 {
		t.Fatalf("new credentials that no worker opens were judged for %d gateways by the old worker, want both", judged())
	}
}

// stubSender is a built sender that is never called: the snapshot only holds it.
type stubSender struct{ sms.Sender }

// sms-r16-24: a working build writes nothing about a gateway whose judgement names OTHER credentials.
// The write that takes a judgement back is conditional on the sum, so it would change nothing, but it
// would still open a transaction on every 30 second reload of every working gateway. The decision is
// the snapshot's, and it needs no database: the marks it returns are the writes the load would make.
func TestAWorkingBuildLeavesAJudgementForOtherCredentialsAlone(t *testing.T) {
	src := smssend.NewSource(nil, nil, senders.Env{Name: "test"}, slog.New(slog.DiscardHandler))
	src.Build = func(string, secret.Bytes) (sms.Sender, error) { return stubSender{}, nil }
	own := sha256.Sum256(nil) // the sum of a gateway with no sealed credentials
	other := sha256.Sum256([]byte("other credentials"))
	for _, c := range []struct {
		name  string
		unfit []byte
		want  int
	}{
		{"no judgement on the row", nil, 0},
		{"a judgement for other credentials", other[:], 0},
		{"a judgement for these credentials, which a working build takes back", own[:], 1},
	} {
		row := store.WorkerGateway{ID: uuid.New(), Provider: "noop", Role: "primary", UnusableCTSum: c.unfit}
		if got := src.UsableMarks([]store.WorkerGateway{row}); got != c.want {
			t.Errorf("%s: %d usable marks, want %d", c.name, got, c.want)
		}
	}
}
