// Package hubtel is the hub's intake of what nodes report (p4-nodes 5.3, 5.4, 5.7 L6 and L10, 5.8): the Heartbeat fields
// written every 30 s, quarantine rows, the clock-skew alert, ReportActivity and its hourly write, ProofObservation,
// LearnedIP and the free part of UploadCounters.
//
// Rules this package keeps, each where it is cheapest to see:
//
//   - The reader of a Control stream never waits on Postgres (L10). Offer only counts, compares and queues; every database
//     write runs on a goroutine of this package, on the telemetry pool or the outside pool it was given (5.7).
//   - Every message is judged by the pair rule before any write (R18): a report from a node outside the Endpoint's current
//     pair, or its previous pair within 24 h of a change, is dropped and counted. The pairs come from a Directory, which is
//     the hub's log view (5.5); without one nothing is accepted.
//   - A tenant write is in the tenant the store's own lookup gave for the row, never one a node sent.
//   - What an outside party can cause (LearnedIP, ProofObservation) has a queue of 256 per node and is worked at 20 a second
//     per node at most; beyond that it is dropped and counted.
package hubtel

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubctl"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hublimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

type unit string

const (
	unitBeat     unit = "hub_tel_beat"
	unitActivity unit = "hub_tel_activity"
	unitOutside  unit = "hub_tel_outside"
	unitAlert    unit = "hub_tel_alert"
	unitQuar     unit = "hub_tel_quarantine"
	unitUpload   unit = "hub_tel_upload"
)

func (u unit) Valid() bool {
	switch u {
	case unitBeat, unitActivity, unitOutside, unitAlert, unitQuar, unitUpload:
		return true
	}
	return false
}

// The numbers of 5.3, 5.4 and 5.7 (D31).
const (
	// BeatEvery is the least time between two writes of one node's Heartbeat fields.
	BeatEvery = 30 * time.Second
	// QuarantinePerHour caps the quarantine rows one node adds in an hour.
	QuarantinePerHour = 60
	// SkewLimit is how far a node's clock may differ from the hub's before the alert (SC 18 item 6).
	SkewLimit = 2 * time.Second
	// ActivityWriteEvery is the least time between two writes of one activity key (Plan activity_heartbeat).
	ActivityWriteEvery = time.Hour
	// ActivityBatchEvery is the least time between two ActivityBatches of one node; ActivityBatchEntries the most entries in one.
	ActivityBatchEvery   = 30 * time.Second
	ActivityBatchEntries = 200_000
	// ActivityKeysPerNode and ActivityKeysTotal bound the keys held in memory.
	ActivityKeysPerNode = 500_000
	ActivityKeysTotal   = 2_000_000
	// OutsideQueue is the queue of messages an outside party can cause, per node, and OutsideRate the most the hub works a second.
	OutsideQueue = 256
	OutsideRate  = 20
	// LearnPerMinute is the rate of LearnedIP for one Endpoint.
	LearnPerMinute = 10
	// QuarantineQueue is the hub-wide queue of reports waiting for their row.
	QuarantineQueue = 1024
	// UploadIdle ends an upload stream that carried nothing for this long, so a stream nobody uses frees its slot (5.8).
	UploadIdle = 15 * time.Minute

	writeTimeout = 10 * time.Second
)

// Store interfaces: each is what the pool it is given may be asked (5.7), so a component cannot reach another pool.

// Alerter raises an alert (telemetry pool).
type Alerter interface {
	HubAlert(ctx context.Context, severity string, kind store.HubAlertKind, params map[string]string) error
}

// TelemetryStore is the telemetry pool's work: Heartbeat fields, quarantine rows, every alert, activity and counters.
type TelemetryStore interface {
	Alerter
	HubWriteBeat(ctx context.Context, node uuid.UUID, in store.HubBeat) error
	HubQuarantineAdd(ctx context.Context, node uuid.UUID, seq uint64, item, reason string) (inserted bool, nodes int, err error)
	HubEndpointTenants(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]uuid.UUID, error)
	HubActivityWrite(ctx context.Context, tenant uuid.UUID, items []store.HubActivityItem) (store.HubActivityResult, error)
	HubFreeCounters(ctx context.Context, node uuid.UUID, batch uint64, bucket int64, items []store.HubFreeItem) (bool, error)
}

// OutsideStore is the outside pool's work: what an outside party can cause.
type OutsideStore interface {
	HubEndpointTenants(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]uuid.UUID, error)
	HubLearnIP(ctx context.Context, tenant uuid.UUID, in store.HubLearn) (store.HubLearnOutcome, error)
	HubProofLookup(ctx context.Context, label string) (tenant, challenge, claim uuid.UUID, found bool, err error)
	HubProofObserve(ctx context.Context, tenant uuid.UUID, in store.HubProof, allow func(endpoint uuid.UUID) bool) (store.HubProofOutcome, error)
}

// Directory is the hub's log view as the pair rule and the client cap need it (5.5).
type Directory interface {
	// Allowed says whether node may report for the Endpoint at now: it is in the Endpoint's current pair, or in its previous
	// pair within 24 h of a change. An Endpoint the view does not know is not allowed.
	Allowed(endpoint, node uuid.UUID, now time.Time) bool
	// ClientCap is client_cap of the Endpoint's latest record in the log view; ok is false when there is none.
	ClientCap(endpoint uuid.UUID) (cap uint32, ok bool)
}

// Config is what a Telemetry is built from.
type Config struct {
	Trackers  *hubctl.Trackers
	Store     TelemetryStore
	Outside   OutsideStore
	Directory Directory
	// ProofKey derives the TXT code of a UDP proof (SC 3.5).
	ProofKey []byte
	Now      func() time.Time
	Log      *slog.Logger

	// Tunables for tests; zero takes the values above.
	BeatTick, ActivityTick time.Duration
	KeysPerNode, KeysTotal int
}

// Stats are the counters of what was dropped and what was written, by name. Tests and the hub's log read them.
type Stats map[string]uint64

type counter struct{ n atomic.Uint64 }

func (c *counter) add() { c.n.Add(1) }

// Telemetry is the intake. Build it with New and start it with Run.
type Telemetry struct {
	cfg Config

	// Drops, by cause (5.3, 5.4, 5.7). Every drop is counted, none is silent.
	dropBeatSkew, dropQuarCap, dropQuarFull                          counter
	dropBatchInvalid, dropBatchRate, dropBatchSize                   counter
	dropPair, dropKeyCap, dropClientCap, dropNoRecord, dropNoTenant  counter
	dropLearnProto, dropLearnRate, dropLearnCap                      counter
	dropOutsideRate, dropOutsideFull, dropProofInvalid, dropProofOld counter
	dropCountersPart, dropCountersItems, dropCountersRate            counter
	wroteBeats, wroteActivity, wroteLearned, wroteProof, wroteFree   counter

	alerts alertQ

	mu       sync.Mutex
	lastBeat map[uuid.UUID]stamp // when each node's fields were last written
	skewed   map[uuid.UUID]bool
	quar     map[uuid.UUID]*hourWindow
	quarQ    quarQueue
	batchAt  map[uuid.UUID]stamp // last accepted ActivityBatch of each node

	act     *activity
	out     *outside
	uploads *uploadSlots
	counts  *hublimit.Keyed // UploadCounters batches per node
}

// stamp, alertQ, quarQueue and wakeCh are named types because a struct that holds a mutex and a time.Time or a channel reads to
// the cache lint as a hand-written cache; none of these is a cache of outside state.
type stamp struct{ t time.Time }

type (
	alertQ    chan alertReq
	quarQueue chan quarReq
)

type alertReq struct {
	severity string
	kind     store.HubAlertKind
	params   map[string]string
}

// New makes a Telemetry. The store, the trackers and the clock are required; a nil Directory accepts no report that needs a
// pair (fail closed), and a nil Outside drops what an outside party causes.
func New(cfg Config) *Telemetry {
	if cfg.BeatTick <= 0 {
		cfg.BeatTick = 5 * time.Second
	}
	if cfg.ActivityTick <= 0 {
		cfg.ActivityTick = 10 * time.Second
	}
	if cfg.KeysPerNode <= 0 {
		cfg.KeysPerNode = ActivityKeysPerNode
	}
	if cfg.KeysTotal <= 0 {
		cfg.KeysTotal = ActivityKeysTotal
	}
	t := &Telemetry{
		cfg:      cfg,
		alerts:   make(alertQ, 64),
		lastBeat: make(map[uuid.UUID]stamp),
		skewed:   make(map[uuid.UUID]bool),
		quar:     make(map[uuid.UUID]*hourWindow),
		quarQ:    make(quarQueue, QuarantineQueue),
		batchAt:  make(map[uuid.UUID]stamp),
		uploads:  newUploadSlots(),
		counts:   hublimit.NewKeyed(1, 4, cfg.Now),
	}
	t.act = newActivity(t)
	t.out = newOutside(t)
	return t
}

// Run starts the writers and returns when ctx ends and they have stopped.
func (t *Telemetry) Run(ctx context.Context) {
	var wg sync.WaitGroup
	start := func(u unit, fn func(context.Context)) {
		wg.Add(1)
		safego.Go(t.cfg.Log, u, func() { defer wg.Done(); fn(ctx) })
	}
	start(unitBeat, t.beatLoop)
	start(unitAlert, t.alertLoop)
	start(unitQuar, t.quarLoop)
	start(unitActivity, t.act.loop)
	for range 2 { // the outside pool has two connections
		start(unitOutside, t.out.worker)
	}
	wg.Wait()
}

// Stats is a snapshot of every counter.
func (t *Telemetry) Stats() Stats {
	return Stats{
		"drop_beat_skew": t.dropBeatSkew.n.Load(), "drop_quarantine_cap": t.dropQuarCap.n.Load(), "drop_quarantine_full": t.dropQuarFull.n.Load(),
		"drop_batch_invalid": t.dropBatchInvalid.n.Load(), "drop_batch_rate": t.dropBatchRate.n.Load(), "drop_batch_size": t.dropBatchSize.n.Load(),
		"drop_pair": t.dropPair.n.Load(), "drop_key_cap": t.dropKeyCap.n.Load(), "drop_client_cap": t.dropClientCap.n.Load(),
		"drop_no_record": t.dropNoRecord.n.Load(), "drop_no_tenant": t.dropNoTenant.n.Load(),
		"drop_learn_proto": t.dropLearnProto.n.Load(), "drop_learn_rate": t.dropLearnRate.n.Load(), "drop_learn_cap": t.dropLearnCap.n.Load(),
		"drop_outside_rate": t.dropOutsideRate.n.Load(), "drop_outside_full": t.dropOutsideFull.n.Load(),
		"drop_proof_invalid": t.dropProofInvalid.n.Load(), "drop_proof_old": t.dropProofOld.n.Load(),
		"drop_counters_part": t.dropCountersPart.n.Load(), "drop_counters_items": t.dropCountersItems.n.Load(), "drop_counters_rate": t.dropCountersRate.n.Load(),
		"wrote_beats": t.wroteBeats.n.Load(), "wrote_activity": t.wroteActivity.n.Load(), "wrote_learned": t.wroteLearned.n.Load(),
		"wrote_proof": t.wroteProof.n.Load(), "wrote_free": t.wroteFree.n.Load(),
	}
}

// Offer is hubctl.Intake: every NodeMessage of a Control stream that passed validation. It does not block and touches no
// database. Heartbeats are already in the trackers; here only the clock is compared.
func (t *Telemetry) Offer(node uuid.UUID, m *hubv1.NodeMessage) {
	switch b := m.Body.(type) {
	case *hubv1.NodeMessage_Heartbeat:
		t.skew(node, b.Heartbeat)
	case *hubv1.NodeMessage_QuarantineReport:
		t.quarantineOffer(node, b.QuarantineReport)
	case *hubv1.NodeMessage_LearnedIp:
		t.out.offer(node, outMsg{learn: b.LearnedIp})
	case *hubv1.NodeMessage_ProofObservation:
		t.out.offer(node, outMsg{proof: b.ProofObservation})
	}
}

// raise queues an alert for the alert writer; a full queue drops it, and the cause that raised it repeats or is logged.
func (t *Telemetry) raise(sev string, kind store.HubAlertKind, params map[string]string) {
	select {
	case t.alerts <- alertReq{sev, kind, params}:
	default:
	}
}

func (t *Telemetry) alertLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case a := <-t.alerts:
			wctx, cancel := context.WithTimeout(ctx, writeTimeout)
			if err := t.cfg.Store.HubAlert(wctx, a.severity, a.kind, a.params); err != nil && t.cfg.Log != nil {
				t.cfg.Log.Warn("hub alert not written")
			}
			cancel()
		}
	}
}

// Raise queues an alert for the telemetry pool's one alert writer. The failover loop and the revocation keeper raise through it,
// so every alert insert of the hub goes through the one queue of 64 (5.7).
func (t *Telemetry) Raise(sev string, kind store.HubAlertKind, params map[string]string) {
	t.raise(sev, kind, params)
}
