package smssend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"sort"
	"sync"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/senders"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Source loads the router's snapshot from the database: the gateways with their
// credentials opened, and the provider template mappings. It is the one place
// the worker opens sms_cred ciphertext.
//
// Building a driver makes an HTTP client, and the snapshot reloads every 30
// seconds, so a built Sender is kept while its sealed credentials are unchanged.
type Source struct {
	db   *store.Store
	keys *keyring.Ring
	env  senders.Env
	log  *slog.Logger

	// Build makes a driver from a provider name and its opened credentials. It is
	// senders.New unless a test replaces it to point the drivers at httptest
	// servers; nothing in production sets it.
	Build func(provider string, creds secret.Bytes) (sms.Sender, error)

	mu    sync.Mutex
	built map[uuid.UUID]built
	rev   uint64 // the last revision given to a build
}

type built struct {
	provider string
	ctSum    [sha256.Size]byte
	sender   sms.Sender
	problem  sms.Code // a gateway that cannot be used is remembered too, so it is logged once and not every reload
	// There is no hold here. The hold of a refused login (sms.Gateway.Held, sms-r11-9) lives in
	// the gateway row, where every worker reads it (sms-r12-3), and heldOf judges it against this
	// entry's ctSum.
	rev uint64 // the number of this build, see sms.Gateway.Revision

	// wrote says this process wrote the unusable judgement for these credentials and the commit went
	// through; yielded says that the row stopped saying so while this build still has no sender, which
	// only a worker whose key ring opens the credentials does (sms-r16-18). A worker that yielded writes
	// no more for these credentials: two rings that disagree used to write and take back the judgement
	// against each other on every reload, and since the poll reloads with no traffic, for the whole
	// overlap of a rolling key rotation. Both live in this entry, so a restart or new credentials (a new
	// sum, a new entry) start clean.
	wrote, yielded bool
}

// NewSource returns a Source. db must be opened as ctrlz_worker.
func NewSource(db *store.Store, keys *keyring.Ring, env senders.Env, log *slog.Logger) *Source {
	return &Source{db: db, keys: keys, env: env, log: log, built: map[uuid.UUID]built{}}
}

var _ sms.Source = (*Source)(nil)

// Load implements sms.Source.
func (s *Source) Load(ctx context.Context) (sms.Snapshot, error) {
	var gws []store.WorkerGateway
	var tpls []store.WorkerProviderTemplate
	err := s.db.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
		if gws, err = g.WorkerGateways(); err != nil {
			return err
		}
		tpls, err = g.WorkerProviderTemplates()
		return err
	})
	if err != nil {
		return sms.Snapshot{}, err
	}

	snap, marks := s.snapshot(gws, tpls)
	// The judgement of each build is written where the login page can read it (sms-r15-1), outside
	// the lock and outside the read: a failed write is retried by the next load, because the row
	// still differs from the build, and never fails the snapshot.
	s.recordUsable(ctx, marks)
	return snap, nil
}

// usableMark is what a build says about its gateway that the row does not yet say.
type usableMark struct {
	id       uuid.UUID
	provider string
	problem  sms.Code // why no sender could be built; empty when usable
	sum      [sha256.Size]byte
	usable   bool // true takes a stale judgement back
}

func (s *Source) snapshot(gws []store.WorkerGateway, tpls []store.WorkerProviderTemplate) (sms.Snapshot, []usableMark) {
	loaded := appclock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := sms.Snapshot{Templates: make(map[sms.TemplateRef]sms.ProviderTemplate, len(tpls))}
	live := map[uuid.UUID]bool{}
	var marks []usableMark
	for _, w := range gws {
		live[w.ID] = true
		g := sms.Gateway{ID: w.ID, Provider: w.Provider, Role: w.Role, Price: w.CostPerMessage}
		if w.BreakerOpenFor > 0 {
			// The database measured how long is left; the router compares with its own clock.
			until := loaded.Add(w.BreakerOpenFor)
			g.BreakerOpenUntil = &until
		}
		b := s.sender(w)
		g.Sender, g.Problem, g.Revision = b.sender, b.problem, b.rev
		g.Held = heldOf(w, b)
		snap.Gateways = append(snap.Gateways, g)
		// One rule for every reason a gateway has no sender: whatever ends in a Problem is written
		// against the ciphertext it was judged for, and a build that works clears it. There is no
		// list of reasons here to forget a new one from.
		switch {
		case b.sender == nil && !bytes.Equal(w.UnusableCTSum, b.ctSum[:]):
			if b.problem == sms.CodeCredentialsUnreadable && b.wrote && !b.yielded {
				// This process wrote the judgement and the row no longer holds it, with no sender built
				// here: another worker, whose key ring opens these credentials, took it back. Each is right
				// about its own ring and the credentials in the row are the newer ring's, so this worker
				// leaves the row to it instead of writing again on every reload (sms-r16-18). Nothing else
				// changes here: the gateway still has no sender and is passed over by this worker.
				b.yielded = true
				s.built[w.ID] = b
				s.log.Info("sms gateway judgement left to a worker whose key ring opens the credentials", logattr.ID("gateway", w.ID), logattr.Enum("provider", sms.ParseProvider(w.Provider)))
			}
			if !b.yielded {
				marks = append(marks, usableMark{id: w.ID, provider: w.Provider, problem: b.problem, sum: b.ctSum})
			}
		case b.sender != nil && bytes.Equal(w.UnusableCTSum, b.ctSum[:]):
			// Only a judgement about THESE credentials is taken back (sms-r16-2). One that names
			// others counts for nothing in the database and is not this build's to touch.
			marks = append(marks, usableMark{id: w.ID, provider: w.Provider, sum: b.ctSum, usable: true})
		}
	}
	for id := range s.built {
		if !live[id] {
			delete(s.built, id)
		}
	}
	for _, t := range tpls {
		snap.Templates[sms.TemplateRef{Gateway: t.GatewayID, Key: t.Key, Locale: t.Locale}] = sms.ProviderTemplate{
			ID: t.ProviderTemplateID, ParamNames: t.ParamNames,
		}
	}
	return snap, marks
}

// recordUsable writes the marks in one transaction. The gateway rows are taken in id order, the
// order recordGateways (the record transaction of every send) takes them in and the one rule 1
// names for rows of one table (sms-r16-7): Load lists them by role, which puts the fallback before
// the primary whatever their ids, so the two writers used to meet in opposite orders and one could
// be aborted with 40P01. The statements are conditional, so two workers that agree write once and
// one that disagrees cannot overwrite a judgement about other credentials.
func (s *Source) recordUsable(ctx context.Context, marks []usableMark) {
	if len(marks) == 0 {
		return
	}
	marks = byGatewayID(marks)
	err := s.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		for _, m := range marks {
			if m.usable {
				won, err := g.GatewayUsable(m.id, m.sum[:])
				if err != nil {
					return err
				}
				if won.Yes() {
					s.log.Info("sms gateway judgement taken back, a sender can be built", logattr.ID("gateway", m.id), logattr.Enum("provider", sms.ParseProvider(m.provider)))
				}
				continue
			}
			won, err := g.GatewayUnusable(m.id, m.sum[:])
			if err != nil {
				return err
			}
			if won.Yes() {
				// Fixed words only: the provider and the Problem code, never the credentials or their sum.
				s.log.Warn("sms gateway judged unusable, kept out of sms_available", logattr.ID("gateway", m.id), logattr.Enum("provider", sms.ParseProvider(m.provider)), logattr.Enum("problem", m.problem))
			}
		}
		return nil
	})
	if err != nil && ctx.Err() == nil {
		s.log.Warn("sms gateway judgement not recorded", logattr.Enum("error_class", errClass(err)))
	}
	if err == nil {
		s.noteWritten(marks)
	}
}

// noteWritten remembers, per build, that the judgement for its credentials was committed, which is
// what lets a later load tell "the row was taken back by someone else" from "my write has not
// happened yet" (sms-r16-18). A write that failed leaves the flag unset, so it is tried again and
// never mistaken for a take-back.
func (s *Source) noteWritten(marks []usableMark) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range marks {
		if b, ok := s.built[m.id]; ok && !m.usable && b.ctSum == m.sum {
			b.wrote = true
			s.built[m.id] = b
		}
	}
}

// sender returns the driver of a gateway, or the reason it cannot be used. The
// reason is a fixed word: nothing from the credentials, and not the error of the
// key ring, reaches a log or an alert.
func (s *Source) sender(w store.WorkerGateway) built {
	sum := sha256.Sum256(w.CredentialsCT)
	if b, ok := s.built[w.ID]; ok && b.provider == w.Provider && b.ctSum == sum {
		return b
	}
	var creds secret.Bytes
	if len(w.CredentialsCT) > 0 {
		c, err := sms.OpenCredentials(s.keys, w.ID, w.Provider, w.CredentialsCT)
		if err != nil {
			// A wrong or missing key, or a row that was changed. The cause is not
			// repeated: ErrOpen is one value for every failure (8.2).
			s.log.Warn("sms gateway credentials unreadable", logattr.ID("gateway", w.ID), logattr.Enum("provider", sms.ParseProvider(w.Provider)))
			return s.keep(w, built{provider: w.Provider, ctSum: sum, problem: sms.CodeCredentialsUnreadable})
		}
		creds = c
		defer creds.Wipe()
	}
	build := s.Build
	if build == nil {
		build = func(p string, c secret.Bytes) (sms.Sender, error) { return senders.New(p, c, s.env) }
	}
	snd, err := build(w.Provider, creds)
	if err != nil {
		var u *senders.ErrUnusable
		if errors.As(err, &u) {
			s.log.Warn("sms gateway unusable", logattr.ID("gateway", w.ID), logattr.Enum("provider", sms.ParseProvider(w.Provider)), logattr.Enum("problem", u.Problem))
			return s.keep(w, built{provider: w.Provider, ctSum: sum, problem: u.Problem})
		}
		// Not cached, so the build is tried again at the next load, but the judgement still names
		// the credentials it was made for (sms-r15-1).
		return built{provider: w.Provider, ctSum: sum, problem: sms.CodeUnusable}
	}
	return s.keep(w, built{provider: w.Provider, ctSum: sum, sender: snd})
}

// keep remembers a build under its gateway and gives it the next revision, so a hold names the
// credentials it was made for.
func (s *Source) keep(w store.WorkerGateway, b built) built {
	s.rev++
	b.rev = s.rev
	s.built[w.ID] = b
	return b
}

// heldOf is the hold of a gateway as the row says it: the refusal, when the row's hold names the
// credentials this build was made from, and nil otherwise. A hold for other credentials (the
// admin saved a new key since) is not read, so saving credentials ends the hold with no write by
// this worker, and a gateway that has no sender has nothing to hold (its Problem already keeps it
// out of the traffic).
func heldOf(w store.WorkerGateway, b built) *sms.Error {
	if w.HeldCode == nil || b.sender == nil || !bytes.Equal(w.HeldCTSum, b.ctSum[:]) {
		return nil
	}
	// A hold is always a refused login, which is the Auth class; the code is the provider's own
	// answer, read back through the closed table.
	return sms.NewError(sms.ParseProvider(w.Provider), sms.Auth, sms.ParseCode(*w.HeldCode))
}

// buildSum is the sum of the sealed credentials a build was made from, when this revision is still
// the current one of the gateway. ok is false for a revision that is gone (the credentials changed
// since the call was made) or that never held a sender.
func (s *Source) buildSum(id uuid.UUID, revision uint64) (sum [sha256.Size]byte, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, found := s.built[id]
	if !found || b.sender == nil || revision == 0 || b.rev != revision {
		return sum, false
	}
	return b.ctSum, true
}

// RecordHold writes the hold or the lifting an attempt asks for, in the transaction that records the
// send (sms-r13-2, sms-r13-5). It used to be written by the router between two gateways, in a
// transaction of its own with a budget of its own: a busy gateway row held it for seconds, the
// fallback found too little of the send's budget left for a call and was not asked, and a write that
// timed out left the refused key to be asked again. In the record transaction the gateway row is
// already locked by this worker's own breaker step (recordGateways walks the rows in id order), so
// the write waits for nothing new, and it commits or rolls back with the delivery it belongs to.
//
// A refused login is a hold (sms-r11-9): every further call with the same credentials is another
// failed login, and a provider answers a run of those by blocking the panel's address (Melipayamak
// -108), which only its support lifts. So the gateway is kept out of the traffic of users until its
// credentials change, and the admin's test send is the explicit probe, whose accepted answer lifts
// the hold. The hold is in the gateway row so every worker sees it, with the sum of the credentials
// it was made for: the statement lands only on those (an attempt made with credentials saved since
// is ignored, in memory by the revision and in the database by the sum). A rekey carries the sum
// forward (store.SMSCredentialsReplace), so it is the credentials that count and not their
// ciphertext. The breaker, the alert and sms_available see the gateway as one whose credentials
// cannot be used, which is what it is.
func (s *Source) RecordHold(g store.GlobalTx, a sms.Attempt) error {
	if a.Hold == sms.HoldNone {
		return nil
	}
	sum, ok := s.buildSum(a.Gateway, a.Revision)
	if !ok {
		return nil
	}
	switch a.Hold {
	case sms.HoldPlace:
		if a.Err == nil {
			return nil
		}
		won, err := g.GatewayHold(a.Gateway, sum[:], sms.StatusOf(a.Err.Code))
		if err != nil {
			return err
		}
		if won.Yes() {
			s.log.Warn("sms gateway held after a refused login", logattr.ID("gateway", a.Gateway), logattr.Enum("provider", a.Err.Provider), logattr.Enum("code", a.Err.Code))
		}
	case sms.HoldLift:
		won, err := g.GatewayRelease(a.Gateway, sum[:])
		if err != nil {
			return err
		}
		if won.Yes() {
			s.log.Info("sms gateway hold lifted by an accepted test send", logattr.ID("gateway", a.Gateway))
		}
	}
	return nil
}

// byGatewayID returns the marks in gateway id order, the lock order of the rows of sms_gateways
// (sms-r16-7). It copies, so no caller's slice is reordered under it.
func byGatewayID(marks []usableMark) []usableMark {
	out := append([]usableMark(nil), marks...)
	sort.SliceStable(out, func(i, j int) bool { return bytes.Compare(out[i].id[:], out[j].id[:]) < 0 })
	return out
}
