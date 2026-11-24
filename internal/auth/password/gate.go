package password

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

// ErrBusy means the gate stayed full for the whole wait. The handler answers
// 503 server_busy with Retry-After: 2 (spec 4.1).
var ErrBusy = errors.New("password: too many hashes in flight")

// ErrOverBudget means a run asked for more memory than one slot of the budget
// holds. It is what the gate answers when a caller gets past the checks that
// come before it (spec 4.1, review round 5, rule argon2-memory-budget).
var ErrOverBudget = errors.New("password: argon2 run is larger than the memory budget of one slot")

// Defaults of 4.1.
const (
	DefaultConcurrency = 2
	DefaultWait        = 2 * time.Second
	// RetryAfterSeconds is the Retry-After value that goes with ErrBusy.
	RetryAfterSeconds = 2
)

// tinyMemKiB is the memory at or under which a run may skip the slot when its
// caller asks for that (the console tools and the admin's one-time password, see
// slotMode). It is the one-time parameters' 8 KiB: a run that small is not memory
// the budget has to count.
const tinyMemKiB = 8

// Gate is a counting semaphore around Argon2 and the one holder of the process's
// Argon2 memory budget. The budget is slots times memory per slot: each hash holds
// about 46 MiB for its whole run, so the number in flight is what keeps a
// container under its memory limit, and the most one run may ask for is the
// budget divided by the slots. A caller that cannot get in within the wait is
// refused instead of queued: the queue would be unbounded memory in request
// goroutines.
type Gate struct {
	// mu guards free and the two queues. A slot that is released goes straight to the head of
	// a queue and is never put back in the pool while anybody waits, so free > 0 means nobody
	// waits.
	mu   sync.Mutex
	size int
	free int
	// proved and plain are the waiters, first come first served inside each. A slot goes to
	// the head of proved before plain (see Proved), except that every plainEvery-th grant in a
	// row to the proved lane yields to the head of plain (see release).
	proved, plain []*waiter
	// provedRun counts the grants the proved lane took since a plain waiter last got one.
	provedRun int
	// inflight is the set of subjects (ProvedAs) that have a hash queued or running right now, one each.
	// It is what keeps a proved flood from being a flood: see ProvedAs.
	inflight map[string]struct{}
	wait     time.Duration
	// budgetKiB is the most Argon2 memory the process may hold at once.
	budgetKiB uint64
	// tried counts every call of Acquire, whether it got a slot or not. The
	// known-or-unknown oracle test compares it between a subject with an account
	// and one without: whether a request reached the gate must never depend on
	// the account (review round 5, rule known-unknown-oracle).
	tried atomic.Uint64
	// computed counts the Argon2 runs that started, so a test can say that building
	// a hasher or a service did none (rule argon2-memory-budget).
	computed atomic.Uint64
}

// NewGate makes a gate of n slots over the default budget. n below 1 is 1.
func NewGate(n int, wait time.Duration) *Gate {
	return newGate(n, wait, DefaultBudgetMiB<<10)
}

// NewGateBudget makes a gate of n slots over a budget of budgetMiB. It is how
// Settings builds the gate, so the budget the operator set is the one the gate
// enforces.
func NewGateBudget(n int, wait time.Duration, budgetMiB uint64) *Gate {
	return newGate(n, wait, budgetMiB<<10)
}

func newGate(n int, wait time.Duration, budgetKiB uint64) *Gate {
	if n < 1 {
		n = 1
	}
	if wait <= 0 {
		wait = DefaultWait
	}
	return &Gate{size: n, free: n, wait: wait, budgetKiB: budgetKiB, inflight: map[string]struct{}{}}
}

// Size is the number of slots.
func (g *Gate) Size() int { return g.size }

// CeilingKiB is the most memory one run may use: the budget divided by the slots,
// and never above the absolute bound on a stored hash. Every consumer, the check
// of a new hasher's parameters and the check of a stored hash, reads this one
// number.
func (g *Gate) CeilingKiB() uint32 {
	return uint32(min(g.budgetKiB/uint64(g.size), maxStoredMemKiB))
}

// Attempts is how many times Acquire was called, refused calls included.
func (g *Gate) Attempts() uint64 { return g.tried.Load() }

// Computed is how many Argon2 runs started under this gate.
func (g *Gate) Computed() uint64 { return g.computed.Load() }

// slotMode says whether a run waits for a slot.
type slotMode int

const (
	// inSlot is every run but the two below: it holds a slot for its whole run.
	inSlot slotMode = iota
	// tinyFree skips the slot for a run of at most tinyMemKiB. The mode is a
	// request, not a right: derive looks at the memory itself, so a caller that
	// asks for it with the normal parameters still takes a slot.
	tinyFree
)

// derive is the one place in the module that calls argon2.IDKey (internal/lint
// TestArgon2OnlyInTheGate fails for any other). Whatever hashes, verifies, makes
// the dummy or serves a console tool arrives here, so the rule "every run is
// inside the budget" is a property of this function and not of its callers: it
// refuses a run larger than one slot of the budget, waits for a slot, and only
// then allocates. The input is not wiped here, the caller owns it.
func (g *Gate) derive(ctx context.Context, in, salt []byte, p Params, n uint32, mode slotMode) ([]byte, error) {
	if p.MemoryKiB > g.CeilingKiB() {
		return nil, ErrOverBudget
	}
	if mode != tinyFree || p.MemoryKiB > tinyMemKiB {
		release, err := g.Acquire(ctx)
		if err != nil {
			return nil, err
		}
		defer release()
	}
	g.computed.Add(1)
	return argon2.IDKey(in, salt, p.Time, p.MemoryKiB, p.Threads, n), nil
}

// proofKey marks a context whose request carries a proof (see Proved).
type proofKey struct{}

// Proved marks a request as carrying a proof, so that it is served before any stranger
// when the gate is full. The proofs are what the service can check without the gate: a session that
// passed its checks (admin or tenant), a device marker that holds for the account, and (tenant) the
// Work step of a proof.Spec whose proof was looked at (proof.Run). It
// is the only way to ask for the priority, and a lint (internal/lint TestGatePriorityIsGivenOnlyByProofs)
// lists the files that may call it, so a route cannot hand it to a request that has none.
//
// Why: the gate is one bucket the whole world shares, and a stranger who keeps its slots full
// refuses every other hash, the owner's included, with a 503. Every unproved login runs
// Argon2 (an unknown username runs the dummy hash), so about ten requests a second from a few
// networks was enough to keep the admin's one slot busy for ever, and the device marker, which
// exempts the owner from the throttle scopes, did nothing for the gate (round 5, admin-r5-9;
// rule budget-keying: a bucket never refuses a request with a verified proof).
func Proved(ctx context.Context) context.Context { return context.WithValue(ctx, proofKey{}, true) }

func provedFrom(ctx context.Context) bool { v, _ := ctx.Value(proofKey{}).(bool); return v }

// subjectKey carries the subject of a proved request (see ProvedAs).
type subjectKey struct{}

// ProvedAs is Proved for a proof that can be used again and again, a session or a device marker, with the
// subject it proves: the account. The gate then lets one subject have ONE hash queued or running at a time
// and refuses its others at once (ErrBusy, the same answer a full gate gives, so every caller's refund of
// a busy attempt applies).
//
// Why: the priority lane is strict, and its only bound was per session (the sensitive class, ten a minute),
// with nothing that caps the sessions of one account. An account holder who opened three hundred sessions
// (a login is a proof and mints a session) had three thousand proved Argon2 runs a minute, the proved
// queue was never empty, and every request without a proof, a new device, a cleared cookie, a first login,
// got 503 at once for as long as he kept it up (round 7, tenant-r7-6). Bounded per subject, the most one
// account takes is one slot of the gate, whatever the number of its sessions, so the lane is a priority
// for the proofs of many accounts and not a lever for one. A proof that is single use (a code, a ticket:
// proof.Run) is bounded by what it costs to make one and keeps the plain Proved. An empty subject is Proved.
func ProvedAs(ctx context.Context, subject string) context.Context {
	ctx = Proved(ctx)
	if subject == "" {
		return ctx
	}
	return context.WithValue(ctx, subjectKey{}, subject)
}

func subjectFrom(ctx context.Context) string { s, _ := ctx.Value(subjectKey{}).(string); return s }

// IsProved says whether ctx carries the mark of Proved. It grants nothing (only the gate reads the
// mark to order its queues); it exists so a test can state which requests are in the lane.
func IsProved(ctx context.Context) bool { return provedFrom(ctx) }

// Waiting is how many requests wait for a slot in the proved lane and in the plain queue. It reads
// the two queues under the lock and changes nothing. A test uses it to know that a request has taken
// its place in the line, so it can hold the slots by construction and then order the arrivals, where
// the earlier form relied on a slow hash and a sleep to build the same pressure (round 16,
// tenant-r16-1: that form passed with the lane removed on a fast runner).
func (g *Gate) Waiting() (proved, plain int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.proved), len(g.plain)
}

// waiter is a request that waits for a slot. granted is set under Gate.mu by whoever hands it
// the slot, so a waiter that gave up at the same moment finds out whether it owns one.
type waiter struct {
	ch      chan struct{}
	granted bool
}

// Acquire takes a slot and returns the function that gives it back. It returns
// ErrBusy after the wait, or the context's error if the request went away first.
//
// A proved request (Proved) waits in a queue that is served first, except on every plainEvery-th
// grant (release). A request with no proof waits in a queue of its own while proved ones are
// queued, but the queue holds one waiter per slot: the rest are refused AT ONCE, without waiting.
// Known and unknown accounts without a proof reach this function the same way, so the order
// tells nothing about the account (rule known-unknown-oracle).
func (g *Gate) Acquire(ctx context.Context) (release func(), err error) {
	g.tried.Add(1)
	proved := provedFrom(ctx)
	subject := ""
	if proved {
		subject = subjectFrom(ctx)
	}
	if subject == "" {
		return g.take(ctx, proved)
	}
	// One hash per subject, queued or running (ProvedAs). The mark is taken before the wait and dropped
	// on every way out, so a request that gives up does not hold its subject.
	g.mu.Lock()
	if _, busy := g.inflight[subject]; busy {
		g.mu.Unlock()
		return nil, ErrBusy
	}
	g.inflight[subject] = struct{}{}
	g.mu.Unlock()
	rel, err := g.take(ctx, proved)
	if err != nil {
		g.forget(subject)
		return nil, err
	}
	return func() { g.forget(subject); rel() }, nil
}

func (g *Gate) forget(subject string) {
	g.mu.Lock()
	delete(g.inflight, subject)
	g.mu.Unlock()
}

// take is the queueing of Acquire: a slot, in the lane the request is in.
func (g *Gate) take(ctx context.Context, proved bool) (release func(), err error) {
	g.mu.Lock()
	// A free slot is taken without a timer, so the common path allocates nothing.
	if g.free > 0 {
		g.free--
		g.mu.Unlock()
		return g.release, nil
	}
	// While proved requests wait, the plain queue holds at most one waiter per slot, and the rest of
	// the strangers are refused at once: they cannot be served ahead of the proofs, only at the
	// plainEvery-th grant, and a longer line would only be goroutines that time out (round 7,
	// primitives-r7-4).
	if !proved && len(g.proved) > 0 && len(g.plain) >= g.size {
		g.mu.Unlock()
		return nil, ErrBusy
	}
	w := &waiter{ch: make(chan struct{})}
	if proved {
		g.proved = append(g.proved, w)
	} else {
		g.plain = append(g.plain, w)
	}
	g.mu.Unlock()

	t := time.NewTimer(g.wait)
	defer t.Stop()
	var cause error
	select {
	case <-w.ch:
		return g.release, nil
	case <-t.C:
		cause = ErrBusy
	case <-ctx.Done():
		cause = ctx.Err()
	}
	g.mu.Lock()
	if w.granted { // the slot arrived while this request was giving up: it is ours, give it on
		g.mu.Unlock()
		g.release()
		return nil, cause
	}
	g.plain, g.proved = without(g.plain, w), without(g.proved, w)
	g.mu.Unlock()
	return nil, cause
}

func without(q []*waiter, w *waiter) []*waiter {
	for i, x := range q {
		if x == w {
			return append(q[:i:i], q[i+1:]...)
		}
	}
	return q
}

// plainEvery is how many grants in a row the proved lane may take while a plain waiter is queued:
// the next one goes to the plain queue. It is the bound the lane never had. The lane is strict
// priority, and a lane is only as honest as its proofs: a proof costs whoever holds it nothing
// to use again, and an account is not scarce, so a handful of accounts (one per slot, now that
// ProvedAs bounds each to one hash) can keep the proved queue non-empty for ever, and every
// request without a proof, a new device, a cleared cookie, a first login, a reset, a registration, got
// 503 for as long as they kept it up (round 7, primitives-r7-4). Priority orders the waiters; it
// does not own the gate. With plainEvery grants to the proved lane for each one to the plain
// queue, strangers keep at least 1 of plainEvery+1 of the slots whatever the proofs do, and a
// proof waits one more hash at most once per plainEvery grants.
const plainEvery = 3

// release hands the slot to the first proved waiter, else to the first plain one, else puts it
// back in the pool; the proved lane yields to the plain queue on every plainEvery-th grant while
// the plain queue is not empty. The waiter is chosen and marked granted under the lock and woken
// after it, so no lock is held across a channel operation (internal/lint TestNoMutexAcrossIO): a
// waiter that gave up in between finds granted set, passes the slot on, and its channel is closed
// all the same, which nobody reads.
func (g *Gate) release() {
	var next *waiter
	g.mu.Lock()
	switch {
	case len(g.proved) > 0 && !(len(g.plain) > 0 && g.provedRun >= plainEvery):
		next = g.proved[0]
		g.proved = g.proved[1:]
		g.provedRun++
	case len(g.plain) > 0:
		next = g.plain[0]
		g.plain = g.plain[1:]
		g.provedRun = 0
	}
	if next != nil {
		next.granted = true
	}
	if next == nil {
		g.free++
	}
	g.mu.Unlock()
	if next != nil {
		close(next.ch)
	}
}

// Env variable names of 4.1 and 17.2.
const (
	EnvMemoryKiB   = "CTRLZ_ARGON2_M_KIB"
	EnvTime        = "CTRLZ_ARGON2_T"
	EnvConcurrency = "CTRLZ_ARGON2_CONCURRENCY"
	// EnvBudgetMiB caps concurrency times memory: the Argon2 memory that can be
	// live at once. Raise it only together with the container's memory limit.
	EnvBudgetMiB = "CTRLZ_ARGON2_BUDGET_MIB"
)

// DefaultBudgetMiB is the most Argon2 memory a process may hold at once when the
// deployment says nothing: 192 MiB. The standard profile's 4 hashes of 46 MiB take
// 184. Compose sets a smaller one for the admin container, whose limit is 128 MiB.
// A setting that would need more is refused at start, where it is a message,
// instead of at the first login burst, where it is a kill by the cgroup.
const DefaultBudgetMiB = 192

// minMemoryKiB is the lowest memory a deployment may configure: OWASP's
// 19 MiB. A test environment (CTRLZ_ENV=test) may go down to the Argon2 minimum
// so that suites do not spend seconds hashing.
const minMemoryKiB = 19456

// OWASP's minimum pairs (Password Storage Cheat Sheet, 4.1): 46 MiB with one
// iteration, or 19 MiB with two. The two floors are not independent, so the
// memory floor above and an iteration count of 1 do not combine.
const (
	owaspMemKiBOneIteration = 47104
	owaspMemKiBTwoIteration = minMemoryKiB
)

// Settings are the Argon2 settings of one process: the cost parameters, the size
// of the gate and the memory budget they must fit in. They are plain values, so
// Config can hold them; the Gate, which has state, is made from them at start.
// Settings is the only way a service gets a Hasher (internal/lint
// TestArgon2HasherOnlyFromSettings), so the floor and the budget below are checked
// for every process and not only for the ones that read the environment.
type Settings struct {
	Params      Params
	Concurrency int
	// BudgetMiB is the memory share of the process: Concurrency times
	// Params.MemoryKiB must fit in it. Zero is refused, not defaulted: a literal
	// that forgot it would otherwise get the biggest budget.
	BudgetMiB uint64
	// Relaxed lowers the floor to the Argon2 minimum. Only CTRLZ_ENV=test sets it,
	// so that suites do not spend seconds hashing.
	Relaxed bool
}

// validate is the floor and the budget, in one place. The messages name the
// variables and never a value.
func (s Settings) validate() error {
	if s.Concurrency < 1 || s.BudgetMiB < 1 {
		return errors.New(EnvConcurrency + " and " + EnvBudgetMiB + " must be positive")
	}
	if err := s.Params.validate(); err != nil {
		return err
	}
	// Reserved for the console one-time hash, which VerifyGateFree reads without a slot (primitives-r8-1). Refused here
	// too, so the process fails when it reads its settings and not when it builds the hasher.
	if s.Params == oneTimeParams() {
		return errors.New(EnvMemoryKiB + " and " + EnvTime + " are the console one-time hash's own pair")
	}
	if !s.Relaxed {
		// The pair, not each value alone (review round 1, primitives-r1-16).
		if m, t := s.Params.MemoryKiB, s.Params.Time; !(m >= owaspMemKiBOneIteration && t >= 1) && !(m >= owaspMemKiBTwoIteration && t >= 2) {
			return errors.New(EnvMemoryKiB + " and " + EnvTime + " are below OWASP's minimum pairs (46 MiB with t=1, 19 MiB with t=2)")
		}
	}
	if uint64(s.Concurrency)*uint64(s.Params.MemoryKiB) > s.BudgetMiB<<10 {
		return errors.New(EnvConcurrency + " times " + EnvMemoryKiB + " exceeds the memory budget " + EnvBudgetMiB)
	}
	return nil
}

// Gate makes the gate for these settings, waiting DefaultWait for a slot.
func (s Settings) Gate() *Gate { return NewGateBudget(s.Concurrency, DefaultWait, s.BudgetMiB) }

// NewHasher makes the process's Hasher after checking the settings against the
// floor and the budget. It allocates no Argon2 memory: that happens on the first
// hash or verify, inside the gate.
func (s Settings) NewHasher() (*Hasher, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	return NewHasher(s.Params, s.Gate())
}

// FromEnv reads the Argon2 settings. Unset variables give the defaults of 4.1.
// getenv is os.Getenv in production. An invalid value is an error that names
// the variable and not the value.
func FromEnv(getenv func(string) string) (Settings, error) {
	st := Settings{Params: DefaultParams(), Concurrency: DefaultConcurrency, BudgetMiB: DefaultBudgetMiB, Relaxed: getenv("CTRLZ_ENV") == "test"}
	floor := uint64(minMemoryKiB)
	if st.Relaxed {
		floor = 8
	}
	if v := getenv(EnvMemoryKiB); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n < floor || n > maxStoredMemKiB {
			return Settings{}, errors.New(EnvMemoryKiB + " is out of range")
		}
		st.Params.MemoryKiB = uint32(n)
	}
	if v := getenv(EnvTime); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n < 1 || n > maxStoredTime {
			return Settings{}, errors.New(EnvTime + " is out of range")
		}
		st.Params.Time = uint32(n)
	}
	if v := getenv(EnvConcurrency); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 64 {
			return Settings{}, errors.New(EnvConcurrency + " is out of range")
		}
		st.Concurrency = n
	}
	if v := getenv(EnvBudgetMiB); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n < 1 || n > 64<<10 {
			return Settings{}, errors.New(EnvBudgetMiB + " is out of range")
		}
		st.BudgetMiB = n
	}
	if err := st.validate(); err != nil {
		return Settings{}, err
	}
	return st, nil
}
