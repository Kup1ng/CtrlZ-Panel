// Package admission decides which heavy request of the api may work, and when (docs/specs/p2-profiles.md 6.5). A heavy
// request is the import, upload, duplicate, export and batch routes and a big rule create. It takes one place for its
// tenant, spools its body to a disk file, waits in one first-in-first-out queue for the weight of its work, works inside
// that weight, gives it back, and only then sends its answer from the file. Nothing a client's time can stretch (its body
// arriving, its answer being read) holds weight, and nothing is sized from a number the client declared.
//
// The package holds the two shared things of that path: the places (one for each tenant, 128 in the process) and the
// weighted work pool. The pipeline in internal/httpx holds the order of the steps and the spool files.
package admission

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

// The numbers of 6.5 (D31). The sizes test of this package holds them against the container.
const (
	// Places is how many tenants may have a heavy request in the process: one place each.
	Places = 128
	// PlaceBytes is what a place holds in memory while its client sends or reads: one 32 KiB buffer, the connection and
	// the bookkeeping. 128 of them are the 10 MiB the sizes test counts.
	PlaceBytes = 80 << 10
	// Pool is the work pool, in bytes of live memory the work of the admitted requests may hold at once.
	Pool = 48 << 20
	// QueueWait is the longest a request waits in the queue.
	QueueWait = 120 * time.Second
	// WorkLimit is the deadline of the work itself.
	WorkLimit = 10 * time.Second
	// AnswerPool is the disk the answers of ordinary operations may hold while their client reads: an answer above 64 KiB
	// is spilled to a file so that no memory waits for a client (p2-B3-r9-4, r10-1 to r10-3). AnswerTenant is what one
	// tenant may hold of it, and the pool is that share for as many tenants as there are places, so another tenant is
	// refused only when 128 tenants hold their shares. The sizes test adds the pool to the disk of 6.5 property 11.
	AnswerPool   = Places * AnswerTenant
	AnswerTenant = 4 << 20
	// AnswerBytes is the most an answer may have: above it the request is a 500. A test holds the largest export there can
	// be below it.
	AnswerBytes = 16 << 20
	// OrdinaryTenant is how many ordinary requests of one tenant run at once, whatever the number of its sessions: the api
	// has 16 database connections and a tenant's rate classes are counted for each session (50 sessions of one account
	// pass 15,000 reads a minute), so without this bound one account holds the pool and its largest reads are in memory
	// together (p2-B3-r13-1). OrdinaryTotal is the same bound for the process; OrdinaryBytes is what the worst ordinary
	// request holds live, which the sizes test adds to the sum of 6.5 property 9. OrdinaryWaiting requests of a tenant
	// wait in line, first in first out and holding no connection, for at most OrdinaryWait; the others, and those that
	// waited that long, are 503 server_busy.
	OrdinaryTenant  = 4
	OrdinaryTotal   = 8
	OrdinaryBytes   = 5 << 20
	OrdinaryWaiting = 64
	OrdinaryWait    = 2 * time.Second
)

// The three weights of 6.5 property 8: the most live memory the worst request of each kind may hold in the work step.
const (
	WeightLarge  = 48 << 20 // Import and Upload with a body above 1 MiB
	WeightExport = 32 << 20 // Export, Export Rules and Duplicate
	WeightSmall  = 16 << 20 // every other heavy operation
)

var (
	// ErrBusy is a refusal for lack of a place: the tenant's own is taken, or all of them are.
	ErrBusy = errors.New("admission: no place")
	// ErrQueueWait is a request that waited the whole QueueWait.
	ErrQueueWait = errors.New("admission: the queue wait ended")
	// ErrAnswerBusy is an answer whose bytes the pool of held answers cannot take now: the tenant's share is used, or the
	// pool is.
	ErrAnswerBusy = errors.New("admission: no room for the answer")
	// ErrOrdinaryBusy is an ordinary request that found its tenant's line full or waited OrdinaryWait for a turn.
	ErrOrdinaryBusy = errors.New("admission: no turn for the ordinary request")
	// ErrWeight is a weight the pool can never hold (a programming error: the weights are constants).
	ErrWeight = errors.New("admission: the weight is above the pool")
)

// Config is what a test changes. The zero value of every number is its constant above.
type Config struct {
	// Dir is the spool directory. Empty makes a private one under the system's temporary directory (tests); a named one
	// is emptied now and must be writable.
	Dir       string
	Places    int
	Pool      int64
	QueueWait time.Duration
	WorkLimit time.Duration
	// ReadBase is the idle bound of a body (6.5 property 3), 15 s when zero. A test shortens it.
	ReadBase time.Duration
	// AnswerPool and AnswerTenant default to the constants of the same names.
	AnswerPool, AnswerTenant int64
	// OrdinaryTenant, OrdinaryTotal, OrdinaryWaiting and OrdinaryWait default to the constants of the same names.
	OrdinaryTenant, OrdinaryTotal, OrdinaryWaiting int
	OrdinaryWait                                   time.Duration
}

// Admission is the one admission point of a process. Make it once and give it to the pipeline.
type Admission struct {
	dir       string
	places    int
	queueWait time.Duration
	workLimit time.Duration
	readBase  time.Duration
	pool      int64
	sem       *semaphore.Weighted

	mu     sync.Mutex
	taken  map[string]struct{}
	inPool int64
	queued int

	answerPool, answerTenant int64
	answers                  int64
	answersOf                map[string]int64

	// The ordinary turns: one weighted semaphore for each tenant that has a request in flight or in line, made when the
	// first arrives and dropped with the last, so the map holds no more than the requests the server holds.
	ordTenant, ordWaiting int
	ordWait               time.Duration
	ordTotal              *semaphore.Weighted
	ordinary              map[string]*turns
}

// turns is one tenant's ordinary requests: sem is the line (a semaphore of OrdinaryTenant keeps first in first out), refs
// counts those that hold or wait for a turn, and waiting those that wait.
type turns struct {
	sem           *semaphore.Weighted
	refs, waiting int
}

// New makes the admission point. It empties the spool directory (a file left by a process that died is data of a client
// who is gone) and writes a probe file into it, so that a directory that cannot be written stops the service at start
// and not at the first import.
func New(c Config) (*Admission, error) {
	a := &Admission{
		dir: c.Dir, places: c.Places, pool: c.Pool, queueWait: c.QueueWait, workLimit: c.WorkLimit, readBase: c.ReadBase,
		taken: map[string]struct{}{}, answerPool: c.AnswerPool, answerTenant: c.AnswerTenant, answersOf: map[string]int64{},
		ordTenant: c.OrdinaryTenant, ordWaiting: c.OrdinaryWaiting, ordWait: c.OrdinaryWait, ordinary: map[string]*turns{},
	}
	if a.ordTenant <= 0 {
		a.ordTenant = OrdinaryTenant
	}
	if a.ordWaiting <= 0 {
		a.ordWaiting = OrdinaryWaiting
	}
	if a.ordWait <= 0 {
		a.ordWait = OrdinaryWait
	}
	total := c.OrdinaryTotal
	if total <= 0 {
		total = OrdinaryTotal
	}
	a.ordTotal = semaphore.NewWeighted(int64(total))
	if a.answerPool <= 0 {
		a.answerPool = AnswerPool
	}
	if a.answerTenant <= 0 {
		a.answerTenant = AnswerTenant
	}
	if a.places <= 0 {
		a.places = Places
	}
	if a.pool <= 0 {
		a.pool = Pool
	}
	if a.queueWait <= 0 {
		a.queueWait = QueueWait
	}
	if a.workLimit <= 0 {
		a.workLimit = WorkLimit
	}
	a.sem = semaphore.NewWeighted(a.pool)
	if a.dir == "" {
		d, err := os.MkdirTemp("", "ctrlz-spool-")
		if err != nil {
			return nil, fmt.Errorf("admission: make the spool directory: %w", err)
		}
		a.dir = d
	} else if err := wipe(a.dir); err != nil {
		return nil, err
	}
	probe, err := os.CreateTemp(a.dir, "probe-")
	if err != nil {
		return nil, fmt.Errorf("admission: the spool directory cannot be written: %w", err)
	}
	name := probe.Name()
	_ = probe.Close()
	if err := os.Remove(name); err != nil {
		return nil, fmt.Errorf("admission: the spool directory cannot be written: %w", err)
	}
	return a, nil
}

// wipe removes the spool files of a process that died and keeps the directory (it is a volume mount point). It removes
// only the names it makes itself (spool-*, probe-*), so a directory that was named by mistake loses nothing else.
func wipe(dir string) error {
	es, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("admission: read the spool directory: %w", err)
	}
	for _, e := range es {
		if n := e.Name(); !strings.HasPrefix(n, "spool-") && !strings.HasPrefix(n, "probe-") {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			return fmt.Errorf("admission: empty the spool directory: %w", err)
		}
	}
	return nil
}

// Dir is the spool directory.
func (a *Admission) Dir() string { return a.dir }

// WorkLimit is the deadline of the work step.
func (a *Admission) WorkLimit() time.Duration { return a.workLimit }

// ReadBase is the time a body may stall before it is cut; zero means the caller's default.
func (a *Admission) ReadBase() time.Duration { return a.readBase }

// Place takes the tenant's place. A tenant has at most one (property 1), and the process has Places of them: either
// refusal is ErrBusy. The release is safe to call more than once.
func (a *Admission) Place(tenant string) (release func(), err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, held := a.taken[tenant]; held || len(a.taken) >= a.places {
		return nil, ErrBusy
	}
	a.taken[tenant] = struct{}{}
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			delete(a.taken, tenant)
			a.mu.Unlock()
		})
	}, nil
}

// Acquire waits, first in first out, for n bytes of the work pool. A request that waits QueueWait gets ErrQueueWait;
// a client that leaves (ctx is done) leaves the queue and gets the error of ctx. x/sync's semaphore keeps the order, and
// a large waiter at the head is not passed by smaller ones that arrive later.
func (a *Admission) Acquire(ctx context.Context, n int64) (release func(), err error) {
	if n <= 0 || n > a.pool {
		return nil, ErrWeight
	}
	wctx, cancel := context.WithTimeout(ctx, a.queueWait)
	defer cancel()
	a.mu.Lock()
	a.queued++
	a.mu.Unlock()
	err = a.sem.Acquire(wctx, n)
	a.mu.Lock()
	a.queued--
	a.mu.Unlock()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrQueueWait
	}
	a.mu.Lock()
	a.inPool += n
	a.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			a.inPool -= n
			a.mu.Unlock()
			a.sem.Release(n)
		})
	}, nil
}

// HoldAnswer takes n bytes of the pool of held answers for the tenant, without waiting: a refusal is ErrAnswerBusy and the
// request is 503 server_busy, which the client retries. It never waits because the bytes are freed by clients that may
// not read for 30 s, and a request parked here would be one more thing a slow reader costs. An n above a tenant's share
// is taken as the share, so one legal answer is never refused for its size alone. The release is safe to call more than once.
func (a *Admission) HoldAnswer(tenant string, n int64) (release func(), err error) {
	n = min(n, a.answerTenant, a.answerPool)
	if n <= 0 {
		return func() {}, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.answersOf[tenant]+n > a.answerTenant || a.answers+n > a.answerPool {
		return nil, ErrAnswerBusy
	}
	a.answersOf[tenant] += n
	a.answers += n
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.answers -= n
			if a.answersOf[tenant] -= n; a.answersOf[tenant] == 0 {
				delete(a.answersOf, tenant)
			}
		})
	}, nil
}

// Ordinary takes a turn for an ordinary request of the tenant: at most OrdinaryTenant of them run at once for a tenant
// and OrdinaryTotal in the process. A request that finds no turn waits in its tenant's line, first in first out, holding
// no database connection (the caller has not taken one yet); the line is OrdinaryWaiting long and a wait ends after
// OrdinaryWait. Either refusal is ErrOrdinaryBusy, and a client that leaves leaves the line with the error of ctx. The
// tenant's turn is taken before the process's, so a tenant that waits for the process holds one of its own turns and
// not another tenant's. The release is safe to call more than once.
func (a *Admission) Ordinary(ctx context.Context, tenant string) (release func(), err error) {
	a.mu.Lock()
	t := a.ordinary[tenant]
	if t == nil {
		t = &turns{sem: semaphore.NewWeighted(int64(a.ordTenant))}
		a.ordinary[tenant] = t
	}
	t.refs++
	if !t.sem.TryAcquire(1) {
		if t.waiting >= a.ordWaiting {
			a.dropLocked(tenant, t)
			a.mu.Unlock()
			return nil, ErrOrdinaryBusy
		}
		t.waiting++
		a.mu.Unlock()
		wctx, cancel := context.WithTimeout(ctx, a.ordWait)
		err = t.sem.Acquire(wctx, 1)
		cancel()
		a.mu.Lock()
		t.waiting--
		if err != nil {
			a.dropLocked(tenant, t)
		}
	}
	a.mu.Unlock()
	if err != nil {
		return nil, refusalOf(ctx)
	}
	if !a.ordTotal.TryAcquire(1) {
		wctx, cancel := context.WithTimeout(ctx, a.ordWait)
		err = a.ordTotal.Acquire(wctx, 1)
		cancel()
		if err != nil {
			t.sem.Release(1)
			a.mu.Lock()
			a.dropLocked(tenant, t)
			a.mu.Unlock()
			return nil, refusalOf(ctx)
		}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			a.ordTotal.Release(1)
			t.sem.Release(1)
			a.mu.Lock()
			a.dropLocked(tenant, t)
			a.mu.Unlock()
		})
	}, nil
}

// refusalOf names why a wait for an ordinary turn ended: the client left, or the time ran out.
func refusalOf(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrOrdinaryBusy
}

// dropLocked gives back one reference of a tenant's turns and forgets the entry with the last one.
func (a *Admission) dropLocked(tenant string, t *turns) {
	if t.refs--; t.refs == 0 && a.ordinary[tenant] == t {
		delete(a.ordinary, tenant)
	}
}

// OrdinaryTenants is how many tenants have an ordinary request in flight or in line, for tests.
func (a *Admission) OrdinaryTenants() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.ordinary)
}

// OrdinaryWaiting is how many requests of the tenant wait for a turn, for tests.
func (a *Admission) OrdinaryWaiting(tenant string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if t := a.ordinary[tenant]; t != nil {
		return t.waiting
	}
	return 0
}

// AnswersHeld is the bytes held by HoldAnswer now, for tests.
func (a *Admission) AnswersHeld() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.answers
}

// Queued is how many requests wait for weight now, for tests.
func (a *Admission) Queued() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.queued
}

// Held reports how many places are taken and how many bytes of the pool are, for tests.
func (a *Admission) Held() (places int, pool int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.taken), a.inPool
}

// Free is the pool's free weight, for tests.
func (a *Admission) Free() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pool - a.inPool
}
