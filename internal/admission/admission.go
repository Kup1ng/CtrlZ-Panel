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
	// AnswerBytes is the most an answer may have: above it the request is a 500. A test holds the largest export there can
	// be below it.
	AnswerBytes = 16 << 20
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
}

// Admission is the one admission point of a process. Make it once and give it to the pipeline.
type Admission struct {
	dir       string
	places    int
	queueWait time.Duration
	workLimit time.Duration
	pool      int64
	sem       *semaphore.Weighted

	mu     sync.Mutex
	taken  map[string]struct{}
	inPool int64
	queued int
}

// New makes the admission point. It empties the spool directory (a file left by a process that died is data of a client
// who is gone) and writes a probe file into it, so that a directory that cannot be written stops the service at start
// and not at the first import.
func New(c Config) (*Admission, error) {
	a := &Admission{
		dir: c.Dir, places: c.Places, pool: c.Pool, queueWait: c.QueueWait, workLimit: c.WorkLimit,
		taken: map[string]struct{}{},
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
