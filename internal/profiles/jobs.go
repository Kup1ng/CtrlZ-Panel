package profiles

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Idempotency and jobs (spec 3.5).

// keyLife is how long an idempotency key lives (D31).
const keyLife = 24 * time.Hour

// ValidKey says whether an Idempotency-Key header is 1 to 64 characters of [A-Za-z0-9_-].
func ValidKey(k string) bool {
	if len(k) < 1 || len(k) > 64 {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// Request identifies a request for the idempotency check: the key, and what makes a request the same one.
type Request struct {
	Key    string
	Method string
	Path   string // the concrete path with its ids
	Params string // the canonical query string
	Body   []byte
}

// hash is a digest of the method, the concrete path, the canonical query and the body, each length-prefixed so
// that two requests cannot collide by moving a byte from one part to the next.
func (r Request) hash() []byte {
	h := sha256.New()
	for _, p := range [][]byte{[]byte(r.Method), []byte(r.Path), []byte(r.Params), r.Body} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		h.Write(n[:])
		h.Write(p)
	}
	return h.Sum(nil)
}

// Replay is a stored answer to give again.
type Replay struct {
	Status int
	Body   []byte
}

// BeginKey is the first statement of a request that carries an Idempotency-Key. proceed is true for the
// request that claimed the key: it does its work and calls FinishKey in the same transaction. A request that
// meets a stored answer gets it back with proceed false; one that reuses the key for another request is
// KindKeyReused. A concurrent twin waits for the first to commit (the lock wait of the transaction bounds it)
// and then finds its answer.
func (e *Env) BeginKey(tx store.Tx, r Request) (proceed bool, replay Replay, err error) {
	won, stored, err := tx.IdempotencyBegin(r.Key, r.Method+" "+r.Path, r.hash(), e.now(), e.now().Add(keyLife))
	if err != nil {
		return false, Replay{}, err
	}
	if won.Yes() {
		return true, Replay{}, nil
	}
	if !stored.Same {
		return false, Replay{}, &Error{Kind: KindKeyReused}
	}
	return false, Replay{Status: stored.Status, Body: stored.Response}, nil
}

// FinishKey stores the answer next to its effect.
func (e *Env) FinishKey(tx store.Tx, r Request, status int, body []byte) error {
	return tx.IdempotencyFinish(r.Key, status, body)
}

// JobRequest is a request above JobThreshold items, validated for shape by the handler.
type JobRequest struct {
	Kind    string // the operation, closed by the handler
	Profile uuid.UUID
	Total   int
	Input   []byte // the validated request
	// Dest is set for a copy: Profile is then only read, so its lock does not refuse the job, and the profile written is
	// the one named here (spec 3.1, 7.3).
	Dest uuid.UUID
}

// QueueJob checks what needs no row work (the path profile exists and is unlocked), then records the job and its
// outbox row in the caller's transaction. A second job while one is queued or running is KindJobRunning.
// Import and Duplicate have no profile yet: Profile is the nil id.
func (e *Env) QueueJob(tx store.Tx, r JobRequest) (uuid.UUID, error) {
	if r.Profile != uuid.Nil {
		// A copy reads its source under the path profile: that one must exist, the one written must not be locked.
		written := r.Profile
		if r.Dest != uuid.Nil {
			if _, found, err := tx.ProfileLocked(r.Profile); err != nil {
				return uuid.Nil, err
			} else if !found {
				return uuid.Nil, notFound()
			}
			written = r.Dest
		}
		locked, found, err := tx.ProfileLocked(written)
		switch {
		case err != nil:
			return uuid.Nil, err
		case !found:
			return uuid.Nil, notFound()
		case locked:
			return uuid.Nil, &Error{Kind: KindLocked}
		}
	}
	id, err := tx.JobQueue(r.Kind, r.Profile, r.Total, r.Input)
	if errors.Is(err, store.ErrConflict) {
		return uuid.Nil, &Error{Kind: KindJobRunning}
	}
	return id, err
}

// jobError is the stored form of a refusal: a code and at most 100 fields, never free text.
type jobError struct {
	Code   string          `json:"code"`
	Fields []jobErrorField `json:"fields,omitempty"`
}

type jobErrorField struct {
	Name string `json:"name"`
	Code string `json:"code"`
}

// RefusalJSON turns a refusal of the work of a job into the error the job row keeps. refused is false for
// anything that is not a refusal (a database error, a lost connection): that is transient and River retries it.
func RefusalJSON(err error) (body []byte, refused bool) {
	var e *Error
	if !errors.As(err, &e) {
		return nil, false
	}
	je := jobError{Code: e.Kind.String()}
	for _, f := range e.Fields {
		je.Fields = append(je.Fields, jobErrorField{Name: f.Name, Code: f.Code})
	}
	b, _ := json.Marshal(je) // closed strings only
	return b, true
}
