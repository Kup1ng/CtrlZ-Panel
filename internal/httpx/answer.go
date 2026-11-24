package httpx

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/admission"
)

// The answers of ordinary operations whose size comes from a tenant's own data (the stored result of a job, a folder list,
// a rule create of 1,000 patterns) are encoded whole before the first byte is written, and the generated code holds the
// buffer until the write returns, so a client that does not read keeps it for as long as the server's WriteTimeout (p2-B3-r9-4,
// r10-1 to r10-3). The pipeline therefore never lets such an answer reach the connection from the handler: the first write
// above answerSpillAt goes to a file of the place's directory, the handler returns and its buffer is garbage, and the file
// is sent from the pipeline with the earned deadline of the heavy path. What a slow reader keeps is then disk, counted
// in one place (here) per tenant and for the process, and a refusal for want of room hits the tenant that holds its share,
// and another tenant only when as many tenants as there are places hold theirs.

// answerSpillAt is the size of one write above which an answer is spilled. Below it the answer goes straight to the
// connection, as it always did: a page of a catalogue or a small object is bounded by its schema and by the rate class.
const answerSpillAt = 64 << 10

// errAnswerBusy is a spilled answer for which the tenant or the process has no room: the request is 503 server_busy.
var errAnswerBusy = errors.New("httpx: no room for the answer")

// answerHold is the disk one request holds for the answer it spills.
type answerHold struct {
	adm     *admission.Admission
	tenant  string
	mu      sync.Mutex
	release []func()
	// reserved is what a handler asked for before its work (HoldAnswer) and the spill has not used yet.
	reserved int64
}

func (h *answerHold) releaseAll() {
	h.mu.Lock()
	rs := h.release
	h.release = nil
	h.mu.Unlock()
	for _, r := range rs {
		r()
	}
}

// take holds n more bytes, from the handler's reservation first.
func (h *answerHold) take(n int64) error {
	h.mu.Lock()
	use := min(h.reserved, n)
	h.reserved -= use
	h.mu.Unlock()
	if n -= use; n <= 0 {
		return nil
	}
	release, err := h.adm.HoldAnswer(h.tenant, n)
	if err != nil {
		return errAnswerBusy
	}
	h.mu.Lock()
	h.release = append(h.release, release)
	h.mu.Unlock()
	return nil
}

// HoldAnswer is for the one ordinary operation whose answer is sent after its work has been committed, a rule create: a
// refusal for want of room cannot be given then, since the rules are already written, so the handler reserves the bytes of
// its answer before it writes, and the spill uses the reservation. The answer is 503 server_busy when there is no room,
// and the client retries. A context with no holder (a request that has no tenant, a pipeline with no admission, a heavy
// operation, whose answer goes through the spool) takes nothing.
func HoldAnswer(ctx context.Context, n int64) *Error {
	h, ok := ctx.Value(keyAnswer).(*answerHold)
	if !ok {
		return nil
	}
	release, err := h.adm.HoldAnswer(h.tenant, n)
	if err != nil {
		return busy()
	}
	h.mu.Lock()
	h.release = append(h.release, release)
	h.reserved += n
	h.mu.Unlock()
	return nil
}

// answerWriter is the ResponseWriter an ordinary operation of a tenant answers to. It defers the status to the first
// write, passes an answer of at most answerSpillAt on to the connection, and spills a bigger one to a file.
type answerWriter struct {
	w    http.ResponseWriter
	hold *answerHold
	dir  string

	status int
	sent   bool // the status and the first bytes went to the connection
	sp     *spoolFile
	size   int64
	err    error // the first failure of the file, of the size cap or of the room
}

func (a *answerWriter) Header() http.Header { return a.w.Header() }

// Unwrap lets http.ResponseController reach the connection.
func (a *answerWriter) Unwrap() http.ResponseWriter { return a.w }

func (a *answerWriter) WriteHeader(code int) {
	if code < 200 {
		a.w.WriteHeader(code)
		return
	}
	if a.status == 0 && !a.sent {
		a.status = code
	}
}

func (a *answerWriter) Write(p []byte) (int, error) {
	if a.err != nil {
		return 0, a.err
	}
	if a.sp == nil {
		if a.sent || len(p) <= answerSpillAt {
			if !a.sent {
				a.sent = true
				if a.status != 0 {
					a.w.WriteHeader(a.status)
				}
			}
			return a.w.Write(p)
		}
		sp, err := newSpool(a.dir)
		if err != nil {
			a.err = err
			return 0, err
		}
		a.sp = sp
	}
	if a.size+int64(len(p)) > admission.AnswerBytes {
		a.err = errAnswerTooLarge
		return 0, a.err
	}
	if err := a.hold.take(int64(len(p))); err != nil {
		a.err = err
		return 0, err
	}
	n, err := a.sp.write(p)
	a.size += int64(n)
	if err != nil {
		a.err = err
	}
	return n, err
}

// finish sends what the handler left: a deferred status, or the spilled file with a length and the earned deadline. A
// spill that failed is the refusal that fits it, and nothing of the handler's own answer is sent.
func (a *answerWriter) finish(api *API, r *http.Request, setWrite func(time.Time)) {
	if a.sp == nil {
		if a.err != nil {
			setWrite(earnedDeadline(time.Now(), writeBase, 0))
			api.refuse(a.w, r, answerRefusal(a.err))
			return
		}
		if !a.sent && a.status != 0 {
			a.w.WriteHeader(a.status)
		}
		return
	}
	defer a.sp.close()
	start := time.Now()
	setWrite(earnedDeadline(start, writeBase, 0))
	if a.err != nil {
		api.refuse(a.w, r, answerRefusal(a.err))
		return
	}
	if a.status == 0 {
		a.status = http.StatusOK
	}
	a.w.Header().Set("Content-Length", strconv.FormatInt(a.size, 10))
	a.w.WriteHeader(a.status)
	// A cut answer closes the connection: the length it declared is not met, which net/http answers by closing.
	_ = copyOut(a.w, a.sp, a.size, start, setWrite)
}

// close removes the file when the handler panicked before finish ran.
func (a *answerWriter) close() {
	if a.sp != nil {
		a.sp.close()
	}
}

func answerRefusal(err error) *Error {
	if errors.Is(err, errAnswerTooLarge) {
		return Internal()
	}
	return busy()
}
