package httpx

import (
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/admission"
)

// The spool of a heavy request (docs/specs/p2-profiles.md 6.5). Its body is copied to a file while the client sends,
// the work reads the file once in one buffer of its known size, and the answer is written to the same file and sent from
// it after the work has given its weight back. So no body and no answer of a heavy operation sits in memory while a
// client is slow, and nothing is sized from a length the client declared.

// spoolChunk is the one buffer a place holds while its client sends or reads, and the unit of the earned time below.
const spoolChunk = 32 << 10

// The earned deadlines of 6.5 property 3. Before each read of the body the deadline of the connection is set to the start
// of the body plus readBase plus one second for each spoolChunk received; before each write of the answer, to the start of
// the answer plus writeBase plus one second for each spoolChunk sent. One formula is the idle bound (a stalled body is cut
// at readBase), the pace (a byte every few seconds earns nothing) and the total (6 MiB passes at 0.25 Mbit/s and is cut
// at 207 s at the latest). The server's ReadTimeout and WriteTimeout do not apply to a heavy request: these replace them.
const (
	readBase  = 15 * time.Second
	writeBase = 30 * time.Second
)

// earnedDeadline is start + base + one second for each spoolChunk of n.
func earnedDeadline(start time.Time, base time.Duration, n int64) time.Time {
	return start.Add(base + time.Duration(n/spoolChunk)*time.Second)
}

var (
	// errSpoolWrite is a file that cannot be made or written (no disk): the request is 503 server_busy.
	errSpoolWrite = errors.New("httpx: the spool file cannot be written")
	// errAnswerTooLarge is an answer above admission.AnswerBytes: the request is a 500.
	errAnswerTooLarge = errors.New("httpx: the answer is larger than the spool allows")
)

// spoolFile is the file of one place. It has mode 0600 (os.CreateTemp), its name is removed as soon as it is open where the
// system allows it, and the only way to it is this handle, so no request can open another's.
type spoolFile struct {
	f        *os.File
	name     string
	unlinked bool
	// off is the next write position: the body is written from 0, and the answer from 0 again after reset.
	off int64
}

func newSpool(dir string) (*spoolFile, error) {
	f, err := os.CreateTemp(dir, "spool-")
	if err != nil {
		return nil, errSpoolWrite
	}
	s := &spoolFile{f: f, name: f.Name()}
	// Windows does not remove an open file; the name is then removed by close.
	if os.Remove(s.name) == nil {
		s.unlinked = true
	}
	return s, nil
}

func (s *spoolFile) close() {
	_ = s.f.Close()
	if !s.unlinked {
		_ = os.Remove(s.name)
	}
}

func (s *spoolFile) write(p []byte) (int, error) {
	n, err := s.f.WriteAt(p, s.off)
	s.off += int64(n)
	if err != nil {
		return n, errSpoolWrite
	}
	return n, nil
}

// reset empties the file for the answer.
func (s *spoolFile) reset() error {
	s.off = 0
	if err := s.f.Truncate(0); err != nil {
		return errSpoolWrite
	}
	return nil
}

// readAll reads the first size bytes into one buffer of exactly that size.
func (s *spoolFile) readAll(size int64) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(io.NewSectionReader(s.f, 0, size), buf); err != nil {
		return nil, errSpoolWrite
	}
	return buf, nil
}

// copyIn copies body to the file with one buffer of spoolChunk, setting the read deadline before each read. It returns the
// bytes written. An error of the file is errSpoolWrite; any other is the body's own (a cut, a limit, a client that left).
func copyIn(sp *spoolFile, body io.Reader, start time.Time, base time.Duration, setDeadline func(time.Time)) (int64, error) {
	buf := make([]byte, spoolChunk)
	var n int64
	for {
		setDeadline(earnedDeadline(start, base, n))
		m, err := body.Read(buf)
		if m > 0 {
			if _, werr := sp.write(buf[:m]); werr != nil {
				return n, werr
			}
			n += int64(m)
		}
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
}

// copyOut sends the first size bytes of the file, setting the write deadline before each write.
func copyOut(w io.Writer, sp *spoolFile, size int64, start time.Time, setDeadline func(time.Time)) error {
	buf := make([]byte, spoolChunk)
	var sent int64
	for sent < size {
		want := min(int64(len(buf)), size-sent)
		m, err := sp.f.ReadAt(buf[:want], sent)
		if m == 0 && err != nil {
			return err
		}
		setDeadline(earnedDeadline(start, writeBase, sent))
		if _, err := w.Write(buf[:m]); err != nil {
			return err
		}
		sent += int64(m)
	}
	return nil
}

// spoolWriter is the ResponseWriter the work step answers to: it keeps the status and writes the body to the file. Its
// Header is the real writer's map, so what the handlers put there (cookies through the outbox, the content type) is what
// the client gets.
type spoolWriter struct {
	hdr    http.Header
	sp     *spoolFile
	status int
	size   int64
	err    error // the first failure of the file or of the size cap
}

func newSpoolWriter(w http.ResponseWriter, sp *spoolFile) (*spoolWriter, error) {
	if err := sp.reset(); err != nil {
		return nil, err
	}
	return &spoolWriter{hdr: w.Header(), sp: sp}, nil
}

func (w *spoolWriter) Header() http.Header { return w.hdr }

func (w *spoolWriter) WriteHeader(code int) {
	if w.status == 0 && code >= 200 {
		w.status = code
	}
}

func (w *spoolWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.err != nil {
		return 0, w.err
	}
	if w.size+int64(len(p)) > admission.AnswerBytes {
		w.err = errAnswerTooLarge
		return 0, w.err
	}
	n, err := w.sp.write(p)
	w.size += int64(n)
	if err != nil {
		w.err = err
	}
	return n, w.err
}
