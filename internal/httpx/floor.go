package httpx

import (
	"context"
	"log"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
)

// Floor runs fn and returns no sooner than d plus up to 50 ms of random jitter,
// whatever fn returned and however fast it was (spec 2.3). It exists for the
// handlers whose time would otherwise tell an attacker something: login (a known
// phone costs an Argon2 run, an unknown one would not), OTP request, passkey
// finish.
//
// It is a thin wrapper over password.Floor, which has no HTTP in it because the
// admin CLI uses the same floor.
func Floor(ctx context.Context, d time.Duration, fn func(context.Context) error) error {
	return password.Floor(ctx, d, fn)
}

// FloorWith is Floor on a given clock, for tests.
func FloorWith(ctx context.Context, t password.Timing, d time.Duration, fn func(context.Context) error) error {
	return t.Floor(ctx, d, fn)
}

// ErrorLog returns the logger for http.Server.ErrorLog. The server writes
// messages such as "http: panic serving 10.0.0.2:5555: <value>" and "TLS
// handshake error from 10.0.0.2:5555: ...", which hold a peer address and a
// panic value. This logger keeps only a coarse class of each message and drops
// the text, and writes at most one line a second so a flood of bad requests
// cannot fill the disk.
func ErrorLog(l *slog.Logger) *log.Logger {
	return log.New(&sanitizedWriter{l: l}, "", 0)
}

// serverErrorKind is the coarse class of a message of the server's own error log: a
// closed type, so the class can be logged and the text cannot.
type serverErrorKind string

const (
	serverOther       serverErrorKind = "other"
	serverPanic       serverErrorKind = "panic"
	serverTLS         serverErrorKind = "tls_handshake"
	serverAccept      serverErrorKind = "accept"
	serverSuperfluous serverErrorKind = "superfluous_write_header"
)

// Valid reports membership.
func (k serverErrorKind) Valid() bool {
	switch k {
	case serverOther, serverPanic, serverTLS, serverAccept, serverSuperfluous:
		return true
	}
	return false
}

type sanitizedWriter struct {
	l    *slog.Logger
	last atomic.Int64
	skip atomic.Int64
}

func (w *sanitizedWriter) Write(p []byte) (int, error) {
	now := time.Now().UnixNano()
	last := w.last.Load()
	if now-last < int64(time.Second) || !w.last.CompareAndSwap(last, now) {
		w.skip.Add(1)
		return len(p), nil
	}
	msg := string(p)
	kind := serverOther
	switch {
	case strings.Contains(msg, "panic serving"):
		kind = serverPanic
	case strings.Contains(msg, "TLS handshake"):
		kind = serverTLS
	case strings.Contains(msg, "Accept error"):
		kind = serverAccept
	case strings.Contains(msg, "superfluous"):
		kind = serverSuperfluous
	}
	w.l.Warn("http server error", logattr.Enum("kind", kind), logattr.Int("suppressed", int(w.skip.Swap(0))))
	return len(p), nil
}
