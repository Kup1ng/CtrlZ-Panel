// Package logattr is the only place a log attribute is made.
//
// A log line is a constant message and attributes from this package, and a lint
// (internal/lint, TestClosedValuesInLogs) fails any call on a *slog.Logger that
// passes anything else: no raw key and value pair, no slog.String, no slog.Any, no
// message built from data. The constructors here take numbers, bools, ids, addresses
// and values of types that name their own closed set (closed.Closed). A value
// outside its set is logged as the fixed word "invalid"; it is never cleaned up and
// never passed through. There is no constructor that takes a plain string value, and
// the lint judges this package's signatures too, so adding one fails the build of
// the tests. The three helpers that do take text (RequestID, Release, TypeName) check
// it against a fixed grammar first.
//
// This replaces the old guard (a scan for runs of digits applied to some fields),
// which each review round found a way round: review round 5, rule
// closed-values-in-logs, spec 8.6.
package logattr

import (
	"log/slog"
	"net/netip"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/closed"
)

// Invalid is what a value outside its closed set is logged as.
const Invalid = "invalid"

// Int is a count, a size, a status.
func Int(key string, n int) slog.Attr { return slog.Int(key, n) }

// Bool is a flag.
func Bool(key string, b bool) slog.Attr { return slog.Bool(key, b) }

// Duration is a length of time.
func Duration(key string, d time.Duration) slog.Attr { return slog.Duration(key, d) }

// ID is an opaque row id.
func ID(key string, id uuid.UUID) slog.Attr { return slog.String(key, id.String()) }

// Addr is a network address. An address is numbers and dots; it cannot spell text.
func Addr(key string, a netip.AddrPort) slog.Attr { return slog.String(key, a.String()) }

// Enum is a member of a closed set, or "invalid".
func Enum[T closed.Closed](key string, v T) slog.Attr {
	if !v.Valid() {
		return slog.String(key, Invalid)
	}
	return slog.String(key, string(v))
}

// Enums is a list of members of a closed set; a value off its list is logged as
// "invalid" in its place.
func Enums[T closed.Closed](key string, vs []T) slog.Attr {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = Invalid
		if v.Valid() {
			out[i] = string(v)
		}
	}
	return slog.Any(key, out)
}

// ErrClass is the class of a failure ("connection", "retry", "timeout", "other"),
// the only thing a log line says about an error: the error text can name a host, a
// user or a value. Callers choose the class; see ClassOf in the packages that know
// their error sentinels.
type ErrClass string

// The classes.
const (
	ErrConnection ErrClass = "connection"
	ErrRetry      ErrClass = "retry"
	ErrTimeout    ErrClass = "timeout"
	ErrOther      ErrClass = "other"
)

// Valid reports membership.
func (c ErrClass) Valid() bool {
	switch c {
	case ErrConnection, ErrRetry, ErrTimeout, ErrOther:
		return true
	}
	return false
}

// RequestID is the id httpx.RequestID makes: sixteen lower-case hex digits. Anything
// else (an empty header, a value a proxy added) is logged as "invalid".
func RequestID(id string) slog.Attr {
	if len(id) == 16 {
		ok := true
		for i := 0; i < len(id); i++ {
			if c := id[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				ok = false
				break
			}
		}
		if ok {
			return slog.String("request_id", id)
		}
	}
	return slog.String("request_id", Invalid)
}

// Release is the build label linked into the binary ("p0", "1.4.2-rc1"): a letter or
// digit, then letters, digits and ".", "_", "+", "-", at most 24 characters, with no
// run of ten digits. It is set by the build, not by data; the grammar is kept
// anyway so that a mis-set label cannot become a way to log a number.
func Release(v string) slog.Attr {
	const key = "version"
	if len(v) == 0 || len(v) > 24 {
		return slog.String(key, Invalid)
	}
	run := 0
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			if run++; run > 9 {
				return slog.String(key, Invalid)
			}
			continue
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c == '.' || c == '_' || c == '+' || c == '-'):
		default:
			return slog.String(key, Invalid)
		}
		run = 0
	}
	return slog.String(key, v)
}

// TypeName is the Go type of a value, for a recovered panic: the type, never the
// value. Type names are program text; the grammar below is the shape of one.
func TypeName(key string, v any) slog.Attr {
	if v == nil {
		return slog.String(key, "nil")
	}
	s := reflect.TypeOf(v).String()
	if len(s) > 80 {
		return slog.String(key, Invalid)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '*' || c == '[' || c == ']' {
			continue
		}
		return slog.String(key, Invalid)
	}
	return slog.String(key, s)
}

// Stack is the call stack of the goroutine that logs it: for each frame the function name,
// the file and the line, and nothing else. It is built from runtime.CallersFrames and not from
// debug.Stack on purpose (round 16, primitives-r16-9): the runtime's own text prints the
// arguments of every frame, and for a value passed by value (an array, an integer, a struct)
// it prints the contents, so a function that took a 16-byte key or a six-digit code as a
// parameter would have put it in the log line of any panic below it (the probe printed
// `main.encode({0xde, 0xad, ...})`). A frame here has no arguments to print, so what reaches the
// log is program text (names and paths) whatever the code below it holds, and no lint has to keep
// secret material out of by-value parameters. TestStackHoldsNoArgumentOfAFrame holds a canary in
// a frame and panics under it.
func Stack() slog.Attr {
	var pcs [maxFrames]uintptr
	// 2 skips runtime.Callers and Stack itself, so the first frame is the caller. When the stack is
	// deeper than maxFrames the innermost frames are kept, the ones nearest the failure.
	n := runtime.Callers(2, pcs[:])
	return slog.String("stack", stackText(pcs[:n]))
}

// maxFrames bounds the log line of a panic below a deep call chain.
const maxFrames = 64

// stackText writes function, file and line for each program counter, and "" for none.
func stackText(pcs []uintptr) string {
	frames := runtime.CallersFrames(pcs)
	var b strings.Builder
	for {
		f, more := frames.Next()
		if f.Function != "" {
			b.WriteString(f.Function)
			b.WriteString("\n\t")
			b.WriteString(f.File)
			b.WriteByte(':')
			b.WriteString(strconv.Itoa(f.Line))
			b.WriteByte('\n')
		}
		if !more {
			break
		}
	}
	return b.String()
}
