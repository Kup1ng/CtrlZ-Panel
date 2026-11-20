package logattr_test

import (
	"bytes"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
)

type colour string

func (c colour) Valid() bool { return c == "red" || c == "green" }

func value(a slog.Attr) string { return a.Value.String() }

func TestEnumLogsOnlyMembers(t *testing.T) {
	if got := value(logattr.Enum("c", colour("red"))); got != "red" {
		t.Errorf("member: %q", got)
	}
	for _, off := range []colour{"", "blue", "09121234567", "०९१२१२३४५६७८९०", "red\n"} {
		if got := value(logattr.Enum("c", off)); got != logattr.Invalid {
			t.Errorf("%q logged as %q", off, got)
		}
	}
	list := logattr.Enums("cs", []colour{"red", "09121234567", "green"})
	if got := value(list); strings.Contains(got, "912") || !strings.Contains(got, "red") || !strings.Contains(got, logattr.Invalid) {
		t.Errorf("list: %q", got)
	}
	if got := value(logattr.Enum("e", logattr.ErrTimeout)); got != "timeout" {
		t.Errorf("error class: %q", got)
	}
	if got := value(logattr.Enum("e", logattr.ErrClass("x"))); got != logattr.Invalid {
		t.Errorf("off-list class: %q", got)
	}
}

func TestRequestID(t *testing.T) {
	if got := value(logattr.RequestID("0123456789abcdef")); got != "0123456789abcdef" {
		t.Errorf("a real id: %q", got)
	}
	for _, bad := range []string{"", "0123456789ABCDEF", "0123456789abcde", "0123456789abcdef0", "09121234567xxxxx", "g123456789abcdef", "०१२३४५६७८९०१२३४५"} {
		if got := value(logattr.RequestID(bad)); got != logattr.Invalid {
			t.Errorf("%q logged as %q", bad, got)
		}
	}
}

func TestRelease(t *testing.T) {
	for _, ok := range []string{"p0", "1.4.2-rc1", "v2026.11+build.7"} {
		if got := value(logattr.Release(ok)); got != ok {
			t.Errorf("%q logged as %q", ok, got)
		}
	}
	for _, bad := range []string{"", "-x", ".1", "a b", "a/b", "09121234567", "v09121234567", strings.Repeat("a", 25), "٠١٢", "a\n"} {
		if got := value(logattr.Release(bad)); got != logattr.Invalid {
			t.Errorf("%q logged as %q", bad, got)
		}
	}
}

type secretError struct{ Value string }

func TestTypeNameLogsTheTypeNeverTheValue(t *testing.T) {
	if got := value(logattr.TypeName("t", secretError{"09121234567"})); got != "logattr_test.secretError" {
		t.Errorf("got %q", got)
	}
	if got := value(logattr.TypeName("t", "09121234567")); got != "string" {
		t.Errorf("got %q", got)
	}
	if got := value(logattr.TypeName("t", nil)); got != "nil" {
		t.Errorf("got %q", got)
	}
}

func TestOthers(t *testing.T) {
	id := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	if value(logattr.ID("i", id)) != id.String() || value(logattr.Int("n", 7)) != "7" || value(logattr.Bool("b", true)) != "true" {
		t.Error("plain kinds")
	}
	if got := value(logattr.Addr("a", netip.MustParseAddrPort("127.0.0.1:8080"))); got != "127.0.0.1:8080" {
		t.Errorf("addr %q", got)
	}
	if !strings.Contains(value(logattr.Stack()), "TestOthers") {
		t.Error("stack")
	}
}

// A handler that logs through the package writes nothing but the closed values.
func TestThroughAHandler(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("x", logattr.Enum("c", colour("09121234567")), logattr.Int("n", 1))
	if strings.Contains(buf.String(), "912") || !strings.Contains(buf.String(), `"c":"invalid"`) {
		t.Errorf("%s", buf.String())
	}
}

// canaryKey is passed by value to a function that panics below. Go's own stack text prints the
// contents of such an argument, so this is the shape that put a key in a log line.
type canaryKey [16]byte

//go:noinline
func holdsTheKeyByValue(k canaryKey, f func()) byte {
	f()
	return k[0]
}

// TestStackHoldsNoArgumentOfAFrame is primitives-r16-9. A panic is recovered below a frame whose
// parameter is a by-value secret; the logged stack names the frame and holds none of the bytes.
func TestStackHoldsNoArgumentOfAFrame(t *testing.T) {
	canary := canaryKey{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x13, 0x37, 0xc0, 0xde, 0xfa, 0xce, 0xb0, 0x0c}
	var got string
	func() {
		defer func() {
			recover()
			got = value(logattr.Stack())
		}()
		holdsTheKeyByValue(canary, func() {
			var m map[string]int
			m["x"] = 1
		})
	}()
	if !strings.Contains(got, "holdsTheKeyByValue") {
		t.Fatalf("the stack does not name the frame under test:\n%s", got)
	}
	for _, needle := range []string{"0xde", "0xad", "0xbe", "0xef", "0xca", "0xfe", "0xc0", "0xb0", "{0x", "(0x"} {
		if strings.Contains(got, needle) {
			t.Errorf("the stack holds %q, so it prints argument words:\n%s", needle, got)
		}
	}
	// Every line is a function name or a tab, a path and a line number: nothing else is let in.
	for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if strings.HasPrefix(line, "\t") {
			if !strings.Contains(line, ":") {
				t.Errorf("a position line without a line number: %q", line)
			}
			continue
		}
		if strings.ContainsAny(line, " {}") && !strings.Contains(line, "[...]") {
			t.Errorf("a function line with arguments: %q", line)
		}
	}
}

// recurse calls Stack at the bottom of a chain n deep.
//
//go:noinline
func recurse(n int) string {
	if n == 0 {
		return value(logattr.Stack())
	}
	return recurse(n-1) + ""
}

// TestStackIsBoundedAndKeepsTheInnermostFrames pins what the machinery answer of primitives-r16-9 says:
// a chain deeper than the bound is cut to MaxFrames frames and the end kept is the one nearest the
// failure, because a panic is read from the bottom up.
func TestStackIsBoundedAndKeepsTheInnermostFrames(t *testing.T) {
	got := recurse(500)
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	frames := 0
	for _, l := range lines {
		if !strings.HasPrefix(l, "\t") {
			frames++
		}
	}
	if frames != logattr.MaxFrames {
		t.Errorf("%d frames in a chain of 500, want the bound %d", frames, logattr.MaxFrames)
	}
	if !strings.HasPrefix(lines[0], "github.com/Kup1ng/CtrlZ-Panel/internal/logattr_test.recurse") {
		t.Errorf("the first frame is not the innermost one: %q", lines[0])
	}
	if strings.Contains(got, "testing.tRunner") {
		t.Error("the outermost frame is kept in a chain deeper than the bound")
	}
	// A shallow chain keeps its outermost frame.
	if !strings.Contains(recurse(3), "testing.tRunner") {
		t.Error("a shallow chain lost its outermost frame")
	}
}

// TestStackOfNoFramesIsEmptyAndDoesNotPanic is the zero-frame answer.
func TestStackOfNoFramesIsEmptyAndDoesNotPanic(t *testing.T) {
	if got := logattr.StackText(nil); got != "" {
		t.Errorf("no frames gave %q, want the empty string", got)
	}
	if got := logattr.StackText([]uintptr{}); got != "" {
		t.Errorf("an empty list gave %q", got)
	}
}
