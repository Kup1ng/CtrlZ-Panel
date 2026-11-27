package secret_test

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// canary is a value that cannot appear by accident. If it shows up in any
// sink below, a secret reached output.
const canary = "CANARY-7f3a9c1e-do-not-print"

// holder embeds the secret the way real code does: some fields exported, one
// not. fmt cannot call methods on the unexported field and prints it by
// reflection, which is the path that would leak an inline string.
type holder struct {
	Name     string
	Exported secret.String
	private  secret.String
	nested   struct{ inner secret.String }
	Ptr      *secret.String
	List     []secret.String
	Map      map[string]secret.String
}

func newHolder() holder {
	s := secret.New(canary)
	h := holder{
		Name:     "db",
		Exported: s,
		private:  s,
		Ptr:      &s,
		List:     []secret.String{s, s},
		Map:      map[string]secret.String{"k": s},
	}
	h.nested.inner = s
	return h
}

func assertClean(t *testing.T, sink, got string) {
	t.Helper()
	if strings.Contains(got, canary) {
		t.Errorf("%s leaked the canary: %q", sink, got)
	}
	// A partial leak (the middle of the value) is still a leak.
	if strings.Contains(got, "7f3a9c1e") {
		t.Errorf("%s leaked part of the canary: %q", sink, got)
	}
}

func TestCanaryFormatVerbs(t *testing.T) {
	s := secret.New(canary)
	h := newHolder()
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%T", "%p", "%10s", "%-30v", "%08.3f", "%U", "%c", "%b", "%o", "%e"}
	for _, verb := range verbs {
		for name, v := range map[string]any{
			"value":   s,
			"pointer": &s,
			"holder":  h,
			"holderP": &h,
			"slice":   []secret.String{s},
			"map":     map[string]secret.String{"a": s},
			"any":     any(s),
			"struct":  struct{ S secret.String }{s},
			"unexp":   struct{ s secret.String }{s},
			"nested":  struct{ In struct{ s secret.String } }{struct{ s secret.String }{s}},
		} {
			assertClean(t, fmt.Sprintf("Sprintf(%s) of %s", verb, name), fmt.Sprintf(verb, v))
		}
	}
	assertClean(t, "Sprint", fmt.Sprint(s, h, &h))
	assertClean(t, "Sprintln", fmt.Sprintln(s, h, &h))
}

func TestCanaryErrors(t *testing.T) {
	s := secret.New(canary)
	err := fmt.Errorf("connect failed with %v: %w", s, errors.New("boom"))
	assertClean(t, "Errorf %v", err.Error())
	err = fmt.Errorf("connect failed: %w", fmt.Errorf("pw=%s h=%+v", s, newHolder()))
	assertClean(t, "wrapped Errorf", err.Error())
	assertClean(t, "errors.Join", errors.Join(err, fmt.Errorf("%v", s)).Error())
}

func TestCanarySlog(t *testing.T) {
	s := secret.New(canary)
	h := newHolder()
	for name, mk := range map[string]func(*bytes.Buffer) slog.Handler{
		"json": func(b *bytes.Buffer) slog.Handler {
			return slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: true})
		},
		"text": func(b *bytes.Buffer) slog.Handler {
			return slog.NewTextHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			l := slog.New(mk(&buf))
			l.Info("direct", "password", s)
			l.Info("any", slog.Any("password", s), slog.Any("ptr", &s))
			l.Info("struct", "cfg", h, "cfgp", &h)
			l.Info("group", slog.Group("db", slog.Any("pw", s), slog.String("name", "x")))
			l.Info("slice", "list", []secret.String{s}, "map", map[string]secret.String{"k": s})
			l.With("pw", s).WithGroup("g").With("pw2", s).Warn("with")
			l.Error("err", "err", fmt.Errorf("failed: %v", s))
			l.Debug("sprintf", "msg", fmt.Sprintf("%v %+v", s, h))
			assertClean(t, "slog "+name, buf.String())
			if !strings.Contains(buf.String(), secret.Redacted) {
				t.Errorf("slog %s output has no redaction marker: %q", name, buf.String())
			}
		})
	}
}

func TestCanaryEncoders(t *testing.T) {
	s := secret.New(canary)
	h := newHolder()
	for name, v := range map[string]any{"value": s, "holder": h, "pointer": &h, "map": map[string]secret.String{"k": s}} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("json.Marshal %s: %v", name, err)
		}
		assertClean(t, "json "+name, string(b))
		b, err = json.MarshalIndent(v, "", " ")
		if err != nil {
			t.Fatalf("json.MarshalIndent %s: %v", name, err)
		}
		assertClean(t, "json indent "+name, string(b))
	}
	// A secret used as a map key goes through MarshalText.
	b, err := json.Marshal(map[secret.String]int{s: 1})
	if err != nil {
		t.Fatal(err)
	}
	assertClean(t, "json map key", string(b))
	b, err = s.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	assertClean(t, "MarshalText", string(b))
}

func TestCanaryRecoveredPanic(t *testing.T) {
	s := secret.New(canary)
	func() {
		defer func() {
			r := recover()
			assertClean(t, "recovered panic value", fmt.Sprint(r))
		}()
		panic(s)
	}()
}

func TestRevealIsTheOnlyWayOut(t *testing.T) {
	s := secret.New(canary)
	if got := s.Reveal(); got != canary {
		t.Fatalf("Reveal() = %q, want the canary (positive control)", got)
	}
	if s.IsZero() {
		t.Error("IsZero() on a set secret")
	}
	var zero secret.String
	if !zero.IsZero() || zero.Reveal() != "" {
		t.Error("zero value must be the empty secret")
	}
	if secret.New("").Reveal() != "" || !secret.New("").IsZero() {
		t.Error("empty secret")
	}
	if !s.Equal(secret.New(canary)) || s.Equal(secret.New("other")) || s.Equal(zero) {
		t.Error("Equal")
	}
	if got := fmt.Sprint(zero); got != secret.Redacted {
		t.Errorf("zero value prints %q, want the marker (an empty secret must not look different)", got)
	}
}

func TestUnmarshalText(t *testing.T) {
	var cfg struct {
		Password secret.String `json:"password"`
	}
	// JSON strings reach UnmarshalText through the text-unmarshaler fallback.
	if err := json.Unmarshal([]byte(`{"password":"`+canary+`"}`), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Password.Reveal() != canary {
		t.Errorf("round trip lost the value")
	}
	assertClean(t, "decoded config", fmt.Sprintf("%+v %v", cfg, cfg))
}

func TestFromFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pw")
	if err := os.WriteFile(p, []byte(canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := secret.FromFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if s.Reveal() != canary {
		t.Errorf("FromFile did not trim one trailing newline")
	}
	if _, err := secret.FromFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file must be an error")
	} else {
		assertClean(t, "FromFile error", err.Error())
	}
}

// The tests below hold secret.Bytes to the same rules as secret.String
// (spec 8.2, 18.4). The extra sinks are the ones a byte slice invites: %x and
// the hex or base64 of the content.

var canaryBytes = []byte(canary)

// bytesHolder is holder for Bytes: exported, unexported, nested, pointer,
// slice and map fields.
type bytesHolder struct {
	Name     string
	Exported secret.Bytes
	private  secret.Bytes
	nested   struct{ inner secret.Bytes }
	Ptr      *secret.Bytes
	List     []secret.Bytes
	Map      map[string]secret.Bytes
}

func newBytesHolder() bytesHolder {
	s := secret.NewBytes(canaryBytes)
	h := bytesHolder{
		Name:     "key",
		Exported: s,
		private:  s,
		Ptr:      &s,
		List:     []secret.Bytes{s, s},
		Map:      map[string]secret.Bytes{"k": s},
	}
	h.nested.inner = s
	return h
}

// assertCleanBytes also looks for the encodings a byte slice is printed in.
func assertCleanBytes(t *testing.T, sink, got string) {
	t.Helper()
	assertClean(t, sink, got)
	for name, enc := range map[string]string{
		"hex":    fmt.Sprintf("%x", canaryBytes),
		"HEX":    fmt.Sprintf("%X", canaryBytes),
		"base64": base64.StdEncoding.EncodeToString(canaryBytes),
		"url64":  base64.RawURLEncoding.EncodeToString(canaryBytes),
		"list":   fmt.Sprint(canaryBytes[:8]),
	} {
		if strings.Contains(got, enc) {
			t.Errorf("%s leaked the canary as %s: %q", sink, name, got)
		}
	}
}

func TestCanaryBytesFormatVerbs(t *testing.T) {
	s := secret.NewBytes(canaryBytes)
	h := newBytesHolder()
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%T", "%p", "%10s", "%-30v", "%08.3f", "%U", "%c", "%b", "%o", "%e", "% x", "%#x"}
	for _, verb := range verbs {
		for name, v := range map[string]any{
			"value":   s,
			"pointer": &s,
			"holder":  h,
			"holderP": &h,
			"slice":   []secret.Bytes{s},
			"map":     map[string]secret.Bytes{"a": s},
			"any":     any(s),
			"struct":  struct{ S secret.Bytes }{s},
			"unexp":   struct{ s secret.Bytes }{s},
			"nested":  struct{ In struct{ s secret.Bytes } }{struct{ s secret.Bytes }{s}},
		} {
			assertCleanBytes(t, fmt.Sprintf("Sprintf(%s) of %s", verb, name), fmt.Sprintf(verb, v))
		}
	}
	assertCleanBytes(t, "Sprint", fmt.Sprint(s, h, &h))
	assertCleanBytes(t, "Sprintln", fmt.Sprintln(s, h, &h))
	if got := fmt.Sprint(secret.Bytes{}); got != secret.Redacted {
		t.Errorf("zero Bytes prints %q, want the marker", got)
	}
}

func TestCanaryBytesErrorsAndPanic(t *testing.T) {
	s := secret.NewBytes(canaryBytes)
	err := fmt.Errorf("open failed with %v: %w", s, errors.New("boom"))
	assertCleanBytes(t, "Errorf", err.Error())
	assertCleanBytes(t, "errors.Join", errors.Join(err, fmt.Errorf("%+v", newBytesHolder())).Error())
	func() {
		defer func() { assertCleanBytes(t, "recovered panic", fmt.Sprint(recover())) }()
		panic(s)
	}()
}

func TestCanaryBytesSlog(t *testing.T) {
	s := secret.NewBytes(canaryBytes)
	h := newBytesHolder()
	for name, mk := range map[string]func(*bytes.Buffer) slog.Handler{
		"json": func(b *bytes.Buffer) slog.Handler {
			return slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: true})
		},
		"text": func(b *bytes.Buffer) slog.Handler {
			return slog.NewTextHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			l := slog.New(mk(&buf))
			l.Info("direct", "key", s)
			l.Info("any", slog.Any("key", s), slog.Any("ptr", &s))
			l.Info("struct", "cfg", h, "cfgp", &h)
			l.Info("group", slog.Group("k", slog.Any("key", s)))
			l.Info("slice", "list", []secret.Bytes{s}, "map", map[string]secret.Bytes{"k": s})
			l.With("key", s).WithGroup("g").With("key2", s).Warn("with")
			l.Error("err", "err", fmt.Errorf("failed: %v", s))
			assertCleanBytes(t, "slog "+name, buf.String())
			if !strings.Contains(buf.String(), secret.Redacted) {
				t.Errorf("slog %s output has no redaction marker: %q", name, buf.String())
			}
		})
	}
}

func TestCanaryBytesEncoders(t *testing.T) {
	s := secret.NewBytes(canaryBytes)
	h := newBytesHolder()
	for name, v := range map[string]any{"value": s, "holder": h, "pointer": &h, "map": map[string]secret.Bytes{"k": s}, "slice": []secret.Bytes{s}} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("json.Marshal %s: %v", name, err)
		}
		assertCleanBytes(t, "json "+name, string(b))
	}
	b, err := json.Marshal(map[string]any{"k": s})
	if err != nil {
		t.Fatal(err)
	}
	assertCleanBytes(t, "json any map", string(b))
	for name, f := range map[string]func() ([]byte, error){"text": s.MarshalText, "binary": s.MarshalBinary, "json": s.MarshalJSON} {
		b, err := f()
		if err != nil {
			t.Fatal(err)
		}
		assertCleanBytes(t, "Marshal "+name, string(b))
	}
	// gob prefers MarshalBinary over reflection, so a Bytes in a struct must
	// come out as the marker.
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(struct{ K secret.Bytes }{s}); err != nil {
		t.Fatal(err)
	}
	assertCleanBytes(t, "gob", buf.String())
}

func TestBytesRules(t *testing.T) {
	src := append([]byte(nil), canaryBytes...)
	s := secret.NewBytes(src)
	clear(src) // the caller wipes its own copy
	if !bytes.Equal(s.Reveal(), canaryBytes) {
		t.Fatal("NewBytes did not copy: wiping the source changed the secret")
	}
	if s.Len() != len(canaryBytes) || s.IsZero() {
		t.Error("Len or IsZero on a set secret")
	}
	var zero secret.Bytes
	if !zero.IsZero() || zero.Len() != 0 || zero.Reveal() != nil || !secret.NewBytes(nil).IsZero() {
		t.Error("zero value must be the empty secret")
	}
	if !s.Equal(secret.NewBytes(canaryBytes)) || s.Equal(secret.NewBytes([]byte("other"))) || s.Equal(zero) || !zero.Equal(secret.Bytes{}) {
		t.Error("Equal")
	}
	// Wipe clears every holder of the same secret.
	t2 := s
	s.Wipe()
	if bytes.Contains(t2.Reveal(), []byte("CANARY")) {
		t.Error("Wipe left the content")
	}
	zero.Wipe() // must not panic
	var d secret.Bytes
	if err := d.UnmarshalText([]byte(canary)); err != nil || string(d.Reveal()) != canary {
		t.Error("UnmarshalText")
	}
}

func TestBytesFromFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "key")
	raw := append(append([]byte{0, 1, 2}, canaryBytes...), '\n')
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := secret.BytesFromFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.Reveal(), raw) {
		t.Error("BytesFromFile must return the file exactly, newline included")
	}
	if _, err := secret.BytesFromFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file must be an error")
	} else {
		assertClean(t, "BytesFromFile error", err.Error())
	}
}
