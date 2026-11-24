package names

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
)

// The first eight outputs of the reference SipHash-2-4 64-bit test set (key
// 00..0f, input 00..n-1, little-endian bytes), from the authors' vectors.h.
// They pin the implementation to the published function, not to itself.
func TestSipHashPublishedVectors(t *testing.T) {
	want := [][8]byte{
		{0x31, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72},
		{0xfd, 0x67, 0xdc, 0x93, 0xc5, 0x39, 0xf8, 0x74},
		{0x5a, 0x4f, 0xa9, 0xd9, 0x09, 0x80, 0x6c, 0x0d},
		{0x2d, 0x7e, 0xfb, 0xd7, 0x96, 0x66, 0x67, 0x85},
		{0xb7, 0x87, 0x71, 0x27, 0xe0, 0x94, 0x27, 0xcf},
		{0x8d, 0xa6, 0x99, 0xcd, 0x64, 0x55, 0x76, 0x18},
		{0xce, 0xe3, 0xfe, 0x58, 0x6e, 0x46, 0xc9, 0xcb},
		{0x37, 0xd1, 0x01, 0x8b, 0xf5, 0x00, 0x02, 0xab},
	}
	var key [16]byte
	for i := range key {
		key[i] = byte(i)
	}
	in := make([]byte, 0, 16)
	for n, w := range want {
		got := Hash64(key, in)
		if got != binary.LittleEndian.Uint64(w[:]) {
			t.Errorf("len %d: got %016x want %016x", n, got, binary.LittleEndian.Uint64(w[:]))
		}
		in = append(in, byte(n))
	}
	// SipHash paper appendix A: 15-byte input.
	in = in[:0]
	for i := 0; i < 15; i++ {
		in = append(in, byte(i))
	}
	if got := Hash64(key, in); got != 0xa129ca6149be45e5 {
		t.Errorf("paper vector: got %016x", got)
	}
}

func TestFromCanonicalWireFolds(t *testing.T) {
	n, err := FromCanonicalWire([]byte("\x03WwW\x07Example\x03COM\x00"))
	if err != nil {
		t.Fatal(err)
	}
	if got := n.String(); got != "www.example.com" {
		t.Fatalf("got %q", got)
	}
	if n.Labels() != 3 {
		t.Fatalf("labels %d", n.Labels())
	}
}

func TestFromWireRejects(t *testing.T) {
	cases := map[string][]byte{
		"self pointer":    {0xC0, 0x00},
		"forward pointer": {0xC0, 0x02, 0x00},
		"truncated label": {0x05, 'a', 'b'},
		"extended label":  {0x40, 0x00},
		"no root":         {0x01, 'a'},
		"long label":      append([]byte{64}, make([]byte, 65)...),
	}
	for name, msg := range cases {
		if _, _, err := FromWire(msg, 0); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFromWirePointerAndOffset(t *testing.T) {
	// "example.com" at 0, then "www" + pointer to 0.
	msg := []byte("\x07example\x03com\x00\x03www\xC0\x00")
	n, next, err := FromWire(msg, 13)
	if err != nil {
		t.Fatal(err)
	}
	if n.String() != "www.example.com" || next != len(msg) {
		t.Fatalf("got %q next %d", n.String(), next)
	}
}

func TestNameLimit(t *testing.T) {
	// 127 one-byte labels is the longest legal name: 254 + root = 255.
	var w []byte
	for i := 0; i < 127; i++ {
		w = append(w, 1, 'a')
	}
	w = append(w, 0)
	n, err := FromCanonicalWire(w)
	if err != nil || n.Labels() != 127 {
		t.Fatalf("127 labels: %v", err)
	}
	if _, err := FromCanonicalWire(append(w[:len(w)-1], 1, 'a', 0)); err == nil {
		t.Fatal("256-byte name accepted")
	}
}

func TestSuffixes(t *testing.T) {
	n := MustString("a.b.example.com")
	var got []string
	for off, k := range n.Suffixes(3) {
		got = append(got, string(rune('0'+k))+":"+string(n.Wire()[off:off+1]))
	}
	// 3 labels first (b.example.com), then 2, then 1.
	if len(got) != 3 || got[0][0] != '3' || got[2][0] != '1' {
		t.Fatalf("got %v", got)
	}
	if !bytes.Equal(n.SuffixWire(2), []byte("\x07example\x03com\x00")) {
		t.Fatalf("SuffixWire(2) = %q", n.SuffixWire(2))
	}
}

func TestStringEscapes(t *testing.T) {
	n, err := FromCanonicalWire([]byte("\x03a.b\x02\x01\xff\x03com\x00"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := n.String(), `a\.b.\001\255.com`; got != want {
		// Label 2 is the two bytes 0x01 0xff.
		t.Fatalf("got %q want %q", got, want)
	}
	r := Root()
	if r.String() != "." {
		t.Fatal("root")
	}
}

func TestParseUser(t *testing.T) {
	ok := map[string]string{
		"Example.COM":       "example.com",
		" example.com. ":    "example.com",
		"bücher.example":    "xn--bcher-kva.example",
		"_dmarc.example.ir": "_dmarc.example.ir",
	}
	for in, want := range ok {
		n, err := ParseUser(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if n.String() != want {
			t.Errorf("%q: got %q want %q", in, n.String(), want)
		}
	}
	for _, in := range []string{"", ".", "1.2.3.4", "[::1]", "::1", "a..b", "exa mple.com", "a*b.com", "a/b.com"} {
		if _, err := ParseUser(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

// FuzzFromWire: any input must either parse into a name that satisfies the
// invariants or fail; it must never panic or loop.
func FuzzFromWire(f *testing.F) {
	f.Add([]byte("\x07example\x03com\x00"), 0)
	f.Add([]byte("\x03www\xC0\x00"), 0)
	f.Add([]byte{0xC0, 0x00}, 0)
	f.Add([]byte("\x01a\xC0\x00"), 0)
	f.Fuzz(func(t *testing.T, msg []byte, off int) {
		n, next, err := FromWire(msg, off)
		if err != nil {
			return
		}
		w := n.Wire()
		if len(w) > MaxWire || len(w) == 0 || w[len(w)-1] != 0 {
			t.Fatalf("bad wire %q", w)
		}
		if next <= off || next > len(msg) {
			t.Fatalf("next %d off %d len %d", next, off, len(msg))
		}
		// Re-parsing the canonical form must be a fixed point.
		m, err := FromCanonicalWire(w)
		if err != nil || !m.Equal(&n) {
			t.Fatalf("not a fixed point: %v", err)
		}
		for i := 0; i < n.Labels(); i++ {
			for _, b := range n.Label(i) {
				if b >= 'A' && b <= 'Z' {
					t.Fatal("unfolded byte")
				}
			}
		}
	})
}

func FuzzFromCanonicalWire(f *testing.F) {
	f.Add([]byte("\x03www\x00"))
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, w []byte) {
		n, err := FromCanonicalWire(w)
		if err != nil {
			return
		}
		_ = n.String()
		for range n.Suffixes(127) {
		}
	})
}

func FuzzParseUser(f *testing.F) {
	f.Add("example.com")
	f.Add("bücher.example")
	f.Add("1.2.3.4")
	f.Fuzz(func(t *testing.T, s string) {
		n, err := ParseUser(s)
		if err != nil {
			return
		}
		if n.IsRoot() {
			t.Fatal("ParseUser returned the root")
		}
		if _, err := FromCanonicalWire(n.Wire()); err != nil {
			t.Fatal(err)
		}
	})
}

// TestParseUserBoundsInputBeforeIDNA is the regression test for unbounded
// Punycode work: a 300 KB non-ASCII token used to take tens of seconds to
// reach its "label longer than 63 bytes" error. The guard is on time as well as
// on the error, because a fix that only moved the length check after ToASCII
// would still return the right error.
func TestParseUserBoundsInputBeforeIDNA(t *testing.T) {
	long := strings.Repeat("ü", 100_000) + ".example"
	start := time.Now()
	_, err := ParseUser(long)
	if !errors.Is(err, ErrInputLen) {
		t.Fatalf("100000-rune token: err = %v, want ErrInputLen", err)
	}
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("rejecting an oversized token took %v; the cap must run before IDNA", d)
	}
	// The boundary is on bytes, and a legal name is far below it.
	if _, err := ParseUser(strings.Repeat("a", MaxUserInput+1)); !errors.Is(err, ErrInputLen) {
		t.Errorf("MaxUserInput+1 bytes: %v", err)
	}
	if _, err := ParseUser(strings.Repeat("a", 63) + ".example.com"); err != nil {
		t.Errorf("a 63-byte label: %v", err)
	}
}
