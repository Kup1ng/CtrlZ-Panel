package noredirect

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/rules"
)

var testEntries = Entries{"digikala.com": ScopeDomain, "shop.example.com": ScopeHost}

func TestNameAndPattern(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"example.ir", true}, {"example.xn--mgba3a4f16a", true}, {"www.digikala.com", true},
		{"shop.example.com", true}, {"www.shop.example.com", false}, {"example.com", false},
		{"*.digikala.com", true}, {"*.shop.example.com", false}, {"@IR", true}, {"!@IR", false},
	} {
		p, err := rules.Parse(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if got := Pattern(p, testEntries); got != c.want {
			t.Errorf("Pattern(%s) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestNameEntryAboveTheLabelBoundIsNeverFound(t *testing.T) {
	// A name of 10 labels is judged by its last 8 only: an entry has at most 8 labels, so a
	// lookup of the whole name could never match and Suffixes must not ask for it.
	n := names.MustString("a.b.c.d.e.f.g.h.example.com")
	for _, s := range Suffixes(n) {
		if len(s) > 0 && countDots(s)+1 > MaxLabels {
			t.Errorf("suffix %q has more than %d labels", s, MaxLabels)
		}
	}
	if !Name(n, Entries{"d.e.f.g.h.example.com": ScopeDomain}) {
		t.Error("an entry of 6 labels under a 10 label name must match")
	}
	if Name(n, Entries{"a.b.c.d.e.f.g.h.example.com": ScopeHost}) {
		t.Error("a host entry longer than the bound is not a valid entry and must not match")
	}
}

func countDots(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			n++
		}
	}
	return n
}
