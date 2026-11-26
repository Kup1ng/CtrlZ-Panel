package rules

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Shared/names"
)

func TestParseValid(t *testing.T) {
	cases := []struct {
		in      string
		kind    Kind
		neg     bool
		key     string
		lit     int
		litByte int
	}{
		{"domain.com", KindDomain, false, "domain.com", 2, 9},
		{"Domain.COM.", KindDomain, false, "domain.com", 2, 9},
		{"ir", KindDomain, false, "ir", 1, 2},
		{"*.domain.com", KindSubdomains, false, "*.domain.com", 2, 9},
		{"server-*.domain.com", KindGlob, false, "server-*.domain.com", 2, 16},
		{"a.*.domain.com", KindGlob, false, "a.*.domain.com", 2, 10},
		{"@ir", KindDestCC, false, "@IR", 0, 0},
		{"!@IR", KindDestCC, true, "!@IR", 0, 0},
		{"#ir", KindSrcCC, false, "#IR", 0, 0},
		{"!#IR", KindSrcCC, true, "!#IR", 0, 0},
		{"@AS1234", KindDestAS, false, "@AS1234", 0, 0},
		{"!@as4294967295", KindDestAS, true, "!@AS4294967295", 0, 0},
		{"@AS", KindDestCC, false, "@AS", 0, 0}, // American Samoa, not an ASN
		{"bücher.example", KindDomain, false, "xn--bcher-kva.example", 2, 20},
	}
	for _, c := range cases {
		p, err := Parse(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if p.Kind != c.kind || p.Negated != c.neg || p.Key() != c.key {
			t.Errorf("%q: kind %v neg %v key %q", c.in, p.Kind, p.Negated, p.Key())
		}
		if c.kind.IsName() && (p.LitLabels != c.lit || p.LitBytes != c.litByte) {
			t.Errorf("%q: lit labels %d bytes %d", c.in, p.LitLabels, p.LitBytes)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	bad := []string{
		"", " ", "!", "!domain.com", "@", "@I", "@IRN", "@1R", "#AS1234", "!#AS5", "@AS0", "@AS01", "@AS4294967296", "@AS-1", "@AS+1",
		"1.2.3.4", "[::1]", "*", "*.", "*.ir", "*.co.uk", "*.com", "a.*", "**.domain.com", "*.*.domain.com", "a*b*.domain.com",
		"*.1.2.3.4", "exa*ple.com", "bü*.example.com", "a..b", "*.domain.com/x", "*a.b*.domain.com",
	}
	for _, in := range bad {
		if p, err := Parse(in); err == nil {
			t.Errorf("%q accepted as %+v", in, p)
		}
	}
}

func TestLiteralSuffix(t *testing.T) {
	p, _ := Parse("a.*.domain.com")
	if got := string(p.LiteralSuffix()); got != "\x06domain\x03com\x00" {
		t.Fatalf("%q", got)
	}
	p, _ = Parse("server-*.domain.com")
	if got := string(p.LiteralSuffix()); got != "\x06domain\x03com\x00" {
		t.Fatalf("%q", got)
	}
	p, _ = Parse("*.domain.com")
	if got := string(p.LiteralSuffix()); got != "\x06domain\x03com\x00" {
		t.Fatalf("%q", got)
	}
}

func TestMergeUpload(t *testing.T) {
	existing := []Item{{"a.com", "f1", "block"}, {"b.com", "f1", "bypass"}, {"c.com", "f2", "block"}}
	incoming := []Item{{"a.com", "f1", "bypass"}, {"b.com", "f1", "bypass"}, {"c.com", "f1", "block"}, {"d.com", "f1", "block"}}
	nr := MergeUpload(existing, incoming, UploadNewOnly)
	if nr.Created != 1 || nr.Updated != 0 || nr.Skipped != 2 || nr.Conflicts != 1 {
		t.Fatalf("new_only %+v", nr)
	}
	up := MergeUpload(existing, incoming, UploadUpsert)
	if up.Created != 1 || up.Updated != 1 || up.Skipped != 1 || up.Conflicts != 1 {
		t.Fatalf("upsert %+v", up)
	}
	if len(up.Merged) != 4 {
		t.Fatalf("nothing may be deleted: %v", up.Merged)
	}
	for _, it := range up.Merged {
		if it.Key == "c.com" && it.Folder != "f2" {
			t.Fatal("conflicting key moved folders")
		}
		if it.Key == "a.com" && it.Payload != "bypass" {
			t.Fatal("upsert did not update")
		}
	}
	// Existing slice must not be modified.
	if existing[0].Payload != "block" {
		t.Fatal("input mutated")
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"domain.com", "*.domain.com", "server-*.domain.com", "a.*.domain.com", "@IR", "!@AS1", "#ir", "!#IR", "*.co.uk", "bücher.*.example.com", "!", "@AS"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := Parse(s)
		if err != nil {
			return
		}
		k := p.Key()
		if k == "" {
			t.Fatalf("empty key for %q", s)
		}
		// rule_key must be a fixed point: parsing the key gives the same key.
		q, err := Parse(k)
		if err != nil {
			t.Fatalf("key %q of %q does not parse: %v", k, s, err)
		}
		if q.Key() != k || q.Kind != p.Kind || q.Negated != p.Negated {
			t.Fatalf("key %q of %q is not stable: %+v", k, s, q)
		}
		if p.Kind.IsName() {
			if strings.Count(k, "*") > 1 {
				t.Fatalf("%q", k)
			}
			_ = p.LiteralSuffix()
		}
	})
}

// TestParseBoundsInputBeforeAnyWork: Parse must refuse an oversized token
// first, for the plain, glob and negated-geo paths alike.
func TestParseBoundsInputBeforeAnyWork(t *testing.T) {
	big := strings.Repeat("ü", 50_000)
	for _, in := range []string{big, big + ".example.com", "*." + big + ".com", "x*" + strings.Repeat("a", 5000) + ".example.com", "!@" + strings.Repeat("A", 5000)} {
		start := time.Now()
		if _, err := Parse(in); !errors.Is(err, names.ErrInputLen) {
			t.Errorf("%.20q...: err = %v, want names.ErrInputLen", in, err)
		}
		if d := time.Since(start); d > 200*time.Millisecond {
			t.Errorf("%.20q...: took %v", in, d)
		}
	}
}
