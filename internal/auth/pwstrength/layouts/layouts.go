// Package layouts holds the keyboard layout data the strength gate reads Persian
// letters through, and the code that turns it into the tables of pwstrength (spec
// 4.3, rule strength-gate-corpus).
//
// Why a package of its own: the tables used to be four constant strings typed from
// memory and then pinned by a test that copied them, so a wrong letter was
// "confirmed" by its own test (review rounds 1 and 2, primitives-r1-1, -12 and
// primitives-r2-1). Now the source of truth is a pair of data files read from the
// operating system's own layouts, the code of pwstrength is generated from them, and
// the corpus test builds its keyboard walks from the same files through a second
// path. Nothing here is imported by the serving code: pwstrength carries the
// generated result.
package layouts

import (
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

//go:embed *.tsv
var files embed.FS

// Layout is one keyboard layout: its keys, each with the US legend it shares.
type Layout struct {
	Name string // "isiri9147" or "kbdfa"; also the file name
	Keys []Key
}

// Key is one physical key. All fields are the characters the key types, as the
// operating system reports them; Normal and Shift can be several characters (a
// macro key such as the rial sign) or empty.
type Key struct {
	Scan    string
	US      string // the key on a US layout, unshifted: what a Persian letter is read as
	USShift string
	Normal  string
	Shift   string
}

// Names lists the layouts in the order pwstrength reads them: the standard first.
func Names() []string { return []string{"isiri9147", "kbdfa"} }

// Load reads one layout from the embedded data.
func Load(name string) (Layout, error) {
	b, err := files.ReadFile(name + ".tsv")
	if err != nil {
		return Layout{}, fmt.Errorf("layouts: %s: %w", name, err)
	}
	l := Layout{Name: name}
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != 5 {
			return Layout{}, fmt.Errorf("layouts: %s line %d: %d columns, want 5", name, i+1, len(cols))
		}
		k := Key{Scan: cols[0]}
		for j, dst := range []*string{&k.US, &k.USShift, &k.Normal, &k.Shift} {
			s, err := decode(cols[j+1])
			if err != nil {
				return Layout{}, fmt.Errorf("layouts: %s line %d: %w", name, i+1, err)
			}
			*dst = s
		}
		l.Keys = append(l.Keys, k)
	}
	if len(l.Keys) == 0 {
		return Layout{}, fmt.Errorf("layouts: %s: no keys", name)
	}
	return l, nil
}

// decode reads "U+0041+U+0042" into "AB". An empty cell is an empty string.
func decode(cell string) (string, error) {
	if cell == "" {
		return "", nil
	}
	var b strings.Builder
	for _, part := range strings.Split(cell, "+U+") {
		part = strings.TrimPrefix(part, "U+")
		v, err := strconv.ParseUint(part, 16, 32)
		if err != nil {
			return "", fmt.Errorf("bad code point %q", part)
		}
		b.WriteRune(rune(v))
	}
	return b.String(), nil
}

// Entry says how one character of a layout is read.
type Entry struct {
	From rune
	// To is the Latin key the character shares, or 0 when the character means
	// nothing in a walk and is dropped (a combining mark after a letter).
	To  rune
	Key string // scan code and legend, for the generated comment
}

// Entries is the reading table of the layout: every non-ASCII character a key
// types, after NFKC (the form a password is checked in), mapped to the US key it
// sits on. ASCII outputs are left alone: they are the same text on a Latin
// keyboard, and "]" typed on a Persian layout is already the key a Latin reading
// would see. A key whose output is a macro (several letters, such as the rial
// sign) has no single reading and is skipped. The result is sorted, and a
// character on two different keys is an error, because the table could not say
// which one it means.
func (l Layout) Entries() ([]Entry, error) {
	seen := map[rune]Entry{}
	add := func(r, to rune, k Key) error {
		e := Entry{From: r, To: to, Key: fmt.Sprintf("%s %q", k.Scan, k.US)}
		if old, ok := seen[r]; ok {
			if old.To == to {
				return nil
			}
			return fmt.Errorf("layouts: %s: %U is on %s and on %s", l.Name, r, old.Key, e.Key)
		}
		seen[r] = e
		return nil
	}
	for _, k := range l.Keys {
		us := []rune(k.US)
		if len(us) != 1 {
			continue // no US legend: nothing to read it as
		}
		for _, out := range []string{k.Normal, k.Shift} {
			rs := []rune(norm.NFKC.String(out))
			if len(rs) == 0 {
				continue
			}
			// "base + marks" is one key press (NFKC of U+06C0 is U+06D5 U+0654);
			// anything else is a macro.
			macro := false
			for _, m := range rs[1:] {
				if !unicode.Is(unicode.Mn, m) {
					macro = true
				}
			}
			if macro {
				// A single code point that NFKC expands into a phrase (U+FDFC, the rial sign on Shift+4 of ISIRI
				// 9147) is typed as that code point. pwstrength reads the typed rune first, so it is the key's
				// entry; the expansion would be read as the letters of the phrase (round 10, primitives-r10-8).
				if raw := []rune(out); len(raw) == 1 && raw[0] >= 0x80 && !unicode.Is(unicode.Cf, raw[0]) {
					if err := add(raw[0], us[0], k); err != nil {
						return nil, err
					}
				}
				continue
			}
			// Zero-width joiners are dropped by pwstrength for every layout, so they
			// are not table entries (ISIRI types a ZWNJ on two keys).
			if rs[0] >= 0x80 && !unicode.Is(unicode.Cf, rs[0]) {
				if err := add(rs[0], us[0], k); err != nil {
					return nil, err
				}
			}
			for _, m := range rs[1:] {
				if err := add(m, 0, k); err != nil {
					return nil, err
				}
			}
		}
	}
	out := make([]Entry, 0, len(seen))
	for _, e := range seen {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].From < out[j].From })
	return out, nil
}

// Grid places a key on the keyboard from its scan code (set 1, the same on every
// layout): row 1 is the number row, 2 the top letter row, 3 the home row and 4 the
// bottom row, and a column is the key's index in its row. The rows are contiguous
// ranges of scan codes, which is why the geometry can be read from the data and
// need not be typed. The key left of 1 (the backtick) is column -1, and the
// backslash (scan 2B) ends the top row. Space, the ISO key and the rest are not on
// the grid.
func Grid(scan string) (row, col int, ok bool) {
	v, err := strconv.ParseUint(scan, 16, 8)
	if err != nil {
		return 0, 0, false
	}
	sc := int(v)
	switch {
	case sc == 0x29:
		return 1, -1, true
	case sc >= 0x02 && sc <= 0x0D:
		return 1, sc - 0x02, true
	case sc >= 0x10 && sc <= 0x1B:
		return 2, sc - 0x10, true
	case sc == 0x2B:
		return 2, 12, true
	case sc >= 0x1E && sc <= 0x28:
		return 3, sc - 0x1E, true
	case sc >= 0x2C && sc <= 0x35:
		return 4, sc - 0x2C, true
	}
	return 0, 0, false
}

// GridPoint is a US character and where its key is.
type GridPoint struct {
	R        rune
	Row, Col int
}

// USGrid lists every character of the US legend (unshifted and shifted) with the
// place of its key. Both layouts carry the same legend; a difference between them is
// an error, because the geometry must not depend on which file was read first.
func USGrid() ([]GridPoint, error) {
	var first map[rune]GridPoint
	for _, name := range Names() {
		l, err := Load(name)
		if err != nil {
			return nil, err
		}
		cur := map[rune]GridPoint{}
		for _, k := range l.Keys {
			row, col, ok := Grid(k.Scan)
			if !ok {
				continue
			}
			for _, s := range []string{k.US, k.USShift} {
				if rs := []rune(s); len(rs) == 1 {
					cur[rs[0]] = GridPoint{rs[0], row, col}
				}
			}
		}
		if first == nil {
			first = cur
			continue
		}
		if len(cur) != len(first) {
			return nil, fmt.Errorf("layouts: %s has a different US legend", name)
		}
		for r, p := range cur {
			if first[r] != p {
				return nil, fmt.Errorf("layouts: %s places %q elsewhere", name, r)
			}
		}
	}
	out := make([]GridPoint, 0, len(first))
	for _, p := range first {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].R < out[j].R })
	return out, nil
}
