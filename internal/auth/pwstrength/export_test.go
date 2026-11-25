package pwstrength

import (
	"context"
	"strings"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength/layouts"
)

// Readings returns the Latin readings of s under each layout table, in table
// order (ISIRI 9147, then legacy Windows). A table that changes nothing gives
// s itself, so the index always matches the layout.
func Readings(c *Checker, s string) []string {
	out := make([]string, len(c.keymaps))
	for i, km := range c.keymaps {
		m, _ := latinFromPersian(km, s)
		out[i] = m
	}
	return out
}

// HoldSlot takes one scoring slot and returns the function that gives it back.
func HoldSlot(c *Checker) (release func()) {
	r, err := c.gate.Acquire(context.Background())
	if err != nil {
		panic(err)
	}
	return r
}

// OnlyLayout is a Checker that reads Persian letters through one layout only (0 is
// ISIRI 9147, 1 the legacy Windows layout), so a corpus run can tell which table a
// refusal came from: the default Checker reads both and a hole in one is covered by
// the other.
func OnlyLayout(c *Checker, i int) *Checker {
	return &Checker{keymaps: c.keymaps[i : i+1], fromLatin: c.fromLatin[i : i+1], presses: c.presses[i : i+1], gate: c.gate}
}

// ScoreOfEntropy is the Persian layer's entropy-to-score arithmetic, for the test that compares it with
// zxcvbn-go's own.
func ScoreOfEntropy(bits float64) int { return scoreOfEntropy(bits) }

// FoldedHead is the text the Persian layer scores for a reading, after the fold.
func FoldedHead(s string) string { return foldedHead(s) }

// OnPersianKeyboard returns what a person types, one text per layout, when they mean the Latin text s
// but the keyboard is left in Persian mode (primitives-r20-2): what the layout types on every key of s,
// shift state included, read from the layout data and not from the tables under test (primitives-r24-2:
// "[" on the shifted P of ISIRI 9147, the four letters of "rial" on the shifted R of the legacy layout, the
// Persian comma on the shifted 2). A character with no key keeps its US form. The layouts are those of
// New, in its order.
func OnPersianKeyboard(c *Checker, s string) []string {
	var out []string
	for i := range c.fromLatin {
		l, err := layouts.Load(layouts.Names()[i])
		if err != nil {
			panic(err)
		}
		typed := map[rune]string{}
		for _, k := range l.Keys {
			for _, p := range [][2]string{{k.US, k.Normal}, {k.USShift, k.Shift}} {
				if us := []rune(p[0]); len(us) == 1 && p[1] != "" {
					if _, dup := typed[us[0]]; !dup { // the ISO key repeats the backslash
						typed[us[0]] = p[1]
					}
				}
			}
		}
		var b strings.Builder
		for _, r := range s {
			if t, ok := typed[r]; ok {
				b.WriteString(t)
				continue
			}
			b.WriteRune(r)
		}
		out = append(out, b.String())
	}
	return out
}

// ZxCounts runs one check and says how many strings it asked zxcvbn about and how many of them zxcvbn
// really ran on (primitives-r26-4).
func ZxCounts(c *Checker, p password.Prepared, in Input, kind password.Kind) (lookups, runs int) {
	_, z, err := c.check(context.Background(), p, in, kind)
	if err != nil || z == nil {
		return 0, 0
	}
	return z.lookups, z.runs
}

// ScoredReadings runs one check and says how many readings of the password it scored (primitives-r26-4).
func ScoredReadings(c *Checker, p password.Prepared, in Input, kind password.Kind) int {
	_, z, err := c.check(context.Background(), p, in, kind)
	if err != nil || z == nil {
		return 0
	}
	return z.scored
}
