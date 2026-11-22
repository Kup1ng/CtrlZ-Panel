package pwstrength

import "context"

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
	return &Checker{keymaps: c.keymaps[i : i+1], fromLatin: c.fromLatin[i : i+1], gate: c.gate}
}

// ScoreOfEntropy is the Persian layer's entropy-to-score arithmetic, for the test that compares it with
// zxcvbn-go's own.
func ScoreOfEntropy(bits float64) int { return scoreOfEntropy(bits) }

// FoldedHead is the text the Persian layer scores for a reading, after the fold.
func FoldedHead(s string) string { return foldedHead(s) }
