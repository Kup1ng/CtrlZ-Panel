package totp

import (
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// rfcKey is the 20-byte SHA-1 key of RFC 6238 appendix B and RFC 4226 appendix D.
var rfcKey = []byte("12345678901234567890")

// TestRFC4226HOTPVectors: RFC 4226 appendix D, counters 0 to 9, 6 digits.
func TestRFC4226HOTPVectors(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for c, w := range want {
		if got := code(rfcKey, int64(c), 6); got != w {
			t.Errorf("HOTP counter %d = %s, want %s", c, got, w)
		}
	}
}

// TestRFC6238Vectors: RFC 6238 appendix B, SHA-1 column, 8 digits, 30 s step.
// The 6-digit code the apps show is the last six digits of the same value.
func TestRFC6238Vectors(t *testing.T) {
	for _, v := range []struct {
		unix  int64
		code8 string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	} {
		at := time.Unix(v.unix, 0)
		if got := code(rfcKey, step(at), 8); got != v.code8 {
			t.Errorf("T=%d: %s, want %s", v.unix, got, v.code8)
		}
		if got := Generate(secret.NewBytes(rfcKey), at); got != v.code8[2:] {
			t.Errorf("T=%d: 6-digit %s, want %s", v.unix, got, v.code8[2:])
		}
	}
}

// TestStepBoundaries: the step number changes exactly on multiples of 30 s.
func TestStepBoundaries(t *testing.T) {
	for unix, want := range map[int64]int64{0: 0, 29: 0, 30: 1, 59: 1, 60: 2, 1111111109: 37037036, 1111111111: 37037037} {
		if got := step(time.Unix(unix, 0)); got != want {
			t.Errorf("step(%d) = %d, want %d", unix, got, want)
		}
	}
}
