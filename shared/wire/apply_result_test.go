package wire

import (
	"testing"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
)

// apply_ms is bounded: a node cannot report an apply that took longer than an
// hour, which would poison the hub's apply-time statistics.
func TestValidateApplyResultBounds(t *testing.T) {
	for _, c := range []struct {
		name string
		a    *hubv1.ApplyResult
		ok   bool
	}{
		{"typical", &hubv1.ApplyResult{Seq: 1, Ok: true, ApplyMs: 250}, true},
		{"at the bound", &hubv1.ApplyResult{Seq: 1, ApplyMs: MaxApplyMillis}, true},
		{"over the bound", &hubv1.ApplyResult{Seq: 1, ApplyMs: MaxApplyMillis + 1}, false},
		{"far over the bound", &hubv1.ApplyResult{Seq: 1, ApplyMs: 1<<32 - 1}, false},
		{"seq 0", &hubv1.ApplyResult{ApplyMs: 5}, false},
		{"nil", nil, false},
	} {
		if err := ValidateApplyResult(c.a); (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}
