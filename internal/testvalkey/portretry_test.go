package testvalkey

import (
	"errors"
	"fmt"
	"testing"
)

// The message Docker gives on Windows (seen in three CI runs) and the one it gives
// on Linux must both read as a taken port, and nothing else may: a retry that also
// swallowed a missing image would hide a real failure for five attempts.
func TestPortTakenReading(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("failed to bind host port 0.0.0.0:60680/tcp: address already in use"), true},
		{fmt.Errorf("start container: %w", errors.New("Bind for 0.0.0.0:5000 failed: port is already allocated")), true},
		{errors.New("pull access denied for postgres"), false},
		{errors.New("context deadline exceeded"), false},
	} {
		if got := portTaken(tc.err); got != tc.want {
			t.Errorf("portTaken(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
