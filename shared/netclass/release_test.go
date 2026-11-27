//go:build !ctrlz_lab

package netclass

import "testing"

func TestReleaseBuildRefusesPrivatePairAddrs(t *testing.T) {
	if AllowPrivatePairAddrs {
		t.Fatal("a release build must not allow Private pair addresses")
	}
}
