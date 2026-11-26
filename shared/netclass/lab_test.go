//go:build ctrlz_lab

package netclass

import "testing"

func TestLabBuildAllowsPrivatePairAddrs(t *testing.T) {
	if !AllowPrivatePairAddrs {
		t.Fatal("a ctrlz_lab build must allow Private pair addresses")
	}
}
