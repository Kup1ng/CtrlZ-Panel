package wire

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/zone"
)

// zone cannot import wire (it is the pure decision package), so the two copies
// of the slot and pair bounds are held equal here: ValidatePairTable admits
// exactly the tables zone.Build can hold.
func TestZoneLimitsMatchWire(t *testing.T) {
	if zone.MaxNodes != MaxNodes {
		t.Fatalf("zone.MaxNodes = %d, wire.MaxNodes = %d", zone.MaxNodes, MaxNodes)
	}
	if zone.MaxPairs != MaxNodes*MaxNodes {
		t.Fatalf("zone.MaxPairs = %d, want %d", zone.MaxPairs, MaxNodes*MaxNodes)
	}
}
