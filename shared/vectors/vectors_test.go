package vectors

import "testing"

// TestReferenceHarness runs every golden vector through the panel's reference
// harness. The node runs the same files through its own harness.
func TestReferenceHarness(t *testing.T) {
	Run(t, Reference{})
}
