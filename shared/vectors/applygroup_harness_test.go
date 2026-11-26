package vectors

import "testing"

// countingApply is a harness that is the reference one and also an ApplyHarness of its own, as a node's would be.
type countingApply struct {
	Reference
	started *int
}

func (c countingApply) Start(cs *ApplyCase) (ApplyNode, error) {
	*c.started++
	return ReferenceApply{}.Start(cs)
}

// plainHarness is an evaluator harness with no apply side, as the node's DNS glue is.
type plainHarness struct{ Harness }

// GP-r1-11: Run sends pair-table-apply through the harness it was given. A harness with an apply side is used for every case; one
// without is skipped and never reported green by the panel's own model.
//
// Fails if: runPairTableApplyGroup ignores h (the counter stays 0, and the plain harness runs and does not skip).
func TestRunSendsThePairTableApplyGroupThroughTheHarness(t *testing.T) {
	g, err := ReadGroup("pair-table-apply")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	t.Run("apply harness", func(t *testing.T) { runPairTableApplyGroup(t, g, countingApply{started: &n}) })
	if n != requiredGroups["pair-table-apply"] {
		t.Errorf("the harness started %d nodes, want one per case (%d)", n, requiredGroups["pair-table-apply"])
	}
	skipped := false
	t.Run("plain harness", func(t *testing.T) {
		defer func() { skipped = t.Skipped() }()
		runPairTableApplyGroup(t, g, plainHarness{Reference{}})
	})
	if !skipped {
		t.Error("a harness with no apply side ran the group instead of skipping it")
	}
}
