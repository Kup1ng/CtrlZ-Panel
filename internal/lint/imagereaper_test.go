package lint_test

import (
	"testing"

	"github.com/testcontainers/testcontainers-go"
)

// TestTheReaperImageIsTheReviewedOne: see reviewedReaper.
func TestTheReaperImageIsTheReviewedOne(t *testing.T) {
	if testcontainers.ReaperDefaultImage != reviewedReaper {
		t.Fatalf("testcontainers now starts %s beside every container test, which holds the Docker socket and is pinned by no digest here; review it, then change reviewedReaper", testcontainers.ReaperDefaultImage)
	}
}
