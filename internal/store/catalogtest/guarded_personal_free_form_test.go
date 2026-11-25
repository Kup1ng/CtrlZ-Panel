package catalogtest

import (
	"strings"
	"testing"
)

// A free-form column whose name looks like nothing, but which holds what a person put there (the SSIDs in
// profile_download_tokens.params), is decided under `personal`, with its readers pinned by check 22. Before, the only
// way to decide it was `open`, and `open` refuses a column that is also under `personal`, so the column could not be
// classed personal at all and a later grant to another role would have passed the catalog silently
// (p3-D1-r2-4). The test is over the pure function, so it starts no container.
func TestFreeFormPersonalColumnIsDecidedByPersonal(t *testing.T) {
	cols := map[string][]column{"profile_download_tokens": {{Name: "params", Type: "jsonb", NotNull: true}}}
	problems := func(g GuardedFile) string { return strings.Join(checkSecretNames(g, cols), "\n") }

	if got := problems(GuardedFile{}); !strings.Contains(got, "profile_download_tokens.params (jsonb) is a free-form column with no decision") {
		t.Errorf("an undecided jsonb column must fail; got %q", got)
	}

	personal := GuardedFile{Personal: map[string]map[string][]string{"profile_download_tokens": {"params": {"tenant"}}}}
	if got := problems(personal); got != "" {
		t.Errorf("a free-form column under personal is decided; got %q", got)
	}

	// Both lists is the contradiction that made the open entry the wrong way out: the column is judged twice.
	both := personal
	both.Open = map[string]OpenColumns{"profile_download_tokens": {
		Why: "names, settings, statuses and the caller's own data", NoPersonal: "no column is about a person", Columns: []string{"params"},
	}}
	if got := problems(both); !strings.Contains(got, "profile_download_tokens.params is in open and in read, secrets, read_open, personal or personal_open") {
		t.Errorf("a column under open and personal must fail; got %q", got)
	}
}
