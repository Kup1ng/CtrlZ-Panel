package api

import (
	"testing"
)

// TestAppleProfileIsStaleAfterThePairChanges: a profile downloaded from the current pair and resolver is not stale; a change of
// the Endpoint's pair (pair_version, which a pair override of P4 moves) makes it stale; a new download makes it current again;
// and another tenant's Endpoint is not touched (spec P3 7.3, T-248). The half of T-248 that compares the private root with
// apple_profile_generated_at needs the CA rotation of P4 and is not tested here. Drop the pair_version arm of the stale
// expression and the second check fails.
func TestAppleProfileIsStaleAfterThePairChanges(t *testing.T) {
	r := newLinkRig(t)
	f, a := r.f, r.a
	B := f.env.B
	path := "/endpoints/" + r.ep.ID.String()
	stale := func() bool {
		t.Helper()
		var ep struct {
			Stale bool `json:"apple_profile_stale"`
		}
		a.get(path).want(200, "").json(&ep)
		return ep.Stale
	}
	download := func() {
		t.Helper()
		var link pLinkURL
		r.apple(map[string]any{"protocol": "doh"}).want(201, "").json(&link)
		r.download(valueOf(t, link.URL)).want(200, "")
	}

	if stale() {
		t.Fatal("an Endpoint with no profile is stale")
	}
	download()
	if stale() {
		t.Fatal("a profile made from the current pair is stale")
	}
	var before int64
	f.env.Scan(t, `SELECT pair_version FROM ctrlz.endpoints WHERE id = $1`, []any{r.ep.ID}, &before)
	f.env.Exec(t, `UPDATE ctrlz.endpoints SET pair_version = pair_version + 1 WHERE id = $1`, r.ep.ID)
	if !stale() {
		t.Error("a profile is not stale after the pair version moved")
	}
	// Another Endpoint of another tenant, whose pair also moved, makes no difference here and has no profile of its own.
	f.env.Exec(t, `UPDATE ctrlz.endpoints SET pair_version = pair_version + 1 WHERE id = $1`, B.Endpoint)
	var bEp struct {
		Stale bool `json:"apple_profile_stale"`
	}
	f.fresh(B.Tenant, B.User).get("/endpoints/"+B.Endpoint.String()).want(200, "").json(&bEp)
	if bEp.Stale {
		t.Error("an Endpoint that never made a profile is stale because its pair moved")
	}
	// A new download is made from the new pair: current again.
	download()
	if stale() {
		t.Error("a profile made after the pair version moved is stale")
	}
	var after int64
	f.env.Scan(t, `SELECT apple_profile_pair_version FROM ctrlz.endpoints WHERE id = $1`, []any{r.ep.ID}, &after)
	if after != before+1 {
		t.Errorf("the profile recorded pair version %d, want %d", after, before+1)
	}
}
