package api

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/admission"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/bearer"
)

// The three public link routes take the tenant's turn of an ordinary request before a connection (docs/specs/p3-endpoints.md 7.1;
// review round 1 of D6, p3-D6-r1-7). They carry no session, so the pipeline's turn of serveResolved never ran for them, and a
// holder of live links could keep the pool for every tenant while the owner's own long batch held the Endpoint's row.
//
// While every turn of tenant A is taken, A's three public routes are 503 server_busy and spend no use, another tenant's link is
// served, and when the turns are given back A's own link opens again.
func TestPublicLinkRoutesTakeTheTenantsTurn(t *testing.T) {
	r := newLinkRig(t)
	f := r.f
	adm := f.withAdmission()
	// withAdmission rebuilds the handler, so the signed-in clients of the rig still work and the public routes now share its turns.
	share := r.share(map[string]any{})
	shareValue := valueOf(t, share.URL)
	var dl pLinkURL
	r.apple(map[string]any{"protocol": "doh"}).want(201, "").json(&dl)
	downloadValue := valueOf(t, dl.URL)

	// Tenant B has a link of its own.
	b := f.makeSession(f.env.B.Tenant, f.env.B.User)
	var bep struct {
		Endpoints []pEndpoint `json:"endpoints"`
	}
	b.do("POST", "/endpoints", map[string]any{"type": f.endpointType(), "names": []string{"b"}, "profile_id": f.env.B.Profile.String()}, idem("turn-b")).want(201, "").json(&bep)
	var bshare pLinkURL
	b.post("/endpoints/"+bep.Endpoints[0].ID.String()+"/share-links", map[string]any{}).want(201, "").json(&bshare)

	var releases []func()
	for i := 0; i < admission.OrdinaryTenant; i++ {
		rel, err := adm.Ordinary(f.env.Ctx, f.env.A.Tenant.String())
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, rel)
	}
	began := time.Now()
	r.open(shareValue).want(503, "server_busy")
	r.f.client().post("/public/share/apple-profile", map[string]any{"link": shareValue, "params": map[string]any{"protocol": "doh"}}).want(503, "server_busy")
	r.download(downloadValue).want(503, "server_busy")
	if took := time.Since(began); took < admission.OrdinaryWait {
		t.Errorf("the refusals came after %v: a request waits its line for OrdinaryWait", took)
	}
	f.client().post("/public/share", map[string]any{"link": valueOf(t, bshare.URL)}).want(200, "")

	// The turn comes before the connection, which is the whole protection: the attack is many waiters per tenant, each holding one
	// of the few pooled connections while it waits (p3-D6-r3-3). A refused request therefore costs the lookup of the value and
	// nothing else; a turn taken inside the tenant's transaction would add the connection of that transaction. The price of the
	// lookup is measured on a value of the same kind that screens and names no row, a fresh one for each route because a value
	// known to name no row is refused at the door afterwards.
	routes := map[string]struct {
		call  func(value string) *resp
		kind  bearer.Kind
		value string
	}{
		"open": {r.open, bearer.ShareLink, shareValue},
		"apple": {func(v string) *resp {
			return f.client().post("/public/share/apple-profile", map[string]any{"link": v, "params": map[string]any{"protocol": "doh"}})
		}, bearer.ShareLink, shareValue},
		"download": {r.download, bearer.DownloadLink, downloadValue},
	}
	for name, route := range routes {
		g, err := f.srv.bearer.Mint(route.kind, uuid.New(), f.ck.now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		before := f.st.Asked()
		route.call(g.Reveal()).want(404, "not_found")
		lookup := f.st.Asked() - before
		if lookup == 0 {
			t.Fatalf("%s: a value that screens cost no lookup", name)
		}
		before = f.st.Asked()
		route.call(route.value).want(503, "server_busy")
		if n := f.st.Asked() - before; n != lookup {
			t.Errorf("%s: a request refused its turn took %d pool connections, want the lookup's %d: the turn is taken after a connection", name, n, lookup)
		}
	}

	for _, rel := range releases {
		rel()
	}
	// The refused requests spent nothing, and the turns are back: the link opens, the download works and is counted once.
	r.open(shareValue).want(200, "")
	r.download(downloadValue).want(200, "")
	var uses int
	f.env.Scan(t, `SELECT uses FROM ctrlz.setup_share_tokens WHERE id = $1`, []any{share.Link.ID}, &uses)
	if uses != 1 {
		t.Errorf("the share link has %d uses spent, want the one open that was served", uses)
	}
	if got := adm.OrdinaryTenants(); got != 0 {
		t.Errorf("%d tenants still hold a turn or a place in line", got)
	}
}
