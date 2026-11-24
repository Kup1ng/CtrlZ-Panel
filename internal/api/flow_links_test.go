package api

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/bearer"
	"github.com/Kup1ng/CtrlZ-Panel/internal/mobileconfig"
)

// The Resolver view, the generators, the share links and the Apple profile end to end (docs/specs/p3-endpoints.md 7, 8, 11.2 E4,
// 11.4 "Links"): the owner's routes with a session, the three public routes with a bearer value and no session, and the answers
// that must not tell one refusal from another.

const linkZone = "dns.links.example.test"

// linkRig is an Endpoint of tenant A with a zone set, and A's session.
type linkRig struct {
	f  *frig
	a  *client
	ep pEndpoint
}

func newLinkRig(t *testing.T) *linkRig {
	f := newFrig(t, frigOpts{})
	f.env.Exec(t, `UPDATE ctrlz.domain_settings SET dns_zone = $1`, linkZone)
	a := f.makeSession(f.env.A.Tenant, f.env.A.User)
	var created struct {
		Endpoints []pEndpoint `json:"endpoints"`
	}
	a.do("POST", "/endpoints", map[string]any{"type": f.endpointType(), "names": []string{"links endpoint"}, "profile_id": f.env.A.Profile.String()},
		idem("links-ep-1")).want(201, "").json(&created)
	return &linkRig{f: f, a: a, ep: created.Endpoints[0]}
}

var valueRE = regexp.MustCompile(`/(?:s|p)/([A-Za-z0-9_-]{64})$`)

// valueOf takes the bearer value out of a link URL.
func valueOf(t *testing.T, url string) string {
	t.Helper()
	m := valueRE.FindStringSubmatch(url)
	if m == nil {
		t.Fatalf("no value in %q", url)
	}
	return m[1]
}

type pShareView struct {
	Endpoint  struct{ Name, Type string } `json:"endpoint"`
	Resolvers struct {
		Ready      bool     `json:"ready"`
		Reason     string   `json:"reason"`
		ResolverID string   `json:"resolver_id"`
		Client     string   `json:"client"`
		Host       string   `json:"host"`
		DohURL     string   `json:"doh_url"`
		Bootstrap  []string `json:"bootstrap"`
		Protocols  []string `json:"protocols"`
		Legacy     struct{ Dns1, Dns2 string }
	} `json:"resolvers"`
	ExpiresAt time.Time `json:"expires_at"`
}

type pShareLinks struct {
	Links []struct {
		ID      uuid.UUID `json:"id"`
		Client  string    `json:"client"`
		Uses    int       `json:"uses"`
		MaxUses int       `json:"max_uses"`
		Revoked bool      `json:"revoked"`
	} `json:"links"`
}

type pLinkURL struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
	Link      struct {
		ID uuid.UUID `json:"id"`
	} `json:"link"`
}

func (r *linkRig) share(body map[string]any) pLinkURL {
	r.f.t.Helper()
	var out pLinkURL
	r.a.post("/endpoints/"+r.ep.ID.String()+"/share-links", body).want(201, "").json(&out)
	return out
}

func (r *linkRig) open(value string) *resp {
	return r.f.client().post("/public/share", map[string]any{"link": value})
}

func (r *linkRig) apple(body map[string]any) *resp {
	return r.a.post("/endpoints/"+r.ep.ID.String()+"/apple-profile", body)
}

func (r *linkRig) download(value string) *resp {
	return r.f.client().get("/public/apple-profile/" + value)
}

func TestResolverViewAndGenerators(t *testing.T) {
	r := newLinkRig(t)
	f, a := r.f, r.a
	path := "/endpoints/" + r.ep.ID.String()

	var view pShareView
	a.get(path+"/resolvers").want(200, "").json(&view.Resolvers)
	got := view.Resolvers
	if !got.Ready || got.ResolverID != r.ep.ResolverID || got.Host != r.ep.ResolverID+"."+linkZone {
		t.Fatalf("view %+v", got)
	}
	if !strings.HasPrefix(got.DohURL, "https://"+got.Host+"/") || len(got.Bootstrap) != 2 || got.Bootstrap[0] != "192.0.2.1" || got.Bootstrap[1] != "192.0.2.2" {
		t.Errorf("DoH URL %q bootstrap %v", got.DohURL, got.Bootstrap)
	}
	if strings.Join(got.Protocols, ",") != "plain,doh,doh3,dot,doq" {
		t.Errorf("protocols %v", got.Protocols)
	}
	// A client is a label: the host carries it, a bad label is refused, and the other tenant's Endpoint is no one's.
	var cv pShareView
	a.get(path+"/resolvers?client=kid").want(200, "").json(&cv.Resolvers)
	if cv.Resolvers.Host != r.ep.ResolverID+"-kid."+linkZone || cv.Resolvers.Client != "kid" {
		t.Errorf("client view %+v", cv.Resolvers)
	}
	if c := a.get(path + "/resolvers?client=-bad-").Code; c < 400 || c > 499 {
		t.Errorf("a bad client label answered %d", c)
	}
	b := f.makeSession(f.env.B.Tenant, f.env.B.User)
	b.get(path+"/resolvers").want(404, "not_found")

	// The generators read only the view.
	rr := a.get(path+"/generators?generator=windows-doh").want(200, "")
	if !strings.HasPrefix(rr.H.Get("Content-Type"), "text/plain") || !strings.Contains(string(rr.Body), "192.0.2.1") || !strings.Contains(string(rr.Body), got.DohURL) {
		t.Errorf("windows script: %q", rr.Body)
	}
	a.get(path+"/generators?generator=nope").want(404, "not_found")
	b.get(path+"/generators?generator=windows-doh").want(404, "not_found")

	// No zone: nothing is generated, and the view says why.
	f.env.Exec(t, `UPDATE ctrlz.domain_settings SET dns_zone = NULL`)
	var off pShareView
	a.get(path+"/resolvers").want(200, "").json(&off.Resolvers)
	if off.Resolvers.Ready || off.Resolvers.Reason != "zone_missing" || off.Resolvers.Host != "" || off.Resolvers.DohURL != "" {
		t.Errorf("not-ready view %+v", off.Resolvers)
	}
	a.get(path+"/generators?generator=windows-doh").want(409, "setup_unavailable")
	a.post(path+"/share-links", map[string]any{}).want(409, "setup_unavailable")
	r.apple(map[string]any{"protocol": "doh"}).want(409, "setup_unavailable")
}

func TestShareLinkFlow(t *testing.T) {
	r := newLinkRig(t)
	f, a := r.f, r.a
	path := "/endpoints/" + r.ep.ID.String() + "/share-links"

	made := r.share(map[string]any{"client": "kid", "ttl_hours": 1})
	if !strings.HasPrefix(made.URL, "https://"+host+"/s/") {
		t.Fatalf("url %q", made.URL)
	}
	value := valueOf(t, made.URL)
	// The list never holds the value.
	lr := a.get(path).want(200, "")
	if strings.Contains(string(lr.Body), value) {
		t.Error("the list shows the value of a share link")
	}
	var list pShareLinks
	lr.json(&list)
	if len(list.Links) != 1 || list.Links[0].Client != "kid" || list.Links[0].MaxUses != 10 || list.Links[0].Uses != 0 {
		t.Fatalf("list %+v", list)
	}

	// Opening needs no session, shows the link's client and counts a use. The page is never kept, indexed or passed on.
	open := r.open(value).want(200, "")
	for h, want := range map[string]string{"Cache-Control": "no-store", "X-Robots-Tag": "noindex", "Referrer-Policy": "no-referrer"} {
		if open.H.Get(h) != want {
			t.Errorf("%s = %q, want %q", h, open.H.Get(h), want)
		}
	}
	var view pShareView
	open.json(&view)
	if view.Endpoint.Name != "links endpoint" || !view.Resolvers.Ready || view.Resolvers.Client != "kid" || view.Resolvers.Host != r.ep.ResolverID+"-kid."+linkZone {
		t.Errorf("share view %+v", view)
	}
	if strings.Contains(string(open.Body), f.env.A.Tenant.String()) || strings.Contains(string(open.Body), f.env.A.Profile.String()) {
		t.Error("the share view holds an id of the tenant")
	}
	a.get(path).want(200, "").json(&list)
	if list.Links[0].Uses != 1 {
		t.Errorf("uses after one open: %d", list.Links[0].Uses)
	}
	// The value is in the body: a query is no place for it.
	f.client().get("/public/share?token="+value).want(400, "bad_request")

	// Ten uses and no more.
	for i := 1; i < 10; i++ {
		r.open(value).want(200, "")
		f.ck.add(2 * time.Second)
	}
	r.open(value).want(404, "not_found")

	// Revoke ends it, and an id that is not the Endpoint's, or another tenant's, is no link.
	var again pLinkURL
	a.post(path, map[string]any{}).want(201, "").json(&again)
	v2 := valueOf(t, again.URL)
	r.open(v2).want(200, "")
	b := f.makeSession(f.env.B.Tenant, f.env.B.User)
	b.do("DELETE", path+"/"+again.Link.ID.String(), nil).want(404, "not_found")
	a.do("DELETE", path+"/"+uuid.NewString(), nil).want(404, "not_found")
	r.open(v2).want(200, "")
	a.do("DELETE", path+"/"+again.Link.ID.String(), nil).want(204, "")
	r.open(v2).want(404, "not_found")
	a.get(path).want(200, "").json(&list)
	revoked := 0
	for _, l := range list.Links {
		if l.Revoked {
			revoked++
		}
	}
	if revoked != 1 {
		t.Errorf("%d revoked links listed, want 1", revoked)
	}

	// The cap counts live links: the first is used up, the second revoked, so ten more fit and the eleventh does not, and a
	// revoke gives the slot back at once.
	var ids []uuid.UUID
	for i := 0; i < 10; i++ {
		var l pLinkURL
		a.post(path, map[string]any{}).want(201, "").json(&l)
		ids = append(ids, l.Link.ID)
	}
	a.post(path, map[string]any{}).want(422, "validation_failed")
	a.do("DELETE", path+"/"+ids[0].String(), nil).want(204, "")
	a.post(path, map[string]any{}).want(201, "")

	// ttl_hours is bounded.
	a.post(path, map[string]any{"ttl_hours": 169}).want(400, "bad_request")
	a.post(path, map[string]any{"ttl_hours": 0}).want(400, "bad_request")
}

// E4: every refusal of a public route is the same answer, and a value that cannot be ours costs no store call.
func TestPublicRefusalsAreOneAnswer(t *testing.T) {
	r := newLinkRig(t)
	f, a := r.f, r.a
	path := "/endpoints/" + r.ep.ID.String() + "/share-links"
	ok := valueOf(t, r.share(map[string]any{}).URL)

	// A value this service would have made for a row that does not exist.
	ghost, err := f.srv.bearer.Mint(bearer.ShareLink, uuid.New(), f.ck.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// A revoked link, a used-up one and the link of an Endpoint that was deleted.
	var rev pLinkURL
	a.post(path, map[string]any{}).want(201, "").json(&rev)
	a.do("DELETE", path+"/"+rev.Link.ID.String(), nil).want(204, "")
	usedUp := r.share(map[string]any{})
	f.env.Exec(t, `UPDATE ctrlz.setup_share_tokens SET uses = max_uses WHERE id = $1`, usedUp.Link.ID)
	var other struct {
		Endpoints []pEndpoint `json:"endpoints"`
	}
	a.do("POST", "/endpoints", map[string]any{"type": f.endpointType(), "names": []string{"doomed"}, "profile_id": f.env.A.Profile.String()}, idem("links-ep-2")).want(201, "").json(&other)
	var doomed pLinkURL
	a.post("/endpoints/"+other.Endpoints[0].ID.String()+"/share-links", map[string]any{}).want(201, "").json(&doomed)
	a.post("/endpoints/"+other.Endpoints[0].ID.String()+":delete", map[string]any{}).want(204, "")
	// A tenant that is not active.
	susp := r.share(map[string]any{})
	// An expired one: the clock of the api moves past its life.
	soon := r.share(map[string]any{"ttl_hours": 1})

	cases := map[string]string{
		"zeros":                              strings.Repeat("A", 64),
		"a share value of a row that is not": ghost.Reveal(),
		"revoked":                            valueOf(t, rev.URL), "used up": valueOf(t, usedUp.URL), "deleted Endpoint": valueOf(t, doomed.URL),
	}
	// A changed last character is another value, with a tag that fails.
	flipped := []byte(ok)
	if flipped[63] == 'A' {
		flipped[63] = 'B'
	} else {
		flipped[63] = 'A'
	}
	cases["tag"] = string(flipped)
	// A download value on the share route.
	d, err := f.srv.bearer.Mint(bearer.DownloadLink, uuid.New(), f.ck.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cases["a download value"] = d.Reveal()

	// A value of the wrong length or alphabet is junk like any other: it is screened before the schema, so it is the one 404 (spec 7.1).
	cases["junk"] = "x"
	cases["short"] = strings.Repeat("A", 63)
	cases["long"] = strings.Repeat("A", 65)
	cases["alphabet"] = strings.Repeat("A", 63) + "="
	var first *resp
	check := func(name string, got *resp) {
		t.Helper()
		got.want(404, "not_found")
		if first == nil {
			first = got
			return
		}
		// The request id is the one member that differs, by design.
		if !bytes.Equal(withoutRequestID(first.Body), withoutRequestID(got.Body)) {
			t.Errorf("%s: body %q differs from %q", name, got.Body, first.Body)
		}
		for _, h := range []string{"Cache-Control", "X-Robots-Tag", "Referrer-Policy", "Content-Type"} {
			if first.H.Get(h) != got.H.Get(h) {
				t.Errorf("%s: header %s %q differs from %q", name, h, got.H.Get(h), first.H.Get(h))
			}
		}
	}
	for name, v := range cases {
		check(name, r.open(v))
		f.ck.add(3 * time.Second)
	}
	f.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'suspended' WHERE id = $1`, f.env.A.Tenant)
	check("suspended tenant", r.open(valueOf(t, susp.URL)))
	f.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'active' WHERE id = $1`, f.env.A.Tenant)
	r.open(valueOf(t, susp.URL)).want(200, "")
	f.ck.add(2 * time.Hour)
	check("expired", r.open(valueOf(t, soon.URL)))
	// The first request after a long step of the clock reloads the public configuration; what is counted below is the value's own cost.
	r.open("x")

	// Junk, a wrong tag and an expired value are answered at the door: no store call at all.
	before := f.st.Asked()
	for _, v := range []string{"x", string(flipped), valueOf(t, soon.URL), strings.Repeat("A", 64)} {
		f.ck.add(2 * time.Second)
		if got := r.open(v); got.Code != 404 {
			t.Errorf("a value that cannot be ours answered %d", got.Code)
		}
	}
	if n := f.st.Asked() - before; n != 0 {
		t.Errorf("%d store calls for values that cannot be ours", n)
	}
	// A value that screens and names no row costs one lookup, once: the next is refused at the door.
	g2, _ := f.srv.bearer.Mint(bearer.ShareLink, uuid.New(), f.ck.now().Add(time.Hour))
	before = f.st.Asked()
	r.open(g2.Reveal()).want(404, "not_found")
	if n := f.st.Asked() - before; n == 0 {
		t.Error("a value that screens cost no lookup: the screen is not the only check")
	}
	before = f.st.Asked()
	for i := 0; i < 3; i++ {
		r.open(g2.Reveal()).want(404, "not_found")
	}
	if n := f.st.Asked() - before; n != 0 {
		t.Errorf("a value known to name no row cost %d more store calls", n)
	}
	// The same value on the other two routes is no value of theirs.
	f.client().post("/public/share/apple-profile", map[string]any{"link": g2.Reveal(), "params": map[string]any{"protocol": "doh"}}).want(404, "not_found")
	f.client().get("/public/apple-profile/"+g2.Reveal()).want(404, "not_found")
}

// The rate of a public value is its own: a flood of one value refuses that value and no other.
func TestOneLinkValueIsRateLimitedOnItsOwnRow(t *testing.T) {
	r := newLinkRig(t)
	f := r.f
	one := valueOf(t, r.share(map[string]any{}).URL)
	two := valueOf(t, r.share(map[string]any{}).URL)
	var refused bool
	for i := 0; i < 40; i++ {
		if got := r.open(one); got.Code == http.StatusTooManyRequests {
			refused = true
			break
		}
	}
	if !refused {
		t.Error("forty opens of one value in one minute were all answered")
	}
	// Another row on the same address, and the same row from another network, are not the refused bucket's.
	r.open(two).want(200, "")
	f.ck.add(2 * time.Minute)
	r.open(one).want(404, "") // used up by now, and answered like every refusal
}

func TestAppleProfileFlow(t *testing.T) {
	r := newLinkRig(t)
	f, a := r.f, r.a
	path := "/endpoints/" + r.ep.ID.String()

	var link pLinkURL
	r.apple(map[string]any{"protocol": "doh", "excluded_ssids": []string{"Home <&> ]]>"}, "excluded_domains": []string{"example.com"},
		"exclude_common": true, "prohibit_disablement": true}).want(201, "").json(&link)
	if !strings.HasPrefix(link.URL, "https://"+host+"/p/") || !within(link.ExpiresAt.Sub(f.ck.now()), 15*time.Minute) {
		t.Fatalf("link %+v", link)
	}
	value := valueOf(t, link.URL)
	var ep0 struct {
		Stale bool `json:"apple_profile_stale"`
	}
	a.get(path).want(200, "").json(&ep0)
	if ep0.Stale {
		t.Error("an Endpoint with no profile is stale")
	}

	dl := r.download(value).want(200, "")
	if dl.H.Get("Content-Type") != "application/x-apple-aspen-config" || !strings.HasPrefix(dl.H.Get("Content-Disposition"), "attachment; filename=\"") ||
		dl.H.Get("Cache-Control") != "no-store" || dl.H.Get("X-Robots-Tag") != "noindex" || dl.H.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("headers %v", dl.H)
	}
	body := string(dl.Body)
	if !strings.Contains(body, "com.apple.dnsSettings.managed") || !strings.Contains(body, r.ep.ResolverID+"."+linkZone) || !strings.Contains(body, "192.0.2.1") ||
		!strings.Contains(body, "Home &lt;&amp;&gt; ]]&gt;") || !strings.Contains(body, "captive.apple.com") || !strings.Contains(body, "ProhibitDisablement") {
		t.Errorf("profile %q", body)
	}
	// Three uses and no more (D31), and the Endpoint knows a profile was made from its current values.
	r.download(value).want(200, "")
	r.download(value).want(200, "")
	r.download(value).want(404, "not_found")
	a.get(path).want(200, "").json(&ep0)
	if ep0.Stale {
		t.Error("a profile made from the current resolver id is stale")
	}
	// A rotation makes it stale (T-248), ends the links of the Endpoint and shows the new id.
	var link2 pLinkURL
	r.apple(map[string]any{"protocol": "dot"}).want(201, "").json(&link2)
	a.post(path+":rotate-resolver", map[string]any{}).want(200, "")
	a.get(path).want(200, "").json(&ep0)
	if !ep0.Stale {
		t.Error("a profile is not stale after the resolver id changed")
	}
	r.download(valueOf(t, link2.URL)).want(404, "not_found")

	// The twenty live links of a tenant: the twenty-first is 422 and a used-up link gives its slot back.
	var urls []string
	for i := 0; i < 20; i++ {
		var l pLinkURL
		r.apple(map[string]any{"protocol": "doh"}).want(201, "").json(&l)
		urls = append(urls, l.URL)
	}
	r.apple(map[string]any{"protocol": "doh"}).want(422, "validation_failed")
	for i := 0; i < 3; i++ {
		r.download(valueOf(t, urls[0])).want(200, "")
	}
	r.apple(map[string]any{"protocol": "doh"}).want(201, "")

	// The request is checked: a protocol, an SSID with a control, too many domains, a folder that is not the tenant's.
	r.apple(map[string]any{"protocol": "dnscrypt"}).want(400, "bad_request")
	r.apple(map[string]any{"protocol": "doh", "from_folder_id": uuid.NewString()}).want(404, "not_found")
	var many []string
	for i := 0; i < 101; i++ {
		many = append(many, fmt.Sprintf("d%d.example.com", i))
	}
	f.ck.add(time.Minute)
	r.apple(map[string]any{"protocol": "doh", "excluded_domains": many}).want(400, "bad_request")
}

// A share link makes its own Apple links, bounded by its uses and not by the tenant's twenty, and they go with it.
func TestShareLinkMakesAppleLinks(t *testing.T) {
	r := newLinkRig(t)
	f, a := r.f, r.a
	path := "/endpoints/" + r.ep.ID.String() + "/share-links"
	withClient := r.share(map[string]any{"client": "kid"})
	plain := r.share(map[string]any{})

	var made pLinkURL
	f.client().post("/public/share/apple-profile", map[string]any{"link": valueOf(t, plain.URL), "params": map[string]any{"protocol": "dot", "client": "tv"}}).want(201, "").json(&made)
	dl := r.download(valueOf(t, made.URL)).want(200, "")
	if !strings.Contains(string(dl.Body), r.ep.ResolverID+"-tv."+linkZone) {
		t.Errorf("profile for the client: %q", dl.Body)
	}
	// A link with a client makes that client's profile only.
	f.client().post("/public/share/apple-profile", map[string]any{"link": valueOf(t, withClient.URL), "params": map[string]any{"protocol": "doh", "client": "tv"}}).want(422, "validation_failed")
	var kid pLinkURL
	f.client().post("/public/share/apple-profile", map[string]any{"link": valueOf(t, withClient.URL), "params": map[string]any{"protocol": "doh"}}).want(201, "").json(&kid)
	if !strings.Contains(string(r.download(valueOf(t, kid.URL)).want(200, "").Body), r.ep.ResolverID+"-kid."+linkZone) {
		t.Error("the link's client is not in the profile")
	}
	// A refused request spends no use; the folder is not a member of the public request.
	var uses int
	f.env.Scan(t, `SELECT uses FROM ctrlz.setup_share_tokens WHERE id = $1`, []any{withClient.Link.ID}, &uses)
	if uses != 1 {
		t.Errorf("uses %d, want 1 (the refused request spent none)", uses)
	}
	f.client().post("/public/share/apple-profile", map[string]any{"link": valueOf(t, plain.URL), "params": map[string]any{"protocol": "doh", "from_folder_id": uuid.NewString()}}).want(400, "")

	// What the request alone decides is refused before any transaction (p3-D4-r1-6): a request that is always refused, posted with a
	// live value, costs the lookup of the value and nothing more, so it never takes the Endpoint's row lock or a second connection.
	// The price of the lookup is measured on a value that screens and names no row, which is all of the work that is left.
	ghost, err := f.srv.bearer.Mint(bearer.ShareLink, uuid.New(), f.ck.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	before := f.st.Asked()
	f.client().post("/public/share/apple-profile", map[string]any{"link": ghost.Reveal(), "params": map[string]any{"protocol": "doh"}}).want(404, "not_found")
	lookup := f.st.Asked() - before
	if lookup == 0 {
		t.Fatal("a value that screens cost no lookup")
	}
	before = f.st.Asked()
	f.client().post("/public/share/apple-profile", map[string]any{"link": valueOf(t, withClient.URL), "params": map[string]any{"protocol": "doh", "client": "tv"}}).want(422, "validation_failed")
	f.client().post("/public/share/apple-profile", map[string]any{"link": valueOf(t, plain.URL), "params": map[string]any{"protocol": "doh", "excluded_domains": []string{"not a domain name"}}}).want(422, "validation_failed")
	if n := f.st.Asked() - before; n != 2*lookup {
		t.Errorf("two requests the shape alone refuses cost %d pool connections, want %d (the lookups only)", n, 2*lookup)
	}
	f.env.Scan(t, `SELECT uses FROM ctrlz.setup_share_tokens WHERE id = $1`, []any{plain.Link.ID}, &uses)
	if uses != 1 {
		t.Errorf("uses %d of the plain link, want 1 (the one that made a link; the refused ones spent none)", uses)
	}
	// The tenant's twenty are untouched: both links were made through a share link.
	var own int
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.profile_download_tokens WHERE tenant_id = $1 AND via_share_id IS NULL`, []any{f.env.A.Tenant}, &own)
	if own != 0 {
		t.Errorf("%d download links count against the tenant's cap", own)
	}
	// Revoking the share link ends the links made through it.
	a.do("DELETE", path+"/"+plain.Link.ID.String(), nil).want(204, "")
	r.download(valueOf(t, made.URL)).want(404, "not_found")
	r.download(valueOf(t, kid.URL)).want(200, "")
}

// The three public routes never answer 5xx while a rotation or a delete of the same Endpoint runs (11.4).
func TestPublicRoutesAgainstRotationAndDelete(t *testing.T) {
	r := newLinkRig(t)
	f, a := r.f, r.a
	path := "/endpoints/" + r.ep.ID.String()
	var share pLinkURL
	a.post(path+"/share-links", map[string]any{}).want(201, "").json(&share)
	var dls []string
	for i := 0; i < 3; i++ {
		var l pLinkURL
		r.apple(map[string]any{"protocol": "doh"}).want(201, "").json(&l)
		dls = append(dls, valueOf(t, l.URL))
		f.ck.add(time.Second)
	}
	sv := valueOf(t, share.URL)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var bad []string
	note := func(what string, code int) {
		if code >= 500 {
			mu.Lock()
			bad = append(bad, fmt.Sprintf("%s: %d", what, code))
			mu.Unlock()
		}
	}
	clients := make([]*client, 0, 12)
	for i := 0; i < 12; i++ {
		clients = append(clients, f.client())
	}
	for i, c := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch i % 3 {
			case 0:
				note("download", c.get("/public/apple-profile/"+dls[i%len(dls)]).Code)
			case 1:
				note("share", c.post("/public/share", map[string]any{"link": sv}).Code)
			default:
				note("share apple", c.post("/public/share/apple-profile", map[string]any{"link": sv, "params": map[string]any{"protocol": "doh"}}).Code)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		note("rotate", a.post(path+":rotate-resolver", map[string]any{}).Code)
		note("delete", a.post(path+":delete", map[string]any{}).Code)
	}()
	wg.Wait()
	if len(bad) > 0 {
		t.Errorf("server errors: %v", bad)
	}
}

// Another tenant's link reaches only that tenant's Endpoint, and a link of A never shows B anything.
func TestLinksOfOneTenantReachOnlyItsEndpoint(t *testing.T) {
	r := newLinkRig(t)
	f := r.f
	b := f.makeSession(f.env.B.Tenant, f.env.B.User)
	var bep struct {
		Endpoints []pEndpoint `json:"endpoints"`
	}
	b.do("POST", "/endpoints", map[string]any{"type": f.endpointType(), "names": []string{"only for tenant B"}, "profile_id": f.env.B.Profile.String()}, idem("links-b-1")).want(201, "").json(&bep)
	a := r.share(map[string]any{})
	got := r.open(valueOf(t, a.URL)).want(200, "")
	if strings.Contains(string(got.Body), bep.Endpoints[0].ResolverID) || strings.Contains(string(got.Body), "only for tenant B") {
		t.Error("A's share view shows B's Endpoint")
	}
	// A's session cannot list, make or revoke links of B's Endpoint, and a link of B's Endpoint has no use for A's id.
	bp := "/endpoints/" + bep.Endpoints[0].ID.String()
	r.a.get(bp+"/share-links").want(404, "not_found")
	r.a.post(bp+"/share-links", map[string]any{}).want(404, "not_found")
	r.a.post(bp+"/apple-profile", map[string]any{"protocol": "doh"}).want(404, "not_found")
}

var requestIDRE = regexp.MustCompile(`"request_id":"[^"]*",?`)

func withoutRequestID(b []byte) []byte { return requestIDRE.ReplaceAll(b, nil) }

// link-create (P3 9.1): a tenant makes at most 200 links a day whatever its sessions, a revoke does not give one back, and the
// other tenant's budget is its own.
func TestLinkCreateIsBoundedPerTenantPerDay(t *testing.T) {
	r := newLinkRig(t)
	f, a := r.f, r.a
	path := "/endpoints/" + r.ep.ID.String() + "/share-links"
	made, refused := 0, 0
	for i := 0; i < 260 && refused == 0; i++ {
		f.ck.add(2 * time.Second)
		got := a.post(path, map[string]any{})
		switch got.Code {
		case 201:
			made++
			var l pLinkURL
			got.json(&l)
			a.do("DELETE", path+"/"+l.Link.ID.String(), nil).want(204, "")
		case 429:
			refused++
			if got.code() != "rate_limited" {
				t.Errorf("refused with %q", got.code())
			}
		default:
			t.Fatalf("create %d: %d %s", i, got.Code, got.Body)
		}
	}
	if made < 200 || made > 205 || refused != 1 {
		t.Fatalf("%d links made and %d refused, want about 200 and one refusal", made, refused)
	}
	// Another session of the tenant shares the day, and another tenant has its own.
	a2 := f.makeSession(f.env.A.Tenant, f.env.A.User)
	a2.post(path, map[string]any{}).want(429, "rate_limited")
	r.apple(map[string]any{"protocol": "doh"}).want(429, "rate_limited")
	b := f.makeSession(f.env.B.Tenant, f.env.B.User)
	var bep struct {
		Endpoints []pEndpoint `json:"endpoints"`
	}
	b.do("POST", "/endpoints", map[string]any{"type": f.endpointType(), "names": []string{"b"}, "profile_id": f.env.B.Profile.String()}, idem("links-b-day")).want(201, "").json(&bep)
	b.post("/endpoints/"+bep.Endpoints[0].ID.String()+"/share-links", map[string]any{}).want(201, "")
	// The next day the budget is back.
	f.ck.add(25 * time.Hour)
	f.makeSession(f.env.A.Tenant, f.env.A.User).post(path, map[string]any{}).want(201, "")
}

// within says a time left is d, to the second the expiry of a link is cut to.
func within(got, d time.Duration) bool { return got <= d && got > d-time.Second }

// A share link opened while the setup is not ready shows nothing, so it is the 409 of every route that generates and it spends no
// use (p3-D4-r2-3): the person asks again when the owner has set the zone, and the link still has its uses.
func TestOpenShareWhileNotReadySpendsNoUse(t *testing.T) {
	r := newLinkRig(t)
	f := r.f
	made := r.share(map[string]any{})
	value := valueOf(t, made.URL)
	uses := func() int {
		var n int
		f.env.Scan(t, `SELECT uses FROM ctrlz.setup_share_tokens WHERE id = $1`, []any{made.Link.ID}, &n)
		return n
	}
	f.env.Exec(t, `UPDATE ctrlz.domain_settings SET dns_zone = NULL`)
	for i := 0; i < 3; i++ {
		r.open(value).want(409, "setup_unavailable")
		f.ck.add(2 * time.Second)
	}
	if n := uses(); n != 0 {
		t.Fatalf("%d uses spent by opens that showed nothing", n)
	}
	f.env.Exec(t, `UPDATE ctrlz.domain_settings SET dns_zone = $1`, linkZone)
	var view pShareView
	r.open(value).want(200, "").json(&view)
	if !view.Resolvers.Ready {
		t.Errorf("view %+v", view.Resolvers)
	}
	if n := uses(); n != 1 {
		t.Errorf("uses %d after the one open that showed the values, want 1", n)
	}
}

// While the panel's private root is not trusted by devices the builder is off for every link, which is decided before a connection
// is taken: a holder of a live link asking for the profile again and again costs the lookup of the value and nothing more, and the
// link keeps its uses (p3-D4-r2-2).
func TestDownloadWhileTheBuilderIsOffTakesNoTransaction(t *testing.T) {
	r := newLinkRig(t)
	f := r.f
	var link pLinkURL
	r.apple(map[string]any{"protocol": "doh"}).want(201, "").json(&link)
	value := valueOf(t, link.URL)
	// The price of the lookup alone is measured on a value that screens and names no row, which is all of the work such a request has.
	ghost, err := f.srv.bearer.Mint(bearer.DownloadLink, uuid.New(), f.ck.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	before := f.st.Asked()
	f.client().get("/public/apple-profile/"+ghost.Reveal()).want(404, "not_found")
	lookup := f.st.Asked() - before
	if lookup == 0 {
		t.Fatal("a value that screens cost no lookup")
	}
	f.srv.ep.Trust = mobileconfig.StaticTrust{M: mobileconfig.TrustPrivateDisabled}
	t.Cleanup(func() { f.srv.ep.Trust = nil })
	r.download(value).want(409, "setup_unavailable")
	f.ck.add(2 * time.Second)
	before = f.st.Asked()
	r.download(value).want(409, "setup_unavailable")
	if n := f.st.Asked() - before; n != lookup {
		t.Errorf("a refused download took %d pool connections, want the lookup's %d", n, lookup)
	}
	var uses int
	f.env.Scan(t, `SELECT uses FROM ctrlz.profile_download_tokens WHERE tenant_id = $1 AND token_hash = $2`,
		[]any{f.env.A.Tenant, bearer.Hash(value)}, &uses)
	if uses != 0 {
		t.Errorf("%d uses spent by refused downloads", uses)
	}
	// With the builder back on, the same link still builds.
	f.srv.ep.Trust = nil
	r.download(value).want(200, "")
}

// An older live share link stays in the owner's list however many used-up links are newer (p3-D4-r2-5), so it can still be revoked.
func TestShareListShowsTheLiveLinkAmongSpentOnes(t *testing.T) {
	r := newLinkRig(t)
	f, a := r.f, r.a
	path := "/endpoints/" + r.ep.ID.String() + "/share-links"
	live := r.share(map[string]any{"ttl_hours": 168})
	f.env.Exec(t, `INSERT INTO ctrlz.setup_share_tokens (tenant_id, endpoint_id, token_hash, expires_at, uses, created_at)
		SELECT $1, $2, convert_to('spent-' || g, 'UTF8'), now() + interval '1 day', 10, now() + g * interval '1 second' FROM generate_series(1, 120) g`,
		f.env.A.Tenant, r.ep.ID)
	var list pShareLinks
	a.get(path).want(200, "").json(&list)
	found := false
	for i, l := range list.Links {
		if l.ID == live.Link.ID {
			found = true
			if i != 0 {
				t.Errorf("the live link is at position %d", i)
			}
		}
	}
	if !found || len(list.Links) != 100 {
		t.Fatalf("%d links listed, the live one found: %v", len(list.Links), found)
	}
	// And the owner can end it by the id the list gave.
	a.do("DELETE", path+"/"+list.Links[0].ID.String(), nil).want(204, "")
	r.open(valueOf(t, live.URL)).want(404, "not_found")
}
