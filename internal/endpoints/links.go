package endpoints

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Shared/appleprofile"
	"github.com/Kup1ng/CtrlZ-Shared/identity"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/bearer"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/mobileconfig"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/setup"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The links without a session and the Resolver view (docs/specs/p3-endpoints.md 7 and 8). This file is the one place that
// writes the two link tables and the one that opens a DoH token for a person to see.
//
// Every transaction here takes its locks in the order of 3.7: the tenant quota lock, then the Endpoint row FOR NO KEY UPDATE,
// then the link rows, then the audit row. A route that reads the Endpoint's current values for a public link locks the Endpoint
// first as well, so a rotation or a delete (which lock the Endpoint before the link rows) never meets a reader going the other
// way.

// Limits of the link requests (D31, spec 3.8).
const (
	// DefaultShareHours and MaxShareHours bound ttl_hours of a share link.
	DefaultShareHours = 24
	MaxShareHours     = 168
	// DownloadLife is how long an Apple profile download link lives (D31).
	DownloadLife = 15 * time.Minute
)

// ---------------------------------------------------------------------------
// The Resolver view.

// ResolverFor builds the view of an Endpoint and a client inside the caller's transaction: the zone, the pair and the opened DoH
// token are read here and nowhere else (8.1). A client is only a label (the grammar of SC 3.1); a label with no row resolves as no
// client at the node. The view is a secret. A view that is not ready is returned as it is; the routes that generate answer 409 on it.
func (e *Env) ResolverFor(tx store.Tx, endpoint uuid.UUID, client string) (setup.ResolverView, store.EndpointRow, error) {
	if client != "" && !identity.ValidClient(client) {
		return setup.ResolverView{}, store.EndpointRow{}, invalid(Field{"client", CodeInvalid})
	}
	row, ok, err := tx.EndpointGet(endpoint)
	if err != nil {
		return setup.ResolverView{}, row, err
	}
	if !ok {
		return setup.ResolverView{}, row, notFound()
	}
	ct, ok, err := tx.EndpointTokenCT(endpoint)
	if err != nil {
		return setup.ResolverView{}, row, err
	}
	if !ok || e.Keys == nil {
		return setup.ResolverView{}, row, notFound()
	}
	token, err := e.Keys.Open(keyring.DomainDOHToken, TokenAAD(endpoint), ct)
	if err != nil {
		return setup.ResolverView{}, row, err
	}
	defer token.Wipe()
	zone, err := tx.DNSZone()
	if err != nil {
		return setup.ResolverView{}, row, err
	}
	pairs, err := tx.EndpointPairIPs()
	if err != nil {
		return setup.ResolverView{}, row, err
	}
	in := setup.Input{ResolverID: row.ResolverID, DoHToken: string(token.Reveal()), Client: client, Zone: zone}
	for _, p := range pairs {
		if p.EndpointID == endpoint {
			in.Primary, in.Fallback = p.PrimaryDNSIP, p.FallbackDNSIP
		}
	}
	v, err := setup.View(in)
	return v, row, err
}

// Generate runs one generator of the registry (8.2) over the Endpoint's current view. An id that is not in the registry is
// KindNotFound and a view that is not ready is KindSetupUnavailable.
func (e *Env) Generate(tx store.Tx, endpoint uuid.UUID, client, id string) (text string, platform string, err error) {
	var gen *setup.Generator
	for _, g := range setup.Generators() {
		if g.ID == id {
			gen = &g
			break
		}
	}
	v, _, err := e.ResolverFor(tx, endpoint, client)
	if err != nil {
		return "", "", err
	}
	if gen == nil {
		return "", "", notFound()
	}
	if !v.Ready {
		return "", "", &Error{Kind: KindSetupUnavailable}
	}
	text, err = gen.Run(v)
	return text, gen.Platform, err
}

// ---------------------------------------------------------------------------
// Share links, made by their owner.

// ShareIn is a share link to make.
type ShareIn struct {
	Endpoint uuid.UUID
	Client   string // empty for none
	TTLHours int    // 0 for the default
}

// ShareOut is a share link made: the row and the value, which is shown once.
type ShareOut struct {
	Link  store.ShareLinkRow
	Value secret.String
}

// ShareCreate makes a share link (7.2). The Endpoint's row is the lock that orders its links and decides the cap of ten live ones;
// a view that is not ready is KindSetupUnavailable, since a link that opens nothing is no link.
func (e *Env) ShareCreate(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, actor Actor, in ShareIn) (ShareOut, error) {
	if e.Bearer == nil {
		return ShareOut{}, errNoBearer
	}
	hours := in.TTLHours
	if hours == 0 {
		hours = DefaultShareHours
	}
	var fs []Field
	if hours < 1 || hours > MaxShareHours {
		fs = append(fs, Field{"/ttl_hours", CodeOutOfRange})
	}
	if in.Client != "" && !identity.ValidClient(in.Client) {
		fs = append(fs, Field{"/client", CodeInvalid})
	}
	if len(fs) > 0 {
		return ShareOut{}, invalid(fs...)
	}
	var out ShareOut
	err := e.Plain(ctx, st, tenant, opts, func(tx store.Tx) error {
		out = ShareOut{}
		found, err := tx.EndpointsLock([]uuid.UUID{in.Endpoint})
		if err != nil {
			return err
		}
		if len(found) != 1 {
			return notFound()
		}
		v, _, err := e.ResolverFor(tx, in.Endpoint, in.Client)
		if err != nil {
			return err
		}
		if !v.Ready {
			return &Error{Kind: KindSetupUnavailable}
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		now := e.now()
		// The expiry the value carries and the one the row holds are one instant, to the second.
		expires := now.Add(time.Duration(hours) * time.Hour).Truncate(time.Second)
		value, err := e.Bearer.Mint(bearer.ShareLink, id, expires)
		if err != nil {
			return err
		}
		won, err := tx.ShareLinkInsert(store.ShareLinkNew{ID: id, Endpoint: in.Endpoint, Client: in.Client, Hash: bearer.Hash(value.Reveal()), Expires: expires, Now: now})
		if err != nil {
			return err
		}
		if !won.Yes() {
			return invalid(Field{"max_share_links_per_endpoint", CodeExceeded})
		}
		row, _, err := tx.ShareLinkGet(in.Endpoint, id)
		if err != nil {
			return err
		}
		if err := audit.Tenant(tx, actor.User, actor.IP, audit.ShareLinkCreate{LinkID: id, EndpointID: in.Endpoint}); err != nil {
			return err
		}
		out = ShareOut{Link: row, Value: value}
		return nil
	})
	return out, err
}

// ShareRevoke ends a share link and deletes the download links made through it, in one transaction (7.1). An id that is not one of
// the Endpoint's is KindNotFound.
func (e *Env) ShareRevoke(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, actor Actor, endpoint, id uuid.UUID) error {
	return e.Plain(ctx, st, tenant, opts, func(tx store.Tx) error {
		found, err := tx.EndpointsLock([]uuid.UUID{endpoint})
		if err != nil {
			return err
		}
		if len(found) != 1 {
			return notFound()
		}
		ok, err := tx.ShareLinkRevoke(endpoint, id)
		if err != nil {
			return err
		}
		if !ok {
			return notFound()
		}
		if err := tx.ShareLinkDownloadsDelete(id); err != nil {
			return err
		}
		return audit.Tenant(tx, actor.User, actor.IP, audit.ShareLinkRevoke{LinkID: id, EndpointID: endpoint})
	})
}

// ---------------------------------------------------------------------------
// Apple profile download links.

// AppleIn is the request of POST /endpoints/{id}/apple-profile.
type AppleIn struct {
	Endpoint uuid.UUID
	Request  AppleRequest
	// Folder is the profile folder whose domain rules are added to the excluded domains, or the nil id.
	Folder uuid.UUID
}

// AppleOut is a download link made: the value is shown once, in the URL.
type AppleOut struct {
	Value   secret.String
	Expires time.Time
}

// appleField turns the error of the shared builder into a field of the request. prefix is "" for the owner's route and "/params"
// for the share link's, whose body holds the request one level down.
func appleField(err error, prefix string) error {
	if ae, ok := err.(*appleprofile.Error); ok {
		return invalid(Field{prefix + ae.Pointer, ae.Code})
	}
	return err
}

// expandApple resolves the request into the stored params, inside the caller's transaction (7.3): the folder's domains and the
// common domains are read here and become the one list that params holds, so a download reads neither a profile nor the catalog.
func expandApple(tx store.Tx, req appleprofile.Request, folder uuid.UUID, prefix string) (appleprofile.Params, error) {
	if folder != uuid.Nil {
		known, err := tx.FolderKnown(folder)
		if err != nil {
			return appleprofile.Params{}, err
		}
		if !known {
			return appleprofile.Params{}, notFound()
		}
		domains, err := tx.FolderDomains(folder)
		if err != nil {
			return appleprofile.Params{}, err
		}
		req.ExcludedDomains = append(append([]string(nil), req.ExcludedDomains...), domains...)
	}
	var common []string
	if req.ExcludeCommon {
		var err error
		if common, err = tx.CommonDomains(); err != nil {
			return appleprofile.Params{}, err
		}
	}
	p, err := appleprofile.Expand(req, common)
	if err != nil {
		return appleprofile.Params{}, appleField(err, prefix)
	}
	return p, nil
}

// newDownload mints a download link for the params and returns its row to insert.
func (e *Env) newDownload(endpoint uuid.UUID, p appleprofile.Params, now time.Time, via uuid.UUID) (store.DownloadLinkNew, secret.String, error) {
	canonical, err := p.Canonical()
	if err != nil {
		return store.DownloadLinkNew{}, secret.String{}, err
	}
	hash, err := p.Hash()
	if err != nil {
		return store.DownloadLinkNew{}, secret.String{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return store.DownloadLinkNew{}, secret.String{}, err
	}
	expires := now.Add(DownloadLife).Truncate(time.Second)
	value, err := e.Bearer.Mint(bearer.DownloadLink, id, expires)
	if err != nil {
		return store.DownloadLinkNew{}, secret.String{}, err
	}
	return store.DownloadLinkNew{ID: id, Endpoint: endpoint, Params: canonical, ParamsHash: hash[:], Hash: bearer.Hash(value.Reveal()),
		Expires: expires, Now: now, Via: via}, value, nil
}

// AppleCreate makes a download link for the owner (7.3): at most twenty live ones a tenant, decided by the statement under the
// tenant quota lock.
func (e *Env) AppleCreate(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, in AppleIn) (AppleOut, error) {
	if e.Bearer == nil {
		return AppleOut{}, errNoBearer
	}
	var out AppleOut
	err := e.Plain(ctx, st, tenant, opts, func(tx store.Tx) error {
		out = AppleOut{}
		if err := tx.QuotaLock(); err != nil {
			return err
		}
		found, err := tx.EndpointsLock([]uuid.UUID{in.Endpoint})
		if err != nil {
			return err
		}
		if len(found) != 1 {
			return notFound()
		}
		v, _, err := e.ResolverFor(tx, in.Endpoint, in.Request.Client)
		if err != nil {
			return err
		}
		if !v.Ready {
			return &Error{Kind: KindSetupUnavailable}
		}
		p, err := expandApple(tx, in.Request.shared(), in.Folder, "")
		if err != nil {
			return err
		}
		n, value, err := e.newDownload(in.Endpoint, p, e.now(), uuid.Nil)
		if err != nil {
			return err
		}
		won, err := tx.DownloadLinkInsert(n)
		if err != nil {
			return err
		}
		if !won.Yes() {
			return invalid(Field{"max_download_links_per_tenant", CodeExceeded})
		}
		out = AppleOut{Value: value, Expires: n.Expires}
		return nil
	})
	return out, err
}

// ---------------------------------------------------------------------------
// The public routes (7.1). A refusal is KindNotFound whatever the cause, and dead says the lookup found no row at all, so the
// pipeline refuses the value at the door from then on.

// ShareView is what a share link shows: the Endpoint's name and type and the Resolver view for the link's client, nothing else.
type ShareView struct {
	Name, Type string
	Resolvers  setup.ResolverView
	ExpiresAt  time.Time
}

// OpenShare spends one use of a share link and shows it (POST /public/share).
func (e *Env) OpenShare(ctx context.Context, st *store.Store, opts store.TxOpts, id uuid.UUID, value string) (out ShareView, dead bool, err error) {
	now := e.now()
	info, ok, err := st.Auth().ShareByHash(ctx, bearer.Hash(value))
	if err != nil {
		return ShareView{}, false, err
	}
	if !ok {
		return ShareView{}, true, notFound()
	}
	if info.TenantStatus != "active" || info.UsesLeft <= 0 || !info.ExpiresAt.After(now) {
		return ShareView{}, false, notFound()
	}
	err = e.Plain(ctx, st, info.TenantID, opts, func(tx store.Tx) error {
		out = ShareView{}
		found, err := tx.EndpointsLock([]uuid.UUID{info.EndpointID})
		if err != nil {
			return err
		}
		if len(found) != 1 {
			return notFound()
		}
		c, won, err := tx.ShareLinkConsume(id, info.EndpointID, now)
		if err != nil {
			return err
		}
		if !won.Yes() {
			return notFound()
		}
		v, row, err := e.ResolverFor(tx, info.EndpointID, c.Client)
		if err != nil {
			return err
		}
		out = ShareView{Name: row.Name, Type: row.Type, Resolvers: v, ExpiresAt: c.ExpiresAt}
		return nil
	})
	return out, false, err
}

// OpenShareApple spends one use of a share link and makes a download link through it (POST /public/share/apple-profile): the
// request is the share page's, with no folder, and the client is the link's when it has one (7.2). The new link carries
// via_share_id, so it is bounded by the share link's uses and not by the tenant's twenty.
func (e *Env) OpenShareApple(ctx context.Context, st *store.Store, opts store.TxOpts, id uuid.UUID, value string, areq AppleRequest) (out AppleOut, dead bool, err error) {
	req := areq.shared()
	if e.Bearer == nil {
		return AppleOut{}, false, errNoBearer
	}
	now := e.now()
	info, ok, err := st.Auth().ShareByHash(ctx, bearer.Hash(value))
	if err != nil {
		return AppleOut{}, false, err
	}
	if !ok {
		return AppleOut{}, true, notFound()
	}
	if info.TenantStatus != "active" || info.UsesLeft <= 0 || !info.ExpiresAt.After(now) {
		return AppleOut{}, false, notFound()
	}
	// What the request alone decides is decided here, before any transaction: a link with a client makes that client's profile only
	// (a link with none lets the page name one), and the shape of the request is Validate's. A refusal inside the transaction spends
	// no use, so max_uses would never bound it, and each attempt would take a pooled connection and the Endpoint's row lock: a holder
	// of one live value could post a request that is always refused as often as public-link allows, with no session (p3-D4-r1-6).
	if info.Client != "" {
		if req.Client != "" && req.Client != info.Client {
			return AppleOut{}, false, invalid(Field{"/params/client", CodeInvalid})
		}
		req.Client = info.Client
	}
	if err := appleprofile.Validate(req); err != nil {
		return AppleOut{}, false, appleField(err, "/params")
	}
	err = e.Plain(ctx, st, info.TenantID, opts, func(tx store.Tx) error {
		out = AppleOut{}
		found, err := tx.EndpointsLock([]uuid.UUID{info.EndpointID})
		if err != nil {
			return err
		}
		if len(found) != 1 {
			return notFound()
		}
		// Every refusal that needs a read comes before the consume, so that none of them writes a row and rolls it back; the
		// consume is the first write and the last decision, and it answers 404 for a link that died since the lookup.
		v, _, err := e.ResolverFor(tx, info.EndpointID, req.Client)
		if err != nil {
			if ee, ok := err.(*Error); ok && ee.Kind == KindValidation {
				return invalid(Field{"/params/client", CodeInvalid})
			}
			return err
		}
		if !v.Ready {
			return &Error{Kind: KindSetupUnavailable}
		}
		p, err := expandApple(tx, req, uuid.Nil, "/params")
		if err != nil {
			return err
		}
		_, won, err := tx.ShareLinkConsume(id, info.EndpointID, now)
		if err != nil {
			return err
		}
		if !won.Yes() {
			return notFound()
		}
		n, value, err := e.newDownload(info.EndpointID, p, now, id)
		if err != nil {
			return err
		}
		if err := tx.DownloadLinkInsertVia(n); err != nil {
			return err
		}
		out = AppleOut{Value: value, Expires: n.Expires}
		return nil
	})
	return out, false, err
}

// Profile is a built Apple profile.
type Profile struct {
	Data     []byte
	FileName string
}

// DownloadApple spends one use of a download link and builds the profile from its stored params and the Endpoint's current view
// (GET /public/apple-profile/{token}, 7.3). It writes the three columns of the Endpoint that tell a profile is stale, a recorded
// exception to AUTH 3.6 (Safari and a QR scanner can only GET). Nothing is stored of the profile.
func (e *Env) DownloadApple(ctx context.Context, st *store.Store, opts store.TxOpts, id uuid.UUID, value string) (out Profile, dead bool, err error) {
	now := e.now()
	info, ok, err := st.Auth().DownloadByHash(ctx, bearer.Hash(value))
	if err != nil {
		return Profile{}, false, err
	}
	if !ok {
		return Profile{}, true, notFound()
	}
	if info.TenantStatus != "active" || info.UsesLeft <= 0 || !info.ExpiresAt.After(now) {
		return Profile{}, false, notFound()
	}
	err = e.Plain(ctx, st, info.TenantID, opts, func(tx store.Tx) error {
		out = Profile{}
		found, err := tx.EndpointsLock([]uuid.UUID{info.EndpointID})
		if err != nil {
			return err
		}
		if len(found) != 1 {
			return notFound()
		}
		c, won, err := tx.DownloadLinkConsume(id, info.EndpointID, now)
		if err != nil {
			return err
		}
		if !won.Yes() {
			return notFound()
		}
		params, err := appleprofile.ParseParams(c.Params)
		if err != nil {
			return notFound()
		}
		// The hash is compared with the one of the parsed value, never with a hash of the stored jsonb text (7.3).
		if h, err := params.Hash(); err != nil || !bytes.Equal(h[:], c.ParamsHash) {
			return notFound()
		}
		v, row, err := e.ResolverFor(tx, info.EndpointID, params.Client)
		if err != nil {
			return err
		}
		if !v.Ready || !sameFamily(v.Legacy.DNS1, v.Legacy.DNS2) {
			// A pair of mixed families works for the Resolvers page and not for a profile (the builder takes one family), so it
			// is the same refusal as no pair: the owner fixes the setup, the person asks again.
			return &Error{Kind: KindSetupUnavailable}
		}
		res, err := mobileconfig.Build(mobileconfig.Input{
			EndpointID: strings.ToLower(row.ID.String()), Name: row.Name, Params: params, Trust: e.Trust, Now: now,
			Resolver: mobileconfig.Resolver{Host: v.Host, DoHURL: v.DoHURL, Primary: v.Legacy.DNS1, Fallback: v.Legacy.DNS2},
		})
		if err != nil {
			if errors.Is(err, mobileconfig.ErrDisabled) {
				return &Error{Kind: KindSetupUnavailable}
			}
			return err
		}
		if err := tx.AppleProfileDownloaded(info.EndpointID, now); err != nil {
			return err
		}
		out = Profile{Data: res.Data, FileName: res.FileName}
		return nil
	})
	return out, false, err
}

func sameFamily(a, b netip.Addr) bool { return a.Is4() == b.Is4() }

// errNoBearer is a wiring fault: the route that makes a link was built with no signer.
var errNoBearer = errors.New("endpoints: no bearer signer")

// AppleRequest is what a person asks of the Apple profile builder: the request of shared/appleprofile, which the api does not
// import (it reaches SHA-1 for the identifiers, and only this package and the builder may).
type AppleRequest struct {
	Client              string
	Protocol            string
	ExcludedSSIDs       []string
	ExcludedDomains     []string
	ExcludeCommon       bool
	ProhibitDisablement bool
}

func (r AppleRequest) shared() appleprofile.Request {
	return appleprofile.Request{Client: r.Client, Protocol: r.Protocol, ExcludedSSIDs: r.ExcludedSSIDs, ExcludedDomains: r.ExcludedDomains,
		ExcludeCommon: r.ExcludeCommon, ProhibitDisablement: r.ProhibitDisablement}
}
