package periodic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// The resolver of the DDNS job (docs/specs/p4-nodes.md 8): the host's own resolver by default, or the DoT or DoH server that
// CTRLZ_DDNS_RESOLVER names. It is one of the few clients of the server binary that dial a host outside the deployment, and
// the destination list of the egress rules is closed at TCP and UDP 53, TCP 443 and TCP 853 (p6-ops 5). So the target is
// parsed strictly, here, to exactly the two shapes the list allows, and every dial the client makes is the one function
// dialTarget: nothing else in this package opens a connection.

// Resolver answers the A and AAAA records of a host name.
type Resolver interface {
	// Lookup returns every address of both families. It fails when either query failed, because a partial answer would make
	// the caller delete the addresses of the family that did not answer. A name with no record of a type is an answer; both
	// types empty is an empty slice, and the caller decides what that means.
	Lookup(ctx context.Context, host string) ([]netip.Addr, error)
}

var (
	// errNoData is the answer "this name has no record of the type": not a failure of the lookup.
	errNoData = errors.New("periodic: no record of the type")
	// errLookup is every failure, with no detail: a host name, a server address and an error text stay out of logs and rows.
	errLookup = errors.New("periodic: the lookup failed")
)

// target is a parsed CTRLZ_DDNS_RESOLVER value.
type target struct {
	scheme string // "tls" or "https"
	host   string // an IP literal or a lower-case DNS name
	port   string // 853 for tls, 443 for https
	path   string // https only
}

const (
	schemeDoT = "tls"
	schemeDoH = "https"
	portDoT   = "853"
	portDoH   = "443"
	pathDoH   = "/dns-query"
)

// parseTarget reads the setting. Empty is not a target (the caller uses the host's resolver). Anything beyond
// `tls://host[:853]` and `https://host[:443][/path]` is refused: user info, a query, a fragment, another port and another
// scheme, so a mistyped or hostile value cannot send the worker's queries somewhere the egress list did not intend.
func parseTarget(spec string) (target, error) {
	u, err := url.Parse(spec)
	if err != nil || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Host == "" {
		return target{}, errors.New("periodic: the DDNS resolver is not a tls:// or https:// URL")
	}
	t := target{scheme: u.Scheme, host: strings.ToLower(u.Hostname()), port: u.Port()}
	switch u.Scheme {
	case schemeDoT:
		if t.port == "" {
			t.port = portDoT
		}
		if t.port != portDoT || (u.Path != "" && u.Path != "/") {
			return target{}, errors.New("periodic: a DoT resolver is tls://host with port 853 and no path")
		}
	case schemeDoH:
		if t.port == "" {
			t.port = portDoH
		}
		t.path = u.Path
		if t.path == "" {
			t.path = pathDoH
		}
		if t.port != portDoH || !validPath(t.path) {
			return target{}, errors.New("periodic: a DoH resolver is https://host with port 443 and a plain path")
		}
	default:
		return target{}, errors.New("periodic: the DDNS resolver scheme is tls or https")
	}
	if !validHost(t.host) {
		return target{}, errors.New("periodic: the DDNS resolver host is not an address or a host name")
	}
	return t, nil
}

func validPath(p string) bool {
	if len(p) == 0 || len(p) > 128 || p[0] != '/' {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '/' || c == '.' || c == '-' || c == '_' || c == '~') {
			return false
		}
	}
	// A dot segment would let a value that looks like a path name another one (the URL parser has already decoded %2e).
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// validHost accepts an IP literal without a zone, or a host name of LDH labels.
func validHost(h string) bool {
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Zone() == ""
	}
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Option adjusts NewResolver. The only one is for tests, which trust the certificate of a local server.
type Option func(*options)

type options struct {
	roots *x509.CertPool
	// dialAddr replaces the address the target is dialled at (a test's local listener), and nothing else about the dial.
	dialAddr string
}

// WithRoots sets the roots the server certificate is verified against; the default is the system's.
func WithRoots(p *x509.CertPool) Option { return func(o *options) { o.roots = p } }

// withDialAddr is for tests: the connection goes to addr, the name checked is still the target's.
func withDialAddr(addr string) Option { return func(o *options) { o.dialAddr = addr } }

// NewResolver builds the resolver of a CTRLZ_DDNS_RESOLVER value: the host's resolver for an empty one.
func NewResolver(spec string, opts ...Option) (Resolver, error) {
	var o options
	for _, f := range opts {
		f(&o)
	}
	if spec == "" {
		return &netResolver{r: net.DefaultResolver}, nil
	}
	t, err := parseTarget(spec)
	if err != nil {
		return nil, err
	}
	d := &dialer{t: t, o: o}
	switch t.scheme {
	case schemeDoT:
		// The Go resolver speaks DNS over any stream connection it is given, so DoT is the system client with a dial that
		// ignores the address of resolv.conf and opens the TLS connection to the target.
		return &netResolver{r: &net.Resolver{PreferGo: true, Dial: d.dialDoT}}, nil
	default:
		return newDoH(d), nil
	}
}

// ---------------------------------------------------------------------------
// The one dial.

type dialer struct {
	t target
	o options
}

const dialTimeout = 5 * time.Second

// dialTarget opens the TCP connection to the target and runs TLS over it. It is the only place of this package that dials.
func (d *dialer) dialTarget(ctx context.Context) (net.Conn, error) {
	addr := net.JoinHostPort(d.t.host, d.t.port)
	if d.o.dialAddr != "" {
		addr = d.o.dialAddr
	}
	td := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: dialTimeout},
		Config:    &tls.Config{ServerName: d.t.host, MinVersion: tls.VersionTLS12, RootCAs: d.o.roots},
	}
	return td.DialContext(ctx, "tcp", addr)
}

// dialDoT is the Dial of the Go resolver. The network and address it asks for are ignored on purpose.
func (d *dialer) dialDoT(ctx context.Context, _, _ string) (net.Conn, error) {
	return d.dialTarget(ctx)
}

// ---------------------------------------------------------------------------
// The host's resolver, and DoT through it.

type netResolver struct{ r *net.Resolver }

const lookupTimeout = 8 * time.Second

// HostLocal says that this resolver reads the machine's own sources (the hosts file, Docker's embedded DNS) before or beside
// the network, so an answer in a private range may be the name of one of the panel's own services. The DDNS pass then reports a
// private-only answer as no_address, the same as a name that does not exist, and a tenant cannot map the panel's service
// names by reading last_error.
func (*netResolver) HostLocal() bool { return true }

func (n *netResolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	return lookupBoth(ctx, host, func(ctx context.Context, host string, v6 bool) ([]netip.Addr, error) {
		network := "ip4"
		if v6 {
			network = "ip6"
		}
		// Rooted, so the search list of the container's resolv.conf never extends the name of a tenant's host into a name of the
		// panel's own networks. (The hosts file and Docker's resolver can still answer for a bare name: see HostLocal.)
		if _, err := netip.ParseAddr(host); err != nil {
			host = strings.TrimSuffix(host, ".") + "."
		}
		a, err := n.r.LookupNetIP(ctx, network, host)
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return nil, errNoData
		}
		if err != nil {
			return nil, errLookup
		}
		return a, nil
	})
}

// lookupBoth asks for A and then AAAA with one function and joins the answers by the rule of Resolver.Lookup.
func lookupBoth(ctx context.Context, host string, ask func(ctx context.Context, host string, v6 bool) ([]netip.Addr, error)) ([]netip.Addr, error) {
	var all []netip.Addr
	failed := false
	for _, v6 := range []bool{false, true} {
		a, err := ask(ctx, host, v6)
		switch {
		case err == nil:
			all = append(all, a...)
		case errors.Is(err, errNoData):
		default:
			failed = true
		}
	}
	if failed {
		return nil, errLookup
	}
	return all, nil
}

// ---------------------------------------------------------------------------
// DoH (RFC 8484), a POST of the wire message.

type doh struct {
	c    *http.Client
	url  string
	host string
}

func newDoH(d *dialer) *doh {
	u := url.URL{Scheme: schemeDoH, Host: net.JoinHostPort(d.t.host, d.t.port), Path: d.t.path}
	tr := &http.Transport{
		// The dial is dialTarget, which already runs TLS; the transport is told it is a plain connection, so it does not
		// run a second handshake, and it speaks HTTP/1.1 (one small request at a time is all the job does).
		DialContext:         func(ctx context.Context, _, _ string) (net.Conn, error) { return d.dialTarget(ctx) },
		MaxIdleConns:        2,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: dialTimeout,
		Proxy:               nil,
	}
	// A redirect would leave the destination the egress list allows.
	c := &http.Client{Transport: tr, Timeout: lookupTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &doh{c: c, url: u.String(), host: d.t.host}
}

const maxDoHBody = 64 << 10

func (d *doh) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	return lookupBoth(ctx, host, d.ask)
}

func (d *doh) ask(ctx context.Context, host string, v6 bool) ([]netip.Addr, error) {
	qt := dnsmessage.TypeA
	if v6 {
		qt = dnsmessage.TypeAAAA
	}
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return nil, errLookup
	}
	q, err := (&dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: qt, Class: dnsmessage.ClassINET}},
	}).Pack()
	if err != nil {
		return nil, errLookup
	}
	// The https scheme here is the one the transport's DialContext already secured; Go sends the request in the clear over
	// that connection only when the URL says http, so the URL is rewritten to http for the wire and the TLS is the dial's.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http"+strings.TrimPrefix(d.url, schemeDoH), strings.NewReader(string(q)))
	if err != nil {
		return nil, errLookup
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.c.Do(req)
	if err != nil {
		return nil, errLookup
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/dns-message") {
		return nil, errLookup
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHBody+1))
	if err != nil || len(body) > maxDoHBody {
		return nil, errLookup
	}
	return parseAnswer(body, qt)
}

// parseAnswer reads the addresses of one type out of a response. NXDOMAIN is "no data" for the type, so a name that exists
// with an A record and no AAAA answers; the caller treats an empty result of both types as its own case.
func parseAnswer(msg []byte, qt dnsmessage.Type) ([]netip.Addr, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || !h.Response || h.Truncated {
		return nil, errLookup
	}
	switch h.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return nil, errNoData
	default:
		return nil, errLookup
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, errLookup
	}
	var out []netip.Addr
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, errLookup
		}
		switch {
		case ah.Type == dnsmessage.TypeA && qt == dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil, errLookup
			}
			out = append(out, netip.AddrFrom4(r.A))
		case ah.Type == dnsmessage.TypeAAAA && qt == dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil, errLookup
			}
			out = append(out, netip.AddrFrom16(r.AAAA))
		default:
			// A CNAME on the way, or a record of the other type: not an address of this query.
			if err := p.SkipAnswer(); err != nil {
				return nil, errLookup
			}
		}
	}
	if len(out) == 0 {
		return nil, errNoData
	}
	return out, nil
}
