// Package mobileconfig builds the Apple DNS profile (.mobileconfig) of P3
// section 7.3: a com.apple.dnsSettings.managed payload for DoH or DoT, the
// on-demand rules that exclude Wi-Fi networks and domains, and optionally
// ProhibitDisablement.
//
// It is pure: values in, bytes out, no clock, no database and no route. The
// download route (P3) reads the stored params and the Endpoint's current
// Resolver view and calls Build; nothing is stored, so a profile always carries
// the values of the moment it is downloaded. Request validation and the stable
// identifiers live in shared/appleprofile, which the node and panel share.
//
// Errors never hold an input value: the DoH URL carries the DoH token and an
// error is logged and returned as it is.
package mobileconfig

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Kup1ng/CtrlZ-Shared/appleprofile"
	"github.com/Kup1ng/CtrlZ-Shared/names"
)

// ErrDisabled is returned in private CA mode when the panel has chosen not to
// build a profile at all (P3 7.3: embed the root with a warning, or disable).
var ErrDisabled = errors.New("mobileconfig: the builder is disabled while the private root is not trusted by devices")

// ErrInput is wrapped by every error that blames the caller's input.
var ErrInput = errors.New("mobileconfig: invalid input")

func bad(what string) error { return fmt.Errorf("%w: %s", ErrInput, what) }

// Warning is a fixed code the UI turns into text.
type Warning string

const (
	// WarnUnsigned is always present: v1 profiles are not signed (D27), so iOS
	// and macOS show "Not Signed" when the profile is opened.
	WarnUnsigned Warning = "unsigned"
	// WarnPrivateRoot says the profile carries the panel's private CA root, so
	// installing it makes the device trust that root (P3 7.3).
	WarnPrivateRoot Warning = "private_root"
)

// TrustMode is how the nodes' certificates are trusted by a device.
type TrustMode uint8

const (
	// TrustPublic: the nodes' certificates chain to a public CA. The profile
	// carries no certificate.
	TrustPublic TrustMode = iota
	// TrustPrivateEmbed: the nodes use a private CA (P4); the profile embeds its
	// root as com.apple.security.root and warns.
	TrustPrivateEmbed
	// TrustPrivateDisabled: private CA and the builder is off.
	TrustPrivateDisabled
)

// Trust is the one thing the builder asks P4 about certificates. A nil Trust
// is TrustPublic. Mode and root are two methods so the caller reads both from
// one snapshot of the CA state.
type Trust interface {
	Mode() TrustMode
	RootDER() []byte
}

// StaticTrust is a Trust with fixed values, for a public setup and for tests.
type StaticTrust struct {
	M   TrustMode
	DER []byte
}

func (s StaticTrust) Mode() TrustMode { return s.M }
func (s StaticTrust) RootDER() []byte { return s.DER }

// Resolver holds the values of one Endpoint and client, all of them read from
// setup.View (P3 8.1) and never typed in.
type Resolver struct {
	// Host is <resolver_id>.dns.<zone> or <resolver_id>-<client>.dns.<zone>.
	Host string
	// DoHURL is https://<Host>/<doh_token>. It is a secret; used for DoH only.
	DoHURL string
	// Primary and Fallback are the two dns_advertised_ip values, in that order
	// (SC 8a.8).
	Primary, Fallback netip.Addr
}

// Input is everything Build needs.
type Input struct {
	// EndpointID is the Endpoint's UUID in lowercase.
	EndpointID string
	// Name is the Endpoint's name, shown on the device; empty uses a fixed name.
	Name     string
	Params   appleprofile.Params
	Resolver Resolver
	Trust    Trust
	// Now is the time the root's validity is judged at. The package reads no clock.
	Now time.Time
}

// Result is a finished profile.
type Result struct {
	Data []byte
	// FileName is ASCII, for Content-Disposition.
	FileName string
	Warnings []Warning
}

const (
	maxNameRunes = 64
	defaultName  = "Ctrl Z DNS"
	organization = "Ctrl Z"
)

// Build writes the profile. It validates every input first and writes nothing
// on error.
func Build(in Input) (Result, error) {
	if err := in.Params.Validate(); err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrInput, err)
	}
	id, err := appleprofile.Identify(in.EndpointID, in.Params.Client)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrInput, err)
	}
	name, err := displayName(in.Name)
	if err != nil {
		return Result{}, err
	}
	if err := checkResolver(in.Params, in.Resolver); err != nil {
		return Result{}, err
	}
	root, warns, err := checkTrust(in.Trust, in.Now)
	if err != nil {
		return Result{}, err
	}

	p := newPlist()
	p.openDict()
	p.key("PayloadContent")
	p.openArray()
	if root != nil {
		writeRoot(p, id, root)
	}
	writeDNS(p, id, in.Params, in.Resolver)
	p.closeArray()
	p.key("PayloadDescription")
	p.str("Encrypted DNS settings from Ctrl Z.")
	p.key("PayloadDisplayName")
	p.str(name)
	p.key("PayloadIdentifier")
	p.str(id.PayloadIdentifier)
	p.key("PayloadOrganization")
	p.str(organization)
	p.key("PayloadType")
	p.str("Configuration")
	p.key("PayloadUUID")
	p.str(id.PayloadUUID)
	p.key("PayloadVersion")
	p.integer(1)
	p.closeDict()
	data, err := p.finish()
	if err != nil {
		return Result{}, err
	}

	file := "ctrlz-dns"
	if in.Params.Client != "" {
		file += "-" + in.Params.Client
	}
	return Result{Data: data, FileName: file + ".mobileconfig", Warnings: warns}, nil
}

func displayName(n string) (string, error) {
	if n == "" {
		return defaultName, nil
	}
	if utf8.RuneCountInString(n) > maxNameRunes || !xmlSafe(n) {
		return "", bad("the Endpoint name cannot be shown on a device")
	}
	return "Ctrl Z - " + n, nil
}

func writeDNS(p *plist, id appleprofile.Identity, params appleprofile.Params, r Resolver) {
	doh := params.Protocol == appleprofile.ProtocolDoH
	p.openDict()

	p.key("DNSSettings")
	p.openDict()
	p.key("DNSProtocol")
	if doh {
		p.str("HTTPS")
	} else {
		p.str("TLS")
	}
	// The primary first (SC 8a.8). A client that spreads queries over both
	// addresses is safe by invariant 1; T-543 measures what iOS does.
	p.key("ServerAddresses")
	p.strs([]string{r.Primary.String(), r.Fallback.String()})
	if doh {
		p.key("ServerURL")
		p.str(r.DoHURL)
	} else {
		p.key("ServerName")
		p.str(r.Host)
	}
	p.closeDict()

	// Rules are evaluated in order. An excluded network switches the settings
	// off; excluded domains are never sent to the resolver; everything else is.
	// The last rule is explicit so that "no rule matched" is never a question.
	if len(params.ExcludedSSIDs) > 0 || len(params.ExcludedDomains) > 0 {
		p.key("OnDemandRules")
		p.openArray()
		if len(params.ExcludedSSIDs) > 0 {
			p.openDict()
			p.key("Action")
			p.str("Disconnect")
			p.key("SSIDMatch")
			p.strs(params.ExcludedSSIDs)
			p.closeDict()
		}
		if len(params.ExcludedDomains) > 0 {
			p.openDict()
			p.key("Action")
			p.str("EvaluateConnection")
			p.key("ActionParameters")
			p.openArray()
			p.openDict()
			p.key("DomainAction")
			p.str("NeverConnect")
			p.key("Domains")
			p.strs(params.ExcludedDomains)
			p.closeDict()
			p.closeArray()
			p.closeDict()
		}
		p.openDict()
		p.key("Action")
		p.str("Connect")
		p.closeDict()
		p.closeArray()
	}

	p.key("PayloadDisplayName")
	if doh {
		p.str("Ctrl Z DNS over HTTPS")
	} else {
		p.str("Ctrl Z DNS over TLS")
	}
	p.key("PayloadIdentifier")
	p.str(id.ContentIdentifier)
	p.key("PayloadType")
	p.str("com.apple.dnsSettings.managed")
	p.key("PayloadUUID")
	p.str(id.ContentUUID)
	p.key("PayloadVersion")
	p.integer(1)
	// ProhibitDisablement is a key of this payload and works on supervised
	// devices only. It has nothing to do with Prevent Deactivation (D8, T-250).
	if params.ProhibitDisablement {
		p.key("ProhibitDisablement")
		p.boolean(true)
	}
	p.closeDict()
}

func writeRoot(p *plist, id appleprofile.Identity, der []byte) {
	p.openDict()
	p.key("PayloadContent")
	p.data(der)
	p.key("PayloadDisplayName")
	p.str("Ctrl Z root certificate")
	p.key("PayloadIdentifier")
	p.str(id.RootIdentifier)
	p.key("PayloadType")
	p.str("com.apple.security.root")
	p.key("PayloadUUID")
	p.str(id.RootUUID)
	p.key("PayloadVersion")
	p.integer(1)
	p.closeDict()
}

func checkTrust(t Trust, now time.Time) (root []byte, warns []Warning, err error) {
	warns = []Warning{WarnUnsigned}
	if t == nil {
		return nil, warns, nil
	}
	switch t.Mode() {
	case TrustPublic:
		return nil, warns, nil
	case TrustPrivateDisabled:
		return nil, nil, ErrDisabled
	case TrustPrivateEmbed:
		der := t.RootDER()
		cert, perr := x509.ParseCertificate(der)
		if perr != nil {
			return nil, nil, bad("the private root is not a certificate")
		}
		if !cert.IsCA || !cert.BasicConstraintsValid {
			return nil, nil, bad("the private root is not a CA certificate")
		}
		// A root is its own issuer. A CA certificate issued by another CA is
		// an intermediate: installing it as a trust anchor would hand a
		// device a narrower-looking certificate whose real authority sits
		// above it, and it is not what private mode issues.
		if cert.CheckSignatureFrom(cert) != nil {
			return nil, nil, bad("the private root is not self-signed")
		}
		if now.IsZero() || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return nil, nil, bad("the private root is not valid now")
		}
		return der, append(warns, WarnPrivateRoot), nil
	}
	// A mode this code does not know is refused, never read as public.
	return nil, nil, bad("unknown trust mode")
}

func checkResolver(params appleprofile.Params, r Resolver) error {
	if err := checkHost(params.Client, r.Host); err != nil {
		return err
	}
	if params.Protocol == appleprofile.ProtocolDoH {
		if err := checkDoHURL(r.Host, r.DoHURL); err != nil {
			return err
		}
	}
	return checkAddrs(r.Primary, r.Fallback)
}

// checkHost holds the host to the shape of SC 3.2, so a value that did not
// come from setup.View, or came for another client, is refused: the profile
// would otherwise send a client's queries under another identity.
func checkHost(client, host string) error {
	n, err := names.ParseUser(host)
	if err != nil || n.String() != host {
		return bad("the resolver host is not a canonical name")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 3 || labels[1] != "dns" {
		return bad("the resolver host is not <id>.dns.<zone>")
	}
	want := labels[0]
	rid, cl, hasClient := strings.Cut(want, "-")
	if !b32(rid, 26) {
		return bad("the resolver host has no resolver id")
	}
	if hasClient != (client != "") || cl != client {
		return bad("the resolver host is not the host of the profile's client")
	}
	return nil
}

// checkDoHURL accepts exactly https://<host>/<doh_token>: no port, query,
// fragment or user. url.Parse errors quote the URL, so they are dropped.
func checkDoHURL(host, raw string) error {
	if strings.ContainsAny(raw, "?#") {
		return bad("the DoH URL has a query or a fragment")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return bad("the DoH URL does not parse")
	}
	if u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Host != host {
		return bad("the DoH URL is not https on the resolver host")
	}
	token, ok := strings.CutPrefix(u.EscapedPath(), "/")
	if !ok || !b32(token, 32) {
		return bad("the DoH URL has no DoH token path")
	}
	return nil
}

func checkAddrs(primary, fallback netip.Addr) error {
	for _, a := range []netip.Addr{primary, fallback} {
		if !a.IsValid() || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() {
			return bad("a server address is not a usable unicast address")
		}
	}
	if primary == fallback {
		return bad("the primary and the fallback address are the same")
	}
	if primary.Is4() != fallback.Is4() {
		return bad("the primary and the fallback address are of different families")
	}
	return nil
}

// b32 reports whether s is n characters of [a-z2-7], the grammar of a
// resolver_id (26) and of a DoH token (32). shared/identity owns it; it is
// written out here because importing identity would put this package in the
// reach of crypto/hmac, which internal/lint/imports.yaml keeps to the code that
// computes MACs. TestGrammarMatchesIdentity holds the two together.
func b32(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !(s[i] >= 'a' && s[i] <= 'z' || s[i] >= '2' && s[i] <= '7') {
			return false
		}
	}
	return true
}
