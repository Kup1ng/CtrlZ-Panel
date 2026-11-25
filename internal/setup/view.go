// Package setup builds every value a user is given to set a device up (P3
// sections 8.1 and 8.2): hostnames, the DoH URL, the legacy addresses, DNS
// Stamps, the client label rules, and the strict-mode artifacts of each client.
//
// It is pure: values in, text out. No database, clock or route. The Resolvers
// page, the share view, the wizard and the Apple profile builder all read the
// ResolverView that View returns, so the primary-first order and the strict
// settings of SC 8a.8 are decided in one place and a value that is not in the
// view cannot reach a user.
//
// Errors never hold an input value: the DoH token is a secret.
package setup

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/names"
)

// ErrInput is wrapped by every error that blames a value the caller read from
// the database or a request: a malformed resolver_id, token, client or zone.
// The caller treats it as an internal error; the inputs were validated when
// they were written.
var ErrInput = errors.New("setup: invalid input")

// ErrNotReady is returned by a generator given a view that is not Ready.
var ErrNotReady = errors.New("setup: resolver view is not ready")

func bad(what string) error { return fmt.Errorf("%w: %s", ErrInput, what) }

// Protocol is one of the five protocols of D24 and D51, and no other.
type Protocol string

const (
	PlainDNS Protocol = "plain"
	DoH      Protocol = "doh"
	DoH3     Protocol = "doh3"
	DoT      Protocol = "dot"
	DoQ      Protocol = "doq"
)

// Protocols is the one list behind ResolverView, the Resolvers page and the
// wizard (check E8), in display order. DNSCrypt is not served and has no entry.
// It builds a fresh slice per call, so no caller can change what the others
// see and no package-level state exists.
func Protocols() []Protocol { return []Protocol{PlainDNS, DoH, DoH3, DoT, DoQ} }

// Reason says why a view is not ready (P3 8.1). A not-ready view generates
// nothing; the routes that generate answer 409 setup_unavailable.
type Reason string

const (
	ReasonZoneMissing Reason = "zone_missing"
	ReasonPairMissing Reason = "pair_missing"
)

// maxHostLen is the longest hostname DNS allows in presentation form.
const maxHostLen = 253

// Input is what View reads. The caller (the Resolver route) opens DoHToken from
// doh_token_ct and fills Zone and the pair from the database.
type Input struct {
	ResolverID string
	// DoHToken is the opened token, a secret.
	DoHToken string
	// Client is the client label, or empty for traffic with no client.
	Client string
	// Zone is domain_settings.dns_zone ("dns.<domain>", SC 3.1) or empty while the
	// admin has not set a domain.
	Zone string
	// Primary and Fallback are the pair's dns_advertised_ip values, from
	// endpoint_pair_ips(); the zero Addr when there is no pair.
	Primary, Fallback netip.Addr
}

// Legacy holds the Plain DNS addresses, primary first (SC 8a.8).
type Legacy struct {
	DNS1 netip.Addr `json:"dns1"`
	DNS2 netip.Addr `json:"dns2"`
}

// AddressStamp is a stamp that names one node's address, so an app that takes a
// list of stamps connects with no plaintext lookup.
type AddressStamp struct {
	IP    netip.Addr `json:"ip"`
	Stamp string     `json:"stamp"`
}

// ProtocolStamps is the stamps of one protocol: the hostname stamp first, then
// the two address stamps, primary first (SC 8a.8).
type ProtocolStamps struct {
	HostnameStamp string         `json:"hostname_stamp"`
	AddressStamps []AddressStamp `json:"address_stamps"`
}

// Stamps holds the three protocols that have a stamp. DoH3 has none of its own
// (D51) and Plain DNS needs none.
type Stamps struct {
	DoH ProtocolStamps `json:"doh"`
	DoT ProtocolStamps `json:"dot"`
	DoQ ProtocolStamps `json:"doq"`
}

// ResolverView is the P3 9.3 schema. DoHURL and the DoH stamps carry the DoH
// token, so a view is a secret: String and GoString never print it.
type ResolverView struct {
	Ready      bool         `json:"ready"`
	Reason     Reason       `json:"reason,omitempty"`
	ResolverID string       `json:"resolver_id"`
	Client     string       `json:"client,omitempty"`
	Host       string       `json:"host,omitempty"`
	DoHURL     string       `json:"doh_url,omitempty"`
	Legacy     *Legacy      `json:"legacy,omitempty"`
	Bootstrap  []netip.Addr `json:"bootstrap,omitempty"`
	Stamps     *Stamps      `json:"stamps,omitempty"`
	Protocols  []Protocol   `json:"protocols"`
}

// String keeps the DoH token out of a log line or an error that formats a view
// by accident.
func (ResolverView) String() string { return "setup.ResolverView{redacted}" }

// GoString is String for %#v.
func (ResolverView) GoString() string { return "setup.ResolverView{redacted}" }

// View builds the view of one Endpoint and client. A missing zone or pair gives
// a view that is not Ready and holds nothing to generate from; a malformed
// value is ErrInput.
func View(in Input) (ResolverView, error) {
	if !identity.ValidResolverID(in.ResolverID) {
		return ResolverView{}, bad("resolver id")
	}
	if !identity.ValidDoHToken(in.DoHToken) {
		return ResolverView{}, bad("DoH token")
	}
	if in.Client != "" && !identity.ValidClient(in.Client) {
		return ResolverView{}, bad("client label")
	}
	v := ResolverView{ResolverID: in.ResolverID, Client: in.Client, Protocols: Protocols()}
	switch {
	case in.Zone == "":
		v.Reason = ReasonZoneMissing
		return v, nil
	case !pairReady(in.Primary, in.Fallback):
		v.Reason = ReasonPairMissing
		return v, nil
	}
	zone, err := names.ParseUser(in.Zone)
	// The zone is "dns.<domain>" (SC 3.1); the Apple builder holds hosts to that shape too.
	if err != nil || zone.String() != in.Zone || !strings.HasPrefix(in.Zone, "dns.") {
		// The zone is stored in its canonical form (P4), so anything else is a
		// stored value that went wrong, not a reason to be not-ready.
		return ResolverView{}, bad("zone")
	}
	if in.Primary == in.Fallback {
		return ResolverView{}, bad("pair addresses")
	}

	host := in.ResolverID
	if in.Client != "" {
		host += "-" + in.Client
	}
	host += "." + in.Zone
	if len(host) > maxHostLen {
		return ResolverView{}, bad("host length")
	}
	// A view is only worth giving if the grammar of the node reads it back to
	// the same Endpoint and client (SC 3.2).
	got := identity.ParseHost(host, []names.Name{zone})
	if got.Kind != identity.HostResolver || got.RID != in.ResolverID || got.Client != in.Client {
		return ResolverView{}, bad("host does not parse back")
	}

	v.Host = host
	v.DoHURL = "https://" + host + "/" + in.DoHToken
	v.Legacy = &Legacy{DNS1: in.Primary, DNS2: in.Fallback}
	v.Bootstrap = []netip.Addr{in.Primary, in.Fallback}
	st, err := buildStamps(host, "/"+in.DoHToken, in.Primary, in.Fallback)
	if err != nil {
		return ResolverView{}, err
	}
	v.Stamps = st
	v.Ready = true
	return v, nil
}

// pairReady reports whether both advertised addresses are usable as a server
// address. They come from inet columns, so an IPv4-mapped or zoned form means
// a stored value that went wrong, and the view calls the pair missing rather
// than hand it to a device.
func pairReady(a, b netip.Addr) bool { return usable(a) && usable(b) }

func usable(a netip.Addr) bool {
	return a.IsValid() && !a.Is4In6() && a.Zone() == "" && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback() && !a.IsLinkLocalUnicast()
}

// Values is what the Resolvers page shows for one protocol, in the order it
// shows it: both addresses for Plain DNS, the URL for DoH and DoH3 (the same
// URL, labelled HTTP/3 by the page), and the hostname for DoT and DoQ. A view
// that is not Ready or an unknown protocol gives nil.
func (v ResolverView) Values(p Protocol) []string {
	if !v.Ready {
		return nil
	}
	switch p {
	case PlainDNS:
		return []string{v.Legacy.DNS1.String(), v.Legacy.DNS2.String()}
	case DoH, DoH3:
		return []string{v.DoHURL}
	case DoT, DoQ:
		return []string{v.Host}
	}
	return nil
}
