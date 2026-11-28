package identity

import (
	"strings"

	"github.com/Kup1ng/CtrlZ-Shared/names"
)

// HostKind is the outcome of ParseHost.
type HostKind uint8

const (
	HostOutOfZone HostKind = iota
	HostApex
	HostVerify
	HostReserved
	HostMalformed
	HostResolver
)

func (k HostKind) String() string {
	switch k {
	case HostOutOfZone:
		return "out_of_zone"
	case HostApex:
		return "apex"
	case HostVerify:
		return "verify"
	case HostReserved:
		return "reserved"
	case HostMalformed:
		return "malformed"
	case HostResolver:
		return "resolver"
	}
	return "unknown"
}

// Host is a parsed hostname. Which fields are set depends on Kind:
// HostVerify sets Label, HostReserved sets Name, HostResolver sets RID and
// (maybe empty) Client.
type Host struct {
	Kind   HostKind
	Label  string
	Name   string
	RID    string
	Client string
}

func reservedName(s string) bool {
	switch s {
	// _acme-challenge.verify holds a dot, so without its own entry it would fall to
	// HostMalformed and the DNS-01 TXT query of the *.verify.<zone> SAN would get
	// NXDOMAIN (SC 3 step 5).
	case "verify", "myip", "_acme-challenge", "_acme-challenge.verify", "ns1", "ns2", "ns3", "ns4":
		return true
	}
	return false
}

// ParseHost classifies an SNI, an :authority value or a qname inside the zone.
// zones holds one zone, or two during a domain change.
//
// The port is stripped first and then one trailing dot, so a fully qualified
// host with a port, "x.zone.:443", is in the zone: curl and browsers send an
// FQDN authority unchanged, and a DoH URL written that way used to get a 404
// (review L1-F11). The order matters only for malformed input: "x.zone:443."
// has its port after the dot is removed, so it stays out of the zone.
func ParseHost(host string, zones []names.Name) Host {
	host = lowerASCII(host)
	host = stripPort(host)
	host = strings.TrimSuffix(host, ".")

	var zone string
	var left string
	var apex bool
	for i := range zones {
		z := zones[i].String()
		if host == z {
			zone, apex = z, true
			break
		}
		if strings.HasSuffix(host, "."+z) {
			zone = z
			left = host[:len(host)-len(z)-1]
			break
		}
	}
	if zone == "" {
		return Host{Kind: HostOutOfZone}
	}
	if apex {
		return Host{Kind: HostApex}
	}
	if label, ok := strings.CutSuffix(left, ".verify"); ok && ValidVerifyLabel(label) {
		return Host{Kind: HostVerify, Label: label}
	}
	if reservedName(left) {
		return Host{Kind: HostReserved, Name: left}
	}
	if strings.Contains(left, ".") || len(left) < ResolverIDLen {
		return Host{Kind: HostMalformed}
	}
	rid := left[:ResolverIDLen]
	if !ValidResolverID(rid) {
		return Host{Kind: HostMalformed}
	}
	if len(left) == ResolverIDLen {
		return Host{Kind: HostResolver, RID: rid}
	}
	if left[ResolverIDLen] != '-' || !ValidClient(left[ResolverIDLen+1:]) {
		return Host{Kind: HostMalformed}
	}
	return Host{Kind: HostResolver, RID: rid, Client: left[ResolverIDLen+1:]}
}

func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// stripPort removes a trailing ":digits". Hosts with more than one colon are
// left alone: an IPv6 literal is never a zone name.
func stripPort(h string) string {
	i := strings.LastIndexByte(h, ':')
	if i < 0 || strings.Count(h, ":") != 1 || i == len(h)-1 {
		return h
	}
	for j := i + 1; j < len(h); j++ {
		if h[j] < '0' || h[j] > '9' {
			return h
		}
	}
	return h[:i]
}

// DoHPath is a parsed DoH request path.
type DoHPath struct {
	// Form is 'A' (/<token>[/<client>], id from :authority) or
	// 'B' (/<id>/<token>[/<client>], :authority may be the apex).
	Form   byte
	RID    string // empty in form A
	Token  string
	Client string
}

// ParseDoHPath splits and validates a DoH path. Segments are split on '/',
// lowercased, and any query string is ignored. The length of the first segment
// picks the form, so the two forms can never be confused. Every failure is
// ErrBadPath.
func ParseDoHPath(path string) (DoHPath, error) {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if !strings.HasPrefix(path, "/") {
		return DoHPath{}, ErrBadPath
	}
	segs := strings.Split(lowerASCII(path[1:]), "/")
	switch len(segs[0]) {
	case DoHTokenLen:
		if len(segs) > 2 || !ValidDoHToken(segs[0]) {
			return DoHPath{}, ErrBadPath
		}
		p := DoHPath{Form: 'A', Token: segs[0]}
		if len(segs) == 2 {
			if !ValidClient(segs[1]) {
				return DoHPath{}, ErrBadPath
			}
			p.Client = segs[1]
		}
		return p, nil
	case ResolverIDLen:
		if len(segs) < 2 || len(segs) > 3 || !ValidResolverID(segs[0]) || !ValidDoHToken(segs[1]) {
			return DoHPath{}, ErrBadPath
		}
		p := DoHPath{Form: 'B', RID: segs[0], Token: segs[1]}
		if len(segs) == 3 {
			if !ValidClient(segs[2]) {
				return DoHPath{}, ErrBadPath
			}
			p.Client = segs[2]
		}
		return p, nil
	}
	return DoHPath{}, ErrBadPath
}

// DoHTarget is who a DoH request addresses.
type DoHTarget struct {
	RID    string
	Token  string
	Client string
}

// ResolveDoH combines the path and :authority (3.3, 3.4). DoH identity is per
// stream and never comes from connection SNI (R7): HTTP/2 and HTTP/3 multiplex
// many authorities over one connection, so only the stream's own values count.
//
// Form A takes the id from :authority, which must be a resolver host.
// Form B takes the id from the path. When the authority is a resolver host
// with a different id, the path wins and the authority is ignored entirely,
// including its client label: a label that belongs to another resolver has no
// business choosing a client here.
// Client precedence: path, then authority, then none.
func ResolveDoH(path, authority string, zones []names.Name) (DoHTarget, error) {
	p, err := ParseDoHPath(path)
	if err != nil {
		return DoHTarget{}, err
	}
	h := ParseHost(authority, zones)
	t := DoHTarget{Token: p.Token, Client: p.Client}
	switch p.Form {
	case 'A':
		if h.Kind != HostResolver {
			return DoHTarget{}, ErrBadPath
		}
		t.RID = h.RID
	case 'B':
		t.RID = p.RID
		if h.Kind != HostResolver || h.RID != p.RID {
			return t, nil
		}
	}
	if t.Client == "" {
		t.Client = h.Client
	}
	return t, nil
}
