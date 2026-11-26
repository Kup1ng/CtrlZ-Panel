package nodeadmin

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// The rules of the domain settings (p4-nodes 3.2 item 6, 9.4, 10.4). They are plain functions of text and time, so
// the route and its tests share one copy, and the database CHECKs that hold the same grammar are only the last line.

// ErrDomain is the one refusal of a domain value: the route answers domain_invalid with the field that failed.
var ErrDomain = errors.New("nodeadmin: domain value refused")

// ErrTransition is the refusal of a zone change while the earlier change is still in its transition window.
var ErrTransition = errors.New("nodeadmin: a zone change is still in its transition")

// hostGrammar is the hostname grammar of the CHECKs of domain_settings: lower-case labels of 1 to 63 characters made of
// letters, digits and hyphens, none starting or ending with a hyphen, at most 253 characters in all. Upper case is not
// folded here: the route lowers the text first, so a value that still has a capital after that is refused.
var hostGrammar = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// ValidHost reports whether s is a hostname of the grammar.
func ValidHost(s string) bool { return len(s) <= 253 && hostGrammar.MatchString(s) }

// ValidZone is the rule of a dns_zone (9.4): the hostname grammar, the prefix `dns.`, and a remainder of at least two
// labels that is not a public suffix by the list embedded with golang.org/x/net/publicsuffix, so a zone can never be
// `dns.ir` or `dns.co.ir`, a name no one owns.
func ValidZone(s string) bool {
	if !ValidHost(s) || !strings.HasPrefix(s, "dns.") {
		return false
	}
	rest := strings.TrimPrefix(s, "dns.")
	if strings.Count(rest, ".") < 1 {
		return false
	}
	suffix, _ := publicsuffix.PublicSuffix(rest)
	return suffix != rest
}

// Below says that host is the name or lies under it.
func Below(host, name string) bool {
	return host == name || strings.HasSuffix(host, "."+name)
}

// DomainInput is a requested change. Panel and Admin are empty when the admin clears the requested host.
type DomainInput struct {
	DNSZone   string
	PanelHost string
	AdminHost string
}

// MaxServedHost is the longest host the apply step can serve: it names the Caddy snippet `<host>.caddy` in a file of the
// Caddy volume, and a file name holds 255 bytes. The grammar and the CHECKs allow 253, so a longer name than this one is
// valid text that no run of domain-apply could ever install; it is refused here, where the admin can still change it.
const MaxServedHost = 249

// DomainState is what the settings row holds before the change.
type DomainState struct {
	DNSZone         string // empty until a zone is set
	PrevDNSZone     string
	TransitionUntil *time.Time
	// ServedPanel and ServedAdmin are the hosts the services answer on now when the request names none: the applied host,
	// else the one of the .env. Empty when unknown. They are judged against the zones as the requested ones are (R17).
	ServedPanel, ServedAdmin string
}

// LiveZones are the zones a node gets in NodeConfig: the zone, and the earlier one until the transition ends.
func (s DomainState) LiveZones(now time.Time) []string {
	var out []string
	if s.DNSZone != "" {
		out = append(out, s.DNSZone)
	}
	if s.PrevDNSZone != "" && s.TransitionUntil != nil && now.Before(*s.TransitionUntil) {
		out = append(out, s.PrevDNSZone)
	}
	return out
}

// DomainHost is a host the change leaves in force, with the name of the field it is reported under.
type DomainHost struct {
	Field     string // panel_host or admin_host
	Host      string
	Requested bool // the request names it; false for the host that serves now and stays
}

// HostsInForce are the two hosts as they will be once the change is applied: the requested one, or, when the request
// names none, the one that serves now (the apply step keeps it). A host that is not known is left out.
func HostsInForce(in DomainInput, cur DomainState) []DomainHost {
	var out []DomainHost
	for _, h := range []DomainHost{
		{"panel_host", in.PanelHost, true}, {"admin_host", in.AdminHost, true},
	} {
		if h.Host == "" {
			if h.Field == "panel_host" {
				h.Host = cur.ServedPanel
			} else {
				h.Host = cur.ServedAdmin
			}
			h.Requested = false
		}
		if h.Host != "" {
			out = append(out, h)
		}
	}
	return out
}

// FailedDomainField names the first value CheckDomain refuses for a reason of text (the zone, a host grammar, a host
// under a zone, the same name twice), or "" when none does.
func FailedDomainField(in DomainInput, cur DomainState, now time.Time) string {
	if !ValidZone(in.DNSZone) {
		return "dns_zone"
	}
	zones := append(cur.LiveZones(now), in.DNSZone)
	hosts := HostsInForce(in, cur)
	for _, h := range hosts {
		// Only a requested host gets the grammar and length checks: the grammar of a host that serves now is the install's
		// business, and refusing it for that would lock the admin out of the settings. Every host in force, served or
		// requested, is still judged against the zones below, since a node would answer a host under a live zone.
		if h.Requested && (!ValidHost(h.Host) || len(h.Host) > MaxServedHost) {
			return h.Field
		}
		for _, z := range zones {
			if Below(h.Host, z) {
				return h.Field
			}
		}
	}
	if len(hosts) == 2 && hosts[0].Host == hosts[1].Host {
		return hosts[1].Field
	}
	return ""
}

// CheckDomain judges a requested change against the current state. A host must lie outside every live zone and the new
// one (R17): a panel served under the zone the nodes answer would be answered by a node. That holds for the host that
// keeps serving when the request names none, too, since a zone change can swallow it. The two hosts must differ, since
// Caddy would serve both services from one name.
func CheckDomain(in DomainInput, cur DomainState, now time.Time) error {
	if FailedDomainField(in, cur, now) != "" {
		return ErrDomain
	}
	// A change of zone is refused while the earlier one is still being phased out; a repeat of the same zone is no change.
	if in.DNSZone != cur.DNSZone && cur.PrevDNSZone != "" && cur.TransitionUntil != nil && now.Before(*cur.TransitionUntil) {
		return ErrTransition
	}
	return nil
}
