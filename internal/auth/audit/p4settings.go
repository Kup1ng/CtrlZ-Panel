package audit

import "github.com/google/uuid"

// The admin events of the P4 settings and certificate routes (p4-nodes 9.1, 9.2): free DNS, the domain and the uploaded
// certificates. They sit in a file of their own beside nodes.go so the P4 routes add events without touching the P1 list.
// None carries a key, a chain, a name of a certificate or a client address.

// CertKind is the kind of an uploaded certificate row, which is all an audit row says of the certificate itself.
type CertKind string

// The kinds the admin may upload (p4-nodes 4.3).
const (
	CertWildcard CertKind = "wildcard"
	CertPanel    CertKind = "panel"
	CertAdmin    CertKind = "admin"
)

// Valid reports membership.
func (k CertKind) Valid() bool {
	switch k {
	case CertWildcard, CertPanel, CertAdmin:
		return true
	}
	return false
}

// DomainName is a zone as the audit row of a domain change records it: a hostname of the operator in the grammar of
// Host, or empty when there was no zone yet (a first set). It is a type of its own because Host has no empty member: the
// RP ID of a first Passkey set is recorded as invalid, which would mislead for a zone.
type DomainName string

// DomainNameInvalid stands for a zone that is not in the grammar, as HostInvalid does for an RP ID.
const DomainNameInvalid DomainName = "invalid"

// DomainNameNone is the empty zone of a first set.
const DomainNameNone DomainName = ""

// DomainNameOf maps a zone to its member: empty stays empty, a name in the grammar stays, anything else is HostInvalid's text.
func DomainNameOf(s string) DomainName {
	if s == "" {
		return DomainNameNone
	}
	return DomainName(HostOf(s))
}

// Valid reports membership.
func (d DomainName) Valid() bool {
	return d == DomainNameNone || d == DomainNameInvalid || hostGrammar(string(d))
}

type (
	// FreeDNSChange records a change of the free DNS switch or rate: the switch before and after and the rate after.
	FreeDNSChange struct {
		FromEnabled bool `json:"from_enabled"`
		ToEnabled   bool `json:"to_enabled"`
		QPS         int  `json:"qps"`
	}
	// DomainChange records a change of the domain settings: the zone before and after as hostnames of the operator, whether
	// a host changed, and the length of the transition when this change started one (0 when it did not).
	DomainChange struct {
		FromZone       DomainName `json:"from_zone"`
		ToZone         DomainName `json:"to_zone"`
		HostsChanged   bool       `json:"hosts_changed"`
		TransitionDays int        `json:"transition_days"`
	}
	// CertificateUpload records an uploaded certificate: its kind and how many names the leaf carries. Never the names,
	// the chain or the key.
	CertificateUpload struct {
		Certificate uuid.UUID `json:"-"`
		Kind        CertKind  `json:"kind"`
		Names       int       `json:"names"`
	}
	// CertificateRetire records the retirement of an uploaded certificate.
	CertificateRetire struct {
		Certificate uuid.UUID `json:"-"`
	}
)

func (FreeDNSChange) Action() string     { return "settings.free_dns" }
func (DomainChange) Action() string      { return "settings.domain" }
func (CertificateUpload) Action() string { return "certificate.upload" }
func (CertificateRetire) Action() string { return "certificate.retire" }

func (FreeDNSChange) Target() string       { return "free_dns_settings" }
func (DomainChange) Target() string        { return "domain_settings" }
func (e CertificateUpload) Target() string { return idTarget("certificate", e.Certificate) }
func (e CertificateRetire) Target() string { return idTarget("certificate", e.Certificate) }

func (FreeDNSChange) adminEvent()     {}
func (DomainChange) adminEvent()      {}
func (CertificateUpload) adminEvent() {}
func (CertificateRetire) adminEvent() {}
