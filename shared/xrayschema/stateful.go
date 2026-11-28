package xrayschema

import "strings"

// transportState says whether a transport keeps state that rmo leaves behind.
type transportState uint8

const (
	never  transportState = iota // nothing outlives the handler
	always                       // a session or connection in a map of the process that nothing closes (hysteria, grpc)
	withH3                       // only with h3 in the alpn of its TLS settings (xhttp)
)

// statefulSet is the classification of one release (see statefulRules).
type statefulSet struct {
	protocols  map[string]bool
	transports map[string]transportState
}

// Stateful reports whether the config holds an outbound, at any depth, whose handler
// keeps a device, a socket or a session that rmo leaves up (p4b-proxy 7.2): protocol
// wireguard or hysteria, transport hysteria or grpc, or xhttp with h3 in an alpn anywhere
// inside its stream settings (tlsSettings, downloadSettings and extra included). B5
// rebuilds such a config in the idle slot on every change, removal or disable.
//
// The answer errs towards true: a fragment that cannot be read, one that the table does
// not pass without accept_unknown, or a table with no rules, is called stateful, because the cost of a wrong true is one rebuild and the
// cost of a wrong false is a second WireGuard device with the same key.
func (t Table) Stateful(fragment []byte) bool {
	if t.rules == nil {
		return true
	}
	// A fragment the table does not pass as it stands (one that cannot be read, one with
	// an accepted unknown key or value) is stateful: nobody read what its handler keeps.
	if r := t.Check(fragment, nil); len(r.Rejected) != 0 || len(r.Warnings) != 0 {
		return true
	}
	root, err := parse(fragment)
	if err != nil {
		return true
	}
	return t.rules().walk(root, false)
}

func (s statefulSet) transport(spelling string) (transportState, bool) {
	// The loader folds the transport with strings.ToLower and knows the old spellings
	// (tcp, splithttp, mkcp, websocket), which the transport enum maps.
	canon, ok := transportEnum().enum[strings.ToLower(strings.TrimSpace(spelling))]
	if !ok {
		return never, false
	}
	st, ok := s.transports[canon]
	return st, ok
}

// walk looks at every object of the tree. inXhttp is true inside the subtree of an
// xhttp stream, where an alpn with h3 makes its dials ride one QUIC session.
func (s statefulSet) walk(v *val, inXhttp bool) bool {
	switch v.k {
	case 'a':
		for _, it := range v.items {
			if s.walk(it, inXhttp) {
				return true
			}
		}
	case 'o':
		xhttp := inXhttp
		for _, m := range v.members {
			if m.v.k != 's' {
				continue
			}
			switch {
			case strings.EqualFold(m.key, "protocol"):
				if s.protocols[strings.ToLower(m.v.s)] {
					return true
				}
			case strings.EqualFold(m.key, "method"), strings.EqualFold(m.key, "network"):
				switch st, ok := s.transport(m.v.s); {
				case ok && st == always:
					return true
				case ok && st == withH3:
					xhttp = true
				}
			}
		}
		for _, m := range v.members {
			if xhttp && strings.EqualFold(m.key, "alpn") && hasH3(m.v) {
				return true
			}
			if s.walk(m.v, xhttp) {
				return true
			}
		}
	}
	return false
}

// hasH3 reads an alpn the way Xray's StringList does: an array, or one string whose
// parts are separated by commas.
func hasH3(v *val) bool {
	switch v.k {
	case 's':
		for _, p := range strings.Split(v.s, ",") {
			if strings.EqualFold(strings.TrimSpace(p), "h3") {
				return true
			}
		}
	case 'a':
		for _, it := range v.items {
			if it.k == 's' && hasH3(it) {
				return true
			}
		}
	}
	return false
}
