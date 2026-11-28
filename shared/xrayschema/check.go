// Package xrayschema is the allow-list of Xray configuration (p4b-proxy 7.2). A
// config a tenant admin pastes or imports is parsed here, checked against the table
// of one Xray release, and written again in a normal form. The panel runs it on
// save, and the node runs it again with the release it has installed before it
// tests the config with that binary.
//
// What it protects: Xray decodes JSON with encoding/json, which matches keys without
// case and ignores keys it does not know. So the checker folds case the same way,
// refuses a key given twice, refuses every key that reaches a file, the environment,
// a process or a script engine of the host, and lets nothing it does not know pass
// without a named, per-path decision (accept_unknown). It never echoes a value of
// the fragment: a rejection names a path and a reason, because a value may be a
// password.
package xrayschema

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Limits of a fragment.
const (
	// MaxFragmentBytes is the largest fragment (D31, p4b-proxy 3.2 item 2).
	MaxFragmentBytes = 32 << 10
	// MaxDepth is the deepest nesting of arrays and objects. A table that contains
	// itself (xhttp downloadSettings) stops here.
	MaxDepth = 32
	// maxMembers and maxItems bound one object and one array.
	maxMembers = 256
	maxItems   = 256
)

// Issue is one finding. Path is outbounds[i]... with the key spelled as it was
// written for an unknown key and in canonical case otherwise.
type Issue struct {
	Path string
	Msg  string
}

// Change is one thing the normal form did to the input, or one decision that let an
// unknown thing pass. Nothing is dropped or changed without one (D11).
type Change struct {
	Path string
	Msg  string
}

// Result is what Check returns. Warnings are blocking: a fragment passes only when
// both lists are empty, and a warning goes away only when its exact path is in
// accept_unknown, which turns it into a Change.
//
// Normalized is the one text a caller may store or hand to Xray, and it is empty
// unless OK(): a caller that writes whatever Normalized holds can never write a
// fragment that still has an unaccepted unknown key. Preview is the same normal form
// for display only, filled when nothing is rejected but warnings remain, so the panel
// can show the admin what an accepted path would let through (p4b-proxy 7.3). Never
// store it.
type Result struct {
	Normalized []byte
	Preview    []byte
	Diff       []Change
	Warnings   []Issue
	Rejected   []Issue
}

// OK reports whether the fragment may be stored.
func (r *Result) OK() bool { return len(r.Warnings) == 0 && len(r.Rejected) == 0 }

// Table is the allow-list of one Xray release.
type Table struct {
	tag   string
	build func() *node
	// rules classifies the state of the release (Stateful).
	rules func() statefulSet
}

// Release is the tag of the Xray release the table was written from.
func (t Table) Release() string { return t.tag }

// ---- parsing ----------------------------------------------------------------------

type val struct {
	k       byte // 'o' object, 'a' array, 's' string, 'n' number, 'b' boolean, 'z' null
	members []member
	items   []*val
	s       string // a string, or the text of a number
	b       bool
}

type member struct {
	key string
	v   *val
	// dead marks a member merged into its twin spelling; it is not written.
	dead bool
}

var errSyntax = errors.New("not valid JSON")
var errDepth = errors.New("nested deeper than the limit")

func parse(data []byte) (*val, error) {
	if !utf8.Valid(data) {
		return nil, errSyntax
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec, 1)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errSyntax
	}
	return v, nil
}

func parseValue(dec *json.Decoder, depth int) (*val, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, errSyntax
	}
	switch t := tok.(type) {
	case json.Delim:
		if depth > MaxDepth {
			return nil, errDepth
		}
		switch t {
		case '{':
			v := &val{k: 'o'}
			for dec.More() {
				kt, err := dec.Token()
				key, ok := kt.(string)
				if err != nil || !ok {
					return nil, errSyntax
				}
				if len(v.members) >= maxMembers {
					return nil, errors.New("an object has too many members")
				}
				c, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				v.members = append(v.members, member{key: key, v: c})
			}
			if _, err := dec.Token(); err != nil {
				return nil, errSyntax
			}
			return v, nil
		case '[':
			v := &val{k: 'a'}
			for dec.More() {
				if len(v.items) >= maxItems {
					return nil, errors.New("an array has too many items")
				}
				c, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				v.items = append(v.items, c)
			}
			if _, err := dec.Token(); err != nil {
				return nil, errSyntax
			}
			return v, nil
		}
		return nil, errSyntax
	case string:
		return &val{k: 's', s: t}, nil
	case json.Number:
		return &val{k: 'n', s: t.String()}, nil
	case bool:
		return &val{k: 'b', b: t}, nil
	case nil:
		// null means "absent" to Go's decoder. A listed or unlisted key with it is dropped
		// with a line in Diff (7.2); inside an accepted unknown subtree it stays as pasted.
		return &val{k: 'z'}, nil
	}
	return nil, errSyntax
}

// ---- the checker ------------------------------------------------------------------

type dialRef struct {
	out  int
	path string
	v    *val
}

type ctx struct {
	accept  map[string]bool
	res     *Result
	freedom bool // the outbound under the walk is freedom
	out     int
	dialers []dialRef
}

func (c *ctx) reject(path, msg string) {
	c.res.Rejected = append(c.res.Rejected, Issue{path, msg})
}

// unknownText ends every warning: the admin who accepts a path must know what the
// acceptance is worth (D11). It names what can go wrong and never a value.
const unknownText = "; Ctrl Z does not judge this, and it can stop the Xray process that every location of the node shares, also later and at a time the exit chooses"

func (c *ctx) warn(path, msg string) {
	if c.accept[path] {
		c.res.Diff = append(c.res.Diff, Change{path, "accepted as unknown by the admin: " + msg})
		return
	}
	c.res.Warnings = append(c.res.Warnings, Issue{path, msg + unknownText})
}

// unfit is the warning of a value that is not of the kind of its key. A structure that
// holds keys is still scanned for what is never allowed, whether or not the path is
// accepted.
func (c *ctx) unfit(path, why string, v *val) {
	c.warn(path, why)
	c.scanRaw(v, path)
}

func (c *ctx) changed(path, msg string) {
	c.res.Diff = append(c.res.Diff, Change{path, msg})
}

// Check parses one fragment, judges it against the table and returns the normal
// form. accept lists the paths the admin accepted as unknown (accept_unknown): each
// must be a path of the form of ValidPath, and it passes only the thing that sits at
// exactly that path.
func (t Table) Check(fragment []byte, accept []string) Result {
	res := Result{}
	c := &ctx{accept: map[string]bool{}, res: &res}
	for _, p := range accept {
		if !ValidPath(p) {
			c.reject(clip(p), "accept_unknown path is not the path of a key inside one outbound")
			continue
		}
		c.accept[p] = true
	}
	if len(fragment) > MaxFragmentBytes {
		c.reject("", "the fragment is larger than the limit")
		return res
	}
	root, err := parse(fragment)
	if err != nil {
		c.reject("", err.Error())
		return res
	}
	if root.k != 'o' {
		c.reject("", "the fragment is not an object")
		return res
	}
	var outs *val
	for i := range root.members {
		m := &root.members[i]
		if !strings.EqualFold(m.key, "outbounds") {
			c.reject(clip(m.key), "a fragment holds one top-level key, outbounds")
			continue
		}
		if outs != nil {
			c.reject("outbounds", "key given twice")
			continue
		}
		m.key = "outbounds"
		outs = m.v
	}
	switch {
	case outs == nil:
		c.reject("outbounds", "missing")
	case outs.k != 'a' || len(outs.items) == 0 || len(outs.items) > MaxOutbounds:
		c.reject("outbounds", "must be an array of 1 to 8 outbounds")
	default:
		for i, o := range outs.items {
			if o.k != 'o' {
				c.reject("outbounds["+strconv.Itoa(i)+"]", "an outbound must be an object")
			}
		}
	}
	if len(res.Rejected) != 0 {
		return res
	}
	node := t.build()
	for i, o := range outs.items {
		c.out = i
		c.freedom = isFreedom(o)
		path := "outbounds[" + strconv.Itoa(i) + "]"
		c.walk(node, o, path)
	}
	if len(res.Rejected) == 0 {
		c.chain(outs)
	}
	if len(res.Rejected) != 0 {
		res.Diff = nil
		return res
	}
	if len(res.Warnings) != 0 {
		res.Preview = encode(root)
		return res
	}
	res.Normalized = encode(root)
	return res
}

func clip(s string) string {
	if len(s) > 64 {
		s = s[:64]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

func isFreedom(o *val) bool {
	if o.k != 'o' {
		return false
	}
	for _, m := range o.members {
		if strings.EqualFold(m.key, "protocol") && m.v.k == 's' {
			l := strings.ToLower(m.v.s)
			return l == "freedom" || l == "direct"
		}
	}
	return false
}

// globalRejected are the keys that reach a file, the environment, a process or a
// script engine of the host, or the sockets of the host, or that the node writes
// itself, at any depth of an outbound (7.2). It is judged before everything else, so a
// null or an empty value does not drop one of them. A key of a free-form map is a value
// and is not judged here.
func globalRejected() map[string]string {
	return map[string]string{
		"xdrivesettings":      "the xdrive transport reads and writes files of the host",
		"script":              "a script runs in the Lua engine of the host",
		"webhook":             "a webhook sends requests from the host",
		"env":                 "reads the environment of the host",
		"metrics":             "opens a listener on the host",
		"geodata":             "reads and writes geodata files of the host",
		"process":             "reaches a process of the host",
		"redirect":            "redirects traffic of the host",
		"reverse":             "opens a reverse tunnel",
		"masterkeylog":        "writes TLS secrets to a file",
		"certificatefile":     "reads a file of the host",
		"keyfile":             "reads a file of the host",
		"dir":                 "reads a directory of the host",
		"sendthrough":         "binds the socket to an address of the host",
		"mark":                "sets a socket mark of the host",
		"interface":           "binds the socket to an interface of the host",
		"tproxy":              "changes how the host's sockets work",
		"customsockopt":       "sets raw socket options",
		"acceptproxyprotocol": "a server-side setting",
		"proxysettings":       "removed from the release; dialerProxy replaces it",
		"portmapping":         "asks the gateway of the host for a UPnP or NAT-PMP port",
		"addressportstrategy": "makes the node resolve SRV or TXT records to choose an address or a port",
		"debug":               "sets HYSTERIA_BBR_DEBUG and HYSTERIA_BRUTAL_DEBUG in the environment of the process",
		// One dial would race up to maxConcurrentTry ports and as many tracked connections,
		// which the dial limits of the node (p4b-proxy 5.5) are not sized for.
		"happyeyeballs": "races several ports for one dial, which the dial limits of the node do not cover",
		// A warning would not do: an exact path in accept_unknown passes a warning, and each
		// testpre starts endless pre-dial goroutines that survive rmo (finding 4).
		"testpre": "starts goroutines that dial the exit for ever and outlive the config",
		// An echConfigList with :// is judged by value (keyedChecks); the rest of the list
		// is unknown like any key.
		"isclient":       "turns the WireGuard client into a server",
		"finalrules":     "the node writes the final rules of every freedom outbound",
		"ipsblocked":     "the node writes the final rules of every freedom outbound",
		"masquesettings": "the masque transport belongs to the masque outbound, which is not allowed",
	}
}

// keyedChecks are the keys whose string value is judged wherever the key sits, in a
// subtree of an accepted unknown key too. echConfigList with "://" makes Xray query a
// DoH, h2c or plain UDP server for the exit's ECH record with socket options of its own,
// and resolve that server's name by the host resolver (7.2, 7.4). Only a standard base64
// list (what Xray decodes with base64.StdEncoding) passes, and then only as an unknown key.
func keyedChecks() map[string]func(string) string {
	return map[string]func(string) string{
		"echconfiglist": checkECHList,
	}
}

func checkECHList(s string) string {
	if _, err := base64.StdEncoding.DecodeString(s); err != nil {
		return "echConfigList must be a base64 list: a value with :// or a name makes Xray query a server of its own"
	}
	return ""
}

// keyedCheck judges a member by its key where no table node does.
func keyedCheck(key string, v *val) (string, bool) {
	if v.k != 's' {
		return "", false
	}
	for k, fn := range keyedChecks() {
		if strings.EqualFold(key, k) {
			if why := fn(v.s); why != "" {
				return why, true
			}
		}
	}
	return "", false
}

// forbiddenKey judges a key with its value: the always-rejected keys at any depth, a
// true allowInsecure (the release refuses it), and a dialerProxy of a freedom outbound.
func (c *ctx) forbiddenKey(key string, v *val) (string, bool) {
	for k, why := range globalRejected() {
		if strings.EqualFold(key, k) {
			return why, true
		}
	}
	if strings.EqualFold(key, "allowInsecure") && v.k == 'b' && v.b {
		return "the release refuses allowInsecure; pin the certificate with pinnedPeerCertSha256", true
	}
	if c.freedom && strings.EqualFold(key, "dialerProxy") {
		return "a freedom outbound is the last hop and has no dialerProxy", true
	}
	return "", false
}

// badValue reports whether a string value, or one comma-separated part of it, starts
// like a reference to a file, the geodata or the environment of the host: ext:,
// ext-site:, geoip:, geosite: and env:, after any number of "!". Xray reads env: in an
// address or a port list, and ext: and the geo prefixes in every list of rules.
func badValue(s string) bool {
	for _, part := range strings.Split(s, ",") {
		// Xray's rule parser strips every leading "!" (and maps geoip: and geosite: to
		// ext:), so one trimmed "!" would let "!!ext:" through. Spaces are trimmed too,
		// because a loader that trims them later must not see a different prefix.
		p := strings.TrimLeft(strings.ToLower(strings.TrimSpace(part)), "! \t\r\n")
		for _, pre := range []string{"ext:", "ext-ip:", "ext-domain:", "ext-site:", "geoip:", "geosite:", "env:"} {
			if strings.HasPrefix(p, pre) {
				return true
			}
		}
	}
	return false
}

func (c *ctx) checkString(path, s string) bool {
	if badValue(s) {
		c.reject(path, "the value reaches a file, the geodata or the environment of the host")
		return false
	}
	return true
}

// rawRejected lists the keys that a subtree without a node must refuse on top of the
// global list. dialerProxy is refused rather than rewritten: a link inside a subtree
// the table does not know cannot join the chain check, so it could name another
// config's outbound.
func rawRejected(key string) (string, bool) {
	if strings.EqualFold(key, "dialerproxy") {
		return "a link in a subtree the table does not know escapes the chain check", true
	}
	return "", false
}

// repeatedKey finds a key that occurs twice in one object under Unicode simple
// folding, the way Go's decoder would pair them (7.2: a repeated key is refused in
// any case). The quadratic loop is bounded by maxMembers.
func repeatedKey(ms []member) (string, bool) {
	for i := range ms {
		for j := i + 1; j < len(ms); j++ {
			if strings.EqualFold(ms[i].key, ms[j].key) {
				return ms[j].key, true
			}
		}
	}
	return "", false
}

// scanRaw judges a subtree the table has no node for (an unknown key, or a value that
// is not of its kind): the keys and values that are never allowed are refused in it
// too, whatever the admin accepted. No bound, pattern or combination is judged there.
func (c *ctx) scanRaw(v *val, path string) {
	switch v.k {
	case 'o':
		if key, dup := repeatedKey(v.members); dup {
			c.reject(path+"."+clip(key), "key given twice")
			return
		}
		for _, m := range v.members {
			p := path + "." + clip(m.key)
			if why, bad := c.forbiddenKey(m.key, m.v); bad {
				c.reject(p, "key is never allowed: "+why)
				continue
			}
			if why, bad := rawRejected(m.key); bad {
				c.reject(p, "key is never allowed here: "+why)
				continue
			}
			if why, bad := keyedCheck(m.key, m.v); bad {
				c.reject(p, why)
				continue
			}
			c.scanRaw(m.v, p)
		}
	case 'a':
		for i, it := range v.items {
			c.scanRaw(it, path+"["+strconv.Itoa(i)+"]")
		}
	case 's':
		c.checkString(path, v.s)
	}
}

// lookup finds the canonical key of a member in an object node. Go's decoder takes
// an exact match first and then the first match under Unicode simple folding, and
// strings.EqualFold is that folding.
func lookup(n *node, key string) (canon string, child *node, viaAlias bool, ok bool) {
	if ch, found := n.fields[key]; found {
		return key, ch, false, true
	}
	if nw, found := n.alias[key]; found {
		return nw, n.fields[nw], true, true
	}
	keys := make([]string, 0, len(n.fields)+len(n.alias))
	for k := range n.fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.EqualFold(key, k) {
			return k, n.fields[k], false, true
		}
	}
	olds := make([]string, 0, len(n.alias))
	for k := range n.alias {
		olds = append(olds, k)
	}
	sort.Strings(olds)
	for _, k := range olds {
		if strings.EqualFold(key, k) {
			return n.alias[k], n.fields[n.alias[k]], true, true
		}
	}
	return "", nil, false, false
}

func (c *ctx) walk(n *node, v *val, path string) {
	switch n.k {
	case kObj:
		if v.k != 'o' {
			c.unfit(path, "must be an object", v)
			return
		}
		c.walkObject(n, v, path)
	case kArr:
		if v.k != 'a' {
			c.unfit(path, "must be an array", v)
			return
		}
		if len(v.items) < n.minN || len(v.items) > n.maxN {
			c.warn(path, "must hold "+strconv.Itoa(n.minN)+" to "+strconv.Itoa(n.maxN)+" items")
		}
		for i, it := range v.items {
			c.walk(n.elem, it, path+"["+strconv.Itoa(i)+"]")
		}
	case kDialer:
		// A link that is no string cannot join the chain check, and it is no kind
		// problem the admin can judge: it is refused.
		if v.k != 's' {
			c.reject(path, "dialerProxy must be a string: it names another outbound of the fragment")
			return
		}
		if c.checkString(path, v.s) {
			c.dialers = append(c.dialers, dialRef{c.out, path, v})
		}
	case kEnum:
		c.walkEnum(n, v, path)
	case kOneOf:
		// The loader folds the case of an enum that sits in a choice (fragment.packets
		// is lower-cased), so it is written in its canonical form like a plain enum.
		if v.k == 's' {
			for _, a := range n.alts {
				if canon, ok := a.enum[strings.ToLower(v.s)]; a.k == kEnum && ok && canon != v.s {
					c.changed(path, "value written in its canonical form")
					v.s = canon
					break
				}
			}
		}
		c.walkLeaf(n, v, path)
	case kHeaders:
		c.walkHeaders(n, v, path)
	default:
		c.walkLeaf(n, v, path)
	}
}

func (c *ctx) walkLeaf(n *node, v *val, path string) {
	if v.k == 's' && !c.checkString(path, v.s) {
		return
	}
	if why := fits(n, v); why != "" {
		c.unfit(path, why, v)
	}
}

// walkEnum folds the value as the loader of the release folds it and writes it in its
// canonical form. A protocol, a security, a cipher or a transport that the table does not
// name can never be accepted, except the values the node lists as soft (kcp).
func (c *ctx) walkEnum(n *node, v *val, path string) {
	if v.k != 's' {
		if n.soft {
			c.unfit(path, "must be a string", v)
		} else {
			c.reject(path, "value is not allowed")
		}
		return
	}
	if !c.checkString(path, v.s) {
		return
	}
	canon, ok := n.enum[strings.ToLower(v.s)]
	switch {
	case !ok && n.soft:
		c.warn(path, "unknown value")
	case !ok:
		c.reject(path, "value is not allowed")
	case n.softVals[canon]:
		// Left as pasted: it is not on the list, so it is not written in a form of ours.
		c.warn(path, "unknown value")
	case canon != v.s:
		c.changed(path, "value written in its canonical form")
		v.s = canon
	}
}

// walkHeaders judges an object of header names. Two equal names are one key of a Go
// map twice, and the first value would be dropped without a word, so they are refused;
// names that differ in case are two keys and stay.
func (c *ctx) walkHeaders(n *node, v *val, path string) {
	if v.k != 'o' {
		c.unfit(path, "must be an object", v)
		return
	}
	seen := make(map[string]bool, len(v.members))
	for _, m := range v.members {
		p := path + "." + clip(m.key)
		if seen[m.key] {
			c.reject(p, "key given twice")
			return
		}
		seen[m.key] = true
		switch m.v.k {
		case 's':
			c.checkString(p, m.v.s)
		case 'a':
			for i, it := range m.v.items {
				if it.k == 's' {
					c.checkString(p+"["+strconv.Itoa(i)+"]", it.s)
				}
			}
		}
		if m.v.k == 'o' || m.v.k == 'a' {
			c.scanRaw(m.v, p)
		}
	}
	if why := fits(n, v); why != "" {
		c.warn(path, why)
	}
}

func repeatedUnknown(ms []*member) (string, bool) {
	for i := range ms {
		for j := i + 1; j < len(ms); j++ {
			if strings.EqualFold(ms[i].key, ms[j].key) {
				return ms[j].key, true
			}
		}
	}
	return "", false
}

type group struct {
	canon string
	child *node
	items []gmember
}

type gmember struct {
	m        *member
	viaAlias bool
}

// emptyValue is the loader's own default for a key: null, or an empty string. A listed
// key with such a value is dropped, and so is an unlisted key whose value is also false.
func emptyValue(v *val, unlisted bool) bool {
	switch v.k {
	case 'z':
		return true
	case 's':
		return v.s == ""
	case 'b':
		return unlisted && !v.b
	}
	return false
}

func (c *ctx) drop(m *member, path, why string) {
	m.dead = true
	c.changed(path, "removed: "+why)
}

func (c *ctx) walkObject(n *node, v *val, path string) {
	// The selector of a variant is read first so the member that depends on it
	// gets the right node.
	selCanon := ""
	if n.sel != nil {
		has := false
		for _, m := range v.members {
			if strings.EqualFold(m.key, n.selKey) && !emptyValue(m.v, false) {
				has = true
				if m.v.k == 's' {
					selCanon = n.fields[n.selKey].enum[strings.ToLower(m.v.s)]
				}
			}
		}
		if !has {
			// Without it no table node judges the settings, and a misspelt key in them
			// would never be shown as unknown.
			c.reject(path+"."+n.selKey, "missing")
		}
	}
	var groups []*group
	byCanon := map[string]*group{}
	var unknown []*member
	for i := range v.members {
		m := &v.members[i]
		if why, bad := c.forbiddenKey(m.key, m.v); bad {
			c.reject(path+"."+clip(m.key), "key is never allowed: "+why)
			continue
		}
		canon, child, viaAlias, ok := lookup(n, m.key)
		if !ok {
			unknown = append(unknown, m)
			continue
		}
		g := byCanon[canon]
		if g == nil {
			g = &group{canon: canon, child: child}
			byCanon[canon] = g
			groups = append(groups, g)
		}
		g.items = append(g.items, gmember{m, viaAlias})
	}
	for _, g := range groups {
		p := path + "." + g.canon
		child := g.child
		if n.sel != nil && g.canon == n.selOn {
			child = n.sel[selCanon]
		}
		newSpelled, oldSpelled := 0, 0
		for _, it := range g.items {
			if it.viaAlias {
				oldSpelled++
			} else {
				newSpelled++
			}
		}
		if newSpelled > 1 || oldSpelled > 1 {
			c.reject(p, "key given twice")
			continue
		}
		live := make([]gmember, 0, len(g.items))
		for _, it := range g.items {
			switch {
			case emptyValue(it.m.v, false):
				c.drop(it.m, p, "null or empty, the default of Xray")
			case g.child != nil && g.child.k == kDropped && (!g.child.zeroOnly || isZero(it.m.v)) && (!g.child.firstOnly || c.out == 0):
				c.drop(it.m, p, "it has no effect on this node")
			case g.child != nil && g.child.k == kDropped:
				// A legacy key with a value that is not its dropped one, or a key that is idle
				// on the first outbound alone and sits on a hop, is unknown.
				c.warn(p, "unknown key")
				c.scanRaw(it.m.v, p)
				live = append(live, it)
			default:
				live = append(live, it)
			}
		}
		for _, it := range live {
			if g.child != nil && g.child.k == kDropped {
				continue
			}
			if child == nil {
				// The selector is not in the table: the rejection of the selector
				// stands, and the settings are only scanned. A soft selector (a mask
				// type, say) is only a warning that the admin may accept, and an
				// acceptance passes the thing at exactly its path. The settings that
				// no table judged get a path of their own, or one acceptance would
				// carry a whole unseen subtree into the stored fragment (B1n-r2-5).
				if sel := n.fields[n.selKey]; n.sel != nil && g.canon == n.selOn && sel != nil && (sel.soft || sel.softVals[selCanon]) {
					c.warn(p, "unknown key")
				}
				c.scanRaw(it.m.v, p)
			} else {
				c.walk(child, it.m.v, p)
			}
		}
		if len(live) == 2 {
			a, b := live[0].m, live[1].m
			if !bytes.Equal(encode(a.v), encode(b.v)) {
				c.reject(p, "the old and the new spelling of the key hold different values")
				continue
			}
			c.changed(p, "the old and the new spelling of the key held one value; written once")
		}
		for _, it := range live {
			if it.m.key != g.canon {
				c.changed(p, "key written in its canonical spelling")
			}
			it.m.key = g.canon
		}
		if len(live) == 2 {
			// Drop the second one; both are equal and now share a key.
			live[1].m.dead = true
		}
	}
	if key, dup := repeatedUnknown(unknown); dup {
		c.reject(path+"."+clip(key), "key given twice")
	}
	for _, m := range unknown {
		p := path + "." + clip(m.key)
		if why, bad := rawRejected(m.key); bad {
			c.reject(p, "key is never allowed here: "+why)
			continue
		}
		if why, bad := keyedCheck(m.key, m.v); bad {
			c.reject(p, why)
			continue
		}
		if emptyValue(m.v, true) {
			c.drop(m, p, "null, false or empty, the default of Xray")
			continue
		}
		c.warn(p, "unknown key")
		c.scanRaw(m.v, p)
	}
	// Remove the merged and dropped members, then judge what is missing.
	kept := v.members[:0]
	for _, m := range v.members {
		if !m.dead {
			kept = append(kept, m)
		}
	}
	v.members = kept
	for _, key := range n.required {
		if memberOf(v, key) == nil {
			c.warn(path+"."+key, "missing")
		}
	}
	if n.post != nil {
		if key, why := n.post(v); why != "" {
			c.warn(path+key, why)
		}
	}
	for _, key := range n.forceTrue {
		found := false
		for i := range v.members {
			if v.members[i].key == key {
				found = true
				if v.members[i].v.k != 'b' || !v.members[i].v.b {
					c.changed(path+"."+key, "set to true: the node cannot open a kernel interface")
					v.members[i].v = &val{k: 'b', b: true}
				}
			}
		}
		if !found {
			c.changed(path+"."+key, "set to true: the node cannot open a kernel interface")
			v.members = append(v.members, member{key: key, v: &val{k: 'b', b: true}})
		}
	}
	sort.SliceStable(v.members, func(i, j int) bool { return v.members[i].key < v.members[j].key })
}

// memberOf finds a member of an object by key, in any case. An object that was walked
// has no key twice.
func memberOf(v *val, key string) *val {
	if v == nil || v.k != 'o' {
		return nil
	}
	for i := range v.members {
		if strings.EqualFold(v.members[i].key, key) {
			return v.members[i].v
		}
	}
	return nil
}

func isZero(v *val) bool { return v.k == 'n' && v.s == "0" }

// chain judges the dialerProxy links of the fragment (7.2): each names the tag of
// exactly one other outbound, there is no cycle, every outbound is reached from the
// first, and the first is not freedom. It then writes the tags n and the links in
// the form of the normal form, so no tag of the user reaches Xray.
func (c *ctx) chain(outs *val) {
	count := map[string]int{}
	index := map[string]int{}
	for i, o := range outs.items {
		for _, m := range o.members {
			if m.key == "tag" && m.v.k == 's' && m.v.s != "" {
				count[m.v.s]++
				index[m.v.s] = i
			}
		}
	}
	edges := make([][]int, len(outs.items))
	for _, d := range c.dialers {
		if d.v.s == "" {
			continue
		}
		t, ok := index[d.v.s]
		if !ok || count[d.v.s] != 1 {
			c.reject(d.path, "dialerProxy names no outbound of the fragment, or more than one")
			continue
		}
		if t == d.out {
			c.reject(d.path, "dialerProxy names its own outbound")
			continue
		}
		edges[d.out] = append(edges[d.out], t)
	}
	if len(c.res.Rejected) != 0 {
		return
	}
	if isFreedom(outs.items[0]) {
		c.reject("outbounds[0].protocol", "the first outbound is the exit and cannot be freedom")
	}
	// Cycles, by depth-first search with colours.
	state := make([]uint8, len(edges))
	var dfs func(i int) bool
	dfs = func(i int) bool {
		state[i] = 1
		for _, j := range edges[i] {
			if state[j] == 1 || state[j] == 0 && dfs(j) {
				return true
			}
		}
		state[i] = 2
		return false
	}
	for i := range edges {
		if state[i] == 0 && dfs(i) {
			c.reject("outbounds["+strconv.Itoa(i)+"]", "the dialerProxy links make a cycle")
			return
		}
	}
	// Reached from the first.
	seen := make([]bool, len(edges))
	var visit func(i int)
	visit = func(i int) {
		if seen[i] {
			return
		}
		seen[i] = true
		for _, j := range edges[i] {
			visit(j)
		}
	}
	visit(0)
	for i, s := range seen {
		if !s {
			c.reject("outbounds["+strconv.Itoa(i)+"]", "not reached from the first outbound through dialerProxy")
		}
	}
	if len(c.res.Rejected) != 0 {
		return
	}
	// A hysteria outbound that is a hop is handed the UDP of the outbound before it
	// (wireguard, hysteria, xhttp over h3, kcp, and any socks or shadowsocks hop between
	// them dial UDP), and it sends that as QUIC datagrams cut to the size the exit
	// announces, with no lower bound. FragUDPMessage counts the fragments in a uint8, so a
	// small size indexes past its slice and ends the process that all locations share
	// (B1n-r3-2). The closed rule is the simple one: hysteria anywhere but first is unknown.
	for i := 1; i < len(outs.items); i++ {
		if p := memberOf(outs.items[i], "protocol"); p != nil && p.k == 's' && p.s == "hysteria" {
			c.warn("outbounds["+strconv.Itoa(i)+"].settings", "a hysteria outbound used as a hop can be handed UDP, which it sends as datagrams of a size the exit chooses")
		}
	}
	for i, o := range outs.items {
		set := false
		for k := range o.members {
			if o.members[k].key == "tag" {
				o.members[k].v = &val{k: 's', s: strconv.Itoa(i)}
				set = true
			}
		}
		if !set {
			o.members = append(o.members, member{key: "tag", v: &val{k: 's', s: strconv.Itoa(i)}})
		}
		sort.SliceStable(o.members, func(a, b int) bool { return o.members[a].key < o.members[b].key })
	}
	for _, d := range c.dialers {
		if d.v.s == "" {
			continue
		}
		d.v.s = strconv.Itoa(index[d.v.s])
	}
}

// ---- output -----------------------------------------------------------------------

func encode(v *val) []byte {
	var b bytes.Buffer
	write(&b, v)
	return b.Bytes()
}

func write(b *bytes.Buffer, v *val) {
	switch v.k {
	case 'o':
		b.WriteByte('{')
		for i, m := range v.members {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, m.key)
			b.WriteByte(':')
			write(b, m.v)
		}
		b.WriteByte('}')
	case 'a':
		b.WriteByte('[')
		for i, it := range v.items {
			if i > 0 {
				b.WriteByte(',')
			}
			write(b, it)
		}
		b.WriteByte(']')
	case 's':
		writeString(b, v.s)
	case 'n':
		b.WriteString(v.s)
	case 'b':
		if v.b {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case 'z':
		b.WriteString("null")
	}
}

func writeString(b *bytes.Buffer, s string) {
	e := json.NewEncoder(b)
	e.SetEscapeHTML(false)
	_ = e.Encode(s)
	// Encode ends the value with a newline.
	b.Truncate(b.Len() - 1)
}
