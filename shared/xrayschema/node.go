package xrayschema

import "strings"

// kind is the shape and the bound of what a table node accepts. Every leaf kind is
// closed: it has a bound that holds for any value, so a listed key never lets a value
// through that nobody sized (p4b-proxy 7.2). A value that is not of its kind is not
// a rejection: it is the same per-path warning as an unknown key.
type kind uint8

const (
	kObj      kind = iota + 1 // object with the keys of fields
	kArr                      // array of elem, minN to maxN items
	kBool                     // true or false
	kInt                      // a whole number within lim
	kRange                    // a whole number, or "x-y" with both ends within lim and x not above y
	kEnum                     // a string that must be one of enum
	kHost                     // an IP literal, or a DNS name with a dot, at most 253 bytes
	kHostPort                 // host:port, or [v6]:port
	kText                     // 1 to 255 bytes, no control character
	kPath                     // 1 to 255 printable ASCII characters, no space
	kHeaders                  // an object of at most 16 HTTP tokens with short printable values
	kUUIDText                 // a UUID, or text of at most 30 bytes
	kKey32                    // 32 bytes as hex or base64 (a WireGuard key)
	kKey32URL                 // 32 bytes as base64url with no padding (a REALITY key)
	kIP                       // an IP address or a prefix, no zone
	kPins                     // 1 to 4 SHA-256 in hex
	kShortID                  // at most 16 hex digits
	kSpiderX                  // "/" and at most 254 of A-Z a-z 0-9 / . _ ~ -
	kOneOf                    // any one of alts
	kDialer                   // a string that names another outbound by its tag (judged by the chain)
	kDropped                  // removed from the fragment with a line in Diff
	kPrefix                   // an IP prefix with its length, no zone
	kHTTPHost                 // a Host value: host or host:port, ASCII only
)

// node is one place of a release table. The tables are built by functions and
// never kept in a package-level variable: the module has no mutable package state,
// and a table is read-only once Check has it.
type node struct {
	k kind
	// fields maps the canonical spelling of each allowed key to its node.
	fields map[string]*node
	// alias maps an old spelling to the canonical (new) one. A member under either
	// is stored under the new one; both with different values is a rejection.
	alias map[string]string
	elem  *node
	// minN and maxN bound the items of a kArr.
	minN, maxN int
	// enum maps the lower-case spelling of a value to its canonical form. The loader
	// of the release folds these values with strings.ToLower before it compares, and so
	// does Check. soft says that an unknown value is a warning that accept_unknown can
	// pass; a hard enum refuses it for good. softVals lists canonical values of a hard
	// enum that are an unknown value and not a rejection (the transport kcp).
	enum     map[string]string
	soft     bool
	softVals map[string]bool
	// A variant picks the node of one member by the value of another: selKey is the
	// member that holds the selector (an enum), selOn the member that depends on it.
	selKey, selOn string
	sel           map[string]*node
	// lim bounds a kInt, and the ends of a kRange.
	lim *limit
	// multi lets a kHeaders value be a list of 1 to 8 strings (the raw http header).
	multi bool
	// alts are the choices of a kOneOf, each a leaf node.
	alts []*node
	// zeroOnly makes a kDropped drop the number 0 alone: a legacy key with any other
	// value is not dropped but unknown.
	zeroOnly bool
	// firstOnly makes a kDropped drop only on the first outbound, the one the SOCKS inbound
	// feeds. A hop can be handed the UDP of the outbound before it, so a key that is idle
	// for the first outbound (mux xudp keys) is an unknown key on a hop.
	firstOnly bool
	// required lists keys that must be present; a missing one is a warning at its path.
	required []string
	// forceTrue lists boolean keys that the normal form always sets to true.
	forceTrue []string
	// post judges a whole object after its members were walked and written in their
	// canonical form, for a rule that depends on several members at once. It returns
	// the path below the object ("" or ".key") and the reason, or an empty reason; the
	// reason is a warning, like any value that is not of its kind. It never echoes a
	// value.
	post func(v *val) (key, why string)
}

type fd struct {
	key string
	n   *node
}

func f(key string, n *node) fd { return fd{key, n} }

func obj(fs ...fd) *node {
	n := &node{k: kObj, fields: make(map[string]*node, len(fs))}
	for _, x := range fs {
		n.fields[x.key] = x.n
	}
	return n
}

// aliased records that old is the former spelling of key.
func (n *node) aliased(key, old string) *node {
	if n.alias == nil {
		n.alias = map[string]string{}
	}
	n.alias[old] = key
	return n
}

// postChecked attaches a check of the whole object (see post).
func (n *node) postChecked(fn func(v *val) (string, string)) *node {
	n.post = fn
	return n
}

func (n *node) forcing(keys ...string) *node {
	n.forceTrue = append(n.forceTrue, keys...)
	return n
}

// needing lists keys that an object must have.
func (n *node) needing(keys ...string) *node {
	n.required = append(n.required, keys...)
	return n
}

// arrN is an array of minN to maxN items of elem. No array of a table is unbounded.
func arrN(minN, maxN int, elem *node) *node {
	return &node{k: kArr, elem: elem, minN: minN, maxN: maxN}
}

func boolean() *node      { return &node{k: kBool} }
func host() *node         { return &node{k: kHost} }
func hostPort() *node     { return &node{k: kHostPort} }
func text() *node         { return &node{k: kText} }
func path() *node         { return &node{k: kPath} }
func uuidText() *node     { return &node{k: kUUIDText} }
func key32() *node        { return &node{k: kKey32} }
func key32URL() *node     { return &node{k: kKey32URL} }
func ipOrPrefix() *node   { return &node{k: kIP} }
func prefixOnly() *node   { return &node{k: kPrefix} }
func httpHost() *node     { return &node{k: kHTTPHost} }
func pins() *node         { return &node{k: kPins} }
func shortID() *node      { return &node{k: kShortID} }
func spiderX() *node      { return &node{k: kSpiderX} }
func dialerTag() *node    { return &node{k: kDialer} }
func dropped() *node      { return &node{k: kDropped} }
func droppedZero() *node  { return &node{k: kDropped, zeroOnly: true} }
func droppedFirst() *node { return &node{k: kDropped, firstOnly: true} }

// headers is an object of HTTP header names with one string each; headersMulti may
// hold a list of 1 to 8 strings (the raw http header of Xray, a map of lists).
func headers() *node      { return &node{k: kHeaders} }
func headersMulti() *node { return &node{k: kHeaders, multi: true} }

// oneOf accepts a value that any one of the alternatives accepts.
func oneOf(alts ...*node) *node { return &node{k: kOneOf, alts: alts} }

// enumOf builds an enum. Each argument is "spelling=canonical" or just the
// canonical spelling. soft says an unknown value is a warning and not a rejection.
func enumOf(soft bool, vals ...string) *node {
	n := &node{k: kEnum, soft: soft, enum: make(map[string]string, len(vals))}
	for _, v := range vals {
		spell, canon, found := strings.Cut(v, "=")
		if !found {
			canon = spell
		}
		n.enum[strings.ToLower(spell)] = canon
	}
	return n
}

// softening marks canonical values of a hard enum that are unknown, not refused.
func (n *node) softening(canon ...string) *node {
	n.softVals = map[string]bool{}
	for _, c := range canon {
		n.softVals[c] = true
	}
	return n
}

// withVariant makes the member selOn depend on the enum member selKey.
func (n *node) withVariant(selKey, selOn string, by map[string]*node) *node {
	n.selKey, n.selOn, n.sel = selKey, selOn, by
	return n
}

// limit is the closed range of values a number or a range of a release table may
// hold. The loader of Xray checks few of them, and a value outside what the code
// below it expects can end the one process every location of the node shares.
type limit struct {
	lo, hi int64
}

// bnum is a whole number in [lo, hi].
func bnum(lo, hi int64) *node { return &node{k: kInt, lim: &limit{lo, hi}} }

// brange is a whole number, or "x-y", with both ends in [lo, hi] and x not above y.
func brange(lo, hi int64) *node { return &node{k: kRange, lim: &limit{lo, hi}} }

// port is a whole number from 1 to 65535.
func port() *node { return bnum(1, 65535) }

// problem names what is wrong with a node of a table, or "". The table of a release
// is walked by a test with it: a leaf of no kind, a number with no bound, an array with
// no upper limit and an enum with no value are refused at build time of the tests, so
// a key can never join a table unbounded (7.2, G4).
func (n *node) problem() string {
	switch n.k {
	case kObj:
		return ""
	case kArr:
		if n.elem == nil || n.maxN < 1 || n.minN < 0 || n.minN > n.maxN {
			return "an array with no bound"
		}
	case kInt, kRange:
		if n.lim == nil || n.lim.lo > n.lim.hi {
			return "a number with no bound"
		}
	case kEnum:
		if len(n.enum) == 0 {
			return "an enum with no value"
		}
	case kOneOf:
		if len(n.alts) == 0 {
			return "a choice with no alternative"
		}
		for _, a := range n.alts {
			if p := a.problem(); p != "" {
				return p
			}
			if a.k == kObj || a.k == kArr {
				return "a choice of a structure"
			}
		}
	case kBool, kHost, kHostPort, kText, kPath, kHeaders, kUUIDText, kKey32, kKey32URL, kIP, kPrefix, kHTTPHost, kPins, kShortID, kSpiderX, kDialer, kDropped:
		// Each of these has a bound written into its check.
	default:
		return "a node of no kind"
	}
	return ""
}
