package vectors

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	"github.com/Kup1ng/CtrlZ-Shared/gtable"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/locations"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/noredirect"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
	"github.com/Kup1ng/CtrlZ-Shared/route"
	"github.com/Kup1ng/CtrlZ-Shared/rules"
	"github.com/Kup1ng/CtrlZ-Shared/schedule"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
)

// TextCase is the shape of grammar and function groups: an operation, its
// inputs, and the text it must produce, or Error for "must be rejected".
type TextCase struct {
	ID     string   `json:"id"`
	Why    string   `json:"why"`
	Op     string   `json:"op"`
	Input  string   `json:"input"`
	Args   []string `json:"args"`
	Expect string   `json:"expect"`
	Error  bool     `json:"error"`
	// ErrorContains is text the error must contain. A negative case that names
	// its cause cannot pass because of another one, such as an input refused for
	// a different reason than the case says.
	ErrorContains string `json:"error_contains"`
	// Repeat, when above 1, repeats Input that many times before the op runs,
	// so a vector can pin a size limit without a kilobyte of JSON.
	Repeat int `json:"repeat"`
}

func runTextGroup(t *testing.T, g *GroupFile) {
	var cases []TextCase
	if err := decodeStrict(g.Cases, &cases); err != nil {
		t.Fatalf("%s: %v", g.Group, err)
	}
	if len(cases) == 0 {
		t.Fatalf("%s has no cases", g.Group)
	}
	seen := map[string]bool{}
	for i := range cases {
		c := &cases[i]
		if c.ID == "" || seen[c.ID] {
			t.Errorf("duplicate or empty case id %q", c.ID)
		}
		seen[c.ID] = true
		t.Run(c.ID, func(t *testing.T) {
			if msg := textVerdict(c); msg != "" {
				t.Error(msg)
			}
		})
	}
}

// textVerdict runs one case and returns why it failed, or "" when it passed.
// An unknown op is never a pass, whatever the case expects: a misspelled op
// would otherwise turn every negative case into a test of nothing. A negative
// case passes only when the error contains the text it names.
func textVerdict(c *TextCase) string {
	got, err := textOp(c)
	switch {
	case errors.Is(err, errUnknownOp):
		return fmt.Sprintf("%v\n  case: %s", err, c.Why)
	case c.Error && err == nil:
		return fmt.Sprintf("accepted, got %q\n  case: %s", got, c.Why)
	case c.Error && !strings.Contains(err.Error(), c.ErrorContains):
		return fmt.Sprintf("rejected for another reason: %v, want text %q\n  case: %s", err, c.ErrorContains, c.Why)
	case !c.Error && err != nil:
		return fmt.Sprintf("rejected: %v\n  case: %s", err, c.Why)
	case !c.Error && got != c.Expect:
		return fmt.Sprintf("got %q want %q\n  case: %s", got, c.Expect, c.Why)
	}
	return ""
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("vector hex: " + err.Error())
	}
	return b
}

func zoneList(args []string) []names.Name {
	var z []names.Name
	for _, a := range args {
		z = append(z, names.MustString(a))
	}
	return z
}

// errUnknownOp is what textOp returns for an op it does not know.
// runTextGroup fails on it even for a negative case.
var errUnknownOp = errors.New("unknown vector op")

func textOp(c *TextCase) (string, error) {
	if c.Repeat > 1 {
		c.Input = strings.Repeat(c.Input, c.Repeat)
	}
	a := c.Args
	switch c.Op {
	// hash
	case "siphash":
		var key [16]byte
		copy(key[:], unhex(a[0]))
		return fmt.Sprintf("%016x", names.Hash64(key, unhex(a[1]))), nil
	case "rid_hash":
		h := identity.RIDHash(c.Input)
		return hex.EncodeToString(h[:]), nil
	case "token_hash":
		h := identity.TokenHash(c.Input)
		return hex.EncodeToString(h[:]), nil
	case "client_hash":
		h := identity.ClientHash(c.Input)
		return hex.EncodeToString(h[:]), nil
	case "proof_code":
		src, err := netip.ParseAddr(a[1])
		if err != nil {
			return "", err
		}
		return identity.ProofCode([]byte(a[0]), c.Input, src), nil
	case "sha256":
		h := sha256.Sum256(unhex(c.Input))
		return hex.EncodeToString(h[:]), nil
	case "entry_hash":
		var prev [32]byte
		copy(prev[:], unhex(a[0]))
		h := wire.EntryHash(prev, unhex(a[1]))
		return hex.EncodeToString(h[:]), nil

	// names
	case "from_wire":
		off := 0
		if len(a) > 0 {
			off, _ = strconv.Atoi(a[0])
		}
		n, next, err := names.FromWire(unhex(c.Input), off)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s next=%d", n.String(), next), nil
	case "parse_user":
		n, err := names.ParseUser(c.Input)
		if err != nil {
			return "", err
		}
		return n.String(), nil
	case "wire_hex":
		n, err := names.ParseUser(c.Input)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(n.Wire()), nil
	case "suffixes":
		n, err := names.FromString(c.Input)
		if err != nil {
			return "", err
		}
		depth, _ := strconv.Atoi(a[0])
		var out []string
		for off, k := range n.Suffixes(depth) {
			out = append(out, fmt.Sprintf("%d@%d", k, off))
		}
		return strings.Join(out, ";"), nil

	// identity
	case "parse_host":
		h := identity.ParseHost(c.Input, zoneList(a))
		s := h.Kind.String()
		switch h.Kind {
		case identity.HostVerify:
			s += " label=" + h.Label
		case identity.HostReserved:
			s += " name=" + h.Name
		case identity.HostResolver:
			s += " rid=" + h.RID + " client=" + h.Client
		}
		return s, nil
	case "token_check":
		var want [32]byte
		copy(want[:], unhex(a[0]))
		if identity.TokenMatches(c.Input, want) {
			return "match", nil
		}
		return "mismatch", nil
	case "parse_doh_path":
		p, err := identity.ParseDoHPath(c.Input)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("form=%c rid=%s token=%s client=%s", p.Form, p.RID, p.Token, p.Client), nil
	case "resolve_doh":
		t, err := identity.ResolveDoH(c.Input, a[0], zoneList(a[1:]))
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("rid=%s token=%s client=%s", t.RID, t.Token, t.Client), nil
	case "slug_client":
		s, ok := identity.SlugClient(c.Input)
		if !ok {
			return "", fmt.Errorf("nothing left")
		}
		return s, nil
	case "token_valid":
		var ok bool
		switch a[0] {
		case "resolver_id":
			ok = identity.ValidResolverID(c.Input)
		case "doh_token":
			ok = identity.ValidDoHToken(c.Input)
		case "verify_label":
			ok = identity.ValidVerifyLabel(c.Input)
		case "client":
			ok = identity.ValidClient(c.Input)
		}
		if !ok {
			return "", fmt.Errorf("invalid")
		}
		return "valid", nil

	// tokens
	case "rules_parse":
		p, err := rules.Parse(c.Input)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("kind=%s negated=%v key=%s lit_labels=%d lit_bytes=%d", p.Kind, p.Negated, p.Key(), p.LitLabels, p.LitBytes), nil

	// no-redirect (D42, contract 10.5)
	case "no_redirect":
		return noRedirect(c)

	// schedule
	case "cell":
		return scheduleCell(c)

	// upload
	case "merge_upload":
		return uploadMerge(c)

	// route
	case "route_match":
		return routeMatch(c)

	// location sets
	case "loc_allowed", "loc_service", "loc_selection":
		return locationSets(c)
	}
	if c.Op == "build_transitions" {
		return zoneTransitions(c)
	}
	if out, ok := manifestOp(c.Op, c.Args); ok {
		return out, nil
	}
	if out, ok, err := appleOp(c.Op, c.Input, c.Args); ok {
		return out, err
	}
	return "", fmt.Errorf("%w %q", errUnknownOp, c.Op)
}

func scheduleCell(c *TextCase) (string, error) {
	// Args: base_offset, "RFC3339=offset;..." transitions, "from-to=window;..." fills.
	base, _ := strconv.Atoi(c.Args[0])
	var trs []schedule.Transition
	if c.Args[1] != "" {
		for _, p := range strings.Split(c.Args[1], ";") {
			k, v, _ := strings.Cut(p, "=")
			at, err := parseTime(k)
			if err != nil {
				return "", err
			}
			off, _ := strconv.Atoi(v)
			trs = append(trs, schedule.Transition{At: at, Offset: int32(off)})
		}
	}
	grid := make([]byte, schedule.Cells)
	maxWin := 0
	if c.Args[2] != "" {
		for _, p := range strings.Split(c.Args[2], ";") {
			rng, w, _ := strings.Cut(p, "=")
			from, to, _ := strings.Cut(rng, "-")
			f, _ := strconv.Atoi(from)
			tt, _ := strconv.Atoi(to)
			win, _ := strconv.Atoi(w)
			maxWin = max(maxWin, win)
			for i := f; i <= tt; i++ {
				grid[i] = byte(win)
			}
		}
	}
	s, err := schedule.New(int32(base), trs, grid, maxWin)
	if err != nil {
		return "", err
	}
	now, err := parseTime(c.Input)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("index=%d value=%d offset=%d", s.CellIndex(now), s.Cell(now), s.Offset(now)), nil
}

func uploadMerge(c *TextCase) (string, error) {
	var ex, in []rules.Item
	for _, a := range c.Args {
		p := strings.Split(a, "|")
		if len(p) != 4 {
			return "", fmt.Errorf("bad item %q", a)
		}
		it := rules.Item{Key: p[1], Folder: p[2], Payload: p[3]}
		if p[0] == "E" {
			ex = append(ex, it)
		} else {
			in = append(in, it)
		}
	}
	mode := rules.UploadNewOnly
	if c.Input == "upsert" {
		mode = rules.UploadUpsert
	}
	r := rules.MergeUpload(ex, in, mode)
	var m []string
	for _, it := range r.Merged {
		m = append(m, it.Key+":"+it.Folder+":"+it.Payload)
	}
	return fmt.Sprintf("created=%d updated=%d skipped=%d conflicts=%d merged=%s", r.Created, r.Updated, r.Skipped, r.Conflicts, strings.Join(m, ",")), nil
}

type geoSets map[string]map[string]bool

func (g geoSets) Has(tag string, n *names.Name) bool { return g[tag][n.String()] }

func routeMatch(c *TextCase) (string, error) {
	var rs []route.Rule
	gs := geoSets{}
	for _, a := range c.Args {
		p := strings.Split(a, "|")
		if p[0] == "G" {
			set := map[string]bool{}
			for _, d := range strings.Split(p[2], ",") {
				set[d] = true
			}
			gs[p[1]] = set
			continue
		}
		order, _ := strconv.Atoi(p[0])
		r, err := route.ParseRule(uint32(order), p[1], p[2], p[3], len(p) > 4 && p[4] == "final")
		if err != nil {
			return "", err
		}
		rs = append(rs, r)
	}
	name, qt, _ := strings.Cut(c.Input, "/")
	n, err := names.FromString(name)
	if err != nil {
		return "", err
	}
	q, ok := route.ParseQType(qt)
	if !ok {
		return "", fmt.Errorf("qtype %q", qt)
	}
	g, ok := route.Match(rs, &n, q, gs)
	if !ok {
		return "none", nil
	}
	return g, nil
}

// locKeys parses "DE:Frankfurt,NL:Amsterdam,US,~label" into keys.
func locKeys(s string) []locations.Key {
	var out []locations.Key
	if s == "" {
		return out
	}
	for _, p := range strings.Split(s, ",") {
		switch {
		case strings.HasPrefix(p, "~"):
			out = append(out, locations.Key{Label: p[1:]})
		default:
			cc, city, _ := strings.Cut(p, ":")
			out = append(out, locations.Key{Country: cc, City: city})
		}
	}
	return out
}

func keysText(ks []locations.Key) string {
	var out []string
	for _, k := range ks {
		if k.Country == "" {
			out = append(out, "~"+k.Label)
		} else if k.City == "" {
			out = append(out, k.Country)
		} else {
			out = append(out, k.Country+":"+k.City)
		}
	}
	return strings.Join(out, ",")
}

func locationSets(c *TextCase) (string, error) {
	switch c.Op {
	case "loc_allowed":
		// Args: "N1=DE:Frankfurt,~gw" node sets, "pairs=N1-N2,N3-N4", "global=N1-N2".
		nodes := locations.NodeSet{}
		ids := map[string]locations.NodeID{}
		id := func(n string) locations.NodeID {
			if v, ok := ids[n]; ok {
				return v
			}
			v := locations.NodeID{byte(len(ids) + 1)}
			ids[n] = v
			return v
		}
		pair := func(s string) locations.PairRef {
			a, b, _ := strings.Cut(s, "-")
			return locations.PairRef{A: id(a), B: id(b)}
		}
		var pairs []locations.PairRef
		var global locations.PairRef
		for _, a := range c.Args {
			k, v, _ := strings.Cut(a, "=")
			switch k {
			case "pairs":
				if v != "" {
					for _, p := range strings.Split(v, ",") {
						pairs = append(pairs, pair(p))
					}
				}
			case "global":
				global = pair(v)
			default:
				set := map[locations.Key]struct{}{}
				for _, key := range locKeys(v) {
					set[key] = struct{}{}
				}
				nodes[id(k)] = set
			}
		}
		return keysText(locations.AllowedLocations(pairs, global, nodes)), nil
	case "loc_service":
		regions := []string(nil)
		if c.Args[0] != "*" {
			regions = []string{}
			if c.Args[0] != "" {
				regions = strings.Split(c.Args[0], ",")
			}
		}
		return keysText(locations.EffectiveService(locKeys(c.Input), regions)), nil
	case "loc_selection":
		var sets [][]locations.Key
		for _, a := range c.Args {
			sets = append(sets, locKeys(a))
		}
		return keysText(locations.EffectiveSelection(sets...)), nil
	}
	return "", fmt.Errorf("%w %q", errUnknownOp, c.Op)
}

// BinaryCase is the shape of the blob and gtable groups: raw bytes in hex and
// the reason code the decoder must report, or "" if the bytes are valid.
type BinaryCase struct {
	ID          string `json:"id"`
	Why         string `json:"why"`
	Hex         string `json:"hex"`
	ExpectError string `json:"expect_error"`
}

func runBinaryGroup(t *testing.T, g *GroupFile) {
	var cases []BinaryCase
	if err := decodeStrict(g.Cases, &cases); err != nil {
		t.Fatalf("%s: %v", g.Group, err)
	}
	if len(cases) == 0 {
		t.Fatalf("%s has no cases", g.Group)
	}
	covered := map[string]bool{}
	for i := range cases {
		c := &cases[i]
		t.Run(c.ID, func(t *testing.T) {
			data, err := hex.DecodeString(c.Hex)
			if err != nil {
				t.Fatalf("bad hex: %v", err)
			}
			var oerr error
			if g.Group == "blob" {
				_, oerr = blob.Open(data)
			} else {
				_, oerr = gtable.Open(data)
			}
			got := string(reason.CodeOf(oerr))
			if oerr != nil && got == "" {
				got = "untyped:" + oerr.Error()
			}
			if got != c.ExpectError {
				t.Errorf("got %q want %q (%v)\n  case: %s", got, c.ExpectError, oerr, c.Why)
			}
		})
		covered[c.ExpectError] = true
	}
	// Every reason code except panic and size_cap must have a corrupt case, so a new code
	// cannot ship without a vector (panic cannot be produced from bytes alone and
	// size_cap needs a 64 MiB file; the unit tests and the fuzz targets cover them;
	// the fuzz targets cover it).
	if g.Group == "blob" {
		var missing []string
		for _, rc := range reason.All() {
			if rc != reason.Panic && rc != reason.SizeCap && !covered[string(rc)] {
				missing = append(missing, string(rc))
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("blob group has no case for reasons %v", missing)
		}
	}
}

// noRedirect parses Input as a rule token and judges it with the entries named in Args
// ("domain:<name>" or "host:<name>"). The answer is iranian_name or allowed, the two
// outcomes the write path has for a Redirect on that pattern.
func noRedirect(c *TextCase) (string, error) {
	p, err := rules.Parse(c.Input)
	if err != nil {
		return "", err
	}
	e := noredirect.Entries{}
	for _, a := range c.Args {
		scope, name, ok := strings.Cut(a, ":")
		if !ok {
			return "", fmt.Errorf("bad entry %q", a)
		}
		switch scope {
		case "domain":
			e[name] = noredirect.ScopeDomain
		case "host":
			e[name] = noredirect.ScopeHost
		default:
			return "", fmt.Errorf("bad entry scope %q", scope)
		}
	}
	if noredirect.Pattern(p, e) {
		return "iranian_name", nil
	}
	return "allowed", nil
}
