package sharelink

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
)

// ImportResult is what a pasted Xray configuration gives: the candidates, and the
// top-level keys the import does not take (inbounds, routing, dns, log, policy,
// observatory, balancers, and the rest), which the panel lists as left out and saves
// only with accept_left_out (p4b-proxy 7.3).
type ImportResult struct {
	Candidates []Candidate
	LeftOut    []string
}

// maxChain is the most outbounds one candidate may hold: the exit and seven hops. It
// is xrayschema.MaxOutbounds, repeated here because this package judges nothing and
// does not import the checker outside its tests, which assert the two are equal.
const maxChain = 8

// maxImportBytes is the largest pasted configuration. A real client configuration
// with a routing table is a few hundred KiB; the route has its own body limit (12).
const maxImportBytes = 384 << 10

// FromJSON reads a pasted Xray configuration, or one outbound object.
//
// Each outbound that is not freedom, blackhole or dns, and that no other outbound
// names as its dialerProxy, is a candidate; the outbounds it reaches through
// dialerProxy, at any depth, follow it in the order they are first reached, so the
// fragment is {"outbounds": [main, chain...]}. Nothing is rewritten here: the text
// of each outbound is kept as it was, and xrayschema judges it.
func FromJSON(data []byte) (ImportResult, error) {
	var res ImportResult
	if len(data) > maxImportBytes {
		return res, errors.New("the configuration is too large")
	}
	top, order, err := topLevel(data)
	if err != nil {
		return res, err
	}
	rawOuts, hasOuts := top["outbounds"]
	if !hasOuts {
		if _, one := top["protocol"]; one {
			c, err := candidateOf([]json.RawMessage{json.RawMessage(bytes.TrimSpace(data))}, 0)
			if err != nil {
				return res, err
			}
			res.Candidates = []Candidate{c}
			return res, nil
		}
		return res, errors.New("neither a configuration with outbounds nor one outbound object")
	}
	var outs []json.RawMessage
	if err := json.Unmarshal(rawOuts, &outs); err != nil {
		return res, errors.New("\"outbounds\" is not an array of objects")
	}
	for _, k := range order {
		if k != "outbounds" {
			res.LeftOut = append(res.LeftOut, k)
		}
	}
	info := make([]outInfo, len(outs))
	byTag := map[string][]int{}
	for i, o := range outs {
		in, err := inspect(o)
		if err != nil {
			return res, errors.New("an outbound is not an object")
		}
		info[i] = in
		if in.tag != "" {
			byTag[in.tag] = append(byTag[in.tag], i)
		}
	}
	// An outbound is named when another outbound (not itself) has its tag as a
	// dialerProxy. The references are counted per tag first, each outbound once per tag,
	// so the work is the number of outbounds plus the number of links: walking every
	// outbound of a tag for every link made one paste of 364 KB cost seven seconds
	// (B1-r3-7).
	refs := map[string]int{}
	for i := range info {
		// inspect sorts the dialers, so a repeat is the neighbour of its twin.
		for k, d := range info[i].dialers {
			if k > 0 && info[i].dialers[k-1] == d {
				continue
			}
			refs[d]++
		}
	}
	named := map[int]bool{}
	for i := range info {
		t := info[i].tag
		if t == "" || refs[t] == 0 {
			continue
		}
		self := 0
		for _, d := range info[i].dialers {
			if d == t {
				self = 1
				break
			}
		}
		if refs[t]-self > 0 {
			named[i] = true
		}
	}
	for i := range outs {
		switch info[i].protocol {
		case "freedom", "direct", "blackhole", "block", "dns", "":
			continue
		}
		if named[i] {
			continue
		}
		// Each candidate copies its whole chain, so without a bound a few hundred small
		// outbounds that name one large outbound make megabytes out of a small paste.
		if len(res.Candidates) >= MaxLinks {
			return res, ErrTooMany
		}
		// Collect the chain: breadth first from i through dialerProxy, each outbound once.
		chain := []int{i}
		seen := map[int]bool{i: true}
		for k := 0; k < len(chain) && len(chain) <= maxChain; k++ {
			for _, d := range info[chain[k]].dialers {
				if ts, ok := byTag[d]; ok && len(ts) == 1 && !seen[ts[0]] {
					seen[ts[0]] = true
					chain = append(chain, ts[0])
				}
			}
		}
		size := 0
		raws := make([]json.RawMessage, 0, len(chain))
		for _, idx := range chain {
			raws = append(raws, outs[idx])
			size += len(outs[idx]) + 1
		}
		// A chain the checker would refuse anyway is not copied: the candidate carries
		// the reason instead of its text, and the others of the paste stay usable.
		if len(chain) > maxChain || size > maxFragmentBytes {
			note := clipNote(info[i].tag)
			res.Candidates = append(res.Candidates, Candidate{Note: note, Protocol: info[i].protocol,
				Err: &LineError{Msg: "the outbound with the outbounds it reaches through dialerProxy is longer than a config may be"}})
			continue
		}
		c, err := candidateOf(raws, 0)
		if err != nil {
			return res, err
		}
		if info[i].tag != "" {
			c.Note = clipNote(info[i].tag)
		}
		res.Candidates = append(res.Candidates, c)
	}
	sort.Strings(res.LeftOut)
	return res, nil
}

// maxFragmentBytes is xrayschema.MaxFragmentBytes (D31), repeated here for the same
// reason as maxChain.
const maxFragmentBytes = 32 << 10

// repeatsAKey reports whether any object of a JSON text gives one key twice, in the
// exact spelling. Decoding into a Go map keeps the last one and says nothing, which
// would drop a value the admin believes is in force (R14). A text that does not parse
// reports false: the caller has already decoded it.
func repeatsAKey(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	dup, err := scanRepeat(dec)
	return err == nil && dup
}

func scanRepeat(dec *json.Decoder) (bool, error) {
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return false, nil
	}
	dup := false
	switch d {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			k, isStr := kt.(string)
			if err != nil || !isStr {
				return false, errors.New("not valid JSON")
			}
			if seen[k] {
				dup = true
			}
			seen[k] = true
			d2, err := scanRepeat(dec)
			if err != nil {
				return false, err
			}
			dup = dup || d2
		}
	case '[':
		for dec.More() {
			d2, err := scanRepeat(dec)
			if err != nil {
				return false, err
			}
			dup = dup || d2
		}
	}
	if _, err := dec.Token(); err != nil {
		return false, err
	}
	return dup, nil
}

func candidateOf(raws []json.RawMessage, line int) (Candidate, error) {
	in, err := inspect(raws[0])
	if err != nil {
		return Candidate{}, errors.New("the outbound is not an object")
	}
	frag, err := json.Marshal(map[string]any{"outbounds": raws})
	if err != nil {
		return Candidate{}, err
	}
	return Candidate{Line: line, Fragment: frag, Note: clipNote(in.tag), Protocol: in.protocol}, nil
}

// topLevel reads the members of the top-level object without decoding the values, and
// refuses a key given twice in any case: with one repeated, which one Xray would take
// is a question the admin should not have to answer.
func topLevel(data []byte) (map[string]json.RawMessage, []string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, nil, errors.New("the configuration is not a JSON object")
	}
	top := map[string]json.RawMessage{}
	seen := map[string]bool{}
	var order []string
	for dec.More() {
		kt, err := dec.Token()
		k, ok := kt.(string)
		if err != nil || !ok {
			return nil, nil, errors.New("the configuration is not valid JSON")
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, nil, errors.New("the configuration is not valid JSON")
		}
		lk := strings.ToLower(k)
		if seen[lk] {
			return nil, nil, errors.New("a top-level key is given twice")
		}
		seen[lk] = true
		top[lk] = v
		order = append(order, lk)
	}
	if _, err := dec.Token(); err != nil {
		return nil, nil, errors.New("the configuration is not valid JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, nil, errors.New("data after the configuration")
	}
	return top, order, nil
}

type outInfo struct {
	protocol string
	tag      string
	dialers  []string
}

// inspect reads the protocol, the tag and every dialerProxy value of an outbound, at
// any depth. Keys match without case, as Xray's decoder does it.
func inspect(raw json.RawMessage) (outInfo, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&v); err != nil {
		return outInfo{}, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return outInfo{}, errors.New("not an object")
	}
	in := outInfo{}
	for k, val := range m {
		s, isStr := val.(string)
		switch strings.ToLower(k) {
		case "protocol":
			if isStr {
				in.protocol = strings.ToLower(s)
			}
		case "tag":
			if isStr {
				in.tag = s
			}
		}
	}
	collectDialers(v, &in.dialers)
	sort.Strings(in.dialers)
	return in, nil
}

func collectDialers(v any, out *[]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			if s, ok := c.(string); ok && strings.EqualFold(k, "dialerProxy") && s != "" {
				*out = append(*out, s)
				continue
			}
			collectDialers(c, out)
		}
	case []any:
		for _, c := range x {
			collectDialers(c, out)
		}
	}
}
