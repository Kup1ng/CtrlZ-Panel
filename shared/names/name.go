// Package names is the leaf of the shared module: canonical DNS names, the
// keyed hash used for table lookups, and suffix iteration.
//
// Everything on the node's hot path compares names in canonical wire form, so
// the rules for that form live here once. Nodes never run IDNA; only the panel
// calls ParseUser.
package names

import (
	"errors"
	"iter"
)

const (
	// MaxWire is the RFC 1035 limit for an uncompressed name including the root byte.
	MaxWire = 255
	// MaxLabel is the RFC 1035 limit for one label.
	MaxLabel = 63
	// MaxLabels is the most labels a 255-byte name can hold (127 one-byte labels).
	MaxLabels = 127
)

var (
	ErrEmpty       = errors.New("names: empty input")
	ErrTruncated   = errors.New("names: message truncated")
	ErrLabelType   = errors.New("names: reserved label type")
	ErrLabelLen    = errors.New("names: label longer than 63 bytes")
	ErrNameLen     = errors.New("names: name longer than 255 bytes")
	ErrPointerLoop = errors.New("names: compression pointer loop")
	ErrNotRooted   = errors.New("names: wire name does not end in the root byte")
	ErrTrailing    = errors.New("names: bytes after the root label")
)

// Name is a canonical name: uncompressed wire labels, ASCII A-Z folded to a-z,
// other bytes unchanged, ending in the root byte (RFC 4034 section 6.2).
//
// It is a plain value with fixed arrays so a query can build one without any
// heap allocation. The zero value is not valid; use Root for the root name.
type Name struct {
	wire [MaxWire]byte
	n    uint8 // bytes used, root byte included
	nl   uint8 // label count
	off  [MaxLabels]uint8
}

// Root returns the root name. It has zero labels and never matches a rule.
func Root() Name {
	var n Name
	n.n = 1
	return n
}

// Wire returns the canonical wire bytes. The slice aliases n, so callers must
// not keep it past the Name's lifetime or modify it.
func (n *Name) Wire() []byte { return n.wire[:n.n] }

// Len is the wire length including the root byte.
func (n *Name) Len() int { return int(n.n) }

// Labels is the number of labels, not counting the root.
func (n *Name) Labels() int { return int(n.nl) }

// IsRoot reports whether the name has no labels.
func (n *Name) IsRoot() bool { return n.nl == 0 }

// Label returns label i counted from the left (0 is the leftmost label).
func (n *Name) Label(i int) []byte {
	o := int(n.off[i])
	l := int(n.wire[o])
	return n.wire[o+1 : o+1+l]
}

// SuffixWire returns the wire bytes of the suffix made of the rightmost k labels.
// k == 0 gives the root byte. k greater than Labels is clamped.
func (n *Name) SuffixWire(k int) []byte {
	if k >= int(n.nl) {
		return n.wire[:n.n]
	}
	if k <= 0 {
		return n.wire[n.n-1 : n.n]
	}
	return n.wire[n.off[int(n.nl)-k]:n.n]
}

// Equal compares canonical forms.
func (n *Name) Equal(o *Name) bool {
	return n.n == o.n && string(n.wire[:n.n]) == string(o.wire[:o.n])
}

// fold lowercases one ASCII byte and leaves everything else alone. DNS names are
// 8-bit clean, so folding must not touch bytes above 0x7f.
func fold(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// FromCanonicalWire builds a Name from an uncompressed wire name that must end
// exactly at the root byte. Case is folded. It is the entry point for data
// that is already wire form but not trusted (blob strings, proto fields).
func FromCanonicalWire(w []byte) (Name, error) {
	var n Name
	if len(w) == 0 {
		return n, ErrEmpty
	}
	if len(w) > MaxWire {
		return n, ErrNameLen
	}
	i := 0
	for {
		if i >= len(w) {
			return Name{}, ErrNotRooted
		}
		l := int(w[i])
		if l == 0 {
			i++
			break
		}
		if l&0xC0 != 0 {
			return Name{}, ErrLabelType
		}
		if l > MaxLabel {
			return Name{}, ErrLabelLen
		}
		if i+1+l > len(w) {
			return Name{}, ErrTruncated
		}
		if int(n.nl) >= MaxLabels {
			return Name{}, ErrNameLen
		}
		n.off[n.nl] = uint8(i)
		n.nl++
		n.wire[i] = byte(l)
		for j := 0; j < l; j++ {
			n.wire[i+1+j] = fold(w[i+1+j])
		}
		i += 1 + l
	}
	if i != len(w) {
		return Name{}, ErrTrailing
	}
	n.n = uint8(i)
	return n, nil
}

// FromWire reads a possibly compressed name from msg at off. It returns the
// folded name and the offset of the first byte after the name in msg.
//
// A compression pointer must point strictly before the pointer itself. That one
// rule makes loops impossible, so no iteration counter is needed for safety;
// the counter below only bounds work on hostile input that is merely slow.
// The question section of a real query never needs a pointer, so being strict
// here costs nothing.
func FromWire(msg []byte, off int) (Name, int, error) {
	var n Name
	if off < 0 || off >= len(msg) {
		return n, 0, ErrTruncated
	}
	pos := off
	next := -1 // offset after the name in msg, fixed at the first pointer
	total := 0
	jumps := 0
	for {
		if pos >= len(msg) {
			return Name{}, 0, ErrTruncated
		}
		l := int(msg[pos])
		switch l & 0xC0 {
		case 0x00:
			if l == 0 {
				if total+1 > MaxWire {
					return Name{}, 0, ErrNameLen
				}
				n.wire[total] = 0
				total++
				n.n = uint8(total)
				if next < 0 {
					next = pos + 1
				}
				return n, next, nil
			}
			if l > MaxLabel {
				return Name{}, 0, ErrLabelLen
			}
			if pos+1+l > len(msg) {
				return Name{}, 0, ErrTruncated
			}
			// +1 for the length byte, +1 reserved for the root byte.
			if total+1+l+1 > MaxWire {
				return Name{}, 0, ErrNameLen
			}
			if int(n.nl) >= MaxLabels {
				return Name{}, 0, ErrNameLen
			}
			n.off[n.nl] = uint8(total)
			n.nl++
			n.wire[total] = byte(l)
			for j := 0; j < l; j++ {
				n.wire[total+1+j] = fold(msg[pos+1+j])
			}
			total += 1 + l
			pos += 1 + l
		case 0xC0:
			if pos+1 >= len(msg) {
				return Name{}, 0, ErrTruncated
			}
			target := (l&0x3F)<<8 | int(msg[pos+1])
			if next < 0 {
				next = pos + 2
			}
			if target >= pos {
				return Name{}, 0, ErrPointerLoop
			}
			jumps++
			if jumps > MaxLabels {
				return Name{}, 0, ErrPointerLoop
			}
			pos = target
		default:
			// 0x40 and 0x80 are extended or unassigned label types.
			return Name{}, 0, ErrLabelType
		}
	}
}

// String is the presentation form used for logs, the UI and ClickHouse
// (qname_norm). It never has a trailing dot except for the root, which is ".".
// Bytes outside [a-z0-9_-] are written as \DDD, and a dot inside a label as \.
// so two different names can never print the same way.
func (n *Name) String() string {
	if n.nl == 0 {
		return "."
	}
	out := make([]byte, 0, int(n.n)+8)
	for i := 0; i < int(n.nl); i++ {
		if i > 0 {
			out = append(out, '.')
		}
		for _, b := range n.Label(i) {
			switch {
			case b >= 'a' && b <= 'z', b >= '0' && b <= '9', b == '_', b == '-':
				out = append(out, b)
			case b == '.':
				out = append(out, '\\', '.')
			default:
				out = append(out, '\\', '0'+b/100, '0'+(b/10)%10, '0'+b%10)
			}
		}
	}
	return string(out)
}

// Suffixes yields the suffixes of n from the longest to the shortest. Each pair
// is the byte offset into Wire() and the label count of that suffix.
//
// A lookup starts at min(labels, maxDepth) labels from the right because a
// table built with a maximum depth cannot hold anything deeper. maxDepth must
// be the compiled maximum of the stack and tables, never a fixed constant
// (R36). A maxDepth below 1 yields nothing.
func (n *Name) Suffixes(maxDepth int) iter.Seq2[int, int] {
	return func(yield func(int, int) bool) {
		start := int(n.nl)
		if maxDepth < start {
			start = maxDepth
		}
		for k := start; k >= 1; k-- {
			if !yield(int(n.off[int(n.nl)-k]), k) {
				return
			}
		}
	}
}
