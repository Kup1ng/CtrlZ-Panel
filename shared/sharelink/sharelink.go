// Package sharelink turns what an admin pastes into candidate Xray fragments
// (p4b-proxy 7.3): share links, one a line, and a whole Xray configuration or one
// outbound object. It builds the text of a fragment and the panel runs every candidate
// through xrayschema, the allow-list, so a link can never get a key past it that a
// pasted fragment could not. A link goes one step further: its fragment is run through
// the allow-list here too, and a warning is an error of its line, because a link gives
// listed keys alone and an exit that needs more is pasted as JSON.
//
// A link that carries a parameter this package does not know is an error for that
// line, named with its line number, and never a silent drop (R14): a parameter the
// converter ignores is a setting the admin believes is on and is not.
package sharelink

import (
	"errors"
	"fmt"
	"strings"
)

// Limits of a paste.
const (
	// MaxLinks is the number of lines that carry a link in one paste (D31).
	MaxLinks = 100
	// MaxLineBytes bounds one link. A VMess JSON link with every field is under 2 KiB.
	MaxLineBytes = 8 << 10
	// MaxPasteBytes bounds the whole text of links.
	MaxPasteBytes = 64 << 10
)

// ErrTooMany is returned by Links when the paste has more than MaxLinks links.
var ErrTooMany = errors.New("sharelink: more than 100 links in one paste")

// ErrTooLarge is returned when the paste is larger than MaxPasteBytes.
var ErrTooLarge = errors.New("sharelink: the paste is too large")

// Candidate is one fragment an admin may save. The Fragment is {"outbounds": [...]}
// with the main outbound first and its chain after it, in the keys xrayschema reads.
type Candidate struct {
	// Line is the 1-based line of the link, and 0 for a candidate of JSON.
	Line int
	// Fragment is the text of the candidate, not yet normalised.
	Fragment []byte
	// Note is what a person would call it: the fragment of the link (its remark), or
	// the tag of the outbound.
	Note string
	// Protocol is the protocol of the first outbound, lower case.
	Protocol string
	// Omitted names what the link carries and the fragment leaves out, because the exit
	// works without it (pqv, and some members of extra): the panel shows each as a line
	// of the diff of the candidate (7.3).
	Omitted []string
	// Err is set instead of Fragment when the line could not be converted, or, for a
	// candidate of JSON (Line 0), when the outbound with its dialerProxy chain is longer
	// than a config may be.
	Err *LineError
}

// LineError names the line of a link and what is wrong with it. Msg holds a
// parameter name and never a value, because a value may be a password.
type LineError struct {
	Line int
	Msg  string
}

func (e *LineError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Msg) }

// Links converts a paste of share links, one a line. Blank lines are skipped, and a
// line that does not start with a known scheme is an error for that line. Every
// non-blank line gives one Candidate, with its Err set when it failed.
func Links(text string) ([]Candidate, error) {
	if len(text) > MaxPasteBytes {
		return nil, ErrTooLarge
	}
	var out []Candidate
	for i, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(out) >= MaxLinks {
			return nil, ErrTooMany
		}
		c := Candidate{Line: i + 1}
		got, err := convert(line)
		if err != nil {
			c.Err = &LineError{Line: i + 1, Msg: err.Error()}
		} else {
			c.Fragment, c.Note, c.Protocol, c.Omitted = got.fragment, got.note, got.protocol, got.omitted
		}
		out = append(out, c)
	}
	return out, nil
}
