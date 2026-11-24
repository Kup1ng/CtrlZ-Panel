package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/ticket"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
)

// tokenProof is the pipeline's TokenProof for the tenant API (D64 nat-proof-tag, P1 auth review round 19, tenant-r19-1).
//
// Only a database read can tell a real ticket, challenge or refresh token from junk, and a request that held one was
// charged to the client's /24 like a stranger's, so one noisy neighbour on a carrier block refused every honest user on
// it with a 429. The values now carry a tag the server checks in process (internal/auth/proofmac): a request whose value
// checks is charged to the account (or the challenge) it names, and one whose value does not is charged to the network
// as before. The tag is only ever a reason to charge elsewhere; the handler still reads the row and decides.
//
// The operations are named here, one place, and TestEveryAuthClassOperationHasItsProofDecided holds the list to the
// document: an operation of the `auth` class is either here or listed there as carrying no bearer value.
func (s *Server) tokenProof(r *http.Request, op apispec.Operation) (id, subject string, ok bool) {
	switch op.ID {
	case "loginTotp", "resetPasskeyBegin", "resetComplete":
		return s.ticketProof(bodyField(r, "ticket"))
	case "resetPasskeyFinish":
		return s.ticketProof(ticket.FromRequest(r))
	case "loginOtp", "resetVerify", "register":
		c, ok := s.otp.OpenChallenge(bodyField(r, "challenge_id"))
		if !ok {
			return "", "", false
		}
		return c.ProofID, c.Subject, true
	case "refreshSession":
		if c, err := r.Cookie(session.CookieRefresh); err == nil {
			if id, subject, ok := s.d.Sessions.ScreenRefresh(c.Value); ok && id != "" && subject != "" {
				return id, subject, true
			}
		}
	}
	return "", "", false
}

// untaggedChallenge is the answer for a challenge_id that is no proof: otp_expired for an id this service issued whose life
// has run out, as the database answers it, and otp_invalid for anything else, which is what a challenge the database does
// not know gets. Either way the request was charged to the network and costs no database call (tenant-r20-1).
func (s *Server) untaggedChallenge(challengeID string) error {
	if s.otp.ChallengeLapsed(challengeID) {
		return otp.ErrExpired
	}
	return otp.ErrInvalid
}

func (s *Server) ticketProof(tok string) (id, subject string, ok bool) {
	id, subject, ok = s.tickets.Screen(tok)
	if !ok || id == "" || subject == "" {
		return "", "", false
	}
	return id, subject, true
}

// maxProofMembers is how many top-level members bodyField looks at. The bodies it reads are the proof routes' and the public link
// routes', whose documents allow two members at most and refuse any other, so a body of more is junk whatever it holds.
const maxProofMembers = 8

// bodyField reads one string field of a JSON body without taking the body away from the schema check. A body that is not
// an object with that field as a string has no value here, and the check that follows refuses it as it always did.
//
// It walks the top level of the object and keeps no member but the one asked for, and it gives up after maxProofMembers: the
// earlier form decoded the whole body into a map, which for 64 KiB of tiny members cost about 10 ms and 1.7 MB, before any bucket,
// on routes that have none until the value screens (p3-D4-r2-4). A later member of the same name wins, as it does for the decoder
// that follows; a body with something after the closing brace has no value, as it did.
func bodyField(r *http.Request, name string) string {
	raw, ok := httpx.PeekBody(r)
	if !ok {
		return ""
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return ""
	}
	var found string
	for n := 0; dec.More(); n++ {
		if n == maxProofMembers {
			return ""
		}
		t, err := dec.Token()
		key, isKey := t.(string)
		if err != nil || !isKey {
			return ""
		}
		if key == name {
			found = ""
			if dec.Decode(&found) != nil {
				return ""
			}
			continue
		}
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			return ""
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return ""
	}
	if _, err := dec.Token(); err != io.EOF {
		return ""
	}
	return found
}
