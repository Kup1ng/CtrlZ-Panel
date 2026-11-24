package api

import (
	"encoding/json"
	"net/http"

	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
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

func (s *Server) ticketProof(tok string) (id, subject string, ok bool) {
	id, subject, ok = s.tickets.Screen(tok)
	if !ok || id == "" || subject == "" {
		return "", "", false
	}
	return id, subject, true
}

// bodyField reads one string field of a JSON body without taking the body away from the schema check. A body that is not
// an object with that field as a string has no value here, and the check that follows refuses it as it always did.
func bodyField(r *http.Request, name string) string {
	raw, ok := httpx.PeekBody(r)
	if !ok {
		return ""
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	var v string
	if json.Unmarshal(m[name], &v) != nil {
		return ""
	}
	return v
}
