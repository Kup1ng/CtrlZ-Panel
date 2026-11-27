package api

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// CreateFeedback is POST /feedback, the "Request Feature and Contact" dialog of the logo menu (docs/specs/p3-endpoints.md 9.2, T-125).
// The day bound of 20 per tenant is the `feedback` class, charged by the pipeline through x-ctrlz-rate-also before this runs.
func (s *Server) CreateFeedback(ctx context.Context, req gen.CreateFeedbackRequestObject) (gen.CreateFeedbackResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	// The document bounds both fields already; this is the check the handler owns, so a body that reaches it by a path that skipped
	// the validator is still refused with the field name and not by a database constraint.
	kind := string(req.Body.Kind)
	// A textarea sends CR LF from some browsers and a paste can carry a lone CR; the inbox of P7 gets one line break form (p3-D6-r2-10).
	message := strings.ReplaceAll(strings.ReplaceAll(req.Body.Body, "\r\n", "\n"), "\r", "\n")
	var bad []httpx.FieldError
	if kind != "feature" && kind != "contact" {
		bad = append(bad, httpx.FieldError{Name: "/kind", Code: "invalid"})
	}
	switch n := utf8.RuneCountInString(message); {
	case strings.TrimSpace(message) == "":
		bad = append(bad, httpx.FieldError{Name: "/body", Code: "required"})
	case n > 4000:
		bad = append(bad, httpx.FieldError{Name: "/body", Code: "too_long"})
	}
	if len(bad) > 0 {
		return nil, invalidFields(bad)
	}
	if err := s.inTenant(ctx, p.TenantID, func(tx store.Tx) error { return tx.FeedbackInsert(kind, message) }); err != nil {
		return nil, err
	}
	return gen.CreateFeedback201Response{}, nil
}
