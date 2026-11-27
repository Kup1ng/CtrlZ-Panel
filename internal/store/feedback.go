package store

// A message from a tenant to us (docs/specs/p3-endpoints.md 9.2, T-125). The table is insert-only for the tenant role (grants.yaml:
// feedback_items); the admin console reads it and answers in P7. One row is one request, and the day bound of 20 per tenant is
// the rate class `feedback` that the pipeline charges, not a cap here. The table also allows false_positive and false_negative, which
// the statistics screens of P5 write; the route (internal/api) sends feature and contact only.

const qFeedbackInsert = `INSERT INTO ctrlz.feedback_items (tenant_id, kind, body) VALUES ($1, $2, $3)`

// FeedbackInsert adds one message of the tenant. kind and body are checked by the table as well (the closed kind list and 4000
// characters), so a caller that skipped its own check meets a constraint error and not a stored row.
func (t Tx) FeedbackInsert(kind, body string) error {
	if _, err := t.tx.Exec(t.ctx, qFeedbackInsert, t.tenant, kind, body); err != nil {
		return sanitize(err)
	}
	return nil
}
