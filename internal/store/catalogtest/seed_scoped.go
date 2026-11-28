package catalogtest

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"text/template"

	"github.com/jackc/pgx/v5"
)

// scopedSeedTmpl is one row of each of the three global tables that carry a tenant under a scoped_tenant policy
// (question 15): a ticket of the tenant, an announcement for the tenant alone, and a challenge stamped with the
// tenant. It is separate from tenantSeedTmpl on purpose: those tables are read by tests all over the repository
// that count their rows, and only the tests that judge the scoped role want the extra ones.
var scopedSeedTmpl = template.Must(template.New("scoped").Parse(`
INSERT INTO ctrlz.auth_tickets (token_hash, kind, subject_tenant, subject_user, expires_at)
  VALUES (sha256(convert_to('scoped-seed-ticket-{{.Index}}', 'UTF8')), 'mfa', '{{.Tenant}}', '{{.User}}', now() + interval '5 minutes');
INSERT INTO ctrlz.announcements (audience, tenant_id, body) VALUES ('tenant', '{{.Tenant}}', 'scoped-seed-announcement-{{.Index}}');
INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, delivery_ct, expires_at, ip, tenant_id)
  VALUES ('+98914000000{{.Index}}', 'login', '\x01', '\x02', now() + interval '5 minutes', '198.51.100.10', '{{.Tenant}}')
`))

// SeedScoped inserts the rows of scopedSeedTmpl for the tenant in ids. It runs as the superuser, after SeedTenant
// (the ticket names the tenant's user).
func SeedScoped(ctx context.Context, conn *pgx.Conn, ids SeedIDs) error {
	var b bytes.Buffer
	if err := scopedSeedTmpl.Execute(&b, ids); err != nil {
		return err
	}
	for _, stmt := range strings.Split(b.String(), ";\n") {
		if stmt = strings.TrimSpace(stmt); stmt == "" {
			continue
		}
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("seed scoped rows: %w", err)
		}
	}
	return nil
}
