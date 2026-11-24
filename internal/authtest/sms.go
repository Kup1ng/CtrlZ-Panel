package authtest

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/google/uuid"
)

// Exec runs setup SQL as the superuser.
func (e *Env) Exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := e.DB.Exec(e.Ctx, sql, args...); err != nil {
		t.Fatalf("setup: %v", err)
	}
}

// Scan reads one row as the superuser, for columns no service role can read.
func (e *Env) Scan(t *testing.T, sql string, args []any, dest ...any) {
	t.Helper()
	if err := e.DB.Scan(e.Ctx, sql, args, dest...); err != nil {
		t.Fatalf("read back: %v", err)
	}
}

// ResetSMS clears the SMS rows the catalog seed plants (a noop gateway, an
// outbox row, an OTP with a sealed code and a decoy, a delivery), so a test that
// counts rows or drains the queue starts from nothing. The templates of
// sms_templates stay.
func (e *Env) ResetSMS(t *testing.T) {
	t.Helper()
	e.Exec(t, `DELETE FROM ctrlz.otp_challenges`)
	e.Exec(t, `DELETE FROM ctrlz.sms_outbox`)
	e.Exec(t, `DELETE FROM ctrlz.sms_deliveries`)
	e.Exec(t, `TRUNCATE ctrlz.sms_counters`)
	e.Exec(t, `DELETE FROM ctrlz.sms_gateways`) // cascades to the provider templates
}

// Gateway describes a gateway row to plant.
type Gateway struct {
	Provider    string // sms_ir, melipayamak or noop
	Role        string // primary, fallback or disabled
	Credentials string // JSON; empty for none
	Price       string // Rial; empty for none
	// ParamName is the provider's name for the code (CODE). Every template is
	// mapped in fa and en; account_exists takes no parameter.
	ParamName string
}

// AddGateway inserts a gateway with its credentials sealed under ring (the key
// ring of the worker) and maps the five templates. It returns the gateway id.
func (e *Env) AddGateway(t *testing.T, ring *keyring.Ring, g Gateway) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	var ct []byte
	if g.Credentials != "" {
		var err error
		ct, err = sms.SealCredentials(ring, id, g.Provider, secret.NewBytes([]byte(g.Credentials)))
		if err != nil {
			t.Fatal(err)
		}
	}
	var price any
	if g.Price != "" {
		price = g.Price
	}
	e.Exec(t, `INSERT INTO ctrlz.sms_gateways (id, provider, role, credentials_ct, cost_per_message) VALUES ($1, $2, $3, $4, $5::numeric)`,
		id, g.Provider, g.Role, ct, price)
	name := g.ParamName
	if name == "" {
		name = "CODE"
	}
	for _, key := range sms.Templates() {
		params := []string{name}
		if n, _ := sms.PlaceholderCount(key); n == 0 {
			params = []string{}
		}
		for _, loc := range []string{"fa", "en"} {
			e.Exec(t, `INSERT INTO ctrlz.sms_provider_templates (gateway_id, key, locale, provider_template_id, param_names) VALUES ($1, $2, $3, $4, $5)`,
				id, key, loc, "1000", params)
		}
	}
	return id
}
