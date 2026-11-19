package apispec_test

import (
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

func doc(op string) []byte { return []byte("paths:\n  /x/{id}:\n    post:\n" + op) }

func TestParseReadsBothExtensions(t *testing.T) {
	ops, err := apispec.Parse(doc("      operationId: doIt\n      x-ctrlz-auth: reauth\n      x-ctrlz-rate: sensitive\n      x-ctrlz-max-body: 65536\n"), ratelimit.Tenant)
	if err != nil || len(ops) != 1 {
		t.Fatalf("%v %v", ops, err)
	}
	o := ops[0]
	if o.ID != "doIt" || o.Method != "POST" || o.Path != "/x/{id}" || o.Auth != apispec.Reauth || o.Rate != "sensitive" || o.MaxBody != 65536 {
		t.Fatalf("%+v", o)
	}
	if o.Key() != "POST /x/{id}" {
		t.Fatal(o.Key())
	}
}

func TestParseRefusesWhatWouldGoLiveUnguarded(t *testing.T) {
	cases := map[string]string{
		"no operationId":    "      x-ctrlz-auth: none\n      x-ctrlz-rate: auth\n",
		"no auth":           "      operationId: a\n      x-ctrlz-rate: auth\n",
		"no rate":           "      operationId: a\n      x-ctrlz-auth: none\n",
		"unknown auth":      "      operationId: a\n      x-ctrlz-auth: sesion\n      x-ctrlz-rate: auth\n",
		"admin auth on api": "      operationId: a\n      x-ctrlz-auth: admin\n      x-ctrlz-rate: auth\n",
		"unknown rate":      "      operationId: a\n      x-ctrlz-auth: none\n      x-ctrlz-rate: fast\n",
		"admin rate on api": "      operationId: a\n      x-ctrlz-auth: none\n      x-ctrlz-rate: admin-login\n",
		"negative body":     "      operationId: a\n      x-ctrlz-auth: none\n      x-ctrlz-rate: auth\n      x-ctrlz-max-body: -1\n",
	}
	for name, op := range cases {
		if _, err := apispec.Parse(doc(op), ratelimit.Tenant); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	dup := "paths:\n  /a:\n    get: {operationId: same, x-ctrlz-auth: none, x-ctrlz-rate: auth}\n  /b:\n    get: {operationId: same, x-ctrlz-auth: none, x-ctrlz-rate: auth}\n"
	if _, err := apispec.Parse([]byte(dup), ratelimit.Tenant); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a repeated operationId: %v", err)
	}
}

func TestHealthOperationsAreOutsideThePipeline(t *testing.T) {
	d := "paths:\n  /healthz:\n    get: {tags: [health], operationId: healthz}\n"
	ops, err := apispec.Parse([]byte(d), ratelimit.Tenant)
	if err != nil || len(ops) != 0 {
		t.Fatalf("%v %v", ops, err)
	}
}

func TestOtherKeysOfAPathItemAreNotOperations(t *testing.T) {
	d := "paths:\n  /a:\n    parameters: [{name: x, in: query}]\n    summary: s\n    get: {operationId: g, x-ctrlz-auth: none, x-ctrlz-rate: auth}\n"
	ops, err := apispec.Parse([]byte(d), ratelimit.Tenant)
	if err != nil || len(ops) != 1 {
		t.Fatalf("%v %v", ops, err)
	}
}

// The tests that matter most: the real documents. A new route without both
// extensions, or with a value the service does not know, fails here before it
// can be merged (spec 2.2, 18.1).
func TestRealDocumentsPass(t *testing.T) {
	tenant, err := apispec.Parse(api.Tenant(), ratelimit.Tenant)
	if err != nil {
		t.Fatalf("api/openapi.yaml: %v", err)
	}
	admin, err := apispec.Parse(api.Admin(), ratelimit.Admin)
	if err != nil {
		t.Fatalf("api/admin-openapi.yaml: %v", err)
	}
	if len(tenant) == 0 || len(admin) == 0 {
		t.Fatal("a document with no operations")
	}
	// Every route that reaches the user's own data or changes a credential must
	// not be 'none'. Today's list: the three session routes.
	for _, o := range tenant {
		switch o.ID {
		case "logout", "logoutAll":
			if o.Auth == apispec.None {
				t.Errorf("%s must need a session", o.ID)
			}
		}
	}
}

// TestAdminFreshListIsMarked walks the admin document for the operations spec
// 10.5 lists as needing a fresh TOTP check. Routes that do not exist yet are not
// failures; each one that does must carry the marker.
func TestAdminFreshListIsMarked(t *testing.T) {
	want := map[string]bool{
		"PUT /settings/registration":                                  true,
		"PUT /settings/webauthn":                                      true,
		"POST /tenants/{tenant_id}/users/{user_id}/one-time-password": true,
		"PUT /sms/gateways/{provider}":                                true,
		"PUT /sms/routing":                                            true,
		"PUT /sms/limits":                                             true,
		"POST /sms/gateways/{provider}/test":                          true,
		"PUT /sms/gateways/{provider}/templates/{key}/{locale}":       true,
	}
	admin, err := apispec.Parse(api.Admin(), ratelimit.Admin)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range admin {
		if want[o.Key()] && o.Auth != apispec.AdminFresh {
			t.Errorf("%s must be admin-fresh (spec 10.5), is %s", o.Key(), o.Auth)
		}
	}
}
