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

// TestEveryTenantOperationDeclaresItsP2Extensions: x-ctrlz-token, x-ctrlz-lock and x-ctrlz-outbox are on every operation
// of the tenant document (P2 spec 8.1), with a value of their closed sets, and the lock and the outbox agree with what the
// operation is: a write that meets the lock says so, and a read writes nothing.
func TestEveryTenantOperationDeclaresItsP2Extensions(t *testing.T) {
	ops, err := apispec.Parse(api.Tenant(), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range ops {
		if err := apispec.CheckP2(op); err != nil {
			t.Error(err)
		}
		if op.Method == "GET" && (op.Lock != "none" || op.Outbox != "none") {
			t.Errorf("%s is a read and declares lock %s and outbox %s", op.ID, op.Lock, op.Outbox)
		}
	}
}

func TestCheckP2RefusesAMissingOrUnknownValue(t *testing.T) {
	for name, op := range map[string]apispec.Operation{
		"no token":   {ID: "a", Lock: "none", Outbox: "none"},
		"bad lock":   {ID: "a", Token: "none", Lock: "gard", Outbox: "none"},
		"bad outbox": {ID: "a", Token: "none", Lock: "none", Outbox: "rule"},
	} {
		if apispec.CheckP2(op) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// freshExempt are the state-changing operations of the ready admin that do not need a fresh code, with
// the reason. The one entry is how a session gets a fresh code at all.
var freshExempt = map[string]string{
	"POST /auth/totp/fresh": "it is the call that proves a code and opens the window",
}

// TestEveryStateChangingAdminOperationIsFresh is the rule of admin-r18-3 and admin-r18-10 by
// construction: an operation of the ready admin (class `admin`) that is not a read needs a code of the
// last five minutes, so a copied cookie without the authenticator changes nothing. The set is not a list
// of names: it is every operation of the document, a route added later is judged the day it is added, and
// an exemption needs a reason here. (Before round 18 the list was by hand and left out creating a user or
// an invite, the text of an OTP message, revoking an invite and silencing an alert.)
func TestEveryStateChangingAdminOperationIsFresh(t *testing.T) {
	admin, err := apispec.Parse(api.Admin(), ratelimit.Admin)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, o := range admin {
		if o.Auth != apispec.Admin || o.Method == "GET" {
			continue
		}
		if _, ok := freshExempt[o.Key()]; ok {
			seen[o.Key()] = true
			continue
		}
		t.Errorf("%s changes state with a plain admin session; it must be admin-fresh, or exempt with a reason", o.Key())
	}
	for k := range freshExempt {
		if !seen[k] {
			t.Errorf("exemption %q matches no operation", k)
		}
	}
}
