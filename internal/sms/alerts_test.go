package sms_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/closed"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
)

// alertParamTypes is the registry of the alert params the SMS layer defines.
func alertParamTypes() []any {
	return []any{sms.GatewayAlert{}, sms.TemplateAlert{}, sms.ReasonAlert{}}
}

// TestAlertParamsAreClosed is the reflection half of rule closed-values-in-logs for
// alerts: every params type is judged by closed.CheckType, and the source is parsed
// so a struct type added to alerts.go and left out of the registry fails.
func TestAlertParamsAreClosed(t *testing.T) {
	have := map[string]bool{}
	for _, v := range alertParamTypes() {
		ty := reflect.TypeOf(v)
		have[ty.Name()] = true
		if err := closed.CheckType(ty); err != nil {
			t.Errorf("%s: %v", ty.Name(), err)
		}
	}
	// The error itself, which is what the log lines and the status columns are built from.
	if err := closed.CheckType(reflect.TypeOf(sms.Error{})); err != nil {
		t.Errorf("Error: %v", err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "alerts.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, s := range gd.Specs {
			ts := s.(*ast.TypeSpec)
			if _, isStruct := ts.Type.(*ast.StructType); isStruct && ts.Name.IsExported() {
				seen++
				if !have[ts.Name.Name] {
					t.Errorf("alerts.go defines %s, which alertParamTypes does not list", ts.Name.Name)
				}
			}
		}
	}
	if seen < 3 {
		t.Fatalf("only %d params types found in alerts.go", seen)
	}
}

func TestAlertParamsCarryOnlyClosedValues(t *testing.T) {
	e := sms.NewError("sms_ir", sms.Auth, sms.StatusCode("10"))
	if got := string(classify.GatewayParams(e).JSON()); got != `{"provider":"sms_ir","class":"auth","code":"10"}` {
		t.Errorf("gateway alert %s", got)
	}
	if got := string(classify.TemplateParams(e, sms.ParseTemplate("otp")).JSON()); got != `{"provider":"sms_ir","class":"auth","code":"10","template":"otp"}` {
		t.Errorf("template alert %s", got)
	}
	// A template key that is not one of the five is the fixed unknown key.
	if got := string(classify.TemplateParams(e, sms.ParseTemplate("09121234567")).JSON()); strings.Contains(got, "912") || !strings.Contains(got, `"template":"unknown"`) {
		t.Errorf("template alert %s", got)
	}
	if got := string(sms.ReasonParams(sms.CodeCap).JSON()); got != `{"reason":"cap"}` {
		t.Errorf("reason alert %s", got)
	}
	// A struct literal that bypasses NewError still cannot put text in the params: the
	// marshal refuses it and the alert is raised with the fixed unknown reason.
	bad := &sms.Error{Provider: "https://x", Class: sms.Auth, Code: "value_09121234567"}
	if got := string(classify.GatewayParams(bad).JSON()); strings.Contains(got, "912") || strings.Contains(got, "https") || got != `{"reason":"unknown"}` {
		t.Errorf("bypassed error: %s", got)
	}
	if bad.Status().Valid() {
		t.Error("a status built from an off-list code must not be valid")
	}
}

func TestStatusColumns(t *testing.T) {
	e := sms.NewError("melipayamak", sms.Transient, sms.HTTPCode(503))
	if s := e.Status(); s.String() != "transient:http_503" || !s.Valid() {
		t.Errorf("status %q valid=%v", s.String(), s.Valid())
	}
	if s := sms.StatusOf(sms.CodeCap); s.String() != "cap" || !s.Valid() {
		t.Errorf("bare status %q", s.String())
	}
	if sms.StatusOf(sms.CodeNone).Valid() {
		t.Error("the zero code is not a status")
	}
}

func TestAlertKeys(t *testing.T) {
	gw := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	k := closed.NewKey(closed.ID(gw), sms.Config, sms.ParseTemplate("otp"), sms.KeyNone)
	if k.String() != "11111111-2222-3333-4444-555555555555:config:otp:none" {
		t.Errorf("key %q", k)
	}
	if closed.NewKey(sms.KeyWord("09121234567")).String() != "" {
		t.Error("an off-list word made a key")
	}
	if closed.NewKey(sms.Class(99)).String() != "" {
		t.Error("an off-list class made a key")
	}
}
