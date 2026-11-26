package audit_test

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"math/rand/v2"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/closed"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

func tenantEvents() []audit.TenantEvent {
	id := uuid.New()
	return []audit.TenantEvent{
		audit.LoginOK{Method: "password", SessionID: id}, audit.LoginFailed{Method: "otp"}, audit.Logout{Count: 1},
		audit.LogoutAll{Count: 3}, audit.SessionRevoke{SessionID: id}, audit.RefreshReuse{FamilyID: id},
		audit.ReauthOK{Method: "totp"}, audit.ReauthFailed{Method: "password"}, audit.PasswordChange{}, audit.PasswordReset{},
		audit.PhoneChange{OldMasked: audit.MaskPhone("+989121234567"), NewMasked: audit.MaskPhone("+989351112233")},
		audit.TOTPEnable{Left: 10}, audit.TOTPDisable{}, audit.RecoveryRegenerate{Left: 10}, audit.RecoveryUsed{Left: 9},
		audit.PasskeyAdd{CredentialRowID: id}, audit.PasskeyRename{CredentialRowID: id}, audit.PasskeyDelete{CredentialRowID: id},
		audit.PasskeyEnforce{Enabled: true}, audit.PasskeyReview{}, audit.PasskeyCloneSuspect{CredentialRowID: id},
		audit.Register{Via: "invite"}, audit.TOTPLost{KeyNumber: 1, Users: 2},
		audit.ProfileLock{ProfileID: id}, audit.ProfileUnlock{ProfileID: id}, audit.ProfileUnlockFailed{ProfileID: id},
		audit.ProfileLockPasswordUsed{ProfileID: id, EndpointID: id}, audit.ProfileLockPasswordFailed{ProfileID: id, EndpointID: id},
		audit.ShareLinkCreate{LinkID: id, EndpointID: id}, audit.ShareLinkRevoke{LinkID: id, EndpointID: id},
		audit.APITokenCreate{TokenID: id}, audit.APITokenUpdate{TokenID: id}, audit.APITokenDelete{TokenID: id},
	}
}

func adminEvents() []audit.AdminEvent {
	id := uuid.New()
	return []audit.AdminEvent{
		audit.AdminBootstrap{Admin: id, Via: "cli"}, audit.AdminPasswordResetCLI{Admin: id, Via: "cli"},
		audit.AdminTOTPResetCLI{Admin: id, Via: "cli"}, audit.AdminUnlockCLI{Admin: id, Via: "cli"},
		audit.AdminLogin{Admin: id}, audit.AdminLogout{Admin: id}, audit.AdminLoginFailed{}, audit.AdminPasswordChange{Admin: id},
		audit.AdminTOTPEnroll{Admin: id}, audit.AdminTOTPFresh{Admin: id}, audit.AdminNoticesAck{Admin: id, Cleared: 1, Kept: 2}, audit.UserCreate{Tenant: id},
		audit.UserPasswordReissue{Tenant: id, UserID: id, WasExpired: true, RevokedSessions: 2},
		audit.InviteCreate{Invite: id, TTLHours: 72}, audit.InviteRevoke{Invite: id},
		audit.RegistrationModeChange{From: "closed", To: "open", Graced: 3, SuspendedAtOnce: 1, GraceDays: 14},
		audit.WebauthnConfigChange{FromRP: "a.test", ToRP: "b.test", Credentials: 2, Users: 1},
		audit.SMSGatewayChange{Gateway: id, Fields: []audit.Field{audit.FieldCredentials}}, audit.SMSRoutingChange{Gateway: id, Fields: []audit.Field{audit.FieldPrimary}},
		audit.SMSTemplateChange{Gateway: id, Fields: []audit.Field{audit.FieldBody}, Key: sms.TemplateOTP, Locale: "fa"}, audit.SMSLimitsChange{Gateway: id, Fields: []audit.Field{audit.FieldOTPCapPhone}},
		audit.SMSTestSend{Gateway: id}, audit.KeyRotated{Domain: "sms_cred", KeyNumber: 2}, audit.KeyDeclaredLost{Domain: "user_totp", KeyNumber: 1},
		audit.KeyRekeyed{Domain: "admin_totp", KeyNumber: 2, Rewritten: 1, Changed: 0, Failed: 1},
		audit.AlertAck{Alert: id, Kind: audit.AlertSMSGateway},
		audit.NodeEnrollmentCreate{Enrollment: id, Bound: true}, audit.NodeEnrollmentConfirm{Enrollment: id, Node: id, Slot: 1}, audit.NodeEnrollmentReject{Enrollment: id},
		audit.NodeApprove{Node: id}, audit.NodeRevoke{Node: id},
		audit.NodeRemove{Node: id, OldDNSIP: "192.0.2.1", OldProxyIP: "192.0.2.2", Name: audit.NodeNameOf("node-1")},
		audit.NodeAddressesChange{Node: id, OldDNSIP: "192.0.2.1", OldProxyIP: "192.0.2.2", Name: audit.NodeNameOf("node-1")},
		audit.NodeUpdate{Node: id, Renamed: true, ProxyBlocked: false}, audit.NodeDNSRequest{Node: id, Kind: audit.DNSRequestHold},
		audit.PairCreate{Pair: id, MakeGlobal: true}, audit.PairUpdate{Pair: id}, audit.PairDelete{Pair: id}, audit.GlobalPairSet{Pair: id},
		audit.FreeDNSChange{FromEnabled: false, ToEnabled: true, QPS: 5},
		audit.DomainChange{FromZone: audit.DomainNameOf("a.example.test"), ToZone: audit.DomainNameOf("b.example.test"), HostsChanged: true, TransitionDays: 7},
		audit.CertificateUpload{Certificate: id, Kind: audit.CertWildcard, Names: 2}, audit.CertificateRetire{Certificate: id},
	}
}

// TestEveryEventFieldIsClosed is the reflection half of rule closed-values-in-logs
// (spec 13.3). Every registered event type is judged by closed.CheckType: each field
// is a bool, an integer, an id, a masked phone, or a value of a named string type that
// declares its closed set. A plain string, a map, an interface, a byte slice or a
// secret.* type fails. The registry is the two lists above; TestEventRegistryIsComplete
// keeps it honest by parsing the package for every type that carries an event marker.
func TestEveryEventFieldIsClosed(t *testing.T) {
	for _, e := range audit.TenantEvents() {
		if err := closed.CheckType(reflect.TypeOf(e)); err != nil {
			t.Errorf("%s: %v", e.Action(), err)
		}
	}
	for _, e := range audit.AdminEvents() {
		if err := closed.CheckType(reflect.TypeOf(e)); err != nil {
			t.Errorf("%s: %v", e.Action(), err)
		}
	}
	// The closed set of a type is real: it has members, and a value that is not one
	// of them is refused. A Valid that returns true for everything would pass the
	// shape check and defeat the rule. The probe holds a "!", which no grammar type (Host, NodeName, NodeAddr, DomainName) admits;
	// a probe of plain letters and an underscore is inside the NodeName grammar and would be a member.
	probe := "x_not_a_member_9!"
	for _, ty := range []reflect.Type{reflect.TypeOf(audit.Method("")), reflect.TypeOf(audit.Via("")), reflect.TypeOf(audit.RegMode("")),
		reflect.TypeOf(audit.KeyDomain("")), reflect.TypeOf(audit.AlertKind("")), reflect.TypeOf(audit.Field("")), reflect.TypeOf(audit.Host("")), reflect.TypeOf(audit.NodeName("")), reflect.TypeOf(audit.NodeAddr("")), reflect.TypeOf(audit.DNSRequestKind("")), reflect.TypeOf(audit.CertKind("")), reflect.TypeOf(audit.DomainName("")),
		reflect.TypeOf(sms.TemplateKey("")), reflect.TypeOf(sms.Locale(""))} {
		v := reflect.New(ty).Elem()
		v.SetString(probe)
		if v.MethodByName("Valid").Call(nil)[0].Bool() {
			t.Errorf("%s accepts %q", ty, probe)
		}
	}
}

// TestEventRegistryIsComplete parses the package source for every type with an
// event marker (tenantEvent or adminEvent) and requires the type to be in the lists
// above, so an event added later is covered by the reflection test without anyone
// remembering to add it.
func TestEventRegistryIsComplete(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	marked := map[string]string{}
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Recv == nil || len(fd.Recv.List) != 1 || (fd.Name.Name != "tenantEvent" && fd.Name.Name != "adminEvent") {
					continue
				}
				switch r := fd.Recv.List[0].Type.(type) {
				case *ast.Ident:
					marked[r.Name] = fd.Name.Name
				case *ast.StarExpr:
					if id, ok := r.X.(*ast.Ident); ok {
						marked[id.Name] = fd.Name.Name
					}
				}
			}
		}
	}
	if len(marked) < 40 {
		t.Fatalf("found only %d event types in the source", len(marked))
	}
	// The registry is production code (registry.go): the spec lint reflects over it too.
	have := map[string]bool{}
	for _, e := range audit.TenantEvents() {
		have[reflect.TypeOf(e).Name()] = true
	}
	for _, e := range audit.AdminEvents() {
		have[reflect.TypeOf(e).Name()] = true
	}
	// The filled-in lists of this file drive the other tests; they must name the same types.
	filled := map[string]bool{}
	for _, e := range tenantEvents() {
		filled[reflect.TypeOf(e).Name()] = true
	}
	for _, e := range adminEvents() {
		filled[reflect.TypeOf(e).Name()] = true
	}
	for name := range have {
		if !filled[name] {
			t.Errorf("event type %s is in the registry but not in tenantEvents or adminEvents of this file", name)
		}
	}
	for name := range filled {
		if !have[name] {
			t.Errorf("event type %s is in this file's lists but not in the registry", name)
		}
	}
	for name := range marked {
		if !have[name] {
			t.Errorf("event type %s is not in audit.TenantEvents or audit.AdminEvents, so the reflection tests do not cover it", name)
		}
	}
	for name := range have {
		if marked[name] == "" {
			t.Errorf("%s is in the registry but carries no event marker", name)
		}
	}
}

func TestEveryDocumentedActionExists(t *testing.T) {
	want := []string{"login.ok", "login.failed", "logout", "logout.all", "session.revoke", "session.refresh_reuse", "reauth.ok", "reauth.failed",
		"password.change", "password.reset", "phone.change", "totp.enable", "totp.disable", "recovery.regenerate", "recovery.used",
		"passkey.add", "passkey.rename", "passkey.delete", "passkey.enforce", "passkey.review", "passkey.clone_suspect", "register", "totp.declared_lost"}
	got := map[string]bool{}
	for _, e := range tenantEvents() {
		got[e.Action()] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("tenant action %s has no event", w)
		}
	}
	wantAdmin := []string{"admin.bootstrap", "admin.password_reset_cli", "admin.totp_reset_cli", "admin.unlock_cli", "admin.login", "admin.logout",
		"admin.login_failed", "admin.password_change", "admin.totp_enroll", "admin.totp_fresh", "admin.notices_ack", "user.create", "user.password_reissue",
		"invite.create", "invite.revoke", "registration.mode_change", "webauthn.config_change", "sms.gateway_change", "sms.routing_change",
		"sms.template_change", "sms.limits_change", "sms.test_send", "key.rotated", "key.declared_lost", "alert.ack"}
	gotA := map[string]bool{}
	for _, e := range adminEvents() {
		gotA[e.Action()] = true
	}
	for _, w := range wantAdmin {
		if !gotA[w] {
			t.Errorf("admin action %s has no event", w)
		}
	}
}

func TestReissueParamsAreExactlyThreeKeys(t *testing.T) {
	var got map[string]any
	e := audit.UserPasswordReissue{Tenant: uuid.New(), UserID: uuid.New(), WasExpired: true, RevokedSessions: 2}
	canon, err := audit.Canonical(time.Now(), uuid.New(), e.Action(), e.Target(), mustParams(t, e), netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Params map[string]any }
	_ = json.Unmarshal(canon, &doc)
	got = doc.Params
	if len(got) != 3 || got["was_expired"] != true || got["revoked_sessions"] != float64(2) || got["user_id"] == nil {
		t.Fatalf("params = %v", got)
	}
	if !strings.HasPrefix(e.Target(), "tenant:") {
		t.Fatalf("target = %s", e.Target())
	}
}

func mustParams(t *testing.T, ev any) []byte {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMaskedPhoneNeverHoldsTheFullNumber(t *testing.T) {
	m := audit.MaskPhone("+989121234567").String()
	if strings.Contains(m, "9121234567") || !strings.Contains(m, "***") {
		t.Fatalf("mask = %s", m)
	}
	b, _ := json.Marshal(audit.PhoneChange{OldMasked: audit.MaskPhone("+989121234567"), NewMasked: audit.MaskPhone("+989351112233")})
	if strings.Contains(string(b), "1234567") || strings.Contains(string(b), "1112233") {
		t.Fatalf("params = %s", b)
	}
}

func TestCanonicalIsSortedCompactAndStable(t *testing.T) {
	at := time.Date(2026, 11, 7, 12, 30, 45, 123456789, time.FixedZone("x", 3600))
	admin := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	a, err := audit.Canonical(at, admin, "x.y", "tenant:t", []byte(`{"b": 2, "a": {"d":1,"c":[1,2]}}`), netip.MustParseAddr("::ffff:203.0.113.9"))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"action":"x.y","admin_id":"11111111-2222-3333-4444-555555555555","at":"2026-11-07T11:30:45.123456Z","ip":"203.0.113.9","params":{"a":{"c":[1,2],"d":1},"b":2},"target":"tenant:t"}`
	if string(a) != want {
		t.Fatalf("got  %s\nwant %s", a, want)
	}
	// jsonb hands the params back reordered and re-spaced; the hash must not care.
	b, _ := audit.Canonical(at, admin, "x.y", "tenant:t", []byte(`{"a":{"c":[1,2],"d":1},"b":2}`), netip.MustParseAddr("203.0.113.9"))
	if !bytes.Equal(a, b) {
		t.Fatal("canonical form depends on the params' spelling")
	}
	// The inet column keeps no zone, so the zone cannot be part of the hash.
	z, _ := audit.Canonical(at, admin, "x.y", "tenant:t", []byte(`{"a":1}`), netip.MustParseAddr("fe80::1%eth0"))
	y, _ := audit.Canonical(at, admin, "x.y", "tenant:t", []byte(`{"a":1}`), netip.MustParseAddr("fe80::1"))
	if !bytes.Equal(z, y) || bytes.Contains(z, []byte("%")) {
		t.Fatalf("zoned and plain IPv6 differ: %s vs %s", z, y)
	}
	n, _ := audit.Canonical(at, uuid.Nil, "x", "", nil, netip.Addr{})
	if string(n) != `{"action":"x","admin_id":null,"at":"2026-11-07T11:30:45.123456Z","ip":null,"params":{},"target":null}` {
		t.Fatalf("nulls: %s", n)
	}
}

func TestVerifyChainOverRealRows(t *testing.T) {
	env := authtest.New(t, cluster)
	st := env.Admin(t)
	admin := uuid.New()
	ip := netip.MustParseAddr("203.0.113.9")
	base := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)

	// Rows are written through both sinks: a global transaction and WithTenant,
	// as the re-issue does. They share one chain.
	for i := 0; i < 3; i++ {
		err := st.WithGlobal(env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			_, err := audit.Admin(g, base.Add(time.Duration(i)*time.Second+123*time.Microsecond), admin, ip, audit.AdminLogin{Admin: admin})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// A zoned IPv6 address and a 4-in-6 one: the inet column keeps neither the
	// zone nor the mapping, and the chain must still verify (primitives-r2-3).
	for i, odd := range []netip.Addr{netip.MustParseAddr("fe80::1%eth0"), netip.MustParseAddr("::ffff:203.0.113.9"), netip.MustParseAddr("2001:db8::7")} {
		err := st.WithGlobal(env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			_, err := audit.Admin(g, base.Add(time.Duration(10+i)*time.Second), admin, odd, audit.AdminLogin{Admin: admin})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	err := st.WithTenant(env.Ctx, env.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, err := audit.Admin(audit.OnTenant(tx), base.Add(time.Minute), admin, ip,
			audit.UserPasswordReissue{Tenant: env.A.Tenant, UserID: env.A.User, WasExpired: true, RevokedSessions: 1})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var rows []store.AuditRow
	if err := st.WithGlobal(env.Ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
		rows, err = g.AuditChain(0, 100)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(rows) < 7 {
		t.Fatalf("only %d rows", len(rows))
	}
	if _, err := audit.VerifyChain(nil, rows); err != nil {
		t.Fatalf("a chain written by the writer must verify: %v", err)
	}
	// A changed row, and a removed row, are both found.
	bad := append([]store.AuditRow(nil), rows...)
	bad[1].Action = "admin.logout"
	var ce *audit.ChainError
	if _, err := audit.VerifyChain(nil, bad); !asChain(err, &ce) || ce.Row != rows[1].ID {
		t.Fatalf("tampered row: %v", err)
	}
	gap := append(append([]store.AuditRow(nil), rows[:1]...), rows[2:]...)
	if _, err := audit.VerifyChain(nil, gap); !asChain(err, &ce) {
		t.Fatalf("missing row: %v", err)
	}
}

func asChain(err error, target **audit.ChainError) bool {
	ce, ok := err.(*audit.ChainError)
	if ok {
		*target = ce
	}
	return ok
}

func TestTenantAuditIsScopedToTheTenant(t *testing.T) {
	env := authtest.New(t, cluster)
	st := env.Tenant(t)
	ip := netip.MustParseAddr("203.0.113.9")
	write := func(tenant, user uuid.UUID, ev audit.TenantEvent) {
		t.Helper()
		if err := st.WithTenant(env.Ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
			return audit.Tenant(tx, user, ip, ev)
		}); err != nil {
			t.Fatal(err)
		}
	}
	write(env.A.Tenant, env.A.User, audit.LoginOK{Method: "password", SessionID: uuid.New()})
	write(env.B.Tenant, env.B.User, audit.PhoneChange{OldMasked: audit.MaskPhone("+989121234567"), NewMasked: audit.MaskPhone("+989351112233")})

	// Each tenant sees its own row and only that: RLS keys on the tenant, so an
	// actor id naming somebody else's user cannot make a row visible elsewhere.
	const qCount = `SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'phone.change'`
	for tenant, want := range map[uuid.UUID]int{env.A.Tenant: 0, env.B.Tenant: 1} {
		var n int
		if err := st.WithTenant(env.Ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
			return tx.DB().QueryRow(env.Ctx, qCount).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Fatalf("tenant %s sees %d phone.change rows, want %d", tenant, n, want)
		}
	}
}

// TestAFullNumberCannotReachAnAuditRow is primitives-r1-8, r2-4 and r3-1 under the new
// rule. Masked is a struct with an unexported field, so audit.Masked("+98...") does not
// compile. Every other string field is a closed type, so a number in any script, with
// any separator, in any field kind, is a value off the list and is refused, and the
// refusal does not repeat the value. There is no scan to get round.
func TestAFullNumberCannotReachAnAuditRow(t *testing.T) {
	numbers := []string{
		"+989121234567", "09121234567", "989121234567", "۰۹۱۲۱۲۳۴۵۶۷", "phone 09121234567 failed",
		"०९१२३४५६७८९०", "০৯১২৩৪৫৬৭৮৯০", "๐๙๑๒๓๔๕๖๗๘๙๐", "０９１２１２３４５６７", "0912१२३४५६७",
		"0912‌123‌4567", "09121‏234567", "9121234567", "12345678", "x_x", "",
	}
	id := uuid.New()
	for _, n := range numbers {
		for name, ev := range map[string]any{
			"login method":  audit.LoginFailed{Method: audit.Method(n)},
			"pointer":       &audit.LoginFailed{Method: audit.Method(n)},
			"reauth":        audit.ReauthOK{Method: audit.Method(n)},
			"via":           audit.Register{Via: audit.Via(n)},
			"cli via":       audit.AdminBootstrap{Admin: id, Via: audit.Via(n)},
			"mode":          audit.RegistrationModeChange{From: audit.RegMode(n), To: audit.RegClosed},
			"rp":            audit.WebauthnConfigChange{FromRP: audit.Host(n), ToRP: audit.HostOf("a.test")},
			"gateway field": audit.SMSGatewayChange{Gateway: id, Fields: []audit.Field{audit.FieldCredentials, audit.Field(n)}},
			"routing":       audit.SMSRoutingChange{Gateway: id, Fields: []audit.Field{audit.Field(n)}},
			"template key":  audit.SMSTemplateChange{Gateway: id, Fields: []audit.Field{audit.FieldBody}, Key: sms.TemplateKey(n), Locale: "fa"},
			"locale":        audit.SMSTemplateChange{Gateway: id, Fields: []audit.Field{audit.FieldBody}, Key: sms.TemplateOTP, Locale: sms.Locale(n)},
			"limits":        &audit.SMSLimitsChange{Gateway: id, Fields: []audit.Field{audit.Field(n)}},
			"key domain":    audit.KeyRotated{Domain: audit.KeyDomain(n), KeyNumber: 1},
			"alert kind":    audit.AlertAck{Alert: id, Kind: audit.AlertKind(n)},
		} {
			_, err := audit.MarshalParams(ev)
			if err == nil {
				t.Errorf("%s: %q got through", name, n)
				continue
			}
			if n != "" && strings.Contains(err.Error(), n) {
				t.Errorf("%s: the error repeats the value: %v", name, err)
			}
		}
	}
	// The Parse functions map anything unlisted to one fixed member, which is fine.
	for _, n := range numbers {
		for _, ev := range []any{
			audit.LoginFailed{Method: audit.MethodOf(n)}, audit.Register{Via: audit.ViaOf(n)},
			audit.RegistrationModeChange{From: audit.RegModeOf(n), To: audit.RegModeOf(n)},
			audit.WebauthnConfigChange{FromRP: audit.HostOf(n), ToRP: audit.HostOf(n)},
			audit.KeyRotated{Domain: audit.KeyDomainOf(n)}, audit.AlertAck{Kind: audit.AlertKindOf(n)},
		} {
			b, err := audit.MarshalParams(ev)
			if err != nil {
				t.Errorf("%T from %q refused: %v", ev, n, err)
			} else if n != "" && strings.Contains(string(b), n) {
				t.Errorf("%T from %q kept the value: %s", ev, n, b)
			}
		}
	}
	// Ordinary values, a masked number and a large count are fine.
	for _, ev := range []any{
		audit.LoginFailed{Method: audit.MethodPassword},
		audit.SMSGatewayChange{Gateway: id, Fields: []audit.Field{audit.FieldCredentials, audit.FieldOTPCapPhone}},
		audit.PhoneChange{OldMasked: audit.MaskPhone("+989121234567"), NewMasked: audit.MaskPhone("+989351112233")},
		audit.Logout{Count: 1234567890123},
		audit.WebauthnConfigChange{FromRP: audit.HostOf("panel.ctrlz.example"), ToRP: audit.HostOf("localhost")},
	} {
		if _, err := audit.MarshalParams(ev); err != nil {
			t.Errorf("%T refused: %v", ev, err)
		}
	}
	// Whatever a Masked holds is the mask: a zero one is an empty string.
	b, err := audit.MarshalParams(audit.PhoneChange{})
	if err != nil || strings.Contains(string(b), "9") {
		t.Errorf("zero PhoneChange: %s %v", b, err)
	}
}

// The relying-party id is the one grammar in the audit vocabulary (values.go).
func TestHostGrammar(t *testing.T) {
	for _, ok := range []string{"localhost", "panel.localhost", "ctrlz.example", "a-b.c1.example", "x1.ir"} {
		if audit.HostOf(ok) != audit.Host(ok) {
			t.Errorf("%q should be a host", ok)
		}
	}
	for _, bad := range []string{"", ".", "a..b", "-a.ir", "a-.ir", "UPPER.ir", "a b.ir", "a_b.ir", "09121234567.ir", "a.09121234567", "a.ir.", "ctrlz.123",
		// Round 16 (primitives-r16-13): a number split by the characters a name may hold.
		"0912-123-4567.example", "0912.123.4567.ir", "0912a123b4567.ir", "09-12-12-34-56-7.ir", "a1b2c3d4e5f6g7h8i9j0.ir",
		"9121234567.ir", "۰۹۱۲.ir", "a/b.ir", "a:80.ir", "a.i", strings.Repeat("a", 64) + ".ir", strings.Repeat("a.", 130) + "ir"} {
		if audit.HostOf(bad) != audit.HostInvalid {
			t.Errorf("%q should not be a host", bad)
		}
	}
}

// TestNoHostCanSpellANumber is the property of the grammar and not a list of cases (primitives-r16-13):
// over a seeded sample of names made of the characters the grammar admits (and a few it does not),
// whatever HostOf accepts holds at most nine digits, so no mobile number or ten-digit code is in an
// audit row however it is split. The alphabet leans on digits, hyphens and dots, the characters a
// number is split with.
func TestNoHostCanSpellANumber(t *testing.T) {
	alphabet := []byte("0123456789012345678901234567890123456789--..aab")
	rnd := rand.New(rand.NewPCG(1, 2))
	accepted := 0
	for range 200000 {
		b := make([]byte, 1+rnd.IntN(40))
		for i := range b {
			b[i] = alphabet[rnd.IntN(len(alphabet))]
		}
		s := string(b)
		if audit.HostOf(s) == audit.HostInvalid {
			continue
		}
		accepted++
		if n := strings.Count(s, "0") + strings.Count(s, "1") + strings.Count(s, "2") + strings.Count(s, "3") + strings.Count(s, "4") +
			strings.Count(s, "5") + strings.Count(s, "6") + strings.Count(s, "7") + strings.Count(s, "8") + strings.Count(s, "9"); n > 9 {
			t.Fatalf("%q is a host with %d digits", s, n)
		}
	}
	if accepted < 100 {
		t.Fatalf("only %d names were accepted; the sample does not reach the grammar", accepted)
	}
}
