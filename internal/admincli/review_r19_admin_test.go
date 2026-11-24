package admincli_test

import (
	"strings"
	"testing"
)

// The recovery text after a lost sms_cred key names the console step that makes the re-entered
// credentials carry codes. Credentials entered on the SMS page are only pending since round 18, so
// a text that stops at "enter them again" leaves every OTP login failing (admin-r19-1).
func TestDeclareLostSMSCredNamesTheConfirmStep(t *testing.T) {
	r := newRig(t)
	r.env.ResetSMS(t)
	if code := r.run("keys", "declare-lost", "sms_cred", "--key-number", "1", "--yes"); code != 0 {
		t.Fatalf("declare-lost sms_cred: exit %d, %q", code, r.errb.String())
	}
	for _, want := range []string{"sms pending", "sms confirm"} {
		if !strings.Contains(r.out.String(), want) {
			t.Errorf("declare-lost sms_cred does not mention %q: %q", want, r.out.String())
		}
	}
}

// The confirmation is the moment the code-carrying credentials change, so it leaves the banner of
// 10.7 on every enabled admin, in the transaction of the change; a confirmation that finds nothing
// leaves none (admin-r19-5).
func TestSMSConfirmLeavesTheGatewayBanner(t *testing.T) {
	r := newRig(t)
	r.readyAdmin()
	plantPending(t, r, "2222")
	banner := func() bool {
		var notice *string
		r.env.Scan(t, `SELECT pending_notice::text FROM ctrlz.admin_users WHERE id = $1`, []any{seedAdmin}, &notice)
		return notice != nil && strings.Contains(*notice, "sms_gateway_changed")
	}
	if banner() {
		t.Fatal("a banner before any confirmation")
	}
	if code := r.run(r.confirmArgs("9999")...); code == 0 || banner() {
		t.Fatalf("a refused confirmation (exit %d) left a banner", code)
	}
	if code := r.run(r.confirmArgs("2222")...); code != 0 {
		t.Fatalf("confirm: exit %d, %q", code, r.errb.String())
	}
	if !banner() {
		t.Fatal("the confirmation left no sms_gateway_changed banner")
	}
}
