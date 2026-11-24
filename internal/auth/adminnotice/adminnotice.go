// Package adminnotice is the shape of admin_users.pending_notice: the banner an
// admin sees at the next login after the server console reset their password or
// TOTP (spec 10.1, T-325).
//
// The column is jsonb and the spec named no shape, so it is defined here, once,
// for the CLI that writes it and the admin API that reads it: a JSON array of
// {"kind", "at"} objects. A list rather than one object, so a reset-password
// followed by a reset-totp before the next login shows both. No notice holds a
// password, a code or anything else secret: it only says what happened and when.
package adminnotice

import (
	"encoding/json"
	"time"
)

// Kinds. They are the enum of AdminMe.notices in the admin OpenAPI document.
const (
	PasswordReset = "password_reset"
	TOTPReset     = "totp_reset"
	// SMSGatewayChanged is shown to every admin when the credentials or the routing
	// of the SMS gateways changed (spec 10.7, review round 2 admin-r2-8). Whoever
	// controls the gateway account reads every login, reset and phone-change code,
	// so a change made with a stolen session must reach the owner.
	SMSGatewayChanged = "sms_gateway_changed"
)

// Notice is one entry.
type Notice struct {
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`
}

// maxNotices bounds the column. Repeated resets with no login in between would
// otherwise grow it for ever; the newest are the ones worth showing.
const maxNotices = 10

// Parse reads the column. A value that is not the expected array is treated as
// no notice rather than an error: it must never stop a login, and it holds
// nothing the admin needs more than the login itself. Unknown kinds are dropped
// so the API never emits a value outside its enum.
func Parse(raw []byte) []Notice {
	if len(raw) == 0 {
		return nil
	}
	var all []Notice
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil
	}
	out := all[:0]
	for _, n := range all {
		if n.Kind == PasswordReset || n.Kind == TOTPReset || n.Kind == SMSGatewayChanged {
			out = append(out, n)
		}
	}
	return out
}

// Append returns the column value with n added at the end, keeping at most the
// newest maxNotices.
func Append(raw []byte, n Notice) ([]byte, error) {
	all := append(Parse(raw), Notice{Kind: n.Kind, At: n.At.UTC().Truncate(time.Millisecond)})
	if len(all) > maxNotices {
		all = all[len(all)-maxNotices:]
	}
	return json.Marshal(all)
}

// Marshal writes a list back as the column value. It is what Append ends with,
// for a caller that removes entries (the acknowledgement).
func Marshal(all []Notice) ([]byte, error) { return json.Marshal(all) }
