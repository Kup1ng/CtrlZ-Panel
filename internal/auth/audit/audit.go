// Package audit writes the audit rows of spec 13: tenant events into
// tenant_audit_log and admin events into the hash-chained audit_log.
//
// What a row may contain is enforced by the types, not by care. An event is a Go
// struct whose fields are integers, booleans, ids, Masked phones and values of named
// string types that list their members (values.go); none is a plain string, a
// secret.* type, a byte slice, a map or an interface. marshalParams hands every
// event to closed.Marshal, which refuses a field off its list, and a reflection test
// walks every event type to keep the shapes so (spec 13.3, review round 5, rule
// closed-values-in-logs). It replaced a scan for runs of digits, which each round
// found a field kind, a script or a separator to get round.
package audit

import (
	"encoding/json"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/phone"
	"github.com/Kup1ng/CtrlZ-Panel/internal/closed"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Masked is a phone number in the log form of phone.MaskForLog. A full number
// cannot be put in an audit row: the field is unexported, so a conversion such
// as Masked(fullNumber) does not compile outside this package and the only way
// to make one is MaskPhone (review round 1, primitives-r1-8).
type Masked struct{ s string }

// MaskPhone masks an E.164 number for an audit row.
func MaskPhone(e164 string) Masked { return Masked{phone.MaskForLog(e164)} }

// String is the masked form.
func (m Masked) String() string { return m.s }

// MarshalJSON writes the masked form as a JSON string.
func (m Masked) MarshalJSON() ([]byte, error) { return json.Marshal(m.s) }

// ClosedOpaque marks Masked as a type that cannot hold free text: its only field is
// unexported and set by MaskPhone.
func (Masked) ClosedOpaque() {}

// ---------------------------------------------------------------------------
// Tenant events (13.2)

// TenantEvent is a row of tenant_audit_log. The method is unexported so only
// this package defines events.
type TenantEvent interface {
	Action() string
	tenantEvent()
}

// The tenant events. Field names are the keys of the params object.
type (
	LoginOK struct {
		Method    Method    `json:"method"`
		SessionID uuid.UUID `json:"session_id"`
	}
	// LoginFailed is written only when the user exists, bounded by the throttle.
	LoginFailed struct {
		Method Method `json:"method"`
	}
	Logout struct {
		Count int `json:"count"`
	}
	LogoutAll struct {
		Count int `json:"count"`
	}
	SessionRevoke struct {
		SessionID uuid.UUID `json:"session_id"`
	}
	RefreshReuse struct {
		FamilyID uuid.UUID `json:"family_id"`
	}
	ReauthOK struct {
		Method Method `json:"method"`
	}
	ReauthFailed struct {
		Method Method `json:"method"`
	}
	PasswordChange struct{}
	PasswordReset  struct{}
	PhoneChange    struct {
		OldMasked Masked `json:"old_masked"`
		NewMasked Masked `json:"new_masked"`
	}
	TOTPEnable struct {
		Left int `json:"left"`
	}
	TOTPDisable struct {
		Left int `json:"left"`
	}
	RecoveryRegenerate struct {
		Left int `json:"left"`
	}
	RecoveryUsed struct {
		Left int `json:"left"`
	}
	PasskeyAdd struct {
		CredentialRowID uuid.UUID `json:"credential_row_id"`
	}
	PasskeyRename struct {
		CredentialRowID uuid.UUID `json:"credential_row_id"`
	}
	PasskeyDelete struct {
		CredentialRowID uuid.UUID `json:"credential_row_id"`
	}
	PasskeyEnforce struct {
		Enabled bool `json:"enabled"`
	}
	PasskeyReview       struct{}
	PasskeyCloneSuspect struct {
		CredentialRowID uuid.UUID `json:"credential_row_id"`
	}
	Register struct {
		Via Via `json:"via"` // open, invite or admin
	}
	// ProfileLock, ProfileUnlock and ProfileUnlockFailed are the lock of a profile (P2 spec 7): the profile only, never the
	// password. ProfileUnlockFailed is written only for an existing profile of the caller's tenant, bounded by profile_unlock
	// and profile_lock_tenant, as LoginFailed is by its throttle.
	ProfileLock struct {
		ProfileID uuid.UUID `json:"profile_id"`
	}
	ProfileUnlock struct {
		ProfileID uuid.UUID `json:"profile_id"`
	}
	// ProfileLockPasswordUsed and ProfileLockPasswordFailed are a lock password presented in the request of an Endpoint write (P3 spec 3.3):
	// the profile and the Endpoint it was needed on, never the password. Both are bounded by the throttle scopes of the unlock.
	ProfileLockPasswordUsed struct {
		ProfileID  uuid.UUID `json:"profile_id"`
		EndpointID uuid.UUID `json:"endpoint_id"`
	}
	ProfileLockPasswordFailed struct {
		ProfileID  uuid.UUID `json:"profile_id"`
		EndpointID uuid.UUID `json:"endpoint_id"`
	}
	// ShareLinkCreate and ShareLinkRevoke are a share link made or ended (P3 7.2): the link and its Endpoint, never the value.
	ShareLinkCreate struct {
		LinkID     uuid.UUID `json:"link_id"`
		EndpointID uuid.UUID `json:"endpoint_id"`
	}
	ShareLinkRevoke struct {
		LinkID     uuid.UUID `json:"link_id"`
		EndpointID uuid.UUID `json:"endpoint_id"`
	}
	ProfileUnlockFailed struct {
		ProfileID uuid.UUID `json:"profile_id"`
	}
	// TOTPLost is written by ctrlz_fn.keytool_totp_declare_lost, not by Go: the
	// database function writes its own row so a lost-key declaration is never
	// silent (review round 3). The type keeps the vocabulary in one place; its
	// fields are the keys the function puts in params.
	TOTPLost struct {
		KeyNumber int `json:"key_number"`
		Users     int `json:"users"`
	}
)

func (LoginOK) Action() string                   { return "login.ok" }
func (LoginFailed) Action() string               { return "login.failed" }
func (Logout) Action() string                    { return "logout" }
func (LogoutAll) Action() string                 { return "logout.all" }
func (SessionRevoke) Action() string             { return "session.revoke" }
func (RefreshReuse) Action() string              { return "session.refresh_reuse" }
func (ReauthOK) Action() string                  { return "reauth.ok" }
func (ReauthFailed) Action() string              { return "reauth.failed" }
func (PasswordChange) Action() string            { return "password.change" }
func (PasswordReset) Action() string             { return "password.reset" }
func (PhoneChange) Action() string               { return "phone.change" }
func (TOTPEnable) Action() string                { return "totp.enable" }
func (TOTPDisable) Action() string               { return "totp.disable" }
func (RecoveryRegenerate) Action() string        { return "recovery.regenerate" }
func (RecoveryUsed) Action() string              { return "recovery.used" }
func (PasskeyAdd) Action() string                { return "passkey.add" }
func (PasskeyRename) Action() string             { return "passkey.rename" }
func (PasskeyDelete) Action() string             { return "passkey.delete" }
func (PasskeyEnforce) Action() string            { return "passkey.enforce" }
func (PasskeyReview) Action() string             { return "passkey.review" }
func (PasskeyCloneSuspect) Action() string       { return "passkey.clone_suspect" }
func (Register) Action() string                  { return "register" }
func (TOTPLost) Action() string                  { return "totp.declared_lost" }
func (ProfileLock) Action() string               { return "profile.lock" }
func (ProfileUnlock) Action() string             { return "profile.unlock" }
func (ProfileUnlockFailed) Action() string       { return "profile.unlock_failed" }
func (ProfileLockPasswordUsed) Action() string   { return "profile.lock_password_used" }
func (ProfileLockPasswordFailed) Action() string { return "profile.lock_password_failed" }
func (ShareLinkCreate) Action() string           { return "share_link.create" }
func (ShareLinkRevoke) Action() string           { return "share_link.revoke" }

func (LoginOK) tenantEvent()                   {}
func (LoginFailed) tenantEvent()               {}
func (Logout) tenantEvent()                    {}
func (LogoutAll) tenantEvent()                 {}
func (SessionRevoke) tenantEvent()             {}
func (RefreshReuse) tenantEvent()              {}
func (ReauthOK) tenantEvent()                  {}
func (ReauthFailed) tenantEvent()              {}
func (PasswordChange) tenantEvent()            {}
func (PasswordReset) tenantEvent()             {}
func (PhoneChange) tenantEvent()               {}
func (TOTPEnable) tenantEvent()                {}
func (TOTPDisable) tenantEvent()               {}
func (RecoveryRegenerate) tenantEvent()        {}
func (RecoveryUsed) tenantEvent()              {}
func (PasskeyAdd) tenantEvent()                {}
func (PasskeyRename) tenantEvent()             {}
func (PasskeyDelete) tenantEvent()             {}
func (PasskeyEnforce) tenantEvent()            {}
func (PasskeyReview) tenantEvent()             {}
func (PasskeyCloneSuspect) tenantEvent()       {}
func (Register) tenantEvent()                  {}
func (TOTPLost) tenantEvent()                  {}
func (ProfileLock) tenantEvent()               {}
func (ProfileUnlock) tenantEvent()             {}
func (ProfileUnlockFailed) tenantEvent()       {}
func (ProfileLockPasswordUsed) tenantEvent()   {}
func (ProfileLockPasswordFailed) tenantEvent() {}
func (ShareLinkCreate) tenantEvent()           {}
func (ShareLinkRevoke) tenantEvent()           {}

// Tenant writes the event into the transaction of the change it records, so a
// change without its audit row cannot commit (13.1). user is the actor, the nil
// uuid for none (a registration has no user yet in the caller's hands).
func Tenant(tx store.Tx, user uuid.UUID, ip netip.Addr, ev TenantEvent) error {
	params, err := marshalParams(ev)
	if err != nil {
		return err
	}
	return tx.AuditAdd(store.TenantAudit{UserID: user, Action: ev.Action(), Params: params, IP: ip.WithZone("")})
}

func marshalParams(ev any) ([]byte, error) { return closed.Marshal(ev) }

// ---------------------------------------------------------------------------
// Admin events (13.2)

// AdminEvent is a row of audit_log.
type AdminEvent interface {
	Action() string
	// Target is "kind:id" or "" for none.
	Target() string
	adminEvent()
}

// The admin events. The id a row is about goes in the target, not in the params.
type (
	// AdminBootstrap, AdminPasswordResetCLI, AdminTOTPResetCLI and AdminUnlockCLI
	// are written by the CLI, which has no session: via says how it ran.
	AdminBootstrap struct {
		Admin uuid.UUID `json:"-"`
		Via   Via       `json:"via"`
	}
	AdminPasswordResetCLI struct {
		Admin uuid.UUID `json:"-"`
		Via   Via       `json:"via"`
	}
	AdminTOTPResetCLI struct {
		Admin uuid.UUID `json:"-"`
		Via   Via       `json:"via"`
	}
	// AdminUnlockCLI says which store the unlock cleared. The row is written even when one store could
	// not be cleared, because the command changes state scope by scope (round 7, admin-r7-3 and -7).
	AdminUnlockCLI struct {
		Admin           uuid.UUID `json:"-"`
		Via             Via       `json:"via"`
		DatabaseCleared bool      `json:"database_cleared"`
		ValkeyCleared   bool      `json:"valkey_cleared"`
	}

	AdminLogin struct {
		Admin uuid.UUID `json:"-"`
	}
	AdminLogout struct {
		Admin uuid.UUID `json:"-"`
	}
	// AdminLoginFailed has no admin id when the username is unknown, and never
	// the username: a password typed into the username box is a classic leak.
	AdminLoginFailed struct {
		Admin uuid.UUID `json:"-"`
	}
	AdminPasswordChange struct {
		Admin uuid.UUID `json:"-"`
	}
	AdminTOTPEnroll struct {
		Admin uuid.UUID `json:"-"`
	}
	AdminTOTPFresh struct {
		Admin uuid.UUID `json:"-"`
	}
	// AdminNoticesAck is written when an admin acknowledges the banner. It records
	// how many notices the session was allowed to clear and how many it was not
	// (those made during the session), never their content.
	AdminNoticesAck struct {
		Admin   uuid.UUID `json:"-"`
		Cleared int       `json:"cleared"`
		Kept    int       `json:"kept"`
	}

	UserCreate struct {
		Tenant uuid.UUID `json:"-"`
	}
	// UserPasswordReissue is written only on success (10.7). It records neither
	// the password nor its expiry.
	UserPasswordReissue struct {
		Tenant          uuid.UUID `json:"-"`
		UserID          uuid.UUID `json:"user_id"`
		WasExpired      bool      `json:"was_expired"`
		RevokedSessions int       `json:"revoked_sessions"`
	}

	InviteCreate struct {
		Invite   uuid.UUID `json:"-"`
		SendSMS  bool      `json:"send_sms"`
		TTLHours int       `json:"ttl_hours"`
	}
	InviteRevoke struct {
		Invite uuid.UUID `json:"-"`
	}

	RegistrationModeChange struct {
		From            RegMode `json:"from"`
		To              RegMode `json:"to"`
		Graced          int     `json:"graced"`
		SuspendedAtOnce int     `json:"suspended_at_once"`
		GraceDays       int     `json:"grace_days"`
	}
	// The switch is recorded beside the RP ID (admin-r12-3): turning passkeys off drops every user with
	// enforce_passkey to a password or an SMS code at once, and a row that held the RP ID alone was the
	// same row as a harmless re-save.
	WebauthnConfigChange struct {
		FromRP      Host `json:"from_rp"`
		ToRP        Host `json:"to_rp"`
		FromEnabled bool `json:"from_enabled"`
		ToEnabled   bool `json:"to_enabled"`
		Credentials int  `json:"credentials"`
		Users       int  `json:"users"`
	}

	// The SMS events record the names of the fields that changed, never values.
	SMSGatewayChange struct {
		Gateway uuid.UUID `json:"-"`
		Fields  []Field   `json:"fields"`
	}
	SMSRoutingChange struct {
		Gateway uuid.UUID `json:"-"`
		Fields  []Field   `json:"fields"`
	}
	SMSTemplateChange struct {
		Gateway uuid.UUID `json:"-"`
		Fields  []Field   `json:"fields"`
		// Key and Locale name the template; a mapping change has a gateway as well.
		Key    sms.TemplateKey `json:"key"`
		Locale sms.Locale      `json:"locale"`
	}
	SMSLimitsChange struct {
		Gateway uuid.UUID `json:"-"`
		Fields  []Field   `json:"fields"`
	}
	SMSTestSend struct {
		Gateway uuid.UUID `json:"-"`
		Fields  []Field   `json:"fields"`
	}

	KeyRotated struct {
		Domain    KeyDomain `json:"-"`
		KeyNumber int       `json:"key_number"`
	}
	KeyDeclaredLost struct {
		Domain    KeyDomain `json:"-"`
		KeyNumber int       `json:"key_number"`
	}
	// KeyRekeyed is `ctrlz-admin rekey` for a domain the admin container holds: how many stored values
	// were sealed again under the newest key. It is written in the transaction of the rewrite whenever
	// the rewrite changed a value, whatever the other values did (a value that could not be opened
	// still ends the command with exit 1 after the rest were committed), so a change of stored
	// ciphertext has a row (round 9, admin-r9-5, rule console-state-change-is-audited). Counts only.
	KeyRekeyed struct {
		Domain    KeyDomain `json:"-"`
		KeyNumber int       `json:"key_number"`
		Rewritten int       `json:"rewritten"`
		Changed   int       `json:"changed"`
		Failed    int       `json:"failed"`
	}

	AlertAck struct {
		Alert uuid.UUID `json:"-"`
		Kind  AlertKind `json:"kind"`
	}
)

func (AdminBootstrap) Action() string         { return "admin.bootstrap" }
func (AdminPasswordResetCLI) Action() string  { return "admin.password_reset_cli" }
func (AdminTOTPResetCLI) Action() string      { return "admin.totp_reset_cli" }
func (AdminUnlockCLI) Action() string         { return "admin.unlock_cli" }
func (AdminLogin) Action() string             { return "admin.login" }
func (AdminLogout) Action() string            { return "admin.logout" }
func (AdminLoginFailed) Action() string       { return "admin.login_failed" }
func (AdminPasswordChange) Action() string    { return "admin.password_change" }
func (AdminTOTPEnroll) Action() string        { return "admin.totp_enroll" }
func (AdminTOTPFresh) Action() string         { return "admin.totp_fresh" }
func (AdminNoticesAck) Action() string        { return "admin.notices_ack" }
func (UserCreate) Action() string             { return "user.create" }
func (UserPasswordReissue) Action() string    { return "user.password_reissue" }
func (InviteCreate) Action() string           { return "invite.create" }
func (InviteRevoke) Action() string           { return "invite.revoke" }
func (RegistrationModeChange) Action() string { return "registration.mode_change" }
func (WebauthnConfigChange) Action() string   { return "webauthn.config_change" }
func (SMSGatewayChange) Action() string       { return "sms.gateway_change" }
func (SMSRoutingChange) Action() string       { return "sms.routing_change" }
func (SMSTemplateChange) Action() string      { return "sms.template_change" }
func (SMSLimitsChange) Action() string        { return "sms.limits_change" }
func (SMSTestSend) Action() string            { return "sms.test_send" }
func (KeyRotated) Action() string             { return "key.rotated" }
func (KeyDeclaredLost) Action() string        { return "key.declared_lost" }
func (KeyRekeyed) Action() string             { return "key.rekeyed" }
func (AlertAck) Action() string               { return "alert.ack" }

func adminTarget(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return "admin:" + id.String()
}
func idTarget(kind string, id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return kind + ":" + id.String()
}

func (e AdminBootstrap) Target() string        { return adminTarget(e.Admin) }
func (e AdminPasswordResetCLI) Target() string { return adminTarget(e.Admin) }
func (e AdminTOTPResetCLI) Target() string     { return adminTarget(e.Admin) }
func (e AdminUnlockCLI) Target() string        { return adminTarget(e.Admin) }
func (e AdminLogin) Target() string            { return adminTarget(e.Admin) }
func (e AdminLogout) Target() string           { return adminTarget(e.Admin) }
func (e AdminLoginFailed) Target() string      { return adminTarget(e.Admin) }
func (e AdminPasswordChange) Target() string   { return adminTarget(e.Admin) }
func (e AdminTOTPEnroll) Target() string       { return adminTarget(e.Admin) }
func (e AdminTOTPFresh) Target() string        { return adminTarget(e.Admin) }
func (e AdminNoticesAck) Target() string       { return adminTarget(e.Admin) }
func (e UserCreate) Target() string            { return idTarget("tenant", e.Tenant) }
func (e UserPasswordReissue) Target() string   { return idTarget("tenant", e.Tenant) }
func (e InviteCreate) Target() string          { return idTarget("invite", e.Invite) }
func (e InviteRevoke) Target() string          { return idTarget("invite", e.Invite) }
func (RegistrationModeChange) Target() string  { return "system_settings" }
func (WebauthnConfigChange) Target() string    { return "webauthn_config" }
func (e SMSGatewayChange) Target() string      { return idTarget("gateway", e.Gateway) }
func (e SMSRoutingChange) Target() string      { return idTarget("gateway", e.Gateway) }
func (e SMSTemplateChange) Target() string     { return idTarget("gateway", e.Gateway) }
func (e SMSLimitsChange) Target() string       { return idTarget("gateway", e.Gateway) }
func (e SMSTestSend) Target() string           { return idTarget("gateway", e.Gateway) }
func (e KeyRotated) Target() string            { return "domain:" + string(e.Domain) }
func (e KeyDeclaredLost) Target() string       { return "domain:" + string(e.Domain) }
func (e KeyRekeyed) Target() string            { return "domain:" + string(e.Domain) }
func (e AlertAck) Target() string              { return idTarget("alert", e.Alert) }

func (AdminBootstrap) adminEvent()         {}
func (AdminPasswordResetCLI) adminEvent()  {}
func (AdminTOTPResetCLI) adminEvent()      {}
func (AdminUnlockCLI) adminEvent()         {}
func (AdminLogin) adminEvent()             {}
func (AdminLogout) adminEvent()            {}
func (AdminLoginFailed) adminEvent()       {}
func (AdminPasswordChange) adminEvent()    {}
func (AdminTOTPEnroll) adminEvent()        {}
func (AdminTOTPFresh) adminEvent()         {}
func (AdminNoticesAck) adminEvent()        {}
func (UserCreate) adminEvent()             {}
func (UserPasswordReissue) adminEvent()    {}
func (InviteCreate) adminEvent()           {}
func (InviteRevoke) adminEvent()           {}
func (RegistrationModeChange) adminEvent() {}
func (WebauthnConfigChange) adminEvent()   {}
func (SMSGatewayChange) adminEvent()       {}
func (SMSRoutingChange) adminEvent()       {}
func (SMSTemplateChange) adminEvent()      {}
func (SMSLimitsChange) adminEvent()        {}
func (SMSTestSend) adminEvent()            {}
func (KeyRotated) adminEvent()             {}
func (KeyDeclaredLost) adminEvent()        {}
func (KeyRekeyed) adminEvent()             {}
func (AlertAck) adminEvent()               {}

// Sink is where an admin entry goes: the chained writer of the store, which runs
// in a global transaction or inside WithTenant (10.7). Both take the advisory
// lock, so the chain has one order.
type Sink interface {
	AuditAppend(store.AuditEntry) (int64, error)
}

type tenantSink struct{ tx store.Tx }

func (s tenantSink) AuditAppend(e store.AuditEntry) (int64, error) { return s.tx.AdminAuditAppend(e) }

// OnTenant adapts a tenant transaction as the sink of an admin entry.
func OnTenant(tx store.Tx) Sink { return tenantSink{tx} }

// Admin appends an admin event to the chain. at is the Go clock, set here and
// inserted explicitly, because the hash covers it and the database must not pick
// another time (13.1). admin is the actor, the nil uuid for the CLI.
func Admin(sink Sink, at time.Time, admin uuid.UUID, ip netip.Addr, ev AdminEvent) (int64, error) {
	params, err := marshalParams(ev)
	if err != nil {
		return 0, err
	}
	// The inet column keeps no zone, so a zoned address would hash differently
	// when verify reads it back (round 2, primitives-r2-3).
	ip = ip.WithZone("").Unmap()
	at = at.UTC().Truncate(time.Microsecond)
	canon, err := Canonical(at, admin, ev.Action(), ev.Target(), params, ip)
	if err != nil {
		return 0, err
	}
	return sink.AuditAppend(store.AuditEntry{
		At: at, AdminID: admin, Action: ev.Action(), Target: ev.Target(), Params: params, IP: ip, Canonical: canon,
	})
}
