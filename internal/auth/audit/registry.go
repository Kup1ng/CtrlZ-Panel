package audit

// The registry of every event type. It is the one list that tooling reflects over:
// the closed-values test walks it, and internal/lint TestSpecFactTables compares
// it with the tables of spec 13.2 in both directions (P1 auth review, rule
// spec-fact-drift), so an event or a params field added here without the spec
// changing fails the build.
//
// The values are zero values, for their types only: reflection reads the field
// names and json tags, and Action and Target do not look at the fields beyond the
// id a test fills in. TestEventRegistryIsComplete parses the package, so an event
// type that carries a marker but is not listed here fails.

// TenantEvents lists a zero value of every tenant event.
func TenantEvents() []TenantEvent {
	return []TenantEvent{
		LoginOK{}, LoginFailed{}, Logout{}, LogoutAll{}, SessionRevoke{}, RefreshReuse{},
		ReauthOK{}, ReauthFailed{}, PasswordChange{}, PasswordReset{}, PhoneChange{},
		TOTPEnable{}, TOTPDisable{}, RecoveryRegenerate{}, RecoveryUsed{},
		PasskeyAdd{}, PasskeyRename{}, PasskeyDelete{}, PasskeyEnforce{}, PasskeyReview{}, PasskeyCloneSuspect{},
		Register{}, TOTPLost{},
		ProfileLock{}, ProfileUnlock{}, ProfileUnlockFailed{}, ProfileLockPasswordUsed{}, ProfileLockPasswordFailed{},
	}
}

// AdminEvents lists a zero value of every admin event.
func AdminEvents() []AdminEvent {
	return []AdminEvent{
		AdminBootstrap{}, AdminPasswordResetCLI{}, AdminTOTPResetCLI{}, AdminUnlockCLI{},
		AdminLogin{}, AdminLogout{}, AdminLoginFailed{}, AdminPasswordChange{}, AdminTOTPEnroll{}, AdminTOTPFresh{},
		AdminNoticesAck{}, UserCreate{}, UserPasswordReissue{}, InviteCreate{}, InviteRevoke{},
		RegistrationModeChange{}, WebauthnConfigChange{},
		SMSGatewayChange{}, SMSRoutingChange{}, SMSTemplateChange{}, SMSLimitsChange{}, SMSTestSend{},
		KeyRotated{}, KeyDeclaredLost{}, KeyRekeyed{}, AlertAck{},
	}
}
