package keyring

import (
	"fmt"
	"time"
)

// This file is the one registry of what each domain key is used for beyond a
// column that can be re-encrypted: which label tags what, how long a value made
// under it stays in use, and what the operator loses by removing the old key line
// too early (spec 8.1, 8.2, 8.4).
//
// Why a registry. The lifetimes were copied by hand into the spec (three places),
// into the operator text of `ctrlz-admin keys status` and `rekey`, and into the
// constants of the packages that set the cookies and sessions, and each review
// round found one copy stale (P1 auth review, rule spec-fact-drift). Now the
// packages take their lifetime from the constants below, the operator text is
// rendered from Uses, and internal/lint TestSpecFactTables compares the marked
// table of spec 8.2 with Uses in both directions.

// The lifetimes. Each is the longest a value tagged or sealed under the label stays
// in use, so it is also how long an old key line has to stay in the key file.
// session, otp and ticket take these as their own constants.
const (
	// LifeOTP is the life of an OTP challenge, and of the delivery text sealed for it.
	LifeOTP = 5 * time.Minute
	// LifeThrottle is the longest throttle window, the long ceiling of the second-factor scopes included
	// (round 9, primitives-r9-2: it was the 15 minute and hour windows only, and the operator text understated the
	// longest count by a factor of 24). The budget registry holds the windows and
	// internal/lint TestThrottleLifeCoversEveryWindow checks both kinds.
	LifeThrottle = 24 * time.Hour
	// LifeDevice is the known-device marker of a user's browser (3.2, 5.5).
	LifeDevice = 365 * 24 * time.Hour
	// LifeAdminDevice is the admin marker. Shorter: it is for one person who signs in often.
	LifeAdminDevice = 90 * 24 * time.Hour
	// LifeUserSession is the absolute life of a Remember me session (3.3).
	LifeUserSession = 90 * 24 * time.Hour
	// LifeAdminSession is the absolute life of an admin session (3.3).
	LifeAdminSession = 8 * time.Hour
	// LifeCeremony is the life of a ticket, stateless ones included (7.5).
	LifeCeremony = 5 * time.Minute
	// LifeInvite is the longest life of an invite link and so the longest the admin may set (D67). A link
	// stays good until its expiry, so it is also how long the old line of invite_sign has to stay in the file.
	LifeInvite = 30 * 24 * time.Hour
	// LifeRefresh is the life of one refresh token (3.3). The proof tag inside it lives as long.
	LifeRefresh = 30 * 24 * time.Hour
)

// throttleRemoved is what removing the old line of a key costs a throttle row, and it is nothing: Ring.MAC always
// uses the newest key and nothing verifies a throttle key under an old line, so the counters restarted when the
// key was rotated (the containers were recreated with the new line first), and the long ceilings of the
// second-factor scopes refilled then. The text used to say "the counters restart from zero" and put the
// restart at the removal (round 9, primitives-r9-2).
const throttleRemoved = "nothing: counters are made under the newest key only, so they restarted at the rotation, and the long ceilings refilled then"

// otpRotated is what a key rotation costs an OTP code hash (round 26, primitives-r26-2). Ring.MAC always uses the
// newest key and the database compares the stored hash with the one made now, so a code sent before the
// containers were recreated no longer matches, whether or not the old line is still in the ring. Throttle rows
// are the same case (throttleRemoved).
const otpRotated = "a live code stops matching when the containers are recreated with the new line, not at the removal: a hash is made and checked under the newest key only, so the user asks for a new code"

// Use is one use of a domain key whose values outlive a restart or sit outside the
// database: a tag on a cookie, a window of rows, a short-lived sealed row.
type Use struct {
	Domain string
	// Label is the HKDF label of the subkey, or "" for a sealed column of the domain
	// that carries none.
	Label string
	// What names the tagged or sealed values, in the words the operator text uses.
	What string
	// Life is how long such a value stays in use.
	Life time.Duration
	// IfRemoved is what happens to a value when the key line it was made under is
	// removed from the ring before it has expired.
	IfRemoved string
}

// Uses lists every use, in the order the spec table and the operator text show them:
// by domain as Domains orders them, longest life first inside a domain.
func Uses() []Use {
	return []Use{
		{DomainOTPDelivery, "", "OTP delivery texts", LifeOTP,
			"the text cannot be opened, so the code is not sent and the user asks again"},
		{DomainAuthMAC, LabelDevice, "known-device markers", LifeDevice,
			"the browser counts as a new device until the user signs in once more"},
		{DomainAuthMAC, LabelSession, "session tags", LifeUserSession,
			"the session ends and its user signs in again"},
		{DomainAuthMAC, LabelProof, "ticket, OTP challenge and refresh token tags", LifeRefresh,
			"a login or reset step in progress starts again, and a Remember me browser signs in again"},
		{DomainAuthMAC, LabelThrottle, "throttle rows", LifeThrottle, throttleRemoved},
		{DomainAuthMAC, LabelOTP, "OTP code hashes", LifeOTP,
			otpRotated},
		{DomainAuthMAC, LabelCeremony, "passkey login tickets", LifeCeremony,
			"a passkey login in progress starts again"},
		{DomainAdminMAC, LabelAdminDevice, "admin device markers", LifeAdminDevice,
			"the admin counts on admin_login_user like a stranger until the next sign-in, and a stranger who spends that scope in the meantime needs `ctrlz-admin unlock`"},
		{DomainAdminMAC, LabelThrottle, "throttle rows", LifeThrottle, throttleRemoved},
		{DomainAdminMAC, LabelSession, "session tags", LifeAdminSession,
			"the session ends and its admin signs in again"},
		{DomainInviteSign, LabelInviteLink, "invite links", LifeInvite,
			"the link no longer opens and the admin makes a new one"},
	}
}

// UsesOf is Uses for one domain, longest life first (the order of Uses already is).
func UsesOf(domain string) []Use {
	var out []Use
	for _, u := range Uses() {
		if u.Domain == domain {
			out = append(out, u)
		}
	}
	return out
}

// LongestLife is the longest life of a use of the domain, zero for none.
func LongestLife(domain string) time.Duration {
	var d time.Duration
	for _, u := range UsesOf(domain) {
		d = max(d, u.Life)
	}
	return d
}

// LifeText writes a life in the unit the spec uses: minutes below an hour, hours below
// a day, days beyond. It is exact (a life that is not a whole number of its unit is
// written in the next smaller one), so the text can be compared, never rounded.
func LifeText(d time.Duration) string {
	unit := func(n int64, one, many string) string {
		if n == 1 {
			return fmt.Sprintf("1 %s", one)
		}
		return fmt.Sprintf("%d %s", n, many)
	}
	switch {
	case d%(24*time.Hour) == 0:
		return unit(int64(d/(24*time.Hour)), "day", "days")
	case d%time.Hour == 0:
		return unit(int64(d/time.Hour), "hour", "hours")
	case d%time.Minute == 0:
		return unit(int64(d/time.Minute), "minute", "minutes")
	}
	return unit(int64(d/time.Second), "second", "seconds")
}

// LabelNames lists the labels the Label constants define, for the test that keeps
// Uses complete. The labels are code, not data.
func LabelNames() []string {
	return []string{LabelOTP, LabelThrottle, LabelDevice, LabelAdminDevice, LabelSession, LabelCeremony, LabelProof, LabelInviteLink}
}

// Primitive is the one primitive a label's subkey may key.
type Primitive int

const (
	// MACOnly labels key HMAC-SHA256 (Ring.MAC, VerifyMAC) and nothing else.
	MACOnly Primitive = iota + 1
	// SealOnly labels key AES-256-GCM (Ring.SealLabeled, OpenLabeled) and nothing else.
	SealOnly
	// SignOnly labels seed Ed25519 (Ring.Sign) and nothing else.
	SignOnly
)

// PrimitiveOf is the registered primitive of a label. A label is a subkey,
// HKDF-Expand(key, label), so a label that keyed both an HMAC and an AES-GCM in one
// domain would feed the same 32 bytes to two primitives and break domain separation with
// no test or error to show it (primitives-r5-5). Each label is registered here with its
// one primitive; MAC, VerifyMAC, SealLabeled and OpenLabeled refuse a label registered for
// the other, and refuse a label that is not registered at all, so a new label is a line in
// this file and a reviewed choice. A label here is as exclusive as Uses lists it: the test
// TestEveryLabelHasOnePrimitive keeps the two lists in step.
func PrimitiveOf(label string) (Primitive, bool) {
	switch label {
	case LabelOTP, LabelThrottle, LabelSession, LabelCeremony, LabelProof:
		return MACOnly, true
	case LabelDevice, LabelAdminDevice:
		return SealOnly, true
	case LabelInviteLink:
		return SignOnly, true
	}
	return 0, false
}

// labelFor reports whether label may key the primitive p.
func labelFor(label string, p Primitive) bool {
	got, ok := PrimitiveOf(label)
	return ok && got == p
}

// Mode is what a domain key is used as. The label registry above gives each label one primitive,
// but the domain key itself had no such rule (review round 6, primitives-r6-8): it is the AES-256-GCM
// key of an unlabeled Seal and also the HKDF-Expand PRK of every labelled subkey, and nothing
// refused a Seal under auth_mac or a MAC under user_totp, which would key two primitives with the
// same 32 bytes. Each domain has one mode, and every operation checks it.
type Mode int

const (
	// ModeSealed domains key AES-256-GCM directly: only the unlabeled Seal and Open apply. These are
	// the sealed columns (user_totp, admin_totp, sms_cred, otp_delivery) and the reserved doh_token
	// and cert_wrap.
	ModeSealed Mode = iota + 1
	// ModeLabeled domains are only the root of labelled subkeys (HKDF-Expand): only MAC, VerifyMAC,
	// SealLabeled and OpenLabeled apply, each with a label registered for its primitive.
	ModeLabeled
	// ModeSigning domains are the root of one Ed25519 seed (D67): only Ring.Sign applies, under the one
	// label Uses lists. The public half is derived for the process that only verifies (public.go).
	ModeSigning
)

// ModeOf is the registered mode of a domain. A new domain is a line here and a reviewed choice;
// TestEveryDomainHasOneMode keeps this list and Domains in step.
func ModeOf(domain string) (Mode, bool) {
	switch domain {
	case DomainUserTOTP, DomainAdminTOTP, DomainSMSCred, DomainOTPDelivery, DomainDOHToken, DomainCertWrap:
		return ModeSealed, true
	case DomainAuthMAC, DomainAdminMAC:
		return ModeLabeled, true
	case DomainInviteSign:
		return ModeSigning, true
	}
	return 0, false
}

// SigningLabel is the one label of a signing domain, the one its Ed25519 seed is derived under.
func SigningLabel(domain string) (string, bool) {
	if !modeFor(domain, ModeSigning) {
		return "", false
	}
	for _, u := range Uses() {
		if u.Domain == domain {
			return u.Label, true
		}
	}
	return "", false
}

// modeFor reports whether domain is registered with mode m.
func modeFor(domain string, m Mode) bool {
	got, ok := ModeOf(domain)
	return ok && got == m
}

// modeAllowsLabel is the registry check every operation makes before it touches a key: an
// unlabeled operation needs a sealed domain, a labelled one a labeled domain AND a (domain, label)
// pair that Uses lists. The pair is the third half of the one-primitive rule (primitives-r7-3): two
// labels registered for the same primitive still share one HKDF subkey inside a domain, so a value
// minted under LabelAdminDevice in auth_mac, or LabelCeremony in admin_mac, would verify as the
// other use of that subkey and defeat the separation the labels exist for. A use that is not a
// line of Uses has no lifetime and no operator text either, so refusing it here keeps those two
// honest as well.
func modeAllowsLabel(domain, label string) bool {
	if label == "" {
		return modeFor(domain, ModeSealed)
	}
	return modeFor(domain, ModeLabeled) && pairListed(domain, label)
}

// pairListed reports whether Uses names the label under the domain.
func pairListed(domain, label string) bool {
	for _, u := range Uses() {
		if u.Domain == domain && u.Label == label {
			return true
		}
	}
	return false
}

// PairListed is pairListed for the lint that compares the constant arguments of every call site
// with the registry.
func PairListed(domain, label string) bool { return pairListed(domain, label) }
