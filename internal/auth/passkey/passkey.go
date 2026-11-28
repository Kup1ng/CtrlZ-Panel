// Package passkey is the thin wrapper over go-webauthn that spec 7 asks for:
// the relying party configuration read from the database and rebuilt when it
// changes (7.2), the user adapter (7.3), and Begin/Finish helpers that take and
// give plain bytes, so the routes never touch the library's types and the
// ceremony state can travel in a ticket payload.
//
// What this package decides, once:
//
//   - Attestation is "none" and the library's metadata provider (MDS) stays nil,
//     so nothing here, or in the library on this path, opens a network
//     connection (7.1). A test dials nothing and runs a full ceremony.
//   - User verification is required, so the library itself refuses an assertion
//     without the UV flag. Passkey login skips TOTP because of that (T-106).
//   - Every failure of a Finish is ErrInvalid. The library's own errors carry
//     detail about what failed; a client must not learn which check it was.
//
// Nothing in this package reads the database. The routes load credentials and
// pass them in.
package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/phone"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Errors. The routes map ErrDisabled to 404 passkey_unavailable and ErrInvalid
// to 401 passkey_invalid.
var (
	// ErrDisabled means Passkey is switched off or has no RP ID yet (7.2).
	ErrDisabled = errors.New("passkey: not enabled")
	// ErrInvalid is any failure of a ceremony. It never says which check failed.
	ErrInvalid = errors.New("passkey: invalid")
)

// CeremonyLife bounds a ceremony: the library refuses session data older than
// this, in step with the 5 minute ticket that carries it.
const CeremonyLife = 5 * time.Minute

// Instance is the relying party at one moment.
type Instance struct {
	wa *webauthn.WebAuthn
	// RPID is the current relying party id. A credential counts as live only
	// while its rp_id equals it (5.7).
	RPID string
}

// Provider builds the relying party from the public configuration and keeps it
// until the configuration changes. The configuration itself is cached for 30
// seconds by the caller, so this adds no database load.
type Provider struct {
	config func(context.Context) (store.PublicConfig, error)

	mu   sync.Mutex
	sig  string
	inst Instance
}

// NewProvider returns a Provider over a configuration source.
func NewProvider(config func(context.Context) (store.PublicConfig, error)) *Provider {
	return &Provider{config: config}
}

// Get returns the relying party, or ErrDisabled when Passkey is off.
func (p *Provider) Get(ctx context.Context) (Instance, error) {
	c, err := p.config(ctx)
	if err != nil {
		return Instance{}, err
	}
	if !c.PasskeyEnabled || c.RPID == "" || len(c.AllowedOrigins) == 0 {
		return Instance{}, ErrDisabled
	}
	sig := c.RPID + "\x00" + strings.Join(c.AllowedOrigins, "\x00")
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sig == sig && p.inst.wa != nil {
		return p.inst, nil
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID: c.RPID, RPDisplayName: "Ctrl Z", RPOrigins: c.AllowedOrigins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
		// Enforce makes the library refuse session data past its life, in addition
		// to the ticket's own expiry.
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: CeremonyLife, TimeoutUVD: CeremonyLife},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: CeremonyLife, TimeoutUVD: CeremonyLife},
		},
	})
	if err != nil {
		// A configuration the library rejects (an RP ID it cannot use) is an
		// admin error, not the user's: Passkey is unavailable until it is fixed.
		return Instance{}, ErrDisabled
	}
	p.sig, p.inst = sig, Instance{wa: wa, RPID: c.RPID}
	return p.inst, nil
}

// User adapts an account to the library (7.3). The id is the 16 bytes of users.id,
// which is opaque and holds no phone; the name is the masked number, so the
// authenticator's stored label does not carry the full number.
type User struct {
	id    uuid.UUID
	name  string
	creds []webauthn.Credential
}

// NewUser builds the adapter from the credentials that are live for the current
// RP ID (see Live). phoneE164 may be empty when only the id matters.
func NewUser(id uuid.UUID, phoneE164 string, live []store.Credential) *User {
	u := &User{id: id, name: "Ctrl Z"}
	if phoneE164 != "" {
		u.name = phone.Mask(phoneE164)
	}
	for _, c := range live {
		u.creds = append(u.creds, toCredential(c))
	}
	return u
}

// WebAuthnID is the user handle: the 16 bytes of the user id.
func (u *User) WebAuthnID() []byte { return u.id[:] }

// WebAuthnName is the masked phone number.
func (u *User) WebAuthnName() string { return u.name }

// WebAuthnDisplayName is fixed.
func (u *User) WebAuthnDisplayName() string { return "Ctrl Z" }

// WebAuthnCredentials are the user's live credentials.
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// Live keeps the credentials that work against rpID: not stale, and registered
// for the current relying party (5.7).
func Live(all []store.Credential, rpID string) []store.Credential {
	var out []store.Credential
	for _, c := range all {
		if c.StaleAt == nil && c.RPID == rpID {
			out = append(out, c)
		}
	}
	return out
}

func toCredential(c store.Credential) webauthn.Credential {
	var aaguid []byte
	if c.AAGUID != nil {
		aaguid = c.AAGUID[:]
	}
	tr := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
	for _, t := range c.Transports {
		tr = append(tr, protocol.AuthenticatorTransport(t))
	}
	return webauthn.Credential{
		ID: c.CredentialID, PublicKey: c.PublicKey, AttestationType: c.AttestationType, Transport: tr,
		// Registration required user verification, so every stored credential
		// was created with UP and UV set.
		Flags: webauthn.CredentialFlags{
			UserPresent: true, UserVerified: true, BackupEligible: c.BackupEligible, BackupState: c.BackupState,
		},
		Authenticator: webauthn.Authenticator{AAGUID: aaguid, SignCount: uint32(max(c.SignCount, 0))},
	}
}

// FromInfo is the user a discoverable login resolved: one credential, with the
// flags the library compares on every assertion.
func FromInfo(credentialID []byte, i store.PasskeyInfo) *User {
	return NewUser(i.UserID, "", []store.Credential{{
		CredentialID: credentialID, PublicKey: i.PublicKey, SignCount: i.SignCount, Transports: i.Transports,
		AAGUID: i.AAGUID, BackupEligible: i.BackupEligible, BackupState: i.BackupState,
	}})
}

// Begin is the first half of a ceremony: the options for the browser and the
// session data to keep in a ticket.
type Begin struct {
	Options json.RawMessage
	Session []byte
}

func descriptors(creds []webauthn.Credential) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(creds))
	for _, c := range creds {
		out = append(out, c.Descriptor())
	}
	return out
}

func pack(options any, sd *webauthn.SessionData) (Begin, error) {
	o, err := json.Marshal(options)
	if err != nil {
		return Begin{}, err
	}
	s, err := json.Marshal(sd)
	if err != nil {
		return Begin{}, err
	}
	return Begin{Options: o, Session: s}, nil
}

// BeginRegistration starts adding a passkey; the user's live credentials are
// excluded so one authenticator is not registered twice.
func (i Instance) BeginRegistration(u *User) (Begin, error) {
	c, sd, err := i.wa.BeginRegistration(u, webauthn.WithExclusions(descriptors(u.creds)))
	if err != nil {
		return Begin{}, ErrInvalid
	}
	return pack(c, sd)
}

// BeginLogin starts an assertion for a known user (7.6): allowCredentials holds
// that user's credentials only.
func (i Instance) BeginLogin(u *User) (Begin, error) {
	if len(u.creds) == 0 {
		return Begin{}, ErrInvalid
	}
	a, sd, err := i.wa.BeginLogin(u)
	if err != nil {
		return Begin{}, ErrInvalid
	}
	// The list stays in the options the browser gets, but not in the session
	// that goes into a ticket: it grew with the number and the length of the
	// credential ids (up to 1023 bytes each), and past 4096 bytes the ticket
	// insert failed and passkey reauth and reset became a 500 (review round 3,
	// tenant-r3-7). Nothing is lost: the library still checks that the asserted
	// id is one of the user's live credentials, which is the list we would have
	// compared it with.
	sd.AllowedCredentialIDs = nil
	return pack(a, sd)
}

// BeginDiscoverable starts a login that does not know the user yet (7.5).
func (i Instance) BeginDiscoverable() (Begin, error) {
	a, sd, err := i.wa.BeginDiscoverableLogin()
	if err != nil {
		return Begin{}, ErrInvalid
	}
	return pack(a, sd)
}

func session(b []byte) (webauthn.SessionData, error) {
	var sd webauthn.SessionData
	if err := json.Unmarshal(b, &sd); err != nil {
		return sd, ErrInvalid
	}
	return sd, nil
}

// Registered is a credential the library accepted, ready to store.
type Registered struct {
	store.Credential
}

// FinishRegistration validates the browser's attestation body.
func (i Instance) FinishRegistration(u *User, sessionJSON, body []byte) (Registered, error) {
	sd, err := session(sessionJSON)
	if err != nil {
		return Registered{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return Registered{}, ErrInvalid
	}
	c, err := i.wa.CreateCredential(u, sd, parsed)
	if err != nil {
		return Registered{}, ErrInvalid
	}
	r := Registered{Credential: store.Credential{
		CredentialID: c.ID, PublicKey: c.PublicKey, SignCount: int64(c.Authenticator.SignCount), Transports: cleanTransports(c.Transport),
		RPID: i.RPID, AttestationType: c.AttestationType,
		BackupEligible: c.Flags.BackupEligible, BackupState: c.Flags.BackupState,
	}}
	if id, err := uuid.FromBytes(c.Authenticator.AAGUID); err == nil && id != uuid.Nil {
		r.AAGUID = &id
	}
	return r, nil
}

// maxTransports bounds the stored list. There are six defined values, so more
// than a handful can only be repeats.
const maxTransports = 8

// cleanTransports keeps the transports the specification defines. The browser
// reports them next to the attestation, outside what the authenticator signs, and
// the library copies any string through. The request is bounded before it gets here
// (WebAuthnResponse in api/openapi.yaml: at most 16 transports, each a short
// lower-case word, so no NUL, no control or format character, no list of thousands;
// rule boundary-input), which is what keeps the insert from failing with a 500
// (review round 3, tenant-r3-6). What the schema cannot say is which words are
// real, and an invented one would be stored and sent back in every list, so only
// the defined ones stay. The old name "cable" is the hybrid transport.
func cleanTransports(in []protocol.AuthenticatorTransport) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range in {
		v := string(t)
		switch v {
		case "cable":
			v = string(protocol.Hybrid)
		case string(protocol.USB), string(protocol.NFC), string(protocol.BLE),
			string(protocol.SmartCard), string(protocol.Hybrid), string(protocol.Internal):
		default:
			continue
		}
		if seen[v] || len(out) >= maxTransports {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// Asserted is a login the library accepted. The sign count and backup state are
// what the credential row is updated with (the clone rule is the store's).
type Asserted struct {
	CredentialID []byte
	SignCount    int64
	BackupState  bool
}

func asserted(c *webauthn.Credential) Asserted {
	return Asserted{CredentialID: c.ID, SignCount: int64(c.Authenticator.SignCount), BackupState: c.Flags.BackupState}
}

// FinishLogin validates an assertion for a known user (7.6).
func (i Instance) FinishLogin(u *User, sessionJSON, body []byte) (Asserted, error) {
	sd, err := session(sessionJSON)
	if err != nil {
		return Asserted{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return Asserted{}, ErrInvalid
	}
	c, err := i.wa.ValidateLogin(u, sd, parsed)
	if err != nil {
		return Asserted{}, ErrInvalid
	}
	return asserted(c), nil
}

// Resolver finds the user a discoverable credential belongs to. It returns an
// error to refuse (unknown, stale, other RP ID, handle mismatch).
type Resolver func(rawID, userHandle []byte) (*User, error)

// FinishDiscoverable validates a login that did not know the user (7.5) and
// returns the user the resolver found.
func (i Instance) FinishDiscoverable(resolve Resolver, sessionJSON, body []byte) (*User, Asserted, error) {
	sd, err := session(sessionJSON)
	if err != nil {
		return nil, Asserted{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return nil, Asserted{}, ErrInvalid
	}
	var resolved *User
	u, c, err := i.wa.ValidatePasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		r, err := resolve(rawID, userHandle)
		if err != nil {
			return nil, err
		}
		resolved = r
		return r, nil
	}, sd, parsed)
	if err != nil || u == nil || resolved == nil {
		return nil, Asserted{}, ErrInvalid
	}
	return resolved, asserted(c), nil
}
