// Package senders builds the Sender of a gateway from its opened credentials.
// It sits apart from internal/sms because the drivers import sms, and sms cannot
// import them back.
//
// The worker is the only caller that sends. The admin service uses
// CheckCredentials to refuse a malformed PUT before it seals anything (15.2).
package senders

import (
	"errors"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/melipayamak"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/noop"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/smsir"
)

// Env is what the factory needs of the process: the environment name decides
// whether noop may exist, and the file is where it records messages.
type Env struct {
	Name     string // production, dev or test
	NoopFile string
}

// The reasons a gateway cannot be built are the Problem codes of the table in
// internal/sms/codes.go (CodeNoCredentials, CodeBadCredentials, CodeNoopInProduction,
// CodeUnknownProvider): the router puts one in an alert, so it is a member of a
// closed set.

// ErrUnusable carries a Problem code.
type ErrUnusable struct{ Problem sms.Code }

func (e *ErrUnusable) Error() string { return "senders: gateway unusable: " + e.Problem.String() }

// New builds the Sender for a provider. creds is the opened credentials JSON,
// empty for noop. The error is an *ErrUnusable, whose text holds no part of the
// credentials.
func New(provider string, creds secret.Bytes, env Env) (sms.Sender, error) {
	switch provider {
	case noop.Provider:
		s, err := noop.New(env.Name, env.NoopFile)
		if errors.Is(err, noop.ErrProduction) {
			return nil, &ErrUnusable{sms.CodeNoopInProduction}
		}
		if err != nil {
			return nil, &ErrUnusable{sms.CodeBadCredentials}
		}
		return s, nil
	case smsir.Provider:
		if creds.IsZero() {
			return nil, &ErrUnusable{sms.CodeNoCredentials}
		}
		c, err := smsir.ParseCredentials(creds.Reveal())
		if err != nil {
			return nil, &ErrUnusable{sms.CodeBadCredentials}
		}
		s, err := smsir.New(smsir.Config{Credentials: c})
		if err != nil {
			return nil, &ErrUnusable{sms.CodeBadCredentials}
		}
		return s, nil
	case melipayamak.Provider:
		if creds.IsZero() {
			return nil, &ErrUnusable{sms.CodeNoCredentials}
		}
		c, err := melipayamak.ParseCredentials(creds.Reveal())
		if err != nil {
			return nil, &ErrUnusable{sms.CodeBadCredentials}
		}
		s, err := melipayamak.New(melipayamak.Config{Credentials: c})
		if err != nil {
			return nil, &ErrUnusable{sms.CodeBadCredentials}
		}
		return s, nil
	}
	return nil, &ErrUnusable{sms.CodeUnknownProvider}
}

// ValidTemplateID reports whether the driver of a provider can send with this provider
// template id. The admin PUT calls it, so an id a provider cannot take is refused at the
// PUT and not discovered as a failed send that counts toward the breaker (sms-r9-2). A
// provider with no rule (noop) is held to the common rule, sms.ParseTemplateNumber.
func ValidTemplateID(provider, id string) bool {
	switch provider {
	case smsir.Provider:
		_, ok := smsir.ParseTemplateID(id)
		return ok
	case melipayamak.Provider:
		_, ok := melipayamak.ParseTemplateID(id)
		return ok
	}
	// A provider with no rule of its own (noop) is held to the common one, so the PUT never
	// takes an id that no driver would (sms-r10-4).
	_, ok := sms.ParseTemplateNumber(id)
	return ok
}

// CheckCredentials validates the shape of credentials JSON for a provider and
// returns the hint to store beside it: the last four characters of an sms.ir
// key of 16 characters or more (a shorter one shows none, admin-r5-5) or of the Melipayamak username, never derived from a password (15.2). The
// error is a fixed string.
func CheckCredentials(provider string, raw []byte) (hint string, err error) {
	switch provider {
	case smsir.Provider:
		c, err := smsir.ParseCredentials(raw)
		if err != nil {
			return "", err
		}
		return sms.KeyHint(c.APIKey.Reveal()), nil
	case melipayamak.Provider:
		c, err := melipayamak.ParseCredentials(raw)
		if err != nil {
			return "", err
		}
		return sms.Hint(c.Username), nil
	}
	return "", errors.New("senders: this provider takes no credentials")
}
