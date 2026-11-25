// Package noop is the SMS gateway for development and tests (spec 9.3). It sends
// nothing: it records {to, template, values} in memory and, when a file is set,
// as one JSON line per message, so a flow test or Playwright can read the OTP it
// would have received.
//
// That makes it a place where codes sit in clear text, so it refuses to exist in
// production: New returns ErrProduction unless the environment is dev or test.
// The admin route that selects the noop gateway applies the same test through
// Allowed.
package noop

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
)

// Provider is the name stored in sms_gateways.provider.
const Provider = "noop"

// ErrProduction is New refusing to build the gateway outside dev and test.
var ErrProduction = errors.New("noop: the noop SMS gateway exists only in dev and test")

// Allowed says whether the environment ("production", "dev" or "test") may use
// the noop gateway.
func Allowed(env string) bool { return env == "dev" || env == "test" }

// maxKept bounds the in-memory list, so a long-running dev worker does not grow
// without end.
const maxKept = 1000

// Sent is one recorded message, with the value in clear text.
type Sent struct {
	To       string            `json:"to"`
	Template string            `json:"template"`
	Locale   string            `json:"locale,omitempty"`
	Values   map[string]string `json:"values"`
}

// Sender is the noop gateway. It also exposes what it recorded.
type Sender struct {
	file string

	mu   sync.Mutex
	sent []Sent
}

var _ sms.Sender = (*Sender)(nil)

// New returns the gateway, or ErrProduction. file may be empty.
func New(env, file string) (*Sender, error) {
	if !Allowed(env) {
		return nil, ErrProduction
	}
	return &Sender{file: file}, nil
}

func (s *Sender) Provider() string { return Provider }

// Send records the message.
func (s *Sender) Send(_ context.Context, m sms.Message, _ sms.ProviderTemplate) (sms.Result, error) {
	rec := Sent{To: m.To, Template: m.Template, Locale: m.Locale, Values: map[string]string{}}
	for k, v := range m.Values {
		rec.Values[k] = v.Reveal()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, rec)
	if len(s.sent) > maxKept {
		s.sent = s.sent[len(s.sent)-maxKept:]
	}
	if s.file != "" {
		line, err := json.Marshal(rec)
		if err != nil {
			return sms.Result{}, sms.NewError(Provider, sms.Config, sms.CodeEncode)
		}
		f, err := os.OpenFile(s.file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return sms.Result{}, sms.NewError(Provider, sms.Transient, sms.CodeFile)
		}
		defer f.Close()
		if _, err := f.Write(append(line, '\n')); err != nil {
			return sms.Result{}, sms.NewError(Provider, sms.Transient, sms.CodeFile)
		}
	}
	return sms.Result{ProviderID: sms.ParseField("noop")}, nil
}

// Balance is a fixed answer.
func (s *Sender) Balance(_ context.Context) (sms.Field, error) { return sms.ParseField("0"), nil }

// Messages returns a copy of what was recorded, oldest first.
func (s *Sender) Messages() []Sent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Sent(nil), s.sent...)
}

// Code returns the value of the newest message to a number, for a test that
// needs the OTP. ok is false when there is none.
func (s *Sender) Code(to string) (secret.String, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.sent) - 1; i >= 0; i-- {
		if s.sent[i].To != to {
			continue
		}
		for _, v := range s.sent[i].Values {
			return secret.New(v), true
		}
		return secret.String{}, true
	}
	return secret.String{}, false
}
