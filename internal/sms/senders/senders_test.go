package senders_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/senders"
)

func problem(t *testing.T, err error) sms.Code {
	t.Helper()
	var u *senders.ErrUnusable
	if !errors.As(err, &u) {
		t.Fatalf("not an ErrUnusable: %v", err)
	}
	return u.Problem
}

func TestNewByProvider(t *testing.T) {
	test := senders.Env{Name: "test"}
	if s, err := senders.New("noop", secret.Bytes{}, test); err != nil || s.Provider() != "noop" {
		t.Fatalf("noop: %v", err)
	}
	if s, err := senders.New("sms_ir", secret.NewBytes([]byte(`{"api_key":"k"}`)), test); err != nil || s.Provider() != "sms_ir" {
		t.Fatalf("sms_ir: %v", err)
	}
	if s, err := senders.New("melipayamak", secret.NewBytes([]byte(`{"username":"u","password":"p"}`)), test); err != nil || s.Provider() != "melipayamak" {
		t.Fatalf("melipayamak: %v", err)
	}
}

func TestNoopInProductionIsUnusable(t *testing.T) {
	// 9.3: a production start with a noop row treats it as disabled.
	for _, env := range []string{"production", ""} {
		_, err := senders.New("noop", secret.Bytes{}, senders.Env{Name: env})
		if problem(t, err) != sms.CodeNoopInProduction {
			t.Errorf("env %q: %v", env, err)
		}
	}
}

func TestUnusableCases(t *testing.T) {
	prod := senders.Env{Name: "production"}
	for name, c := range map[string]struct {
		provider string
		creds    string
		want     sms.Code
	}{
		"sms_ir without credentials":    {"sms_ir", "", sms.CodeNoCredentials},
		"melipayamak without":           {"melipayamak", "", sms.CodeNoCredentials},
		"sms_ir with the other's shape": {"sms_ir", `{"username":"u","password":"CANARY-PW"}`, sms.CodeBadCredentials},
		"melipayamak with api_key":      {"melipayamak", `{"api_key":"CANARY-KEY"}`, sms.CodeBadCredentials},
		"unknown provider":              {"twilio", `{}`, sms.CodeUnknownProvider},
	} {
		_, err := senders.New(c.provider, secret.NewBytes([]byte(c.creds)), prod)
		if got := problem(t, err); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
		// The error text names the problem and nothing of the credentials.
		if strings.Contains(err.Error(), "CANARY") || strings.Contains(err.Error(), "username") {
			t.Errorf("%s: error text %q repeats the credentials", name, err.Error())
		}
	}
}

func TestCheckCredentialsGivesTheHint(t *testing.T) {
	h, err := senders.CheckCredentials("sms_ir", []byte(`{"api_key":"abcdefgh12345678"}`))
	if err != nil || h != "5678" {
		t.Errorf("sms_ir hint: %q %v", h, err)
	}
	// The hint of Melipayamak comes from the username and never from the password.
	h, err = senders.CheckCredentials("melipayamak", []byte(`{"username":"owner9876","password":"hunter2hunter2"}`))
	if err != nil || h != "9876" {
		t.Errorf("melipayamak hint: %q %v", h, err)
	}
	if _, err := senders.CheckCredentials("melipayamak", []byte(`{"api_key":"x"}`)); err == nil {
		t.Error("wrong shape accepted")
	}
	if _, err := senders.CheckCredentials("noop", []byte(`{}`)); err == nil {
		t.Error("noop takes no credentials")
	}
}

// TestShortAPIKeysShowNoHint is admin-r5-5: the hint is plain text in GET /sms/gateways, and for
// a key of four characters or fewer it was the whole key. No key of any length shows more than a
// quarter of itself, and a key under 16 characters shows nothing.
func TestShortAPIKeysShowNoHint(t *testing.T) {
	for n := 1; n <= 64; n++ {
		key := strings.Repeat("k", n-1) + "Z"
		h, err := senders.CheckCredentials("sms_ir", []byte(`{"api_key":"`+key+`"}`))
		if err != nil {
			t.Fatalf("a key of %d characters: %v", n, err)
		}
		if len(h) > n/4 {
			t.Errorf("a key of %d characters shows %q: more than a quarter of it", n, h)
		}
		if n < 16 && h != "" {
			t.Errorf("a key of %d characters shows the hint %q", n, h)
		}
		if n >= 16 && h != "kkkZ" {
			t.Errorf("a key of %d characters shows %q, want its last four", n, h)
		}
	}
}
