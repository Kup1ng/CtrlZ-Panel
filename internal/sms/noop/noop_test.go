package noop_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/noop"
)

func TestRefusesProduction(t *testing.T) {
	for _, env := range []string{"production", "", "staging", "TEST"} {
		if _, err := noop.New(env, ""); !errors.Is(err, noop.ErrProduction) {
			t.Errorf("env %q: %v", env, err)
		}
		if noop.Allowed(env) {
			t.Errorf("env %q allowed", env)
		}
	}
	for _, env := range []string{"dev", "test"} {
		if _, err := noop.New(env, ""); err != nil {
			t.Errorf("env %q: %v", env, err)
		}
	}
}

func TestSendRecordsInMemoryAndInFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sms.jsonl")
	n, err := noop.New("test", file)
	if err != nil {
		t.Fatal(err)
	}
	m := sms.Message{To: "+989121234567", Template: "otp", Locale: "fa", Values: map[string]secret.String{"CODE": secret.New("012345")}}
	res, err := n.Send(context.Background(), m, sms.ProviderTemplate{})
	if err != nil || res.ProviderID.IsZero() {
		t.Fatalf("%+v %v", res, err)
	}
	m.To = "+989351111111"
	m.Values["CODE"] = secret.New("999999")
	if _, err := n.Send(context.Background(), m, sms.ProviderTemplate{}); err != nil {
		t.Fatal(err)
	}

	if got := n.Messages(); len(got) != 2 || got[0].Values["CODE"] != "012345" {
		t.Errorf("memory: %+v", got)
	}
	if c, ok := n.Code("+989121234567"); !ok || c.Reveal() != "012345" {
		t.Errorf("Code: %v %v", c, ok)
	}
	if _, ok := n.Code("+989000000000"); ok {
		t.Error("Code found a message nobody sent")
	}

	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var lines []noop.Sent
	for sc.Scan() {
		var s noop.Sent
		if err := json.Unmarshal(sc.Bytes(), &s); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		lines = append(lines, s)
	}
	if len(lines) != 2 || lines[1].To != "+989351111111" || lines[1].Values["CODE"] != "999999" || lines[0].Template != "otp" {
		t.Errorf("file: %+v", lines)
	}
}

func TestNoCodeTemplateHasNoValue(t *testing.T) {
	n, _ := noop.New("test", "")
	_, _ = n.Send(context.Background(), sms.Message{To: "+989121234567", Template: "account_exists"}, sms.ProviderTemplate{})
	if c, ok := n.Code("+989121234567"); !ok || !c.IsZero() {
		t.Errorf("account_exists: %v %v", c, ok)
	}
}

func TestMemoryIsBounded(t *testing.T) {
	n, _ := noop.New("dev", "")
	var wg sync.WaitGroup
	for i := 0; i < 1200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = n.Send(context.Background(), sms.Message{To: "+989121234567"}, sms.ProviderTemplate{})
		}()
	}
	wg.Wait()
	if len(n.Messages()) != 1000 {
		t.Errorf("kept %d", len(n.Messages()))
	}
}

func TestUnwritableFileIsATransientFailure(t *testing.T) {
	n, _ := noop.New("test", filepath.Join(t.TempDir(), "no-such-dir", "x.jsonl"))
	_, err := n.Send(context.Background(), sms.Message{To: "+989121234567"}, sms.ProviderTemplate{})
	var e *sms.Error
	if !errors.As(err, &e) || e.Class != sms.Transient {
		t.Errorf("%v", err)
	}
}
