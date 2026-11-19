package smshttp_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/smshttp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testtls"
)

func TestHostPort(t *testing.T) {
	for in, want := range map[string]string{
		"https://api.sms.ir/v1":           "api.sms.ir:443",
		"https://rest.payamak-panel.com/": "rest.payamak-panel.com:443",
		"https://[::1]:9000":              "[::1]:9000",
		"https://127.0.0.1:8080/x":        "127.0.0.1:8080",
	} {
		got, err := smshttp.HostPort(in)
		if err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "api.sms.ir", "ftp://x/", "https://", "http://api.sms.ir/v1", "http://127.0.0.1:443/", "HTTP://api.sms.ir", "//api.sms.ir/v1"} {
		if _, err := smshttp.HostPort(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestClientDialsOnlyItsHost is the dial guard of 9.3: a request for any other
// host fails before a connection is made, whatever URL it carries.
func TestClientDialsOnlyItsHost(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	home := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "home") }))
	defer home.Close()
	homeURL, _ := url.Parse(home.URL)
	c := smshttp.NewClient(homeURL.Host, smshttp.Options{Total: 2 * time.Second, RootCAs: testtls.Roots()})

	req, _ := http.NewRequest("GET", home.URL, nil)
	resp, err := smshttp.Do(c, req)
	if err != nil || string(resp.Body) != "home" {
		t.Fatalf("home: %+v %v", resp, err)
	}
	req, _ = http.NewRequest("GET", other.URL+"/anything", nil)
	_, err = smshttp.Do(c, req)
	if !errors.Is(err, smshttp.ErrRefused) {
		t.Errorf("another host: %v", err)
	}
	if elsewhere.Load() != 0 {
		t.Error("another host was reached")
	}
	// The error holds no URL: the host and the path of the refused request are
	// not in it.
	if strings.Contains(err.Error(), "anything") || strings.Contains(err.Error(), other.URL) {
		t.Errorf("error holds the URL: %v", err)
	}
}

func TestEnvironmentProxyIsIgnored(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxied.Add(1) }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	home := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer home.Close()
	homeURL, _ := url.Parse(home.URL)
	c := smshttp.NewClient(homeURL.Host, smshttp.Options{Total: 2 * time.Second, RootCAs: testtls.Roots()})
	req, _ := http.NewRequest("GET", "http://example.invalid.test/", nil)
	if _, err := smshttp.Do(c, req); err == nil {
		t.Error("a request for another host succeeded")
	}
	req, _ = http.NewRequest("GET", home.URL, nil)
	if _, err := smshttp.Do(c, req); err != nil {
		t.Fatal(err)
	}
	if proxied.Load() != 0 {
		t.Error("the environment's proxy was used for a gateway call")
	}
}

func TestDoReportsCancelAndTimeoutApart(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	u, _ := url.Parse(srv.URL)
	c := smshttp.NewClient(u.Host, smshttp.Options{Total: 200 * time.Millisecond, RootCAs: testtls.Roots()})

	req, _ := http.NewRequest("GET", srv.URL, nil)
	if _, err := smshttp.Do(c, req); !errors.Is(err, smshttp.ErrTimeout) {
		t.Errorf("timeout: %v", err)
	}

	c = smshttp.NewClient(u.Host, smshttp.Options{Total: 5 * time.Second, RootCAs: testtls.Roots()})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	req, _ = http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	if _, err := smshttp.Do(c, req); !errors.Is(err, context.Canceled) {
		t.Errorf("cancel: %v", err)
	}
}

func TestDefaultsAreTheSpecs(t *testing.T) {
	if smshttp.ConnectTimeout != 3*time.Second || smshttp.TotalTimeout != 6*time.Second || smshttp.MaxBody != 64<<10 {
		t.Error("9.1 and 9.3 numbers changed")
	}
	c := smshttp.NewClient("x:443", smshttp.Options{})
	if hc := smshttp.HTTPClient(c); hc.Timeout != 6*time.Second {
		t.Errorf("default total timeout %v", hc.Timeout)
	}
}

// TestDoNormalisesTheBody: the byte order mark, white space around the answer and a UTF-16 dress
// are removed before any driver sees the body (sms-r12-1), and nothing else is touched.
func TestDoNormalisesTheBody(t *testing.T) {
	const bom = "\xEF\xBB\xBF"
	for name, c := range map[string]struct{ in, want string }{
		"plain":           {"abc", "abc"},
		"bom":             {bom + "abc", "abc"},
		"crlf and bom":    {"\r\n" + bom + "abc\r\n", "abc\r\n"},
		"two boms":        {bom + bom + "x", "x"},
		"inner bom stays": {"a" + bom + "b", "a" + bom + "b"},
		"utf16 le":        {"\xFF\xFEa\x00b\x00", "ab"},
		"utf16 be":        {"\xFE\xFF\x00a\x00b", "ab"},
		"utf16 odd tail":  {"\xFF\xFEa\x00b", "a"},
		"empty":           {"", ""},
	} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, c.in) }))
		u, _ := url.Parse(srv.URL)
		req, _ := http.NewRequest("GET", srv.URL, nil)
		resp, err := smshttp.Do(smshttp.NewClient(u.Host, smshttp.Options{Total: 2 * time.Second, RootCAs: testtls.Roots()}), req)
		srv.Close()
		if err != nil || string(resp.Body) != c.want {
			t.Errorf("%s: %q %v, want %q", name, resp.Body, err, c.want)
		}
	}
}

// TestClientHasNothingToSet is the half of the R21 rule that is about the type (sms-r14-3): the
// client a driver holds has no exported field and no exported method, so no driver can turn off
// TLS verification, replace the dial guard, put the environment's proxy back or follow a redirect.
// The lint keeps a driver from naming the net/http types behind it; this keeps the type shut.
func TestClientHasNothingToSet(t *testing.T) {
	typ := reflect.TypeOf(smshttp.Client{})
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).IsExported() {
			t.Errorf("smshttp.Client has the exported field %s", typ.Field(i).Name)
		}
	}
	if n := reflect.TypeOf(&smshttp.Client{}).NumMethod(); n != 0 {
		t.Errorf("smshttp.Client has %d exported methods", n)
	}
}

// TestTheClientKeepsTheR21Rules reads the wrapped client once: verification on, a TLS floor, no
// proxy, no redirect followed.
func TestTheClientKeepsTheR21Rules(t *testing.T) {
	hc := smshttp.HTTPClient(smshttp.NewClient("x:443", smshttp.Options{}))
	tr, ok := hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T", hc.Transport)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("TLS config %+v", tr.TLSClientConfig)
	}
	if tr.Proxy != nil {
		t.Error("the client has a proxy")
	}
	if tr.DialContext == nil {
		t.Error("the client has no dial guard")
	}
	if hc.CheckRedirect == nil || hc.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Error("a redirect is followed")
	}
}

// TestDialGuardStillRefusesAnotherHost keeps the guard of the transport itself under test: Do
// refuses another host first (sms-r15-3), so the guard is reached only through the wrapped client,
// which is what a bug in Do's own check would leave in front of it.
func TestDialGuardStillRefusesAnotherHost(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	c := smshttp.NewClient("127.0.0.1:1", smshttp.Options{Total: 2 * time.Second, RootCAs: testtls.Roots()})
	req, _ := http.NewRequest("GET", other.URL, nil)
	if resp, err := smshttp.HTTPClient(c).Do(req); err == nil {
		_ = resp.Body.Close()
		t.Error("the transport dialled a host it was not built for")
	}
	if elsewhere.Load() != 0 {
		t.Error("another host was reached")
	}
}

// TestDoRefusesAnythingButHTTPSToItsOwnHost is sms-r15-3: the dial guard compares host and port and
// never sees a scheme, so http://host:443 went out in clear text with every other check green. The
// refusal is before any dial and carries nothing of the request.
func TestDoRefusesAnythingButHTTPSToItsOwnHost(t *testing.T) {
	var hits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer secure.Close()
	plainURL, _ := url.Parse(plain.URL)
	secureURL, _ := url.Parse(secure.URL)
	for name, tc := range map[string]struct{ host, target string }{
		"the client's own plain server":  {plainURL.Host, plain.URL + "/send"},
		"https host, http scheme":        {secureURL.Host, "http://" + secureURL.Host + "/send?code=123456"},
		"uppercase scheme is still http": {plainURL.Host, "HTTP://" + plainURL.Host + "/send"},
		"a scheme-relative URL":          {secureURL.Host, "//" + secureURL.Host + "/send"},
		"ftp":                            {secureURL.Host, "ftp://" + secureURL.Host + "/send"},
		"another port of the same host":  {secureURL.Host, "https://127.0.0.1:1/send"},
	} {
		c := smshttp.NewClient(tc.host, smshttp.Options{Total: 2 * time.Second, RootCAs: testtls.Roots()})
		req, err := http.NewRequest("POST", tc.target, strings.NewReader("password=CANARY"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_, err = smshttp.Do(c, req)
		if !errors.Is(err, smshttp.ErrRefused) {
			t.Errorf("%s: %v, want ErrRefused", name, err)
		} else if strings.Contains(err.Error(), "CANARY") || strings.Contains(err.Error(), "send") {
			t.Errorf("%s: the error holds part of the request: %v", name, err)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("%d requests reached a server that should not have been called", hits.Load())
	}
	// The client's own https host still works.
	c := smshttp.NewClient(secureURL.Host, smshttp.Options{Total: 2 * time.Second, RootCAs: testtls.Roots()})
	req, _ := http.NewRequest("GET", secure.URL, nil)
	if _, err := smshttp.Do(c, req); err != nil {
		t.Errorf("https to its own host: %v", err)
	}
}
