// Package smshttp is the HTTP plumbing both SMS drivers share (spec 9.3). The
// point of having it in one place is that every rule of R21 holds for both
// drivers at once:
//
//   - the client dials the driver's one fixed host and nothing else, and uses no
//     proxy from the environment, so no value from the database or the process
//     environment can aim a request somewhere else;
//   - TLS verification is on, always (the sample code of one provider turns it
//     off, and ours never does), and a request that is not https, or that names a
//     host and port other than the client's, is refused by Do before any dial
//     (sms-r15-3), so no base URL and no URL a driver builds per request can send
//     a credential, a code or a phone number in clear text;
//   - a redirect is not followed, so a credential in a header or a body cannot be
//     replayed to the place a reply points at;
//   - an error from the transport is reduced to a fixed value before it leaves
//     this package. Go's own error holds the full URL, and the host name of a
//     gateway is not secret but a query string or a future driver's path might be;
//   - the reply body is read to 64 KiB, handed to the driver, and dropped.
package smshttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"
)

// The timeouts of spec 9.1.
const (
	ConnectTimeout = 3 * time.Second
	TotalTimeout   = 6 * time.Second
	// MaxBody is how much of a reply is read.
	MaxBody = 64 << 10
)

// SendableCredential says a credential value is one the HTTP layer can send exactly as it is
// stored, and that a person did not paste by accident. A driver's ParseCredentials is the only
// gate between the admin's PUT and a sealed value, so it accepts a credential only when this
// is true: a header value with a NUL, a control character or DEL is refused by net/http before
// any dial, and Do reports every such local refusal as a network error, so a bad key looked
// like an outage (breaker and sms_down) and the provider's own Auth answer, the critical alert
// that names the gateway, never came (sms-r8-2). A value with white space at either end is a
// paste artefact too: it reaches the provider, which refuses it, while the hint on the admin
// page (last four characters, trimmed) shows a key that was not the one sent.
func SendableCredential(s string) bool {
	if s == "" || s != strings.TrimSpace(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// The two ways a call fails before there is an HTTP reply. Neither carries a URL.
var (
	ErrTimeout = errors.New("smshttp: timeout")
	ErrNetwork = errors.New("smshttp: network error")
	// errDial is the dial guard refusing an address other than the fixed host.
	errDial = errors.New("smshttp: dial refused")
)

// Options configure a client. The zero value is the production client.
type Options struct {
	// Total replaces the 6 second limit. Tests shorten it; nothing else does.
	Total time.Duration
	// RootCAs replaces the system roots. Tests use it to trust a throw-away
	// certificate; verification itself stays on.
	RootCAs *x509.CertPool
}

// Client is the one HTTP client a driver may hold, and it is opaque on purpose (sms-r14-3). It
// used to be the *http.Client itself, a fully mutable value: a driver that set
// c.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify, replaced DialContext, put
// back the environment's proxy or cleared CheckRedirect took away every rule of R21 at once, and
// a lint that reads the names a driver uses is only as good as the spellings it knows. With no
// exported field and no exported method there is nothing to set, so the rules hold for every
// driver, present and future, by the shape of the type (TestClientHasNothingToSet); the lint only
// has to keep a driver from naming the net/http types behind it.
type Client struct {
	c        *http.Client
	hostPort string // the one host:port a request may name, see Do
}

// NewClient returns a client that can reach hostPort only (for example
// "api.sms.ir:443").
func NewClient(hostPort string, o Options) *Client {
	total := o.Total
	if total <= 0 {
		total = TotalTimeout
	}
	dialer := &net.Dialer{Timeout: ConnectTimeout}
	tr := &http.Transport{
		// No proxy: the environment's HTTP_PROXY must not redirect a gateway call.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != hostPort {
				return nil, errDial
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.RootCAs},
		TLSHandshakeTimeout:   ConnectTimeout,
		ResponseHeaderTimeout: total,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &Client{hostPort: hostPort, c: &http.Client{
		Transport: tr,
		Timeout:   total,
		// A 3xx is returned to the driver, which treats it as a failure.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// HostPort returns the dial address of a base URL: host and port, the port defaulting to 443.
// Only https is accepted (sms-r15-3): R21 says TLS verification is always on, and a base URL that
// names http would send the provider's credentials, the code and the phone in clear text with
// every check of this package still green, because the dial guard compares only host and port.
func HostPort(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.Scheme != "https" {
		return "", errors.New("smshttp: invalid base URL")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

// ErrRefused is Do declining a request before any dial: it is not https, or it names a host and
// port other than the client's. It carries nothing of the request.
var ErrRefused = errors.New("smshttp: request refused")

// allows says whether req may be sent by this client. The scheme is the one half the dial guard
// cannot see (it gets a host:port and not a scheme, so http://host:443 passes it and goes out in
// plain text), and the host check here is the same one the guard makes at dial time, made first so
// that a driver that builds a URL per request fails in every test that exercises it and not only
// when a connection is attempted.
func (c *Client) allows(req *http.Request) bool {
	if req == nil || req.URL == nil || req.URL.Scheme != "https" || req.URL.Host == "" {
		return false
	}
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(req.URL.Hostname(), port) == c.hostPort
}

// Response is a reply: the status and at most MaxBody bytes.
type Response struct {
	Status int
	Body   []byte
}

// Do sends the request. A failure before a reply is ErrTimeout or ErrNetwork, or
// the context's own error when the caller's context ended (so the router can tell
// a shutdown from a dead gateway). The underlying error is dropped on purpose.
func Do(c *Client, req *http.Request) (Response, error) {
	if !c.allows(req) {
		return Response{}, ErrRefused
	}
	resp, err := c.c.Do(req)
	if err != nil {
		if cerr := req.Context().Err(); cerr != nil && !errors.Is(cerr, context.DeadlineExceeded) {
			return Response{}, cerr
		}
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			return Response{}, ErrTimeout
		}
		return Response{}, ErrNetwork
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return Response{}, ErrTimeout
		}
		return Response{}, ErrNetwork
	}
	return Response{Status: resp.StatusCode, Body: Normalize(body)}, nil
}

// utf8BOM is the UTF-8 byte order mark, U+FEFF.
const utf8BOM = "\xEF\xBB\xBF"

// Normalize is the one place a reply body is made ready to parse (sms-r12-1). A gateway built on
// ASP.NET (Melipayamak) is known to start a reply with a UTF-8 byte order mark, and a body may
// carry leading white space or line breaks; none of that is part of the answer. Before this a
// driver that forgot to skip the mark read an accepted message as "not a value": the router sent
// it again through the other gateway, the user got two codes, both billed, and the breaker of the
// gateway that delivers opened. Doing it here, before any driver sees the body, means a driver
// cannot forget it. A UTF-16 body (byte order mark FF FE or FE FF) is converted to UTF-8 for the
// same reason. The result is a prefix-trimmed view of the input or a new slice, never longer than
// the 64 KiB read.
func Normalize(b []byte) []byte {
	if len(b) >= 2 && ((b[0] == 0xFF && b[1] == 0xFE) || (b[0] == 0xFE && b[1] == 0xFF)) {
		b = decodeUTF16(b)
	}
	for {
		b = bytes.TrimLeft(b, " \t\r\n")
		if !bytes.HasPrefix(b, []byte(utf8BOM)) {
			return b
		}
		b = b[len(utf8BOM):]
	}
}

// decodeUTF16 converts a body that starts with a UTF-16 byte order mark. An odd last byte is
// dropped; an unpaired surrogate becomes U+FFFD, which no driver reads as a value.
func decodeUTF16(b []byte) []byte {
	bigEndian := b[0] == 0xFE
	b = b[2:]
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		if bigEndian {
			u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
		} else {
			u = append(u, uint16(b[i+1])<<8|uint16(b[i]))
		}
	}
	return []byte(string(utf16.Decode(u)))
}
