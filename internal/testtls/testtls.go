// Package testtls gives tests the trust they need to talk to an httptest TLS server. It is imported
// from test files only.
//
// Since sms-r15-3 the SMS HTTP layer (internal/sms/smshttp) refuses any request that is not https,
// so a driver test cannot use a plain httptest.NewServer any more, and it must not get around that
// with a switch in the production package. httptest.NewTLSServer serves one fixed throw-away
// certificate for 127.0.0.1 whatever the server, so the pool that trusts it is one value, and a
// test passes it as the driver's RootCAs (verification itself stays on).
package testtls

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
)

// Roots returns a pool that trusts the certificate every httptest TLS server presents.
func Roots() *x509.CertPool {
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}
