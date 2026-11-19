package smshttp

import "net/http"

// HTTPClient hands the wrapped client to the tests of this package, and to nothing else: the type
// is opaque to drivers on purpose (sms-r14-3), and a _test.go file is not part of the package a
// driver imports.
func HTTPClient(c *Client) *http.Client { return c.c }
