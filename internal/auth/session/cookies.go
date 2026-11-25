// Package session holds the session rules of spec 3: tokens, cookies, lifetimes,
// Remember me and refresh, the gates every request passes, and the rotation and
// revocation table of 3.7. The rules are code here, once, so a route cannot
// forget to rotate or to revoke the other sessions.
//
// The package knows no HTTP routing and no JSON. It returns sentinel errors, and
// the router maps them to API errors, which keeps the session rules testable
// without a server.
package session

import (
	"net/http"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// Cookie names (spec 3.2). The __Host- prefix makes a browser refuse a cookie
// without Secure, with a Domain, or with a Path other than /, so the panel's
// cookies are never sent to the admin host or to a sibling subdomain.
const (
	CookieSession = "__Host-ctrlz_session"
	CookieRefresh = "__Host-ctrlz_refresh"
	CookieDevice  = "__Host-ctrlz_device"
	CookieAdmin   = "__Host-ctrlz_admin"
	// CookieAdminDevice marks a browser the admin signed in from (spec 10.2).
	CookieAdminDevice = "__Host-ctrlz_admin_device"
)

// Device cookie lifetime (spec 3.2, 5.5).
const DeviceMaxAge = keyring.LifeDevice

// AdminDeviceMaxAge is how long an admin device marker lasts. Shorter than the
// user marker: it is for one person, who signs in often.
const AdminDeviceMaxAge = keyring.LifeAdminDevice

// base is the attribute set every cookie shares. There is never a Domain.
func base(name, value string, same http.SameSite) *http.Cookie {
	return &http.Cookie{
		Name: name, Value: value, Path: "/",
		Secure: true, HttpOnly: true, SameSite: same,
	}
}

// SessionCookie is the session token: a browser session cookie with no Max-Age,
// so it dies with the browser, and the server enforces 2 h idle and the absolute
// limit besides. SameSite=Lax lets a link from another site land on a logged-in
// page; every write is non-GET and passes the CSRF layers (3.6).
func SessionCookie(token secret.String) *http.Cookie {
	return base(CookieSession, token.Reveal(), http.SameSiteLaxMode)
}

// RefreshCookie is the Remember me token, lasting maxAge.
func RefreshCookie(token secret.String, maxAge time.Duration) *http.Cookie {
	c := base(CookieRefresh, token.Reveal(), http.SameSiteLaxMode)
	c.MaxAge = int(maxAge / time.Second)
	return c
}

// DeviceCookie is the known-device marker of 5.5.
func DeviceCookie(sealed string) *http.Cookie {
	c := base(CookieDevice, sealed, http.SameSiteLaxMode)
	c.MaxAge = int(DeviceMaxAge / time.Second)
	return c
}

// AdminCookie is the admin session. SameSite=Strict, since the admin host never
// needs to be reached by a link from elsewhere.
func AdminCookie(token secret.String) *http.Cookie {
	return base(CookieAdmin, token.Reveal(), http.SameSiteStrictMode)
}

// AdminDeviceCookie is the known-device marker of an admin. Strict like the
// session, since the admin host is never entered by a link from elsewhere.
func AdminDeviceCookie(sealed string) *http.Cookie {
	c := base(CookieAdminDevice, sealed, http.SameSiteStrictMode)
	c.MaxAge = int(AdminDeviceMaxAge / time.Second)
	return c
}

// Expire turns a cookie into its own deletion: the same name and attributes with
// an empty value and Max-Age=0. A __Host- cookie can be removed only by a
// Set-Cookie that also satisfies the prefix rules.
func Expire(c *http.Cookie) *http.Cookie {
	e := *c
	e.Value = ""
	e.MaxAge = -1
	return &e
}

// ClearPanel is the pair of Set-Cookie values that end a panel login on the
// client: the session and the refresh cookie. The device cookie stays.
func ClearPanel() []*http.Cookie {
	return []*http.Cookie{
		Expire(base(CookieSession, "", http.SameSiteLaxMode)),
		Expire(base(CookieRefresh, "", http.SameSiteLaxMode)),
	}
}

// ClearAdmin ends an admin login on the client.
func ClearAdmin() *http.Cookie {
	return Expire(base(CookieAdmin, "", http.SameSiteStrictMode))
}

// Read returns the value of a cookie, or "" when it is absent. When a request
// carries two cookies of one name the first wins, as Go's parser orders them;
// the value is then checked by shape and by hash, so a duplicate gains nothing.
func Read(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}
