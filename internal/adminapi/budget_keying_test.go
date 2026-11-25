package adminapi

import (
	"net/netip"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
)

// TestKnownAdminDeviceIsNotRefusedByTheScopesStrangersFill is the admin side of rule
// budget-keying: strangers on the admin's own network (a carrier NAT) fill every scope
// a network or a username can fill, and the browser that carries the admin's device
// marker still signs in, because it is charged to the marker's own scope and to no
// network scope. A browser with no marker on that network is refused, and a marker that
// has spent its own scope is refused wherever it goes.
func TestKnownAdminDeviceIsNotRefusedByTheScopesStrangersFill(t *testing.T) {
	r := newRig(t)
	seed := r.setupAdmin(t, true)
	home := r.browser()
	home.mustLogin(seed)
	if home.jar[session.CookieAdminDevice] == nil {
		t.Fatal("a login should leave a device marker")
	}
	svc := throttle.NewAdmin(r.adm.Admin(), r.keys)
	ip := netip.MustParseAddr(home.ip)
	who := throttle.Who{Username: adminName, IP: ip}
	for _, sc := range []throttle.Scope{throttle.AdminLogin, throttle.AdminLoginUser, throttle.AdminLoginNet} {
		for i := 0; i < 100; i++ {
			if svc.Charge(r.env.Ctx, sc, who) != nil {
				break
			}
		}
	}

	stranger := r.browser()
	stranger.ip = home.ip
	r.freeStep(t)
	stranger.login(adminPW, totpNow(seed)).want(429, "too_many_attempts")
	r.freeStep(t)
	home.login(adminPW, totpNow(seed)).want(200, "")

	// The marker's own scope is the one budget it has, wherever it comes from.
	pb, _ := budget.FindScope("admin_login_marker")
	mover := r.browser()
	mover.jar[session.CookieAdminDevice] = home.jar[session.CookieAdminDevice]
	refused := 0
	for i := 0; i < pb.Max+3; i++ {
		mover.ip = freshIP()
		if mover.login("wrong-wrong-wrong-1", "").Code == 429 {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("a marker that moved networks on every try was never refused")
	}
}
