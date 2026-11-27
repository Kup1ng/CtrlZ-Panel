package store

import (
	"context"
	"net/netip"

	"github.com/jackc/pgx/v5"
)

// PublicFreeDNS is what the route without a login shows (p4-nodes 9.3, Plan T-556): whether free DNS is on, and the
// advertised addresses of the global pair's primary and fallback, each nil when there is no global pair or that node is
// not active. It is install values of the operator: no tenant data, no client address.
type PublicFreeDNS struct {
	Enabled  bool
	Primary  *netip.Addr
	Fallback *netip.Addr
}

const qFreeDNSPublic = `SELECT enabled, primary_dns_ip, fallback_dns_ip FROM ctrlz_fn.free_dns_public()`

// FreeDNSPublic reads free_dns_public(). ctrlz_tenant has no grant on the tables and WithGlobal refuses that role, so a
// definer function is the way, as for PublicConfig.
func (a AuthLookups) FreeDNSPublic(ctx context.Context) (PublicFreeDNS, error) {
	v, ok, err := one(ctx, a.s, qFreeDNSPublic, func(r pgx.Row) (p PublicFreeDNS, err error) {
		err = r.Scan(&p.Enabled, scanAddr(&p.Primary), scanAddr(&p.Fallback))
		return p, err
	})
	if err == nil && !ok {
		err = ErrDriver // the function always returns its one row; none is a broken database
	}
	return v, err
}
