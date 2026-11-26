package hubctl

import (
	"crypto/sha256"
	"net/netip"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubtrust"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// ConfigBuilder turns the rows of one node into its NodeConfig (p4-nodes 4.4). It holds the proof key, which the nodes get
// only through this message and which no table stores.
type ConfigBuilder struct {
	ProofKey []byte
	Now      func() time.Time
}

func ipBytes(a netip.Addr) []byte {
	if !a.IsValid() {
		return nil
	}
	a = a.Unmap()
	return a.AsSlice()
}

func kindOf(s string) commonv1.UpstreamKind {
	switch s {
	case "udp":
		return commonv1.UpstreamKind_UPSTREAM_KIND_UDP
	case "doh":
		return commonv1.UpstreamKind_UPSTREAM_KIND_DOH
	case "dot":
		return commonv1.UpstreamKind_UPSTREAM_KIND_DOT
	case "doq":
		return commonv1.UpstreamKind_UPSTREAM_KIND_DOQ
	}
	return commonv1.UpstreamKind_UPSTREAM_KIND_UNSPECIFIED
}

func modeOf(s string) commonv1.ResolveMode {
	switch s {
	case "recursive":
		return commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE
	case "upstream":
		return commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM
	case "mixed":
		return commonv1.ResolveMode_RESOLVE_MODE_HYBRID
	}
	return commonv1.ResolveMode_RESOLVE_MODE_UNSPECIFIED
}

// Zones are the live zones of a read (4.3).
func (b *ConfigBuilder) Zones(r store.HubConfigRead) []string {
	return hubtrust.LiveZones(store.HubZones{DNSZone: r.DNSZone, PrevDNSZone: r.PrevZone, TransitionUntil: r.PrevUntil}, b.Now())
}

// Build makes the message with version 0 (the stream gives the version, L1) and checks it with the node's own validator,
// so the hub never sends what the node would refuse: a row the database allows and the validator does not (a rule that does
// not parse) keeps the node on its last config and is logged by the caller.
func (b *ConfigBuilder) Build(r store.HubConfigRead) (*hubv1.NodeConfig, error) {
	// The validator wants all four addresses, and a node enrolled with no proxy address has none in its row. Until the proxy
	// exists (P4b) it is told its DNS address in the proxy fields: nothing listens there, and the node has no other way to
	// say "none" in a message the validator accepts.
	proxyBind, proxyAdv := r.ProxyBind, r.ProxyAdv
	if !proxyBind.IsValid() {
		proxyBind = r.DNSBind
	}
	if !proxyAdv.IsValid() {
		proxyAdv = r.DNSAdv
	}
	c := &hubv1.NodeConfig{
		DnsBindIp: ipBytes(r.DNSBind), DnsAdvertisedIp: ipBytes(r.DNSAdv),
		ProxyBindIp: ipBytes(proxyBind), ProxyAdvertisedIp: ipBytes(proxyAdv),
		Zones: b.Zones(r), Mode: modeOf(r.ResolveMode), ProofKey: b.ProofKey,
	}
	for _, h := range []string{r.PanelHost, r.AdminHost} {
		if h = strings.ToLower(h); h != "" {
			c.PanelHostnames = append(c.PanelHostnames, h)
		}
	}
	groups := map[string]*hubv1.UpstreamGroup{}
	for _, u := range r.Upstreams { // ordered by group and position
		c.Upstreams = append(c.Upstreams, &hubv1.Upstream{
			Id: u.ID[:], Kind: kindOf(u.Kind), Address: u.Address, BootstrapIp: ipBytes(u.Bootstrap), TlsName: u.TLSName,
			TimeoutMs: uint32(u.TimeoutMS), HealthIntervalS: uint32(u.HealthSec), Trusted: u.Trusted, ViaLocation: uint32(u.ViaWire),
		})
		g := groups[u.Group]
		if g == nil {
			g = &hubv1.UpstreamGroup{Name: u.Group}
			groups[u.Group] = g
			c.Groups = append(c.Groups, g)
		}
		g.UpstreamIds = append(g.UpstreamIds, u.ID[:])
	}
	for _, x := range r.Rules {
		c.Rules = append(c.Rules, &hubv1.ResolverRule{Order: uint32(x.Position), MatchType: x.MatchType, MatchValue: x.Value, Group: x.Group, FinalDefault: x.Final})
	}
	if err := wire.ValidateNodeConfig(c); err != nil {
		return nil, err
	}
	return c, nil
}

// Hash is the SHA-256 of the content, version aside: the hub sends again only when it changes (4.4, L1).
func Hash(c *hubv1.NodeConfig) []byte {
	v := c.Version
	c.Version = 0
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(c)
	c.Version = v
	sum := sha256.Sum256(b)
	return sum[:]
}

// NextVersion is the version of the next NodeConfig for a node: above what the node reported and above what the hub last sent
// it, and never below the clock in milliseconds, so neither a hub restart nor a panel clock stepped back leaves a node refusing
// (L1).
func NextVersion(reported, lastSent uint64, now time.Time) uint64 {
	return max(reported+1, lastSent+1, uint64(now.UnixMilli()))
}
