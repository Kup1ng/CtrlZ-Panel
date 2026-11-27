package setup

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Generator is one artifact the panel gives a user for one kind of client
// (P3 8.2). Run reads only the ResolverView, so every host, URL and address in
// the output is one the view holds and the order and strict settings of
// SC 8a.8 live in the generators and nowhere else.
//
// The Apple profile is the registry's one member that is not here: it is built
// by internal/mobileconfig from the same view. The Linux script and the in-panel
// guide join in P7 (T-367, T-452).
type Generator struct {
	ID       string
	Platform string
	Run      func(ResolverView) (string, error)
}

// Generators returns the registry, built fresh on each call. Check E7 walks it.
func Generators() []Generator {
	return []Generator{
		{ID: "windows-doh", Platform: "windows", Run: WindowsCommands},
		{ID: "firefox-policy", Platform: "firefox", Run: FirefoxPolicy},
		{ID: "chromium-policy", Platform: "chrome edge brave", Run: ChromiumPolicy},
		{ID: "android-private-dns", Platform: "android", Run: AndroidPrivateDNS},
		{ID: "address-list", Platform: "router apple-tv android-tv fire-tv samsung-tv", Run: AddressList},
	}
}

// WindowsCommands is R31: Set-DnsClientServerAddress with the primary first, and
// one DoH template per address, each with -AllowFallbackToUdp $False and
// -AutoUpgrade $True. Without the first, Windows would fall back to plaintext
// when the server fails; with it, a failure gives no DNS for that minute, which
// is the outage the owner accepted (SC 8a.8). The DoH template is the Endpoint's
// URL, which carries the DoH token; the person pastes it into their own
// PowerShell.
func WindowsCommands(v ResolverView) (string, error) {
	if !v.Ready {
		return "", ErrNotReady
	}
	p, f := v.Legacy.DNS1.String(), v.Legacy.DNS2.String()
	var b strings.Builder
	// The loop sets every adapter that is up, so the person names no interface.
	b.WriteString("Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | ForEach-Object {\n")
	b.WriteString("  Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses ('" + p + "','" + f + "')\n")
	b.WriteString("}\n")
	for _, a := range []string{p, f} {
		b.WriteString("Add-DnsClientDohServerAddress -ServerAddress '" + a + "' -DohTemplate '" + v.DoHURL +
			"' -AllowFallbackToUdp $False -AutoUpgrade $True\n")
	}
	return b.String(), nil
}

func policyJSON(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// FirefoxPolicy is the enterprise policy DNSOverHTTPS with Fallback false: the
// same as network.trr.mode 3 (Max Protection), and never mode 2. There is no
// bootstrap address, so Firefox resolves the hostname itself and follows the
// failover of SC 8a.3.
func FirefoxPolicy(v ResolverView) (string, error) {
	if !v.Ready {
		return "", ErrNotReady
	}
	type doh struct {
		Enabled     bool   `json:"Enabled"`
		ProviderURL string `json:"ProviderURL"`
		Locked      bool   `json:"Locked"`
		Fallback    bool   `json:"Fallback"`
	}
	return policyJSON(map[string]map[string]doh{"policies": {"DNSOverHTTPS": {
		Enabled: true, ProviderURL: v.DoHURL, Locked: true, Fallback: false,
	}}})
}

// ChromiumPolicy is the policy pair Chrome, Edge and Brave all read: mode
// "secure" (never "automatic", which falls back to plaintext) with the
// Endpoint's URL as the template. The URL holds the hostname and no address.
func ChromiumPolicy(v ResolverView) (string, error) {
	if !v.Ready {
		return "", ErrNotReady
	}
	return policyJSON(struct {
		Mode      string `json:"DnsOverHttpsMode"`
		Templates string `json:"DnsOverHttpsTemplates"`
	}{"secure", v.DoHURL})
}

// AndroidPrivateDNS is the "Private DNS provider hostname" value, which is the
// Endpoint hostname. "Automatic" is never offered: it falls back to plaintext.
func AndroidPrivateDNS(v ResolverView) (string, error) {
	if !v.Ready {
		return "", ErrNotReady
	}
	return v.Host + "\n", nil
}

// AddressList is what routers and TVs take, which are set by address: DNS1 the
// primary and DNS2 the fallback. Plain DNS identity is the claim of the
// network (SC 3.3), which the wizard step explains.
func AddressList(v ResolverView) (string, error) {
	if !v.Ready {
		return "", ErrNotReady
	}
	return "DNS1 " + v.Legacy.DNS1.String() + "\nDNS2 " + v.Legacy.DNS2.String() + "\n", nil
}
