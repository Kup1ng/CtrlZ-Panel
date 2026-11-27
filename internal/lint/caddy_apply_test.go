package lint_test

import (
	"regexp"
	"strings"
	"testing"
)

// The Caddyfile and `ctrlz domain-apply` meet in two places (p4-nodes 10.4): the global option that keeps Caddy from
// asking an OCSP responder (rule 9: nothing at run time depends on the international internet, and a public certificate
// names a responder abroad), and the one line each site imports the apply step's snippet by. The snippet holds the only
// "tls" line a site ever has, so a site that also says "tls" itself would meet two. This checks the file for both, and
// the apply step's own test checks that what it writes is what these lines import.

var (
	caddyGlobalBlock = regexp.MustCompile(`(?s)\A(?:#[^\n]*\n|\s)*\{\n(.*?)\n\}\n`)
	caddySiteHead    = regexp.MustCompile(`(?m)^(\{\$CTRLZ_(PANEL|ADMIN)_HOST:[a-z.]+\}) \{$`)
)

func caddyApplyProblems(cf string) []string {
	var out []string
	g := caddyGlobalBlock.FindStringSubmatch(cf)
	if g == nil {
		return []string{"the Caddyfile has no global options block"}
	}
	if !regexp.MustCompile(`(?m)^\tocsp_stapling off$`).MatchString(g[1]) {
		out = append(out, "the global block does not say `ocsp_stapling off`: Caddy would ask the responder named in a public certificate")
	}
	if !regexp.MustCompile(`(?m)^\tlocal_certs$`).MatchString(g[1]) {
		out = append(out, "the global block does not say `local_certs`: a host with no certificate of ours would ask a public CA")
	}
	if !regexp.MustCompile(`(?m)^\tskip_install_trust$`).MatchString(g[1]) {
		out = append(out, "the global block does not say `skip_install_trust`: Caddy would try to write its root into the read-only trust store and log a fault at every start")
	}
	heads := caddySiteHead.FindAllStringSubmatchIndex(cf, -1)
	if len(heads) != 2 {
		return append(out, "the Caddyfile does not have exactly the panel and the admin site blocks")
	}
	for i, h := range heads {
		end := len(cf)
		if i+1 < len(heads) {
			end = heads[i+1][0]
		}
		block := cf[h[0]:end]
		name := cf[h[2]:h[3]]
		want := "\timport /data/ctrlz-tls/" + strings.TrimSuffix(name, "}") + "}.cadd?\n"
		if strings.Count(block, want) != 1 {
			out = append(out, "the site "+name+" does not import its apply snippet by exactly the line "+strings.TrimSpace(want))
		}
		if regexp.MustCompile(`(?m)^\s*tls\b`).MatchString(block) {
			out = append(out, "the site "+name+" has a tls line of its own; the snippet of domain-apply is the only one it may have")
		}
	}
	return out
}

func TestCaddyfileImportsTheApplySnippetsAndStopsOCSP(t *testing.T) {
	if p := caddyApplyProblems(readDeploy(t, "caddy", "Caddyfile")); len(p) != 0 {
		t.Fatalf("%s", strings.Join(p, "\n"))
	}
}

func TestCaddyApplyLintCanFail(t *testing.T) {
	good := readDeploy(t, "caddy", "Caddyfile")
	if p := caddyApplyProblems(good); len(p) != 0 {
		t.Fatalf("the real file is refused: %v", p)
	}
	for name, c := range map[string]struct{ old, repl, want string }{
		"ocsp on again":         {"\tocsp_stapling off\n", "", "ocsp_stapling"},
		"no local certs":        {"\tlocal_certs\n", "", "local_certs"},
		"trust install on":      {"\tskip_install_trust\n", "", "skip_install_trust"},
		"a site without import": {"\timport /data/ctrlz-tls/{$CTRLZ_ADMIN_HOST:admin.localhost}.cadd?\n", "", "does not import"},
		"a site with its own tls": {"\timport /data/ctrlz-tls/{$CTRLZ_PANEL_HOST:panel.localhost}.cadd?\n",
			"\timport /data/ctrlz-tls/{$CTRLZ_PANEL_HOST:panel.localhost}.cadd?\n\ttls internal\n", "tls line"},
	} {
		if !strings.Contains(good, c.old) {
			t.Fatalf("%s: the anchor %q is not in the Caddyfile", name, c.old)
		}
		p := strings.Join(caddyApplyProblems(strings.Replace(good, c.old, c.repl, 1)), "\n")
		if !strings.Contains(p, c.want) {
			t.Errorf("%s: not caught (%q)", name, p)
		}
	}
}
