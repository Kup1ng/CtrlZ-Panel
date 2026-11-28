package sharelink

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Kup1ng/CtrlZ-Shared/xrayschema"
)

// Convert turns one share link into the text of a fragment {"outbounds":[outbound]}.
// note is the remark of the link, protocol the Xray protocol of the outbound. The
// error never holds a value of the link, only the name of a parameter.
func Convert(link string) (fragment []byte, note, protocol string, err error) {
	c, err := convert(link)
	if err != nil {
		return nil, "", "", err
	}
	return c.fragment, c.note, c.protocol, nil
}

// converted is what one link gives. omitted names what the link carries and the
// fragment leaves out because the exit works without it: the panel lists each in the diff
// of the candidate (7.3).
type converted struct {
	fragment []byte
	note     string
	protocol string
	omitted  []string
}

func convert(link string) (converted, error) {
	if len(link) > MaxLineBytes {
		return converted{}, errors.New("the link is too long")
	}
	if !utf8.ValidString(link) {
		return converted{}, errors.New("the link is not valid UTF-8")
	}
	scheme, rest, ok := strings.Cut(link, "://")
	if !ok || rest == "" {
		return converted{}, errors.New("not a share link: no scheme")
	}
	var (
		ob      map[string]any
		note    string
		omitted []string
		err     error
	)
	switch strings.ToLower(scheme) {
	case "vless":
		ob, note, omitted, err = convertVLESS(rest)
	case "vmess":
		ob, note, omitted, err = convertVMess(rest)
	case "trojan":
		ob, note, omitted, err = convertTrojan(rest)
	case "ss":
		ob, note, omitted, err = convertSS(rest)
	case "hysteria2", "hy2":
		ob, note, omitted, err = convertHysteria2(rest)
	default:
		return converted{}, errors.New("unknown scheme: the converter knows vless, vmess, trojan, ss and hysteria2")
	}
	if err != nil {
		return converted{}, err
	}
	protocol, _ := ob["protocol"].(string)
	fragment, err := json.Marshal(map[string]any{"outbounds": []any{ob}})
	if err != nil {
		return converted{}, err
	}
	// A link gives keys of the allow-list alone, so its candidate never carries a warning
	// (7.3): a value that is not of the kind of its key is an error of the line, because
	// the exit may not work without it. The reason names the key and its kind, never the
	// value.
	r := xrayschema.Newest().Check(fragment, nil)
	switch {
	case len(r.Rejected) != 0:
		return converted{}, fmt.Errorf("%s: %s", r.Rejected[0].Path, r.Rejected[0].Msg)
	case len(r.Warnings) != 0:
		reason, _, _ := strings.Cut(r.Warnings[0].Msg, "; Ctrl Z does not judge")
		return converted{}, fmt.Errorf("%s: %s; the link cannot be used as it is, and an exit like this is pasted as JSON", r.Warnings[0].Path, reason)
	}
	sort.Strings(omitted)
	return converted{fragment: fragment, note: clipNote(note), protocol: protocol, omitted: omitted}, nil
}

func clipNote(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > 120 {
		s = string([]rune(s)[:120])
	}
	return s
}

// ---- parameters ---------------------------------------------------------------------

// params is the query of a link, by lower-case name. A name given twice is an
// error, and a name nobody read is an error too: that is how "unknown parameter" is
// found without a list per scheme.
type params struct {
	m    map[string]string
	used map[string]bool
	// omitted names what the link carries and the converter leaves out (7.3).
	omitted []string
}

func (p *params) omit(name string) { p.omitted = append(p.omitted, name) }

func newParams() *params { return &params{m: map[string]string{}, used: map[string]bool{}} }

func parseQuery(raw string) (*params, error) {
	p := newParams()
	if raw == "" {
		return p, nil
	}
	for _, kv := range strings.Split(raw, "&") {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		k, err1 := url.QueryUnescape(k)
		v, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil {
			return nil, errors.New("a parameter is not percent-encoded correctly")
		}
		k = strings.ToLower(k)
		if _, dup := p.m[k]; dup {
			return nil, fmt.Errorf("parameter %q is given twice", clipName(k))
		}
		p.m[k] = v
	}
	return p, nil
}

func clipName(s string) string {
	if len(s) > 32 {
		s = s[:32]
	}
	return strings.ToValidUTF8(s, "?")
}

func (p *params) get(name string) string {
	p.used[name] = true
	return p.m[name]
}

func (p *params) has(name string) bool {
	p.used[name] = true
	_, ok := p.m[name]
	return ok
}

// leftover fails on the first parameter nobody read.
func (p *params) leftover() error {
	var names []string
	for k := range p.m {
		if !p.used[k] {
			names = append(names, k)
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	return fmt.Errorf("unknown parameter %q", clipName(names[0]))
}

func (p *params) boolean(name string) (bool, error) {
	switch strings.ToLower(p.get(name)) {
	case "", "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	}
	return false, fmt.Errorf("parameter %q is not 0, 1, true or false", name)
}

// ---- host, port ---------------------------------------------------------------------

func splitHostPort(hostport string) (string, int, error) {
	host, port := "", ""
	switch {
	case strings.HasPrefix(hostport, "["):
		end := strings.Index(hostport, "]")
		if end < 0 || end+1 >= len(hostport) || hostport[end+1] != ':' {
			return "", 0, errors.New("the address is not [host]:port")
		}
		host, port = hostport[1:end], hostport[end+2:]
	default:
		i := strings.LastIndex(hostport, ":")
		if i < 0 {
			return "", 0, errors.New("the address has no port")
		}
		host, port = hostport[:i], hostport[i+1:]
	}
	return checkHostPort(host, port)
}

func checkHostPort(host, port string) (string, int, error) {
	if host == "" || len(host) > 253 {
		return "", 0, errors.New("the host is empty or too long")
	}
	for _, r := range host {
		if r <= 0x20 || r == 0x7f {
			return "", 0, errors.New("the host has a space or a control character")
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return "", 0, errors.New("the port is not a number from 1 to 65535")
	}
	return host, n, nil
}

// parseURL reads scheme-less text after "scheme://" through net/url.
func parseURL(scheme, rest string) (*url.URL, error) {
	u, err := url.Parse(scheme + "://" + rest)
	if err != nil {
		return nil, errors.New("the link is not a valid URL")
	}
	return u, nil
}

func hostPortOf(u *url.URL) (string, int, error) {
	return checkHostPort(u.Hostname(), u.Port())
}

// ---- stream settings ----------------------------------------------------------------

// streamParams are the parameters stream reads. Each is judged as used or stray.
func streamParams() []string {
	return []string{"type", "security", "host", "path", "headertype", "servicename", "authority", "mode", "extra", "seed",
		"sni", "fp", "alpn", "allowinsecure", "pcs", "ech", "pbk", "sid", "spx", "pqv"}
}

func parseBool(name, v string) (bool, error) {
	switch strings.ToLower(v) {
	case "", "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	}
	return false, fmt.Errorf("parameter %q is not 0, 1, true or false", name)
}

// stream builds streamSettings from the parameters every scheme shares. security is
// the default when the link names none. A parameter that carries a value the chosen
// transport or security does not use is an error: it would be a setting the admin
// believes is on.
func stream(p *params, defaultSecurity string) (map[string]any, error) {
	consumed := map[string]bool{}
	rd := func(name string) string { consumed[name] = true; return p.m[name] }
	ss := map[string]any{}
	typ := strings.ToLower(rd("type"))
	switch typ {
	case "", "tcp", "raw":
		ss["method"] = "raw"
		switch strings.ToLower(rd("headertype")) {
		case "", "none":
		case "http":
			req := map[string]any{}
			if path := rd("path"); path != "" {
				req["path"] = splitList(path)
			}
			if host := rd("host"); host != "" {
				req["headers"] = map[string]any{"Host": splitList(host)}
			}
			ss["rawSettings"] = map[string]any{"header": map[string]any{"type": "http", "request": req}}
		default:
			return nil, errors.New("parameter \"headertype\" has a value the converter does not know for tcp")
		}
	case "ws", "websocket":
		ss["method"] = "ws"
		ws := map[string]any{}
		setIf(ws, "path", rd("path"))
		setIf(ws, "host", rd("host"))
		ss["wsSettings"] = ws
	case "httpupgrade":
		// Not on the list (7.2): its dialer panics when the exit sends bytes after the 101
		// header, so an exit that offers it is pasted as JSON, where the admin accepts it.
		return nil, errors.New("parameter \"type\" is httpupgrade, which is not on the list of the allow-list: use ws or xhttp, or paste the exit as JSON")
	case "grpc":
		ss["method"] = "grpc"
		g := map[string]any{}
		setIf(g, "serviceName", rd("servicename"))
		setIf(g, "authority", rd("authority"))
		switch strings.ToLower(rd("mode")) {
		case "multi":
			// Not on the list (7.2): one message of the exit makes the client of the
			// release allocate gigabytes, so a multi exit is pasted as JSON, where the
			// admin accepts it knowing that (B1n-r2-3).
			return nil, errors.New("parameter \"mode\" is multi for grpc, which is not on the list of the allow-list: use gun, or paste the exit as JSON")
		case "", "gun":
		default:
			return nil, errors.New("parameter \"mode\" is not gun for grpc")
		}
		ss["grpcSettings"] = g
	case "xhttp", "splithttp":
		ss["method"] = "xhttp"
		x := map[string]any{}
		setIf(x, "path", rd("path"))
		setIf(x, "host", rd("host"))
		setIf(x, "mode", rd("mode"))
		if e := rd("extra"); e != "" {
			var extra map[string]any
			if err := json.Unmarshal([]byte(e), &extra); err != nil || extra == nil {
				return nil, errors.New("parameter \"extra\" is not a JSON object")
			}
			if repeatsAKey([]byte(e)) {
				return nil, errors.New("parameter \"extra\" gives a key twice")
			}
			kept, err := filterExtra(p, extra)
			if err != nil {
				return nil, err
			}
			if len(kept) > 0 {
				x["extra"] = kept
			}
		}
		ss["xhttpSettings"] = x
	case "kcp", "mkcp":
		// kcp is an unknown value of 7.2 and its settings moved to masks in this release, so
		// a link cannot carry it: the exit is pasted as JSON, where the admin accepts it.
		return nil, errors.New("parameter \"type\" is kcp, which is not on the list of the allow-list: paste the exit as JSON")
	case "h2", "http", "quic":
		return nil, errors.New("this transport was removed from Xray: use xhttp")
	default:
		return nil, errors.New("parameter \"type\" names a transport the converter does not know")
	}

	sec := strings.ToLower(rd("security"))
	if sec == "" {
		sec = defaultSecurity
	}
	switch sec {
	case "none":
	case "tls":
		ss["security"] = "tls"
		t := map[string]any{}
		setIf(t, "serverName", rd("sni"))
		setIf(t, "fingerprint", rd("fp"))
		if a := rd("alpn"); a != "" {
			t["alpn"] = splitList(a)
		}
		ins, err := parseBool("allowinsecure", rd("allowinsecure"))
		if err != nil {
			return nil, err
		}
		if ins {
			// The pinned release refuses allowInsecure true whatever else is set, so a
			// candidate that carries it could only fail at the node's -test.
			return nil, errNoInsecure("allowinsecure", "pcs")
		}
		// Links separate several pins with "~"; the loader of Xray splits on "," alone.
		setIf(t, "pinnedPeerCertSha256", strings.ReplaceAll(rd("pcs"), "~", ","))
		// ECH is not on the list (7.2), and the exit may not work without it, so the link is
		// an error of its line and the exit is pasted as JSON. A value with :// would also
		// make Xray ask a DoH, h2c or UDP server for the record, which is refused for good.
		if rd("ech") != "" {
			return nil, errors.New("parameter \"ech\" is not on the list of the allow-list: paste the exit as JSON")
		}
		ss["tlsSettings"] = t
	case "reality":
		ss["security"] = "reality"
		r := map[string]any{}
		setIf(r, "serverName", rd("sni"))
		setIf(r, "fingerprint", rd("fp"))
		setIf(r, "publicKey", rd("pbk"))
		setIf(r, "shortId", rd("sid"))
		// Xray reads p, c, t, i and r of a query in spiderX as unbounded crawler settings of
		// the REALITY fallback; a link needs only a path.
		if spx := rd("spx"); strings.Contains(spx, "?") {
			return nil, errors.New("parameter \"spx\" has a query part: only a path is accepted")
		} else {
			setIf(r, "spiderX", spx)
		}
		// The post-quantum verification only adds a check of the server; the exit works
		// without it, so it is left out with a line in the diff (7.3).
		if rd("pqv") != "" {
			p.omit("pqv")
		}
		if r["publicKey"] == nil {
			return nil, errors.New("security reality needs parameter \"pbk\"")
		}
		ss["realitySettings"] = r
	case "xtls":
		return nil, errors.New("legacy XTLS was removed from Xray: use flow with tls or reality")
	default:
		return nil, errors.New("parameter \"security\" has a value the converter does not know")
	}
	for _, name := range streamParams() {
		p.used[name] = true
		if v := p.m[name]; v != "" && !consumed[name] && !(name == "allowinsecure" && (v == "0" || strings.EqualFold(v, "false"))) {
			return nil, fmt.Errorf("parameter %q does not apply to this transport or security", name)
		}
	}
	return ss, nil
}

// errNoInsecure names the parameter and the one that replaces it. The release refuses
// tlsSettings.allowInsecure true for good, so the converter says so by name instead of
// handing the checker a value it must refuse.
func errNoInsecure(param, instead string) error {
	return fmt.Errorf("parameter %q is refused: Xray no longer accepts it, pin the certificate with %q", param, instead)
}

// noPassword refuses the password part of the user info of a link whose scheme has
// only an id there: "id:extra@host" would otherwise lose ":extra" without a word (R14).
func noPassword(u *url.URL) error {
	if _, has := u.User.Password(); has {
		return errors.New("the user info has a password part, and the id of this scheme has none")
	}
	return nil
}

func setIf(m map[string]any, key, val string) {
	if val != "" {
		m[key] = val
	}
}

func splitList(s string) []any {
	var out []any
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func remark(u *url.URL) string { return u.Fragment }

// ---- schemes ------------------------------------------------------------------------

func newOutbound(protocol string, settings, ss map[string]any) map[string]any {
	ob := map[string]any{"protocol": protocol, "settings": settings}
	if len(ss) > 0 {
		ob["streamSettings"] = ss
	}
	return ob
}

func convertVLESS(rest string) (map[string]any, string, []string, error) {
	u, err := parseURL("vless", rest)
	if err != nil {
		return nil, "", nil, err
	}
	host, port, err := hostPortOf(u)
	if err != nil {
		return nil, "", nil, err
	}
	id := u.User.Username()
	if id == "" || len(id) > 64 {
		return nil, "", nil, errors.New("the user id is empty or too long")
	}
	if err := noPassword(u); err != nil {
		return nil, "", nil, err
	}
	p, err := parseQuery(u.RawQuery)
	if err != nil {
		return nil, "", nil, err
	}
	enc := p.get("encryption")
	if enc == "" {
		enc = "none"
	}
	// Only none is on the list (7.2): the post-quantum text carries sleeps that nothing
	// cancels, and the exit may not work without it, so the link is an error of its line.
	if enc != "none" {
		return nil, "", nil, errors.New("parameter \"encryption\" is not none: paste the exit as JSON")
	}
	settings := map[string]any{"address": host, "port": port, "id": id, "encryption": enc}
	setIf(settings, "flow", p.get("flow"))
	ss, err := stream(p, "none")
	if err != nil {
		return nil, "", nil, err
	}
	if err := p.leftover(); err != nil {
		return nil, "", nil, err
	}
	return newOutbound("vless", settings, ss), remark(u), p.omitted, nil
}

func convertTrojan(rest string) (map[string]any, string, []string, error) {
	u, err := parseURL("trojan", rest)
	if err != nil {
		return nil, "", nil, err
	}
	host, port, err := hostPortOf(u)
	if err != nil {
		return nil, "", nil, err
	}
	pw := u.User.Username()
	if p, ok := u.User.Password(); ok {
		pw += ":" + p
	}
	if pw == "" {
		return nil, "", nil, errors.New("the password is empty")
	}
	p, err := parseQuery(u.RawQuery)
	if err != nil {
		return nil, "", nil, err
	}
	if p.has("flow") {
		return nil, "", nil, errors.New("parameter \"flow\" is not supported for trojan in this release")
	}
	ss, err := stream(p, "tls")
	if err != nil {
		return nil, "", nil, err
	}
	if err := p.leftover(); err != nil {
		return nil, "", nil, err
	}
	settings := map[string]any{"address": host, "port": port, "password": pw}
	return newOutbound("trojan", settings, ss), remark(u), p.omitted, nil
}

// decodeBase64 takes the four spellings a link may use: standard or URL alphabet,
// with or without padding.
func decodeBase64(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

func convertVMess(rest string) (map[string]any, string, []string, error) {
	if strings.Contains(rest, "@") {
		return convertVMessURI(rest)
	}
	body, _, _ := strings.Cut(rest, "#")
	b, ok := decodeBase64(strings.TrimSpace(body))
	if !ok {
		return nil, "", nil, errors.New("the vmess link is neither base64 JSON nor a URI")
	}
	var j map[string]any
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&j); err != nil || j == nil {
		return nil, "", nil, errors.New("the vmess link does not hold a JSON object")
	}
	// Decode reads one value and ignores what follows it, so a second object or a stray
	// word after the first would be dropped without a word (R14).
	if _, err := dec.Token(); err != io.EOF {
		return nil, "", nil, errors.New("the vmess link has text after its JSON object")
	}
	if repeatsAKey(b) {
		return nil, "", nil, errors.New("the vmess JSON gives a field twice")
	}
	str := func(k string) (string, error) {
		v, ok := j[k]
		if !ok {
			return "", nil
		}
		switch x := v.(type) {
		case string:
			return x, nil
		case json.Number:
			return x.String(), nil
		case bool:
			return strconv.FormatBool(x), nil
		}
		return "", fmt.Errorf("field %q is not a string or a number", clipName(k))
	}
	known := map[string]bool{"v": true, "ps": true, "add": true, "port": true, "id": true, "aid": true, "scy": true, "net": true,
		"type": true, "host": true, "path": true, "tls": true, "sni": true, "alpn": true, "fp": true, "allowinsecure": true}
	lower := map[string]string{}
	var keys []string
	for k := range j {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		lk := strings.ToLower(k)
		if !known[lk] {
			return nil, "", nil, fmt.Errorf("unknown field %q", clipName(k))
		}
		if _, dup := lower[lk]; dup {
			return nil, "", nil, fmt.Errorf("field %q is given twice", clipName(lk))
		}
		s, err := str(k)
		if err != nil {
			return nil, "", nil, err
		}
		lower[lk] = s
	}
	if aid := lower["aid"]; aid != "" && aid != "0" {
		return nil, "", nil, errors.New("field \"aid\" must be 0: legacy VMess is not supported")
	}
	host, port, err := checkHostPort(lower["add"], lower["port"])
	if err != nil {
		return nil, "", nil, err
	}
	if lower["id"] == "" || len(lower["id"]) > 64 {
		return nil, "", nil, errors.New("the user id is empty or too long")
	}
	p := newParams()
	net := strings.ToLower(lower["net"])
	switch net {
	case "", "tcp":
		p.m["type"] = "tcp"
		p.m["headertype"] = lower["type"]
		p.m["host"], p.m["path"] = lower["host"], lower["path"]
	case "ws", "xhttp":
		p.m["type"] = net
		p.m["host"], p.m["path"] = lower["host"], lower["path"]
		// v2rayN keeps the xhttp mode in "type"; for ws it holds only none.
		switch t := strings.ToLower(lower["type"]); {
		case t == "" || t == "none":
		case net == "xhttp":
			p.m["mode"] = lower["type"]
		default:
			return nil, "", nil, errors.New("field \"type\" must be none or empty for ws")
		}
	case "grpc":
		p.m["type"] = "grpc"
		p.m["servicename"], p.m["authority"], p.m["mode"] = lower["path"], lower["host"], lower["type"]
	case "kcp", "mkcp":
		p.m["type"] = "kcp"
		p.m["seed"], p.m["headertype"] = lower["path"], lower["type"]
		// host has no place in kcp; stream refuses it by name, so it is not lost silently.
		p.m["host"] = lower["host"]
	default:
		p.m["type"] = net
	}
	switch tls := strings.ToLower(lower["tls"]); tls {
	case "", "none":
		p.m["security"] = "none"
	case "tls":
		p.m["security"] = "tls"
	default:
		return nil, "", nil, errors.New("field \"tls\" is not tls or empty")
	}
	p.m["sni"], p.m["alpn"], p.m["fp"] = lower["sni"], lower["alpn"], lower["fp"]
	p.m["allowinsecure"] = lower["allowinsecure"]
	ss, err := stream(p, "none")
	if err != nil {
		return nil, "", nil, err
	}
	scy := lower["scy"]
	if scy == "" {
		scy = "auto"
	}
	settings := map[string]any{"address": host, "port": port, "id": lower["id"], "security": scy}
	return newOutbound("vmess", settings, ss), lower["ps"], p.omitted, nil
}

func convertVMessURI(rest string) (map[string]any, string, []string, error) {
	u, err := parseURL("vmess", rest)
	if err != nil {
		return nil, "", nil, err
	}
	host, port, err := hostPortOf(u)
	if err != nil {
		return nil, "", nil, err
	}
	id := u.User.Username()
	if id == "" || len(id) > 64 {
		return nil, "", nil, errors.New("the user id is empty or too long")
	}
	if err := noPassword(u); err != nil {
		return nil, "", nil, err
	}
	p, err := parseQuery(u.RawQuery)
	if err != nil {
		return nil, "", nil, err
	}
	scy := p.get("encryption")
	if scy == "" {
		scy = "auto"
	}
	ss, err := stream(p, "none")
	if err != nil {
		return nil, "", nil, err
	}
	if err := p.leftover(); err != nil {
		return nil, "", nil, err
	}
	settings := map[string]any{"address": host, "port": port, "id": id, "security": scy}
	return newOutbound("vmess", settings, ss), remark(u), p.omitted, nil
}

// convertSS reads SIP002 (base64url or percent-encoded user info before @), SIP022
// (a plain "method:password" with a base64 key, percent-encoded) and the old whole-link
// base64 form. A plugin is refused: it would run a program on the node.
func convertSS(rest string) (map[string]any, string, []string, error) {
	rest, frag, _ := strings.Cut(rest, "#")
	note, err := url.PathUnescape(frag)
	if err != nil {
		return nil, "", nil, errors.New("the remark is not percent-encoded correctly")
	}
	rest, query, _ := strings.Cut(rest, "?")
	rest = strings.TrimSuffix(rest, "/")
	var method, password, hostport string
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		ui, err := url.PathUnescape(rest[:i])
		if err != nil {
			return nil, "", nil, errors.New("the user info is not percent-encoded correctly")
		}
		hostport = rest[i+1:]
		if !strings.Contains(ui, ":") {
			b, ok := decodeBase64(ui)
			if !ok {
				return nil, "", nil, errors.New("the user info is neither base64 nor method:password")
			}
			ui = string(b)
		}
		method, password, _ = strings.Cut(ui, ":")
	} else {
		b, ok := decodeBase64(rest)
		if !ok {
			return nil, "", nil, errors.New("the ss link is neither SIP002 nor base64")
		}
		whole := string(b)
		i := strings.LastIndex(whole, "@")
		if i < 0 {
			return nil, "", nil, errors.New("the decoded ss link has no @")
		}
		method, password, _ = strings.Cut(whole[:i], ":")
		hostport = whole[i+1:]
	}
	if method == "" || password == "" {
		return nil, "", nil, errors.New("the method or the password is empty")
	}
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return nil, "", nil, err
	}
	p, err := parseQuery(query)
	if err != nil {
		return nil, "", nil, err
	}
	if p.has("plugin") {
		return nil, "", nil, errors.New("parameter \"plugin\" is refused: a plugin would run a program on the node")
	}
	ss, err := stream(p, "none")
	if err != nil {
		return nil, "", nil, err
	}
	if err := p.leftover(); err != nil {
		return nil, "", nil, err
	}
	settings := map[string]any{"address": host, "port": port, "method": strings.ToLower(method), "password": password}
	return newOutbound("shadowsocks", settings, ss), note, p.omitted, nil
}

func convertHysteria2(rest string) (map[string]any, string, []string, error) {
	u, err := parseURL("hysteria2", rest)
	if err != nil {
		return nil, "", nil, err
	}
	host, port, err := hysteria2HostPort(u)
	if err != nil {
		return nil, "", nil, err
	}
	auth := u.User.Username()
	if pw, ok := u.User.Password(); ok {
		auth += ":" + pw
	}
	if auth == "" {
		return nil, "", nil, errors.New("the auth is empty")
	}
	p, err := parseQuery(u.RawQuery)
	if err != nil {
		return nil, "", nil, err
	}
	// mport of one port or one a-b is the udphop mask of 7.2; a list is not of its kind.
	hop := ""
	if p.has("mport") {
		hop = p.get("mport")
		if !hopPorts(hop) {
			return nil, "", nil, errors.New("parameter \"mport\" is not one port or one range a-b")
		}
	}
	tls := map[string]any{}
	setIf(tls, "serverName", p.get("sni"))
	if a := p.get("alpn"); a != "" {
		tls["alpn"] = splitList(a)
	}
	if ins, err := p.boolean("insecure"); err != nil {
		return nil, "", nil, err
	} else if ins {
		return nil, "", nil, errNoInsecure("insecure", "pinsha256")
	}
	if pin := p.get("pinsha256"); pin != "" {
		hex := strings.ToLower(strings.ReplaceAll(pin, ":", ""))
		if len(hex) != 64 || strings.Trim(hex, "0123456789abcdef") != "" {
			return nil, "", nil, errors.New("parameter \"pinsha256\" is not a SHA-256 in hex")
		}
		tls["pinnedPeerCertSha256"] = hex
	}
	ss := map[string]any{
		"method": "hysteria", "security": "tls", "tlsSettings": tls,
		"hysteriaSettings": map[string]any{"version": 2, "auth": auth},
	}
	var masks []any
	switch obfs := strings.ToLower(p.get("obfs")); obfs {
	case "":
		if p.has("obfs-password") {
			return nil, "", nil, errors.New("parameter \"obfs-password\" needs obfs=salamander")
		}
	case "salamander":
		pw := p.get("obfs-password")
		if pw == "" {
			return nil, "", nil, errors.New("obfs salamander needs parameter \"obfs-password\"")
		}
		masks = append(masks, map[string]any{"type": "salamander", "settings": map[string]any{"password": pw}})
	default:
		return nil, "", nil, errors.New("parameter \"obfs\" is not salamander")
	}
	if hop != "" {
		// The URI carries no hop interval, so the default of Hysteria 2 (30 s) is written
		// down: the exit hops the way the client of the link does. The salamander mask comes
		// first, because the release writes the list in reverse and the hop must dial.
		masks = append(masks, map[string]any{"type": "udphop", "settings": map[string]any{"mode": "intervalRemote", "interval": 30, "remotePorts": hop}})
	}
	if len(masks) > 0 {
		ss["finalmask"] = map[string]any{"udp": masks}
	}
	if err := p.leftover(); err != nil {
		return nil, "", nil, err
	}
	settings := map[string]any{"version": 2, "address": host, "port": port}
	return newOutbound("hysteria", settings, ss), remark(u), p.omitted, nil
}

// hysteria2HostPort is hostPortOf with the default of the URI form: the port of
// hysteria2://[auth@]host[:port]/ is optional and 443. A list or a range of ports is
// not a URL port at all (net/url refuses it), so it comes in the mport parameter.
func hysteria2HostPort(u *url.URL) (string, int, error) {
	if u.Port() == "" {
		return checkHostPort(u.Hostname(), "443")
	}
	return hostPortOf(u)
}

// extraKept are the members of the extra object of an xhttp link that the allow-list
// lists; extraOmitted are the ones that the exit works without, which the candidate
// leaves out with a line in its diff (7.3). Any other member is an error of the line:
// the exit may not work without it (downloadSettings, the padding and placement keys).
func extraKept() map[string]string {
	return map[string]string{"headers": "headers", "nogrpcheader": "noGRPCHeader", "xpaddingbytes": "xPaddingBytes", "scmaxeachpostbytes": "scMaxEachPostBytes"}
}

func extraOmitted() map[string]string {
	return map[string]string{"xmux": "xmux", "scminpostsintervalms": "scMinPostsIntervalMs", "scmaxbufferedposts": "scMaxBufferedPosts",
		"scstreamupserversecs": "scStreamUpServerSecs", "nosseheader": "noSSEHeader", "servermaxheaderbytes": "serverMaxHeaderBytes"}
}

func filterExtra(p *params, extra map[string]any) (map[string]any, error) {
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	kept := map[string]any{}
	for _, k := range keys {
		lk := strings.ToLower(k)
		if canon, ok := extraKept()[lk]; ok {
			if _, dup := kept[canon]; dup {
				return nil, fmt.Errorf("parameter \"extra\" gives member %q twice", canon)
			}
			kept[canon] = extra[k]
		} else if canon, ok := extraOmitted()[lk]; ok {
			p.omit("extra." + canon)
		} else {
			return nil, fmt.Errorf("parameter \"extra\" has the member %q, which is not on the list of the allow-list: paste the exit as JSON", clipName(k))
		}
	}
	return kept, nil
}

// hopPorts reads the mport of a Hysteria 2 link: one port or one a-b, which is the form
// of the udphop mask. A list is not.
func hopPorts(s string) bool {
	a, b, two := strings.Cut(s, "-")
	ok := func(x string) bool {
		n, err := strconv.Atoi(x)
		return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == x
	}
	return ok(a) && (!two || ok(b))
}
