package xrayschema

// ValidReleaseTag reports whether s is an Xray release tag in the form the
// panel and the nodes exchange: v<major>.<minor>.<patch>, digits only. One
// grammar keeps a tag that crosses the wire from naming a file or a table that
// the loader of this package would not.
func ValidReleaseTag(s string) bool {
	if len(s) < 6 || len(s) > 32 || s[0] != 'v' {
		return false
	}
	dots := 0
	prevDigit := false
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			prevDigit = true
		case c == '.' && prevDigit && dots < 2:
			dots++
			prevDigit = false
		default:
			return false
		}
	}
	return dots == 2 && prevDigit
}

// MaxOutbounds is the number of outbounds a fragment may hold: the exit and at
// most seven hops (7.2).
const MaxOutbounds = 8

// ValidPath reports whether p is a path in the form of Issue.Path and of the
// accept_unknown list: outbounds[i] with i from 0 to MaxOutbounds-1, then at
// least one segment, each ".key" or "[n]", the first one a key. It checks the
// form only; whether the path names something that exists is the checker's.
func ValidPath(p string) bool {
	const head = "outbounds["
	if len(p) > MaxPathBytes || len(p) < len(head)+3 || p[:len(head)] != head {
		return false
	}
	i := len(head)
	if p[i] < '0' || p[i] >= '0'+MaxOutbounds || p[i+1] != ']' {
		return false
	}
	i += 2
	if i >= len(p) || p[i] != '.' {
		return false
	}
	for i < len(p) {
		switch p[i] {
		case '.':
			j := i + 1
			for j < len(p) && isKeyByte(p[j]) {
				j++
			}
			if j == i+1 {
				return false
			}
			i = j
		case '[':
			j := i + 1
			for j < len(p) && p[j] >= '0' && p[j] <= '9' {
				j++
			}
			if j == i+1 || j-i > 6 || j >= len(p) || p[j] != ']' {
				return false
			}
			i = j + 1
		default:
			return false
		}
	}
	return true
}

// MaxPathBytes bounds a path. Keys are short and depth is at most 32.
const MaxPathBytes = 256

func isKeyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}
