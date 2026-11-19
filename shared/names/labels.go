package names

// The grammar of two labels that appear in hostnames and in rows that other
// packages validate. They live here, the leaf of the module, so that wire can
// hold a free-text field to the same rule identity uses without importing it
// (contract section 1).

const (
	// ClientMax is the longest client label. The cap leaves room for
	// "<26 id>-<client>" inside one 63-byte label.
	ClientMax = 36
	// VerifyLen is the length of a proof challenge label.
	VerifyLen = 26
)

// ValidClientLabel reports whether s matches
// [a-z0-9](?:[a-z0-9-]{0,34}[a-z0-9])?  (1 to 36 bytes, no edge hyphen).
func ValidClientLabel(s string) bool {
	if len(s) == 0 || len(s) > ClientMax {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if !alnum && !(c == '-' && i != 0 && i != len(s)-1) {
			return false
		}
	}
	return true
}

// ValidVerifyLabel reports whether s matches [a-z2-7]{26}, the label of a
// proof challenge (contract 3.1).
func ValidVerifyLabel(s string) bool {
	if len(s) != VerifyLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}
