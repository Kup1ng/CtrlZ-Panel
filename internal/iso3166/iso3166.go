// Package iso3166 holds the ISO 3166-1 alpha-2 country codes, so Home Countries
// (spec 12.1, T-311) can be checked with no network and no dependency. The list
// is a constant: the workspace rule bans package-level mutable state.
package iso3166

import "strings"

// codes is the officially assigned set, space separated, upper case.
const codes = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ " +
	"CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR " +
	"GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP " +
	"KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ " +
	"NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW " +
	"SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ " +
	"UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW"

// Valid reports whether s is an assigned alpha-2 code, in upper case.
func Valid(s string) bool {
	if len(s) != 2 {
		return false
	}
	for i := 0; i+2 <= len(codes); i += 3 {
		if codes[i:i+2] == s {
			return true
		}
	}
	return false
}

// Count is the number of codes, for the test that pins the list.
func Count() int { return len(strings.Fields(codes)) }
