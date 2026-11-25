package store

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// appendixA is every SQLSTATE of PostgreSQL's Appendix A (error codes), by class. It is
// listed from the documentation and not from what the code handles, so that "which codes did
// we forget" is a question about this table and never about sanitize (rule sqlstate-class,
// db-r6-1: 25P03, the idle-in-transaction timeout every service role is configured with, was
// the third pressure code found one at a time).
var appendixA = map[string][]string{
	"00": {"00000"},
	"01": {"01000", "0100C", "01008", "01003", "01007", "01006", "01004", "01P01"},
	"02": {"02000", "02001"},
	"03": {"03000"},
	"08": {"08000", "08003", "08006", "08001", "08004", "08007", "08P01"},
	"09": {"09000"},
	"0A": {"0A000"},
	"0B": {"0B000"},
	"0F": {"0F000", "0F001"},
	"0L": {"0L000", "0LP01"},
	"0P": {"0P000"},
	"0Z": {"0Z000", "0Z002"},
	"20": {"20000"},
	"21": {"21000"},
	"22": {"22000", "2202E", "22021", "22008", "22012", "22005", "2200B", "22022", "22015", "2201E", "22014",
		"22016", "2201F", "2201G", "22018", "22007", "22019", "2202D", "22025", "22P06", "22010", "22023",
		"22013", "2201B", "2201W", "2201X", "2202H", "2202G", "22009", "2200C", "2200G", "22004", "22002",
		"22003", "2200H", "22026", "22001", "22011", "22027", "22024", "2200F", "22P01", "22P02", "22P03",
		"22P04", "22P05", "2200L", "2200M", "2200N", "2200S", "2200T", "22030", "22031", "22032", "22033",
		"22034", "22035", "22036", "22037", "22038", "22039", "2203A", "2203B", "2203C", "2203D", "2203E",
		"2203F", "2203G"},
	"23": {"23000", "23001", "23502", "23503", "23505", "23514", "23P01"},
	"24": {"24000"},
	"25": {"25000", "25001", "25002", "25008", "25003", "25004", "25005", "25006", "25007", "25P01", "25P02", "25P03", "25P04"},
	"26": {"26000"},
	"27": {"27000"},
	"28": {"28000", "28P01"},
	"2B": {"2B000", "2BP01"},
	"2D": {"2D000"},
	"2F": {"2F000", "2F005", "2F002", "2F003", "2F004"},
	"34": {"34000"},
	"38": {"38000", "38001", "38002", "38003", "38004"},
	"39": {"39000", "39001", "39004", "39P01", "39P02", "39P03"},
	"3B": {"3B000", "3B001"},
	"3D": {"3D000"},
	"3F": {"3F000"},
	"40": {"40000", "40002", "40001", "40003", "40P01"},
	"42": {"42000", "42601", "42501", "42846", "42803", "42P20", "42P19", "42830", "42602", "42622", "42939",
		"42804", "42P18", "42P21", "42P22", "42809", "42703", "42883", "42P01", "42P02", "42704", "42701",
		"42P03", "42P04", "42723", "42P05", "42P06", "42P07", "42712", "42710", "42702", "42725", "42P08",
		"42P09", "42P10", "42611", "42P11", "42P12", "42P13", "42P14", "42P15", "42P16", "42P17"},
	"44": {"44000"},
	"53": {"53000", "53100", "53200", "53300", "53400"},
	"54": {"54000", "54001", "54011", "54023"},
	"55": {"55000", "55006", "55P02", "55P03", "55P04"},
	"57": {"57000", "57014", "57P01", "57P02", "57P03", "57P04", "57P05"},
	"58": {"58000", "58030", "58P01", "58P02"},
	"72": {"72000"},
	"F0": {"F0000", "F0001"},
	"HV": {"HV000", "HV005", "HV002", "HV010", "HV021", "HV024", "HV007", "HV008", "HV004", "HV006", "HV091",
		"HV00B", "HV00C", "HV00D", "HV090", "HV00A", "HV009", "HV014", "HV001", "HV00P", "HV00J", "HV00K",
		"HV00Q", "HV00R", "HV00L", "HV00M", "HV00N"},
	"P0": {"P0000", "P0001", "P0002", "P0003", "P0004"},
	"XX": {"XX000", "XX001", "XX002"},
}

// classDecision says, for each class of the appendix, what a code of it is answered as when
// no code of the class is an exception. Every class has a line and a reason, so a class is
// never "not thought about".
var classDecision = map[string]struct {
	kind   error
	reason string
}{
	"00": {nil, "successful completion, never an error"},
	"01": {nil, "warning, never raised as an error to the caller"},
	"02": {nil, "no data"},
	"03": {nil, "SQL statement not yet complete"},
	"08": {ErrConnection, "connection exception"},
	"09": {nil, "triggered action exception: a defect of the program"},
	"0A": {nil, "feature not supported: a defect of the program"},
	"0B": {nil, "invalid transaction initiation"},
	"0F": {nil, "locator exception"},
	"0L": {nil, "invalid grantor"},
	"0P": {nil, "invalid role specification"},
	"0Z": {nil, "diagnostics exception"},
	"20": {nil, "case not found"},
	"21": {nil, "cardinality violation: a defect of the program"},
	"22": {nil, "data exception: the request, decided by sanitize where it is a constraint"},
	"23": {nil, "integrity violation: decided by sanitize (conflict or constraint), never pressure"},
	"24": {nil, "invalid cursor state"},
	"25": {nil, "invalid transaction state: the program, except the two timeouts below that close the connection; 25006 (read-only after a failover) is a deployment decision (P7)"},
	"26": {nil, "invalid SQL statement name"},
	"27": {nil, "triggered data change violation"},
	"28": {nil, "invalid authorization specification: a configuration fault, not load"},
	"2B": {nil, "dependent privilege descriptors still exist"},
	"2D": {nil, "invalid transaction termination"},
	"2F": {nil, "SQL routine exception"},
	"34": {nil, "invalid cursor name"},
	"38": {nil, "external routine exception"},
	"39": {nil, "external routine invocation exception"},
	"3B": {nil, "savepoint exception"},
	"3D": {nil, "invalid catalog name"},
	"3F": {nil, "invalid schema name"},
	"40": {ErrRetry, "transaction rollback: serialization failure, deadlock; run again as a whole"},
	"42": {nil, "syntax error or access rule violation: the program, 42501 is decided by sanitize"},
	"44": {nil, "with check option violation"},
	"53": {ErrRetry, "insufficient resources: disk full, out of memory, too many connections"},
	"54": {nil, "program limit exceeded: the size of the request"},
	"55": {nil, "object not in prerequisite state: the program, except 55P03 lock timeout named below"},
	"57": {ErrConnection, "operator intervention: the connection is gone or going; 57014 is named below"},
	"58": {nil, "system error: I/O; whether it is the caller's depends on the deployment (P7)"},
	"72": {nil, "snapshot failure"},
	"F0": {nil, "configuration file error"},
	"HV": {nil, "foreign data wrapper error"},
	"P0": {nil, "PL/pgSQL error: the program (P0001 is our own RAISE)"},
	"XX": {nil, "internal error: a defect, so a 500 and a WARN are right"},
}

// codeDecision is every code whose answer differs from its class: either named in
// namedKind, or decided by an explicit case of sanitize.
var codeDecision = map[string]error{
	"55P03": ErrRetry,      // lock_timeout
	"57014": ErrRetry,      // statement_timeout
	"25P03": ErrConnection, // idle_in_transaction_session_timeout (every service role sets it)
	"25P04": ErrConnection, // transaction_timeout
	"23505": ErrConflict, "23P01": ErrConflict,
	"23503": ErrConstraint, "23514": ErrConstraint, "23502": ErrConstraint, "23000": ErrConstraint,
	"22P02": ErrConstraint, "22001": ErrConstraint, "22003": ErrConstraint,
	"42501": ErrPermission,
}

// TestEveryAppendixACodeHasADecision is the enforcement of rule sqlstate-class: every code of
// PostgreSQL's appendix A, in every class, has an explicit decision and sanitize gives it.
// A code that a later round finds answered as a 500 is a wrong row of THIS table, never a new
// case in sanitize.
func TestEveryAppendixACodeHasADecision(t *testing.T) {
	for class := range appendixA {
		if _, ok := classDecision[class]; !ok {
			t.Errorf("class %s has no decision in classDecision", class)
		}
	}
	for class, d := range classDecision {
		if _, ok := appendixA[class]; !ok {
			t.Errorf("class %s is decided and has no codes in appendixA", class)
		}
		if strings.TrimSpace(d.reason) == "" {
			t.Errorf("class %s has no reason", class)
		}
	}
	seen := map[string]bool{}
	for class, codes := range appendixA {
		for _, code := range codes {
			if len(code) != 5 || code[:2] != class {
				t.Errorf("code %q is listed under class %s", code, class)
			}
			if seen[code] {
				t.Errorf("code %s is listed twice", code)
			}
			seen[code] = true
			want := classDecision[class].kind
			if k, ok := codeDecision[code]; ok {
				want = k
			}
			e, _ := sanitize(&pgconn.PgError{Code: code, Message: "canceling " + code}).(*Error)
			if e == nil {
				t.Fatalf("%s: sanitize did not return a database error", code)
			}
			if e.kind != want {
				t.Errorf("SQLSTATE %s is answered as %v, want %v", code, e.kind, want)
			}
		}
	}
	for code := range codeDecision {
		if !seen[code] {
			t.Errorf("codeDecision names %s, which is not in appendixA", code)
		}
	}
	// A class nobody listed is judged by its class alone, so a new Appendix A class
	// arrives unclassified until a person decides it (and then must add its row above).
	if e, _ := sanitize(&pgconn.PgError{Code: "ZZ000"}).(*Error); e == nil || e.kind != nil {
		t.Error("an unknown class must stay unclassified")
	}
}
