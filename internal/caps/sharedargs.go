package caps

import "strings"

// SharedArgsProblem judges what stands INSIDE every call of ctrlz.cap_reached(spent, cap) (P1 auth
// review round 18, sms-r18-11; rule caps-and-endings).
//
// ReadsLimit and UnsharedCompare cut each call out with its balanced arguments before they look at
// the text, on the argument that a limit compared inside the shared expression is compared by it. That
// is true only while the arguments are values. `ctrlz.cap_reached(CASE WHEN $1 > (SELECT
// s.otp_cap_global FROM ctrlz.system_settings s) THEN 1 ELSE 0 END, 1)` compares a limit by hand inside
// the call, with `>` and not with the expression of migration 0044 (a NaN or a NULL cap fails OPEN
// there), and no guard looked at it. The arguments are now an allow list over what a value can be:
//
//  1. Outside a predicate, a token is a name, a number, a string, a parameter, one of
//     . , ( ) [ ] + - * / :: , the words select, from, join and as, or a call of coalesce, count or
//     sum. A comparison or boolean operator, a decision word (CASE, BETWEEN, IS, IN, AND, OR, NOT,
//     ANY, ALL, EXISTS, GREATEST, LEAST and the rest of the lexicon) and a call of any other function
//     fail, so a spelling nobody listed (a function that compares) fails too.
//  2. A predicate of a subselect inside the arguments (WHERE, ON, HAVING up to the end of its clause)
//     may compare, because the spent of a day is a SELECT with a WHERE, but it must not name a limit
//     column: a limit is reached only by the call itself.
//
// The nested call of ctrlz.cap_reached is a call of another function and fails by rule 1. Contract: it
// judges the text of one statement or one function body as written; it does not see a limit reached
// through a name the text never holds (EXECUTE of a built query).
func SharedArgsProblem(src string) string {
	toks := lexSQL(src)
	for i := 0; i+3 < len(toks); i++ {
		if !(isWordTok(toks[i], "ctrlz") && isPunct(toks[i+1], ".") && isWordTok(toks[i+2], "cap_reached") && isPunct(toks[i+3], "(")) {
			continue
		}
		end := matchParen(toks, i+3)
		if end < 0 {
			return "a call of ctrlz.cap_reached whose parenthesis is never closed"
		}
		if p := judgeArgs(toks[i+4 : end]); p != "" {
			return p
		}
		i = end
	}
	return ""
}

func isWordTok(t token, w string) bool { return t.kind == tokIdent && t.s == w }
func isPunct(t token, p string) bool   { return t.kind == tokPunct && t.s == p }

// matchParen returns the index of the parenthesis that closes the one opened at toks[open], or -1.
func matchParen(toks []token, open int) int {
	depth := 0
	for i := open; i < len(toks); i++ {
		switch {
		case isPunct(toks[i], "("):
			depth++
		case isPunct(toks[i], ")"):
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// valueFunctions are the calls a value may hold: the spent of a day is a COALESCE of a SUM, and a count
// of rows is a count. Everything else that is called is refused, including every function that compares.
func valueFunctions() []string { return []string{"coalesce", "count", "sum"} }

// valueWords are the words that are not names and may stand in a value: the shape of a subselect.
func valueWords() []string {
	return []string{"select", "from", "join", "as", "lateral", "left", "right", "inner", "outer", "cross", "full", "natural"}
}

// decisionWords are the words of the SQL lexicon that make a value a decision. They are not names of
// this program: the list is the language's, and a word that is not on it and not a name is refused as
// a call (rule 1) or as an operator.
func decisionWords() []string {
	return []string{"case", "when", "then", "else", "end", "between", "is", "in", "like", "ilike", "similar", "and", "or", "not", "any", "all", "some", "exists", "greatest", "least", "distinct", "filter", "over", "within"}
}

// predicateEnd are the words that end a predicate clause at its own depth.
func predicateEnd() []string {
	return []string{"group", "order", "limit", "offset", "union", "intersect", "except", "for", "window", "returning"}
}

func judgeArgs(a []token) string {
	var predicate []bool // per open parenthesis: inside a WHERE, ON or HAVING of this level
	inPred := func() bool { return len(predicate) > 0 && predicate[len(predicate)-1] }
	var predText []string
	flush := func() string {
		if len(predText) == 0 {
			return ""
		}
		if col := NamesLimit(strings.Join(predText, " ")); col != "" {
			return "the limit " + col + " is named in a predicate inside the arguments of ctrlz.cap_reached; a limit is reached by the call and by nothing in its arguments"
		}
		predText = nil
		return ""
	}
	// The outermost level has no parenthesis of its own.
	predicate = append(predicate, false)
	for i, t := range a {
		switch {
		case isPunct(t, "("):
			// A parenthesis inside a predicate is part of it: the spend of a day compares k.day with
			// (now() AT TIME ZONE ...)::date, and a limit named in a nested subselect of a predicate is the
			// same hand comparison.
			predicate = append(predicate, inPred())
			continue
		case isPunct(t, ")"):
			if p := flush(); p != "" {
				return p
			}
			if len(predicate) > 1 {
				predicate = predicate[:len(predicate)-1]
			}
			continue
		}
		if t.kind == tokIdent && isOneOf(t.s, "where", "on", "having") {
			if p := flush(); p != "" {
				return p
			}
			predicate[len(predicate)-1] = true
			continue
		}
		if inPred() {
			if t.kind == tokIdent && isOneOf(t.s, predicateEnd()...) {
				if p := flush(); p != "" {
					return p
				}
				predicate[len(predicate)-1] = false
			} else if t.kind == tokIdent {
				predText = append(predText, t.s)
			}
			continue
		}
		switch t.kind {
		case tokNum, tokStr, tokParam:
		case tokPunct:
			if !isOneOf(t.s, ".", ",", "[", "]", "+", "-", "*", "/", "::") {
				return "an operator " + quote(t.s) + " inside the arguments of ctrlz.cap_reached: an argument is a value, and a comparison of a limit made in it is not the shared expression"
			}
		case tokIdent:
			if isOneOf(t.s, decisionWords()...) {
				return "the word " + quote(t.s) + " inside the arguments of ctrlz.cap_reached: an argument is a value, and a decision made in it compares a limit by hand"
			}
			if i > 0 && isPunct(a[i-1], "::") {
				continue // a type, numeric(10, 2) included
			}
			if i+1 < len(a) && isPunct(a[i+1], "(") && !isOneOf(t.s, valueWords()...) && !isOneOf(t.s, valueFunctions()...) {
				return "a call of " + quote(t.s) + " inside the arguments of ctrlz.cap_reached: only coalesce, count and sum may be called in a value"
			}
		}
	}
	return flush()
}
