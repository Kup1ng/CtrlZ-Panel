package httpx

// MultilinePattern is the request schemas' pattern for a message a person writes in a textarea (api/openapi.yaml, the
// anchor `multiline`; today the body of POST /feedback, P3 spec 9.2). The name pattern of the other fields refuses every
// control character, which made a two-paragraph message a 400 with no field named (p3-D6-r2-1 and -10). Here a line feed,
// a carriage return and a tab pass, and so do the half-space (U+200C), U+200D, the left-to-right, right-to-left and Arabic
// letter marks (U+200E, U+200F, U+061C) that a Persian keyboard or a paste carries. Every other control, format and
// private-use character is still refused, the zero width space, the bidi overrides and isolates and NUL among them, and a
// message does not start with a blank. The handler folds CR LF and CR to LF before it stores the text.
// TestMultilinePatternIsTheOnePatternOfTheDocument holds this text and the document together.
const MultilinePattern = `^[^\s\p{C}](?:[^\p{C}]|[\t\n\r\x{200C}\x{200D}\x{200E}\x{200F}\x{061C}])*$`

// MultilineMark says whether r is one of the characters that the pattern lets through although it is a control or
// format character; the boundary lint and the boundary fuzz use it to know which probe is an accepted mark.
func MultilineMark(r rune) bool {
	switch r {
	case '\t', '\n', '\r', 0x200c, 0x200d, 0x200e, 0x200f, 0x061c:
		return true
	}
	return false
}
