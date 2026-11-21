package logattr

// StackText lets the external tests call the formatter with a chosen list of program counters.
func StackText(pcs []uintptr) string { return stackText(pcs) }

// MaxFrames is the bound of one logged stack.
const MaxFrames = maxFrames
