package recovery

// Encode lets the external test pin the bit packing.
func Encode(b [10]byte) string { return encode(b[:]) }
