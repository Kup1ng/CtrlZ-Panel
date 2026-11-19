package app

// NewRuntimeForTest lets the external test package build a role's runtime without a
// database: newRuntime is what every entry point, services and console tools, goes
// through to get its keys and its hasher (rule argon2-memory-budget).
func NewRuntimeForTest(cfg Config, consoleTool bool) (*Runtime, error) {
	return newRuntime(cfg, discardLog(), consoleTool)
}
