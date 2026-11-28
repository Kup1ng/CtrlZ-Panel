package app

// NewRuntimeForTest lets the external test package build a role's runtime without a
// database: newRuntime is what every entry point, services and console tools, goes
// through to get its keys and its hasher (rule argon2-memory-budget).
func NewRuntimeForTest(cfg Config, consoleTool bool) (*Runtime, error) {
	return newRuntime(cfg, discardLog(), consoleTool)
}

// PlainHTTPOriginForTest exposes the mapping from the environment to the Origin scheme policy.
var PlainHTTPOriginForTest = plainHTTPOrigin

// CheckWorkerResolversForTest exposes the start check of the worker's resolvers on a resolv.conf path of the test's choosing.
var CheckWorkerResolversForTest = checkWorkerResolvers

// StartWorkerForTest exposes startWorker, so a test can hold that it makes the resolver check before anything else.
var StartWorkerForTest = startWorker
