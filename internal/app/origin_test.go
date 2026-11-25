package app_test

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/app"
)

// TestPlainHTTPOriginIsADevelopmentAndTestThing is tenant-r18-18: an http Origin is accepted only by a development
// or a test run. Production is strict, and so is a value nobody listed (the answer is never true by default).
func TestPlainHTTPOriginIsADevelopmentAndTestThing(t *testing.T) {
	for env, want := range map[app.Env]bool{
		app.EnvProduction: false, app.EnvDev: true, app.EnvTest: true, "": false, "staging": false,
	} {
		if got := app.PlainHTTPOriginForTest(env); got != want {
			t.Errorf("env %q: plain http Origin accepted = %v, want %v", env, got, want)
		}
	}
}
