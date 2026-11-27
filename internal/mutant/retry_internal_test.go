package mutant

import (
	"context"
	"errors"
	"testing"
	"time"
)

var dockerDown = testOutcome{
	tests: map[string]string{},
	pkgOutput: []string{
		"testpg: cannot start Postgres (Docker is required; use -short to skip): start container: run postgres: generic container: get provider: rootless Docker is not supported on Windows, failed to create Docker provider",
	},
}

func TestInfrastructureFailureIsOnlyTheContainerSignature(t *testing.T) {
	cases := map[string]struct {
		out  testOutcome
		want bool
	}{
		"postgres did not start": {dockerDown, true},
		"valkey did not start":   {testOutcome{tests: map[string]string{}, pkgOutput: []string{"testvalkey: cannot start Valkey (Docker is required)"}}, true},
		"a test ran and failed":  {testOutcome{tests: map[string]string{"TestX": "fail"}, pkgOutput: dockerDown.pkgOutput}, false},
		"the build failed":       {testOutcome{tests: map[string]string{}, buildFailed: true, pkgOutput: dockerDown.pkgOutput}, false},
		"died of something else": {testOutcome{tests: map[string]string{}, pkgOutput: []string{"panic: nil pointer in TestMain"}}, false},
		"no output at all":       {testOutcome{tests: map[string]string{}}, false},
	}
	for name, c := range cases {
		if got := infrastructureFailure(c.out); got != c.want {
			t.Errorf("%s: infrastructureFailure = %v, want %v", name, got, c.want)
		}
	}
}

func TestRetryInfra(t *testing.T) {
	pass := testOutcome{tests: map[string]string{"TestX": "fail"}}
	run := func(outs ...testOutcome) (func() (testOutcome, error), *int) {
		n := 0
		return func() (testOutcome, error) {
			o := outs[min(n, len(outs)-1)]
			n++
			return o, nil
		}, &n
	}

	t.Run("a start that fails twice is retried to a result", func(t *testing.T) {
		f, n := run(dockerDown, dockerDown, pass)
		out, err := retryInfra(context.Background(), 3, 0, f)
		if err != nil || out.tests["TestX"] != "fail" || *n != 3 {
			t.Fatalf("out %+v err %v after %d runs", out, err, *n)
		}
	})
	t.Run("a start that never works is given up, still looking like infrastructure", func(t *testing.T) {
		f, n := run(dockerDown)
		out, _ := retryInfra(context.Background(), 3, 0, f)
		if *n != 3 || !infrastructureFailure(out) {
			t.Fatalf("%d runs, infra %v", *n, infrastructureFailure(out))
		}
	})
	t.Run("a real result is never run twice", func(t *testing.T) {
		f, n := run(pass)
		if _, err := retryInfra(context.Background(), 3, 0, f); err != nil || *n != 1 {
			t.Fatalf("%d runs, err %v", *n, err)
		}
	})
	t.Run("a package that died of something else is not retried", func(t *testing.T) {
		f, n := run(testOutcome{tests: map[string]string{}, pkgOutput: []string{"panic: boom"}})
		retryInfra(context.Background(), 3, 0, f)
		if *n != 1 {
			t.Fatalf("%d runs", *n)
		}
	})
	t.Run("an error of the runner itself is returned at once", func(t *testing.T) {
		n := 0
		_, err := retryInfra(context.Background(), 3, 0, func() (testOutcome, error) { n++; return testOutcome{}, errors.New("go not found") })
		if err == nil || n != 1 {
			t.Fatalf("%d runs, err %v", n, err)
		}
	})
	t.Run("a cancelled run stops waiting", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		f, n := run(dockerDown)
		if _, err := retryInfra(ctx, 3, time.Hour, f); err == nil || *n != 1 {
			t.Fatalf("%d runs, err %v", *n, err)
		}
	})
}
