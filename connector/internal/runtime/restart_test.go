package runtime

import (
	"errors"
	"testing"
	"time"
)

func TestRestartPolicyUsesBoundedExponentialBackoff(t *testing.T) {
	policy := newRestartPolicy(100*time.Millisecond, 800*time.Millisecond)
	wantDelays := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		800 * time.Millisecond,
		800 * time.Millisecond,
	}
	for index, wantDelay := range wantDelays {
		delay, rapidFailures, err := policy.afterFailure(50 * time.Millisecond)
		if err != nil {
			t.Fatalf("failure %d returned error: %v", index+1, err)
		}
		if delay != wantDelay || rapidFailures != index+1 {
			t.Fatalf("failure %d = (%s, %d), want (%s, %d)", index+1, delay, rapidFailures, wantDelay, index+1)
		}
	}
}

func TestRestartPolicyStableRunResetsDelayAndBudget(t *testing.T) {
	policy := newRestartPolicy(100*time.Millisecond, 800*time.Millisecond)
	for range 3 {
		if _, _, err := policy.afterFailure(10 * time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}

	delay, rapidFailures, err := policy.afterFailure(800 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if delay != 100*time.Millisecond || rapidFailures != 1 {
		t.Fatalf("stable-run failure = (%s, %d), want (100ms, 1)", delay, rapidFailures)
	}
}

func TestRestartPolicyOpensCircuitAfterRapidRestartBudget(t *testing.T) {
	policy := newRestartPolicy(100*time.Millisecond, time.Second)
	for attempt := 1; attempt <= maxRapidAppServerRestarts; attempt++ {
		if _, gotAttempt, err := policy.afterFailure(time.Millisecond); err != nil || gotAttempt != attempt {
			t.Fatalf("attempt %d = (%d, %v)", attempt, gotAttempt, err)
		}
	}

	delay, rapidFailures, err := policy.afterFailure(time.Millisecond)
	if delay != 0 || rapidFailures != maxRapidAppServerRestarts+1 || !errors.Is(err, errAppServerCrashLoop) {
		t.Fatalf("open circuit = (%s, %d, %v)", delay, rapidFailures, err)
	}
}

func TestRestartPolicyRunBelowStableThresholdDoesNotReset(t *testing.T) {
	policy := newRestartPolicy(100*time.Millisecond, time.Second)
	_, _, _ = policy.afterFailure(time.Millisecond)

	delay, rapidFailures, err := policy.afterFailure(time.Second - time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	if delay != 200*time.Millisecond || rapidFailures != 2 {
		t.Fatalf("short run failure = (%s, %d), want (200ms, 2)", delay, rapidFailures)
	}
}
