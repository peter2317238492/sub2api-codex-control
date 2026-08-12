package runtime

import (
	"errors"
	"time"
)

const maxRapidAppServerRestarts = 8

var errAppServerCrashLoop = errors.New("codex app-server restart circuit is open")

type restartPolicy struct {
	minimum       time.Duration
	maximum       time.Duration
	stableAfter   time.Duration
	nextDelay     time.Duration
	rapidFailures int
}

func newRestartPolicy(minimum, maximum time.Duration) restartPolicy {
	return restartPolicy{
		minimum: minimum, maximum: maximum, stableAfter: maximum, nextDelay: minimum,
	}
}

func (policy *restartPolicy) afterFailure(lifetime time.Duration) (time.Duration, int, error) {
	if lifetime >= policy.stableAfter {
		policy.rapidFailures = 0
		policy.nextDelay = policy.minimum
	}
	policy.rapidFailures++
	if policy.rapidFailures > maxRapidAppServerRestarts {
		return 0, policy.rapidFailures, errAppServerCrashLoop
	}

	delay := policy.nextDelay
	if policy.nextDelay >= policy.maximum/2 {
		policy.nextDelay = policy.maximum
	} else {
		policy.nextDelay *= 2
	}
	return delay, policy.rapidFailures, nil
}
