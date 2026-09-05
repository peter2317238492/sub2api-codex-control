//go:build productioncanary && !(darwin || linux)

package transport

import "errors"

func EnableProductionCanaryCrashHook(string) (func(), error) {
	return nil, errors.New("production canary crash proof requires darwin or linux")
}

func productionCanaryLockEmit(string) bool { return false }

func productionCanaryUnlockEmit(bool) {}

func productionCanaryLockFlush() {}

func productionCanaryUnlockFlush() {}

func productionCanaryAfterSpool(string) {}

func productionCanaryTokenFailure(error) {}
