//go:build !productioncanary

package transport

func EnableProductionCanaryCrashHook(string) (func(), error) {
	return func() {}, nil
}

func productionCanaryLockEmit(string) bool { return false }

func productionCanaryUnlockEmit(bool) {}

func productionCanaryLockFlush() {}

func productionCanaryUnlockFlush() {}

func productionCanaryAfterSpool(string) {}

func productionCanaryTokenFailure(error) {}
