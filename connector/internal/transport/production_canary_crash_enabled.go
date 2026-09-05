//go:build productioncanary && (darwin || linux)

package transport

import (
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/auth"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

const productionCanaryCrashExitCode = 86

var productionCanaryCrashArmed atomic.Bool
var productionCanaryFlushMutex sync.Mutex
var productionCanaryStateDir string

func EnableProductionCanaryCrashHook(stateDir string) (func(), error) {
	if stateDir == "" || !filepath.IsAbs(stateDir) {
		return nil, errors.New("production canary state directory is invalid")
	}
	productionCanaryFlushMutex.Lock()
	productionCanaryStateDir = stateDir
	productionCanaryFlushMutex.Unlock()
	signals := make(chan os.Signal, 1)
	stopped := make(chan struct{})
	done := make(chan struct{})
	signal.Notify(signals, syscall.SIGUSR1)
	go func() {
		defer close(done)
		select {
		case <-signals:
			marker := filepath.Join(stateDir, "production-canary-crash-armed.json")
			productionCanaryFlushMutex.Lock()
			productionCanaryCrashArmed.Store(true)
			if securefile.WriteJSON(marker, map[string]any{"armed": true, "version": 1}) != nil {
				productionCanaryCrashArmed.Store(false)
			}
			productionCanaryFlushMutex.Unlock()
		case <-stopped:
		}
	}()
	var stopOnce sync.Once
	return func() {
		stopOnce.Do(func() {
			signal.Stop(signals)
			close(stopped)
			<-done
			productionCanaryFlushMutex.Lock()
			productionCanaryCrashArmed.Store(false)
			productionCanaryStateDir = ""
			productionCanaryFlushMutex.Unlock()
		})
	}, nil
}

func productionCanaryTokenFailure(err error) {
	if !errors.Is(err, auth.ErrInvalidDeviceCredential) {
		return
	}
	productionCanaryFlushMutex.Lock()
	defer productionCanaryFlushMutex.Unlock()
	if productionCanaryStateDir != "" {
		marker := filepath.Join(productionCanaryStateDir, "production-canary-credential-rejected.json")
		if _, statErr := os.Lstat(marker); !errors.Is(statErr, os.ErrNotExist) {
			return
		}
		// A failed write leaves the canary unverified; no credential is recorded.
		_ = securefile.WriteJSON(marker,
			map[string]any{"credential_rejected": true, "version": 1})
	}
}

func productionCanaryLockEmit(envelopeType string) bool {
	if envelopeType != protocol.TypeCommandAck || !productionCanaryCrashArmed.Load() {
		return false
	}
	productionCanaryFlushMutex.Lock()
	if !productionCanaryCrashArmed.Load() {
		productionCanaryFlushMutex.Unlock()
		return false
	}
	return true
}

func productionCanaryUnlockEmit(locked bool) {
	if locked {
		productionCanaryFlushMutex.Unlock()
	}
}

func productionCanaryLockFlush() {
	productionCanaryFlushMutex.Lock()
}

func productionCanaryUnlockFlush() {
	productionCanaryFlushMutex.Unlock()
}

func productionCanaryAfterSpool(envelopeType string) {
	if envelopeType == protocol.TypeCommandAck && productionCanaryCrashArmed.Swap(false) {
		os.Exit(productionCanaryCrashExitCode)
	}
}
