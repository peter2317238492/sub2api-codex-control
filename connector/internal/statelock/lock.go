package statelock

import (
	"errors"
	"path/filepath"
	"sync"
)

const lockFileName = "connector.lock"

// ErrInUse is returned when another Connector owns the state directory.
var ErrInUse = errors.New("connector state directory is already in use")

// Lock owns the process-wide state-directory lock until Release is called or
// the process exits.
type Lock struct {
	once       sync.Once
	release    func() error
	releaseErr error
}

// Acquire takes a non-blocking exclusive lock for the Connector state
// directory. Callers must hold the returned Lock for their complete lifetime.
func Acquire(stateDir string) (*Lock, error) {
	if err := checkPlatform(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(stateDir) || stateDir == string(filepath.Separator) {
		return nil, errors.New("connector state directory must be an absolute non-root path")
	}
	release, err := acquireStateDir(stateDir)
	if err != nil {
		return nil, err
	}
	return &Lock{release: release}, nil
}

// Release relinquishes the state-directory lock. It is safe to call more than
// once; all calls return the first release result.
func (lock *Lock) Release() error {
	if lock == nil {
		return nil
	}
	lock.once.Do(func() {
		if lock.release != nil {
			lock.releaseErr = lock.release()
		}
	})
	return lock.releaseErr
}
