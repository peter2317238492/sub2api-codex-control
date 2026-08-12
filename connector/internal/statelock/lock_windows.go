//go:build windows

package statelock

import "errors"

func checkPlatform() error {
	return errors.New("connector state locking is unsupported on Windows")
}

func acquireStateDir(string) (func() error, error) {
	return nil, errors.New("connector state locking is unsupported on Windows")
}
