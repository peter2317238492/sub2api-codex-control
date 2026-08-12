//go:build windows

package securefile

import (
	"errors"
	"os"
)

func ownerID(os.FileInfo) (uint32, error) {
	return 0, errors.New("secure state files are unsupported on Windows")
}

func validateACL(*os.File) error {
	return errors.New("secure state files are unsupported on Windows")
}
