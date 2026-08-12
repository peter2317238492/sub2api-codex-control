//go:build darwin || linux

package securefile

import (
	"errors"
	"os"
	"syscall"
)

func ownerID(info os.FileInfo) (uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("state object owner is unavailable")
	}
	return stat.Uid, nil
}
