//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package appserver

import (
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

type appServerProcessTree struct {
	mu   sync.Mutex
	pgid int
}

func prepareAppServerProcess(command *exec.Cmd) (*appServerProcessTree, error) {
	tree := &appServerProcessTree{}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = tree.kill
	command.WaitDelay = forcedShutdownWait
	return tree, nil
}

func (t *appServerProcessTree) attach(process *os.Process) error {
	if process == nil || process.Pid <= 0 {
		return errors.New("app-server process is unavailable")
	}
	t.mu.Lock()
	t.pgid = process.Pid
	t.mu.Unlock()
	return nil
}

func (t *appServerProcessTree) kill() error {
	t.mu.Lock()
	pgid := t.pgid
	t.mu.Unlock()
	if pgid <= 0 {
		return os.ErrProcessDone
	}
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return nil
}

func (t *appServerProcessTree) close() error {
	err := t.kill()
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}
