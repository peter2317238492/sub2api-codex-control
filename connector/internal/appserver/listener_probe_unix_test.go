//go:build darwin || linux

package appserver_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
)

// newListenerProbe reports an inbound socket opened anywhere in the app-server
// process group. lsof selects by process group directly, so a grandchild is
// covered without walking the tree.
func newListenerProbe(t *testing.T) func(context.Context, int) error {
	t.Helper()
	lsof, err := exec.LookPath("lsof")
	if err != nil {
		t.Fatal("lsof is required for live app-server listener admission")
	}
	return func(ctx context.Context, processGroupID int) error {
		return assertNoProcessGroupListeners(ctx, lsof, processGroupID)
	}
}

func assertNoProcessGroupListeners(ctx context.Context, lsof string, processGroupID int) error {
	for _, selector := range [][]string{
		{"-iTCP", "-sTCP:LISTEN"},
		{"-iUDP"},
	} {
		arguments := []string{"-nP", "-a", "-g", strconv.Itoa(processGroupID)}
		arguments = append(arguments, selector...)
		command := exec.CommandContext(ctx, lsof, arguments...)
		output, err := command.CombinedOutput()
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			return fmt.Errorf("Connector-owned app-server process group opened an inbound socket")
		}
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) || exitError.ExitCode() != 1 || len(bytes.TrimSpace(output)) != 0 {
			return fmt.Errorf("cannot verify app-server process-group listeners")
		}
	}
	return nil
}

// assertProcessTreeTerminated confirms the Connector-owned process group holds
// no live process. Signal 0 only probes for existence.
func assertProcessTreeTerminated(t *testing.T, processGroupID int) {
	t.Helper()
	err := syscall.Kill(-processGroupID, 0)
	if !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("app-server process group %d survived shutdown: %v", processGroupID, err)
	}
}
