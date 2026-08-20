//go:build windows

package appserver

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	queryLimitedInformationAccess = 0x1000
	stillActiveExitCode           = 259
)

func TestVerifyVersionAndSpawnRejectShimBinaries(t *testing.T) {
	tests := []struct {
		name      string
		present   []string
		binary    string
		extension string
	}{
		{name: "cmd shim", present: []string{"codex.cmd"}, binary: "codex.cmd", extension: ".cmd"},
		{name: "bat shim", present: []string{"codex.bat"}, binary: "codex.bat", extension: ".bat"},
		{name: "powershell shim", present: []string{"codex.ps1"}, binary: "codex.ps1", extension: ".ps1"},
		{name: "com shim", present: []string{"codex.com"}, binary: "codex.com", extension: ".com"},
		{name: "upper case shim", present: []string{"CODEX.CMD"}, binary: "CODEX.CMD", extension: ".cmd"},
		// npm installs codex beside codex.cmd, and os/exec appends PATHEXT to
		// the extensionless name at start time, so this is the shim too.
		{name: "npm shim behind an extensionless name", present: []string{"codex", "codex.cmd"}, binary: "codex", extension: ".cmd"},
		{name: "executable image", present: []string{"codex.exe"}, binary: "codex.exe"},
		{name: "upper case image", present: []string{"CODEX.EXE"}, binary: "CODEX.EXE"},
		{name: "extensionless name beside an image", present: []string{"codex", "codex.exe"}, binary: "codex"},
		{name: "extensionless name", binary: "codex"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			for _, name := range test.present {
				if err := os.WriteFile(filepath.Join(directory, name), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			binary := filepath.Join(directory, test.binary)
			rejected := test.extension != ""
			err := requireExecutableImage(binary)
			if rejected != (err != nil) {
				t.Fatalf("requireExecutableImage(%q) = %v, rejected = %v", binary, err, rejected)
			}
			command := exec.CommandContext(t.Context(), binary, "app-server")
			if !rejected {
				tree, spawnErr := prepareAppServerProcess(command, time.Second)
				if spawnErr != nil {
					t.Fatalf("prepareAppServerProcess(%q) = %v, want an accepted image", binary, spawnErr)
				}
				_ = tree.close()
				return
			}
			if !strings.Contains(err.Error(), test.extension) || !strings.Contains(err.Error(), "job object") {
				t.Fatalf("rejection names neither the shim nor why it is rejected: %v", err)
			}
			versionErr := VerifyVersion(t.Context(), binary, "0.147.0")
			if versionErr == nil || !strings.Contains(versionErr.Error(), "shim") {
				t.Fatalf("VerifyVersion(%q) = %v, want the shim rejection", binary, versionErr)
			}
			tree, spawnErr := prepareAppServerProcess(command, time.Second)
			if spawnErr == nil {
				_ = tree.close()
				t.Fatalf("prepareAppServerProcess(%q) accepted a shim binary", binary)
			}
			if !strings.Contains(spawnErr.Error(), "shim") {
				t.Fatalf("prepareAppServerProcess(%q) = %v, want the shim rejection", binary, spawnErr)
			}
		})
	}
}

func TestPrepareAppServerProcessSuspendsAndHidesTheChild(t *testing.T) {
	command := exec.CommandContext(t.Context(), filepath.Join(t.TempDir(), "codex.exe"))
	tree, err := prepareAppServerProcess(command, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer tree.close()
	if command.SysProcAttr == nil || !command.SysProcAttr.HideWindow {
		t.Fatalf("SysProcAttr = %+v, want HideWindow", command.SysProcAttr)
	}
	if command.SysProcAttr.CreationFlags&createSuspended == 0 {
		t.Fatal("child is not created suspended")
	}
	if command.SysProcAttr.CreationFlags&createNoWindow == 0 {
		t.Fatal("child is created with a console window")
	}
	if command.Cancel == nil {
		t.Fatal("Cancel is not installed, so a cancelled context cannot terminate the job")
	}
	// WaitDelay starts when the child exits but the Connector only escalates to
	// terminating the tree once the grace period is up, so a delay that does not
	// outlast the grace period lets Wait abandon the pipes before the
	// descendants holding them are killed.
	if command.WaitDelay <= time.Second {
		t.Fatalf("WaitDelay = %v, want more than the 1s grace period", command.WaitDelay)
	}
}

func TestAppServerChildRunsOnlyAfterJobAssignment(t *testing.T) {
	binary := buildFakeCodex(t)
	marker := filepath.Join(t.TempDir(), "started")
	command := exec.CommandContext(t.Context(), binary, "app-server", "--listen", "stdio://")
	command.Env = append(os.Environ(), "FAKE_CODEX_MODE=marker", "FAKE_CODEX_MARKER="+marker)
	tree, err := prepareAppServerProcess(command, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		_ = tree.close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = tree.kill()
		_ = command.Wait()
		_ = tree.close()
	})
	time.Sleep(250 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("child ran before it was assigned to the job object: %v", err)
	}
	// attach fails unless the primary thread had exactly the one suspension the
	// Connector created, so a successful attach is itself the ordering proof.
	if err := tree.attach(command.Process); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "resumed child marker", func() bool {
		_, err := os.Stat(marker)
		return err == nil
	})
}

func TestKillTerminatesAppServerDescendants(t *testing.T) {
	binary := buildFakeCodex(t)
	pidPath := filepath.Join(t.TempDir(), "descendant.pid")
	command := exec.CommandContext(t.Context(), binary, "app-server", "--listen", "stdio://")
	command.Env = append(os.Environ(), "FAKE_CODEX_MODE=spawn", "FAKE_CODEX_PID="+pidPath)
	tree, err := prepareAppServerProcess(command, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		_ = tree.close()
		t.Fatal(err)
	}
	if err := tree.attach(command.Process); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = tree.close()
		t.Fatal(err)
	}
	descendant := openDescendant(t, pidPath)
	defer syscall.CloseHandle(descendant)

	if err := tree.kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	if err := tree.close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "descendant termination", func() bool {
		return !handleReportsRunning(t, descendant)
	})
}

func TestForcedShutdownTerminatesTheJobObjectTree(t *testing.T) {
	binary := buildFakeCodex(t)
	pidPath := filepath.Join(t.TempDir(), "descendant.pid")
	t.Setenv("FAKE_CODEX_MODE", "appserver")
	t.Setenv("FAKE_CODEX_PID", pidPath)
	client, err := Start(t.Context(), StartOptions{
		Binary: binary, ExpectedVersion: "0.147.0", ConnectorVersion: "test",
		InitializeTimeout: 15 * time.Second, ShutdownGracePeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	descendant := openDescendant(t, pidPath)
	defer syscall.CloseHandle(descendant)

	client.Close()
	if err := client.Wait(); err == nil {
		t.Fatal("forced app-server shutdown unexpectedly reported a clean exit")
	}
	waitFor(t, 5*time.Second, "descendant termination", func() bool {
		return !handleReportsRunning(t, descendant)
	})
}

func TestProcessTreeCloseIsIdempotent(t *testing.T) {
	command := exec.CommandContext(t.Context(), filepath.Join(t.TempDir(), "codex.exe"))
	tree, err := prepareAppServerProcess(command, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.close(); err != nil {
		t.Fatal(err)
	}
	if err := tree.close(); err != nil {
		t.Fatalf("second close = %v, want nil", err)
	}
	if err := tree.kill(); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("kill after close = %v, want os.ErrProcessDone", err)
	}
	if err := tree.attach(command.Process); err == nil {
		t.Fatal("attach accepted an unstarted process")
	}
}

func openDescendant(t *testing.T, pidPath string) syscall.Handle {
	t.Helper()
	var handle syscall.Handle
	waitFor(t, 10*time.Second, "descendant pid", func() bool {
		data, err := os.ReadFile(pidPath)
		if err != nil {
			return false
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 0 {
			return false
		}
		handle, err = syscall.OpenProcess(syscall.SYNCHRONIZE|queryLimitedInformationAccess, false, uint32(pid))
		return err == nil
	})
	return handle
}

// handleReportsRunning polls a handle opened while the descendant was alive so
// the answer cannot be confused by pid reuse after termination.
func handleReportsRunning(t *testing.T, handle syscall.Handle) bool {
	t.Helper()
	var code uint32
	if err := syscall.GetExitCodeProcess(handle, &code); err != nil {
		t.Fatal(err)
	}
	return code == stillActiveExitCode
}

func waitFor(t *testing.T, timeout time.Duration, what string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
