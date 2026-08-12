//go:build darwin || linux

package statelock

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	helperModeEnv  = "SUB2API_STATE_LOCK_HELPER"
	helperDirEnv   = "SUB2API_STATE_LOCK_DIR"
	passiveModeEnv = "SUB2API_STATE_LOCK_PASSIVE_HELPER"
)

func TestStateLockIsExclusiveAcrossProcessesAndReleasedAfterExit(t *testing.T) {
	stateDir := canonicalTestPath(t, filepath.Join(t.TempDir(), "state"))
	helper := startLockHelper(t, stateDir)
	defer helper.stop(t)

	startedAt := time.Now()
	lock, err := Acquire(stateDir)
	if lock != nil {
		_ = lock.Release()
	}
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("second acquire error = %v, want ErrInUse", err)
	}
	if err.Error() != ErrInUse.Error() {
		t.Fatalf("contention error = %q, want bounded sentinel %q", err, ErrInUse)
	}
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("non-blocking acquire took %s", elapsed)
	}

	helper.exitNormally(t)
	reacquired, err := Acquire(stateDir)
	if err != nil {
		t.Fatalf("reacquire after helper exit: %v", err)
	}
	if err := reacquired.Release(); err != nil {
		t.Fatalf("release reacquired lock: %v", err)
	}
}

func TestDistinctStateDirectoriesCanBeLockedConcurrently(t *testing.T) {
	firstDir := canonicalTestPath(t, filepath.Join(t.TempDir(), "first"))
	helper := startLockHelper(t, firstDir)
	defer helper.stop(t)

	secondDir := canonicalTestPath(t, filepath.Join(t.TempDir(), "second"))
	second, err := Acquire(secondDir)
	if err != nil {
		t.Fatalf("acquire distinct state directory: %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatalf("release distinct state directory: %v", err)
	}
}

func TestStateLockCreatesNestedPrivateDirectoryComponents(t *testing.T) {
	base := canonicalTestPath(t, t.TempDir())
	first := filepath.Join(base, "first")
	second := filepath.Join(first, "second")
	stateDir := filepath.Join(second, "state")

	lock, err := Acquire(stateDir)
	if err != nil {
		t.Fatalf("acquire nested state directory: %v", err)
	}
	defer lock.Release()

	for _, path := range []string{first, second, stateDir} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("created component %s mode = %v, want private directory", path, info.Mode())
		}
	}
	lockInfo, err := os.Lstat(filepath.Join(stateDir, lockFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("lock file mode = %v, want private regular file", lockInfo.Mode())
	}
}

func TestStateLockReleasedAfterForcedProcessTermination(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Process.Kill release semantics are covered on supported Unix release targets")
	}
	stateDir := canonicalTestPath(t, filepath.Join(t.TempDir(), "state"))
	helper := startLockHelper(t, stateDir)
	if err := helper.command.Process.Kill(); err != nil {
		helper.stop(t)
		t.Fatal(err)
	}
	if err := helper.command.Wait(); err == nil {
		helper.done = true
		t.Fatal("killed lock helper exited successfully")
	}
	helper.done = true
	_ = helper.stdin.Close()

	lock, err := Acquire(stateDir)
	if err != nil {
		t.Fatalf("reacquire after forced termination: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("release after forced termination: %v", err)
	}
}

func TestStateLockDescriptorIsNotInheritedByChildProcess(t *testing.T) {
	stateDir := canonicalTestPath(t, filepath.Join(t.TempDir(), "state"))
	lock, err := Acquire(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	helper := startPassiveHelper(t)
	defer helper.stop(t)

	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	reacquired, err := Acquire(stateDir)
	if err != nil {
		t.Fatalf("child process inherited state lock descriptor: %v", err)
	}
	if err := reacquired.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestStateLockSurvivesLockFileReplacement(t *testing.T) {
	stateDir := canonicalTestPath(t, filepath.Join(t.TempDir(), "state"))
	first, err := Acquire(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()
	lockPath := filepath.Join(stateDir, lockFileName)
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := Acquire(stateDir)
	if second != nil {
		_ = second.Release()
	}
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("acquire after lock-file replacement = %v, want ErrInUse", err)
	}
}

func TestStateLockRejectsReplaceableAncestor(t *testing.T) {
	parent := filepath.Join(canonicalTestPath(t, t.TempDir()), "replaceable")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(parent, "state")
	if lock, err := Acquire(stateDir); err == nil {
		_ = lock.Release()
		t.Fatal("state directory below a replaceable ancestor was accepted")
	}
	if _, err := os.Lstat(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state directory was created below an untrusted ancestor: %v", err)
	}
}

func TestStateLockRejectsSymlinkedAncestorWithoutCanonicalizing(t *testing.T) {
	base := canonicalTestPath(t, t.TempDir())
	target := filepath.Join(base, "safe-target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "state-parent")
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	stateDir := filepath.Join(alias, "state")
	if lock, err := Acquire(stateDir); err == nil {
		_ = lock.Release()
		t.Fatal("state directory below a symbolic-link ancestor was accepted")
	}
	if _, err := os.Lstat(filepath.Join(target, "state")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state directory was created after resolving an untrusted ancestor: %v", err)
	}
}

func TestStateDirectoryReplacementDetectedDuringAcquisition(t *testing.T) {
	parent := canonicalTestPath(t, t.TempDir())
	stateDir := filepath.Join(parent, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	root, directory, err := openTrustedDirectoryWithHook(stateDir, func() {
		if renameErr := os.Rename(stateDir, filepath.Join(parent, "original")); renameErr != nil {
			t.Fatal(renameErr)
		}
		if mkdirErr := os.Mkdir(stateDir, 0o700); mkdirErr != nil {
			t.Fatal(mkdirErr)
		}
	})
	if root != nil {
		_ = root.Close()
	}
	if directory != nil {
		_ = directory.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "path changed") {
		t.Fatalf("directory replacement error = %v, want identity rejection", err)
	}
}

func TestStateDirectorySymlinkReplacementDetectedDuringAcquisition(t *testing.T) {
	parent := canonicalTestPath(t, t.TempDir())
	stateDir := filepath.Join(parent, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(parent, "original")
	root, directory, err := openTrustedDirectoryWithHook(stateDir, func() {
		if renameErr := os.Rename(stateDir, original); renameErr != nil {
			t.Fatal(renameErr)
		}
		if symlinkErr := os.Symlink(original, stateDir); symlinkErr != nil {
			t.Fatal(symlinkErr)
		}
	})
	if root != nil {
		_ = root.Close()
	}
	if directory != nil {
		_ = directory.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "inspect connector state directory path") {
		t.Fatalf("directory symlink replacement error = %v, want path rejection", err)
	}
}

func TestStateLockFileIsPrivateAndReleaseIsIdempotent(t *testing.T) {
	stateDir := filepath.Join(canonicalTestPath(t, t.TempDir()), "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(stateDir, lockFileName)
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(lockPath, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	lock, err := Acquire(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("lock file mode = %v, want private regular file", info.Mode())
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("second release: %v", err)
	}
}

func TestStateLockRejectsSymbolicLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symbolic links can require additional Windows privileges")
	}
	t.Run("state directory", func(t *testing.T) {
		realDir := canonicalTestPath(t, t.TempDir())
		alias := filepath.Join(canonicalTestPath(t, t.TempDir()), "state-link")
		if err := os.Symlink(realDir, alias); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if lock, err := Acquire(alias); err == nil {
			_ = lock.Release()
			t.Fatal("symbolic-link state directory was accepted")
		}
	})

	t.Run("lock file", func(t *testing.T) {
		stateDir := canonicalTestPath(t, t.TempDir())
		target := filepath.Join(t.TempDir(), "target")
		original := []byte("do not touch")
		if err := os.WriteFile(target, original, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(stateDir, lockFileName)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if lock, err := Acquire(stateDir); err == nil {
			_ = lock.Release()
			t.Fatal("symbolic-link lock file was accepted")
		}
		contents, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		if string(contents) != string(original) {
			t.Fatal("symbolic-link target was modified")
		}
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("symbolic-link target mode = %04o, want 0644", info.Mode().Perm())
		}
	})

	t.Run("hard-linked lock file", func(t *testing.T) {
		stateDir := canonicalTestPath(t, t.TempDir())
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(target, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(target, filepath.Join(stateDir, lockFileName)); err != nil {
			t.Skipf("hard links unavailable: %v", err)
		}
		if lock, err := Acquire(stateDir); err == nil {
			_ = lock.Release()
			t.Fatal("hard-linked lock file was accepted")
		}
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("hard-link target mode = %04o, want 0644", info.Mode().Perm())
		}
	})
}

func TestStateLockHelper(t *testing.T) {
	if os.Getenv(helperModeEnv) != "1" {
		t.Skip("subprocess helper")
	}
	lock, err := Acquire(os.Getenv(helperDirEnv))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stdout.WriteString("locked\n"); err != nil {
		_ = lock.Release()
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestStateLockPassiveHelper(t *testing.T) {
	if os.Getenv(passiveModeEnv) != "1" {
		t.Skip("subprocess helper")
	}
	if _, err := os.Stdout.WriteString("ready\n"); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}

type lockHelper struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	done    bool
}

func startLockHelper(t *testing.T, stateDir string) *lockHelper {
	t.Helper()
	return startHelper(
		t,
		"^TestStateLockHelper$",
		[]string{helperModeEnv + "=1", helperDirEnv + "=" + stateDir},
		"locked\n",
	)
}

func startPassiveHelper(t *testing.T) *lockHelper {
	t.Helper()
	return startHelper(t, "^TestStateLockPassiveHelper$", []string{passiveModeEnv + "=1"}, "ready\n")
}

func canonicalTestPath(t *testing.T, path string) string {
	t.Helper()
	current := filepath.Clean(path)
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return filepath.Clean(resolved)
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("resolve test path %q: %v", path, err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			t.Fatalf("resolve test path %q: %v", path, err)
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func startHelper(t *testing.T, testPattern string, environment []string, readyLine string) *lockHelper {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run="+testPattern)
	command.Env = append(os.Environ(), environment...)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		t.Fatal(err)
	}
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		t.Fatal(err)
	}
	helper := &lockHelper{command: command, stdin: stdin}
	ready := make(chan error, 1)
	go func() {
		line, readErr := bufio.NewReader(stdout).ReadString('\n')
		if readErr == nil && line != readyLine {
			readErr = errors.New("state lock helper returned an invalid readiness message")
		}
		ready <- readErr
	}()
	select {
	case err := <-ready:
		if err != nil {
			helper.stop(t)
			t.Fatalf("wait for state lock helper: %v; stderr=%q", err, stderr.String())
		}
	case <-time.After(3 * time.Second):
		helper.stop(t)
		t.Fatalf("state lock helper did not acquire the lock; stderr=%q", stderr.String())
	}
	return helper
}

func (helper *lockHelper) exitNormally(t *testing.T) {
	t.Helper()
	if helper.done {
		return
	}
	if err := helper.stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := helper.command.Wait(); err != nil {
		t.Fatal(err)
	}
	helper.done = true
}

func (helper *lockHelper) stop(t *testing.T) {
	t.Helper()
	if helper == nil || helper.done {
		return
	}
	_ = helper.stdin.Close()
	if helper.command.Process != nil {
		_ = helper.command.Process.Kill()
	}
	_ = helper.command.Wait()
	helper.done = true
}
