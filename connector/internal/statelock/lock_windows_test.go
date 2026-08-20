//go:build windows

package statelock

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

const (
	helperModeEnv  = "SUB2API_STATE_LOCK_HELPER"
	helperBaseEnv  = "SUB2API_STATE_LOCK_BASE"
	helperDirEnv   = "SUB2API_STATE_LOCK_DIR"
	passiveModeEnv = "SUB2API_STATE_LOCK_PASSIVE_HELPER"
)

func TestStateVolumeRootRejectsRootsAndDeviceNamespaces(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		want      string
		wantError string
	}{
		{name: "drive rooted path", path: `C:\ProgramData\connector\state`, want: `C:\`},
		{name: "nested drive rooted path", path: `D:\a\b\c`, want: `D:\`},
		{name: "trailing separator", path: `D:\state\`, want: `D:\`},
		{name: "unc path", path: `\\nas\share\connector\state`, want: `\\nas\share\`},
		{name: "drive root", path: `D:\`, wantError: "absolute non-root path"},
		{name: "drive root without separator", path: `D:`, wantError: "absolute non-root path"},
		{name: "share root", path: `\\nas\share`, wantError: "absolute non-root path"},
		{name: "relative path", path: `connector\state`, wantError: "absolute non-root path"},
		{name: "rooted without drive", path: `\connector\state`, wantError: "absolute non-root path"},
		{name: "extended length prefix", path: `\\?\C:\state`, wantError: "drive-letter or UNC path"},
		{name: "device namespace", path: `\\.\C:\state`, wantError: "drive-letter or UNC path"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, err := stateVolumeRoot(test.path)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("stateVolumeRoot(%q) error = %v, want %s", test.path, err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("stateVolumeRoot(%q): %v", test.path, err)
			}
			if root != test.want {
				t.Fatalf("stateVolumeRoot(%q) = %q, want %q", test.path, root, test.want)
			}
		})
	}
}

func TestAcquireRejectsVolumeRootStateDirectory(t *testing.T) {
	lock, err := Acquire(filepath.VolumeName(t.TempDir()) + `\`)
	if lock != nil {
		_ = lock.Release()
	}
	if err == nil || !strings.Contains(err.Error(), "absolute non-root path") {
		t.Fatalf("volume root acquire error = %v, want non-root rejection", err)
	}
}

func TestStateComponentsRejectsPathsOutsideBase(t *testing.T) {
	if _, err := stateComponents(`C:\base`, `C:\other\state`); err == nil {
		t.Fatal("path outside the validated base was accepted")
	}
	components, err := stateComponents(`C:\`, `C:\a\b`)
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 2 || components[0] != "a" || components[1] != "b" {
		t.Fatalf("stateComponents = %v, want [a b]", components)
	}
}

func TestStateLockIsExclusiveWithinProcessAndReleasable(t *testing.T) {
	base := trustedBase(t)
	stateDir := filepath.Join(base, "state")
	lock, err := acquireTestLock(base, stateDir)
	if err != nil {
		t.Fatalf("acquire state directory: %v", err)
	}

	startedAt := time.Now()
	second, err := acquireTestLock(base, stateDir)
	if second != nil {
		_ = second.Release()
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

	if err := lock.Release(); err != nil {
		t.Fatalf("release state directory: %v", err)
	}
	reacquired, err := acquireTestLock(base, stateDir)
	if err != nil {
		t.Fatalf("reacquire after release: %v", err)
	}
	if err := reacquired.Release(); err != nil {
		t.Fatalf("release reacquired lock: %v", err)
	}
	if err := reacquired.Release(); err != nil {
		t.Fatalf("second release: %v", err)
	}
}

func TestDistinctStateDirectoriesCanBeLockedConcurrently(t *testing.T) {
	base := trustedBase(t)
	first, err := acquireTestLock(base, filepath.Join(base, "first"))
	if err != nil {
		t.Fatalf("acquire first state directory: %v", err)
	}
	defer first.Release()
	second, err := acquireTestLock(base, filepath.Join(base, "second"))
	if err != nil {
		t.Fatalf("acquire second state directory: %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatalf("release second state directory: %v", err)
	}
}

func TestStateLockCreatesPrivateDirectoryComponents(t *testing.T) {
	base := trustedBase(t)
	first := filepath.Join(base, "first")
	second := filepath.Join(first, "second")
	stateDir := filepath.Join(second, "state")

	lock, err := acquireTestLock(base, stateDir)
	if err != nil {
		t.Fatalf("acquire nested state directory: %v", err)
	}
	for _, path := range []string{first, second, stateDir} {
		directory, openErr := openStateComponent(path, false)
		if openErr != nil {
			t.Fatalf("open %s: %v", path, openErr)
		}
		info, validateErr := securefile.ValidateOwnerAndACL(directory, false)
		_ = directory.Close()
		if validateErr != nil {
			t.Fatalf("created component %s is not private: %v", path, validateErr)
		}
		if !info.IsDir() {
			t.Fatalf("created component %s is not a directory", path)
		}
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	info, err := securefile.StatPrivateFile(filepath.Join(stateDir, lockFileName))
	if err != nil {
		t.Fatalf("state lock is not a private file: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("state lock mode = %v, want regular file", info.Mode())
	}
}

func TestStateLockPinsStateDirectoryAndMarker(t *testing.T) {
	base := trustedBase(t)
	stateDir := filepath.Join(base, "state")
	lock, err := acquireTestLock(base, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(stateDir, lockFileName)); err == nil {
		_ = lock.Release()
		t.Fatal("state lock marker was removed while the lock was held")
	}
	if err := os.Rename(stateDir, stateDir+"-moved"); err == nil {
		_ = lock.Release()
		t.Fatal("state directory was renamed while the lock was held")
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(stateDir, stateDir+"-moved"); err != nil {
		t.Fatalf("state directory stayed pinned after release: %v", err)
	}
}

func TestStateLockRejectsReparsePointComponents(t *testing.T) {
	t.Run("ancestor", func(t *testing.T) {
		base := trustedBase(t)
		target := filepath.Join(base, "target")
		if err := securefile.EnsureDir(target); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(base, "alias")
		createReparsePoint(t, alias, target)
		stateDir := filepath.Join(alias, "state")
		lock, err := acquireTestLock(base, stateDir)
		if lock != nil {
			_ = lock.Release()
		}
		if err == nil {
			t.Fatal("state directory below a reparse-point ancestor was accepted")
		}
		if !strings.Contains(err.Error(), "reparse point") {
			t.Fatalf("reparse-point ancestor error = %v, want reparse point rejection", err)
		}
		if _, statErr := os.Lstat(filepath.Join(target, "state")); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("state directory was created through a reparse point: %v", statErr)
		}
	})

	t.Run("state directory", func(t *testing.T) {
		base := trustedBase(t)
		target := filepath.Join(base, "target")
		if err := securefile.EnsureDir(target); err != nil {
			t.Fatal(err)
		}
		stateDir := filepath.Join(base, "state")
		createReparsePoint(t, stateDir, target)
		lock, err := acquireTestLock(base, stateDir)
		if lock != nil {
			_ = lock.Release()
		}
		if err == nil {
			t.Fatal("reparse-point state directory was accepted")
		}
		if !strings.Contains(err.Error(), "reparse point") && !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("reparse-point state directory error = %v, want reparse point rejection", err)
		}
		if _, statErr := os.Lstat(filepath.Join(target, lockFileName)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("state lock was created through a reparse point: %v", statErr)
		}
	})
}

func TestStateLockAncestorAccessControlRules(t *testing.T) {
	tests := []struct {
		name      string
		grant     string
		wantError string
	}{
		{name: "foreign read", grant: "(RX)"},
		{name: "foreign create", grant: "(AD)"},
		{name: "foreign delete child", grant: "(DC)", wantError: "writable by an untrusted principal"},
		{name: "foreign delete", grant: "(D)", wantError: "writable by an untrusted principal"},
		{name: "foreign change permissions", grant: "(WDAC)", wantError: "writable by an untrusted principal"},
		{name: "foreign take ownership", grant: "(WO)", wantError: "writable by an untrusted principal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := trustedBase(t)
			ancestor := filepath.Join(base, "ancestor")
			if err := securefile.EnsureDir(ancestor); err != nil {
				t.Fatal(err)
			}
			grantForeignAccess(t, ancestor, test.grant)
			stateDir := filepath.Join(ancestor, "state")
			lock, err := acquireTestLock(base, stateDir)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("ancestor granting %s rejected: %v", test.grant, err)
				}
				if err := lock.Release(); err != nil {
					t.Fatal(err)
				}
				return
			}
			if lock != nil {
				_ = lock.Release()
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("ancestor granting %s error = %v, want %s", test.grant, err, test.wantError)
			}
			if !strings.Contains(err.Error(), ancestor) {
				t.Fatalf("ancestor rejection does not name %s: %v", ancestor, err)
			}
			if _, statErr := os.Lstat(stateDir); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("state directory was created below an untrusted ancestor: %v", statErr)
			}
		})
	}
}

func TestStateLockRejectsStateDirectoryReachableByAnotherPrincipal(t *testing.T) {
	base := trustedBase(t)
	stateDir := filepath.Join(base, "state")
	if err := securefile.EnsureDir(stateDir); err != nil {
		t.Fatal(err)
	}
	grantForeignAccess(t, stateDir, "(RX)")
	lock, err := acquireTestLock(base, stateDir)
	if lock != nil {
		_ = lock.Release()
	}
	if err == nil || !strings.Contains(err.Error(), "unsafe access control list") {
		t.Fatalf("state directory readable by another principal = %v, want unsafe access control list", err)
	}
	if _, statErr := os.Lstat(filepath.Join(stateDir, lockFileName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("state lock was created in a shared state directory: %v", statErr)
	}
}

func TestStateDirectoryReplacementDetectedDuringAcquisition(t *testing.T) {
	base := trustedBase(t)
	ancestor := filepath.Join(base, "ancestor")
	stateDir := filepath.Join(ancestor, "state")
	if err := securefile.EnsureDir(stateDir); err != nil {
		t.Fatal(err)
	}
	replaced := false
	directory, err := openTrustedDirectoryWithHook(base, stateDir, func(component string) {
		if replaced || component != ancestor {
			return
		}
		replaced = true
		if renameErr := os.Rename(ancestor, filepath.Join(base, "original")); renameErr != nil {
			t.Fatal(renameErr)
		}
		if mkdirErr := securefile.EnsureDir(ancestor); mkdirErr != nil {
			t.Fatal(mkdirErr)
		}
	})
	if directory != nil {
		_ = directory.Close()
	}
	if !replaced {
		t.Fatal("replacement hook did not run")
	}
	if err == nil || !strings.Contains(err.Error(), "changed during validation") {
		t.Fatalf("component replacement error = %v, want identity rejection", err)
	}
}

func TestAcquireRejectsVolumeWithoutPersistentAccessControl(t *testing.T) {
	path := filepath.Join(volumeWithoutPersistentACLs(t), "sub2api-statelock-volume-check")
	lock, err := Acquire(path)
	if lock != nil {
		_ = lock.Release()
	}
	if err == nil || !strings.Contains(err.Error(), "access control lists") {
		t.Fatalf("unsupported volume error = %v, want access control list rejection", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		_ = os.Remove(path)
		t.Fatal("state directory was created on a volume without persistent access control lists")
	}
	t.Logf("volume rejection: %v", err)
}

func TestMeasuredHostAncestorOutcomes(t *testing.T) {
	profile := os.Getenv("USERPROFILE")
	if profile == "" {
		t.Skip("USERPROFILE is not set")
	}
	tests := []struct {
		name      string
		path      string
		wantError string
	}{
		{name: "state volume root", path: `D:\`},
		{name: "user profile", path: profile, wantError: "writable by an untrusted principal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateAncestorPath(t, test.path)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("ancestor %s error = %v, want %s", test.path, err, test.wantError)
				}
				return
			}
			if err == nil {
				return
			}
			if strings.Contains(err.Error(), "untrusted owner") {
				t.Skipf("ancestor %s is owned by a principal outside design-doc section 3: %v", test.path, err)
			}
			t.Fatalf("ancestor %s rejected: %v", test.path, err)
		})
	}
}

// TestMeasuredAncestorAccessControlOutcomes replays the two access control
// lists design-doc section 2.2 and 2.3 measured on this host onto directories
// the test owns, so the ancestor rule is exercised independently of who owns
// the real volume root and profile directory.
func TestMeasuredAncestorAccessControlOutcomes(t *testing.T) {
	tests := []struct {
		name      string
		grants    []string
		wantError string
	}{
		{
			name:   "state volume root",
			grants: []string{"*S-1-5-32-545:(OI)(CI)(RX)", "*S-1-5-11:(OI)(CI)(IO)(M)", "*S-1-5-11:(AD)"},
		},
		{
			name:      "user profile",
			grants:    []string{"*S-1-5-32-545:(OI)(CI)(M,DC)"},
			wantError: "writable by an untrusted principal",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ancestor := filepath.Join(t.TempDir(), "ancestor")
			if err := securefile.EnsureDir(ancestor); err != nil {
				t.Fatal(err)
			}
			for _, grant := range test.grants {
				grantAccess(t, ancestor, grant)
			}
			err := validateAncestorPath(t, ancestor)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("ancestor %v rejected: %v", test.grants, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("ancestor %v error = %v, want %s", test.grants, err, test.wantError)
			}
		})
	}
}

func TestStateLockIsExclusiveAcrossProcessesAndReleasedAfterExit(t *testing.T) {
	base := trustedBase(t)
	stateDir := filepath.Join(base, "state")
	helper := startLockHelper(t, base, stateDir)
	defer helper.stop(t)

	lock, err := acquireTestLock(base, stateDir)
	if lock != nil {
		_ = lock.Release()
	}
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("acquire while another process holds the lock = %v, want ErrInUse", err)
	}

	helper.exitNormally(t)
	reacquired, err := acquireTestLock(base, stateDir)
	if err != nil {
		t.Fatalf("reacquire after helper exit: %v", err)
	}
	if err := reacquired.Release(); err != nil {
		t.Fatalf("release reacquired lock: %v", err)
	}
}

func TestStateLockReleasedAfterForcedProcessTermination(t *testing.T) {
	base := trustedBase(t)
	stateDir := filepath.Join(base, "state")
	helper := startLockHelper(t, base, stateDir)
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

	lock, err := acquireTestLock(base, stateDir)
	if err != nil {
		t.Fatalf("reacquire after forced termination: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("release after forced termination: %v", err)
	}
}

func TestStateLockHandleIsNotInheritedByChildProcess(t *testing.T) {
	base := trustedBase(t)
	stateDir := filepath.Join(base, "state")
	lock, err := acquireTestLock(base, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	helper := startPassiveHelper(t)
	defer helper.stop(t)

	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	reacquired, err := acquireTestLock(base, stateDir)
	if err != nil {
		t.Fatalf("child process inherited the state lock handle: %v", err)
	}
	if err := reacquired.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestStateLockHelper(t *testing.T) {
	if os.Getenv(helperModeEnv) != "1" {
		t.Skip("subprocess helper")
	}
	release, err := acquireStateDirFrom(os.Getenv(helperBaseEnv), os.Getenv(helperDirEnv))
	if err != nil {
		t.Fatal(err)
	}
	lock := &Lock{release: release}
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

func trustedBase(t *testing.T) string {
	t.Helper()
	base := filepath.Join(t.TempDir(), "base")
	if err := securefile.EnsureDir(base); err != nil {
		t.Fatalf("create trusted state base: %v", err)
	}
	return base
}

func acquireTestLock(base, stateDir string) (*Lock, error) {
	release, err := acquireStateDirFrom(base, stateDir)
	if err != nil {
		return nil, err
	}
	return &Lock{release: release}, nil
}

func validateAncestorPath(t *testing.T, path string) error {
	t.Helper()
	directory, err := openStateComponent(path, false)
	if err != nil {
		t.Skipf("open %s: %v", path, err)
	}
	defer directory.Close()
	return validateStateComponent(directory, false)
}

func createReparsePoint(t *testing.T, link, target string) {
	t.Helper()
	if err := os.Symlink(target, link); err == nil {
		return
	}
	output, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		t.Skipf("reparse points unavailable: %v: %s", err, output)
	}
	information, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	data, ok := information.Sys().(*syscall.Win32FileAttributeData)
	if !ok || data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		t.Skip("created link is not a reparse point")
	}
}

func grantForeignAccess(t *testing.T, path, rights string) {
	t.Helper()
	grantAccess(t, path, "*S-1-5-32-545:"+rights)
}

func grantAccess(t *testing.T, path, grant string) {
	t.Helper()
	output, err := exec.Command("icacls", path, "/grant", grant).CombinedOutput()
	if err != nil {
		t.Skipf("icacls unavailable: %v: %s", err, output)
	}
}

func volumeWithoutPersistentACLs(t *testing.T) string {
	t.Helper()
	for letter := 'A'; letter <= 'Z'; letter++ {
		root := string(letter) + `:\`
		if _, err := os.Stat(root); err != nil {
			continue
		}
		if err := securefile.RequirePersistentACLs(root); err != nil &&
			strings.Contains(err.Error(), "access control lists") {
			return root
		}
	}
	t.Skip("no reachable volume lacks persistent access control lists")
	return ""
}

type lockHelper struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	done    bool
}

func startLockHelper(t *testing.T, base, stateDir string) *lockHelper {
	t.Helper()
	return startHelper(
		t,
		"^TestStateLockHelper$",
		[]string{helperModeEnv + "=1", helperBaseEnv + "=" + base, helperDirEnv + "=" + stateDir},
		"locked\n",
	)
}

func startPassiveHelper(t *testing.T) *lockHelper {
	t.Helper()
	return startHelper(t, "^TestStateLockPassiveHelper$", []string{passiveModeEnv + "=1"}, "ready\n")
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
	case <-time.After(10 * time.Second):
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
