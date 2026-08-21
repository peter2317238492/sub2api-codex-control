package main

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/statelock"
)

// trustedStateParent returns a directory that can hold a Connector state
// directory, meaning its complete ancestor chain passes the same validation the
// Connector applies at startup.
//
// t.TempDir() qualifies on Linux, on macOS, and on a stock Windows install. It
// does not qualify wherever an ancestor of the temp directory lets a foreign
// principal replace what sits beneath it: a Windows host that has installed
// Codex grants CodexSandboxUsers FILE_DELETE_CHILD on the user profile, and
// %TEMP% lives under that profile, so the ancestor walk refuses it — correctly,
// because such a principal really could substitute the state directory. There
// the fallback is a directory directly under the volume root, whose only
// ancestor is the OS-owned root itself.
func trustedStateParent(t *testing.T) string {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if stateParentIsTrusted(parent) {
		return parent
	}
	volume := filepath.VolumeName(parent)
	if volume == "" {
		t.Skipf("no trusted state parent is available under %s", parent)
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	fallback := filepath.Join(volume+string(filepath.Separator), "sub2api-connector-test-"+hex.EncodeToString(suffix))
	// EnsureDir validates before it restricts, so it can only adopt a directory
	// that is already private. Letting it create this one instead means the
	// volume root's inheritable grants never apply to it, even briefly.
	if err := securefile.EnsureDir(fallback); err != nil {
		t.Fatalf("create trusted state parent: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(fallback) })
	if !stateParentIsTrusted(fallback) {
		t.Fatalf("%s is not a usable state parent", fallback)
	}
	return fallback
}

func stateParentIsTrusted(parent string) bool {
	probe := filepath.Join(parent, "trusted-probe")
	lock, err := statelock.Acquire(probe)
	if err != nil {
		return false
	}
	releaseErr := lock.Release()
	_ = os.RemoveAll(probe)
	return releaseErr == nil
}
