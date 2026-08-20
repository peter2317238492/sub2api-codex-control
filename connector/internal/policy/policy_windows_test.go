//go:build windows

package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuardRejectsALocalWindowsCWDFromTheControlPlane(t *testing.T) {
	root := t.TempDir()
	guard, err := NewGuard([]string{root}, "workspace-write")
	if err != nil {
		t.Fatal(err)
	}
	local := guard.WorkspaceRoots()[0]
	if _, err := guard.CanonicalCWD(local); err == nil {
		t.Fatalf("guard accepted the local path %q as a remote cwd", local)
	}
	if _, err := guard.Enforce("thread/start", json.RawMessage(`{"cwd":`+quote(local)+`}`)); err == nil {
		t.Fatalf("thread/start accepted the Windows path %q", local)
	}
}

func TestGuardHandsAppServerAWindowsPath(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "project")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(child)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewGuard([]string{root}, "workspace-write")
	if err != nil {
		t.Fatal(err)
	}
	remote, err := pathMapper.Remote(resolved)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(remote, "/") || strings.ContainsRune(remote, '\\') {
		t.Fatalf("remote cwd %q is not an absolute POSIX path", remote)
	}
	guarded, err := guard.Enforce("thread/start", json.RawMessage(`{"cwd":`+quote(remote)+`}`))
	if err != nil {
		t.Fatal(err)
	}
	var params map[string]any
	if err := json.Unmarshal(guarded, &params); err != nil {
		t.Fatal(err)
	}
	cwd, _ := params["cwd"].(string)
	if filepath.VolumeName(cwd) == "" || !strings.ContainsRune(cwd, '\\') {
		t.Fatalf("app-server cwd = %q, want a local Windows path", cwd)
	}
	if cwd != resolved {
		t.Fatalf("app-server cwd = %q, want %q", cwd, resolved)
	}
}

func TestProjectResultReplacesAWindowsThreadCWD(t *testing.T) {
	projected, err := ProjectResult(
		"thread/start",
		json.RawMessage(`{"thread":{"id":"thread-1"},"cwd":`+quote(`C:\work\project`)+`}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := projectedCWD(t, projected); got != "/c/work/project" {
		t.Fatalf("projected cwd = %q, want %q", got, "/c/work/project")
	}
	if strings.ContainsRune(string(projected), '\\') || strings.Contains(string(projected), "C:") {
		t.Fatalf("projection leaked a Windows path: %s", projected)
	}
}

func TestProjectResultRejectsAUNCShareRootThreadCWD(t *testing.T) {
	if _, err := ProjectResult(
		"thread/start",
		json.RawMessage(`{"thread":{"id":"thread-1"},"cwd":`+quote(`\\nas\share`)+`}`),
	); err == nil {
		t.Fatal("a UNC share root was projected as a thread cwd")
	}
}
