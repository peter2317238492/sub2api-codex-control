package securefile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadJSONLimitRejectsOversizedPrivateFileBeforeDecode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"value":"too large"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var value map[string]json.RawMessage
	if err := ReadJSONLimit(path, &value, 8); err == nil || !strings.Contains(err.Error(), "exceeds 8 bytes") {
		t.Fatalf("ReadJSONLimit error = %v, want size rejection", err)
	}
}

func TestEnsureDirCreatesNestedPrivateDirectory(t *testing.T) {
	base := t.TempDir()
	first := filepath.Join(base, "first")
	second := filepath.Join(first, "second")
	directory := filepath.Join(second, "state")

	if err := EnsureDir(directory); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	for _, path := range []string{first, second, directory} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("created component %s mode = %v, want private directory", path, info.Mode())
		}
	}
}

func TestTrustedOwnerPolicy(t *testing.T) {
	const effectiveUID = uint32(501)
	tests := []struct {
		name      string
		owner     uint32
		allowRoot bool
		want      bool
	}{
		{name: "effective user", owner: effectiveUID, want: true},
		{name: "root ancestor", owner: 0, allowRoot: true, want: true},
		{name: "root state object", owner: 0, want: false},
		{name: "other user", owner: 502, allowRoot: true, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := trustedOwner(test.owner, effectiveUID, test.allowRoot); got != test.want {
				t.Fatalf("trustedOwner(%d, %d, %t) = %t, want %t", test.owner, effectiveUID, test.allowRoot, got, test.want)
			}
		})
	}
}

func TestPrivateFileHelpersValidateIdentityAndPermissions(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	contents := []byte("private state\n")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := ReadPrivateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(contents) {
		t.Fatalf("private file contents = %q", data)
	}
	info, err := StatPrivateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != int64(len(contents)) {
		t.Fatalf("private file size = %d, want %d", info.Size(), len(contents))
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateFile(path); err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
		t.Fatalf("unsafe-mode read error = %v", err)
	}
}

func TestPrivateFileHelpersRejectSymbolicLinks(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("target\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "state.json")
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if _, err := ReadPrivateFile(alias); err == nil || !strings.Contains(err.Error(), "private regular file") {
		t.Fatalf("symbolic-link read error = %v", err)
	}
	if _, err := StatPrivateFile(alias); err == nil || !strings.Contains(err.Error(), "private regular file") {
		t.Fatalf("symbolic-link stat error = %v", err)
	}
}

func TestValidateOwnerAndACLRejectsRootOwnedFinalObject(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is the effective owner in this test environment")
	}
	root, err := os.Open(string(filepath.Separator))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := ValidateOwnerAndACL(root, false); err == nil || !strings.Contains(err.Error(), "untrusted owner") {
		t.Fatalf("root-owned final object error = %v", err)
	}
	if _, err := ValidateOwnerAndACL(root, true); err != nil {
		t.Fatalf("root-owned ancestor rejected: %v", err)
	}
}
