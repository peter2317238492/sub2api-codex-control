package securefile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureDirCreatesPrivateDirectoryChain(t *testing.T) {
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
		if !info.IsDir() {
			t.Fatalf("created component %s is not a directory", path)
		}
	}
	if err := EnsureDir(directory); err != nil {
		t.Fatalf("EnsureDir on existing directory: %v", err)
	}
}

func TestWriteJSONRoundTripsThroughPrivateState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "state.json")
	written := map[string]string{"value": "private"}
	if err := WriteJSON(path, written); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var read map[string]string
	if err := ReadJSON(path, &read); err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if read["value"] != written["value"] {
		t.Fatalf("round-tripped value = %q, want %q", read["value"], written["value"])
	}
	info, err := StatPrivateFile(path)
	if err != nil {
		t.Fatalf("StatPrivateFile: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("state file is empty")
	}
	if err := WriteJSON(path, map[string]string{"value": "replaced"}); err != nil {
		t.Fatalf("WriteJSON replacement: %v", err)
	}
	if err := ReadJSON(path, &read); err != nil {
		t.Fatalf("ReadJSON after replacement: %v", err)
	}
	if read["value"] != "replaced" {
		t.Fatalf("replaced value = %q", read["value"])
	}
}

func TestReadJSONLimitRejectsOversizedStateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "state.json")
	if err := WriteJSON(path, map[string]string{"value": "too large"}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var value map[string]json.RawMessage
	if err := ReadJSONLimit(path, &value, 8); err == nil || !strings.Contains(err.Error(), "exceeds 8 bytes") {
		t.Fatalf("ReadJSONLimit error = %v, want size rejection", err)
	}
}

func TestReadJSONRejectsTrailingDocument(t *testing.T) {
	var value map[string]string
	if err := decodeJSON([]byte("{}\n{}\n"), &value); err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("decodeJSON error = %v, want multiple-value rejection", err)
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

func TestValidateOwnerAndACLRejectsClosedObject(t *testing.T) {
	if _, err := ValidateOwnerAndACL(nil, false); err == nil || !strings.Contains(err.Error(), "not open") {
		t.Fatalf("nil state object error = %v", err)
	}
}
