package identity

import (
	"path/filepath"
	"testing"
)

func TestLoadOrCreatePersistsPrivateIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "identity.json")
	first, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	requirePrivateIdentity(t, path)
	second, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if first.PublicKeyString() != second.PublicKeyString() {
		t.Fatal("device identity changed after reload")
	}
}
