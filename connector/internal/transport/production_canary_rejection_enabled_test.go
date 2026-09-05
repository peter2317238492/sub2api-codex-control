//go:build productioncanary && (darwin || linux)

package transport

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/auth"
)

func TestCanaryMarkerDoesNotCountGenericTokenFailures(t *testing.T) {
	directory := t.TempDir()
	stop, err := EnableProductionCanaryCrashHook(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	path := filepath.Join(directory, "production-canary-credential-rejected.json")
	productionCanaryTokenFailure(errors.New("network failure"))
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("generic token failure created a credential-rejection proof")
	}
	productionCanaryTokenFailure(auth.ErrInvalidDeviceCredential)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Rejected bool `json:"credential_rejected"`
		Version  int  `json:"version"`
	}
	if json.Unmarshal(raw, &result) != nil || !result.Rejected || result.Version != 1 {
		t.Fatal("credential-rejection marker is invalid")
	}
	metadata, err := os.Stat(path)
	if err != nil || metadata.Mode().Perm() != 0600 {
		t.Fatal("marker is not private")
	}
}
