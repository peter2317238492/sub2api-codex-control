//go:build windows

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestIsVolumeRootCoversDriveAndUNCRoots(t *testing.T) {
	for _, test := range []struct {
		path string
		want bool
	}{
		{`C:\`, true},
		{`C:`, true},
		{`\\host\share`, true},
		{`\\host\share\`, true},
		{`C:\Users`, false},
		{`\\host\share\project`, false},
	} {
		if got := isVolumeRoot(test.path); got != test.want {
			t.Fatalf("isVolumeRoot(%q) = %v, want %v", test.path, got, test.want)
		}
	}
}

// A case-variant path names the same directory on Windows, so the overlap
// checks compare without case. The differing component must not exist, because
// resolving an existing one already recovers the on-disk casing.
func TestStateDirOverlapWithCodexHomeIgnoresCase(t *testing.T) {
	base := t.TempDir()
	t.Setenv("CODEX_HOME", filepath.Join(base, "Codex"))
	configPath := filepath.Join(t.TempDir(), "connector.json")
	writeConfig(t, configPath, map[string]any{
		"control_url":     "wss://control.example/device",
		"pairing_url":     "https://control.example/pair",
		"token_url":       "https://control.example/token",
		"display_name":    "test",
		"state_dir":       filepath.Join(base, "codex", "state"),
		"workspace_roots": []string{t.TempDir()},
		"schema_digest":   PinnedSchemaDigest,
	})
	_, err := Load(configPath)
	if err == nil || !strings.Contains(err.Error(), "state_dir must not overlap CODEX_HOME") {
		t.Fatalf("case-variant state directory inside CODEX_HOME was accepted: %v", err)
	}
}
