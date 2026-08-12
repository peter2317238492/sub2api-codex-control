package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadAppliesSecureDefaults(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(t.TempDir(), "connector.json")
	writeConfig(t, path, map[string]any{
		"control_url":     "wss://control.example/device",
		"pairing_url":     "https://control.example/v1/device-pairings/start",
		"token_url":       "https://control.example/v1/devices/token",
		"display_name":    "test device",
		"state_dir":       filepath.Join(t.TempDir(), "state"),
		"workspace_roots": []string{root},
		"schema_digest":   PinnedSchemaDigest,
	})
	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.SandboxCap != "workspace-write" || config.ApprovalTimeout.Value() != 120*time.Second {
		t.Fatalf("defaults = %#v", config)
	}
}

func TestLoadRejectsUnknownFieldsAndUnsafeSchemes(t *testing.T) {
	root := t.TempDir()
	base := map[string]any{
		"control_url":  "ws://control.example/device",
		"pairing_url":  "https://control.example/pair",
		"token_url":    "https://control.example/token",
		"display_name": "test", "state_dir": filepath.Join(t.TempDir(), "state"),
		"workspace_roots": []string{root},
		"schema_digest":   PinnedSchemaDigest, "unexpected": true,
	}
	path := filepath.Join(t.TempDir(), "connector.json")
	writeConfig(t, path, base)
	if _, err := Load(path); err == nil {
		t.Fatal("expected invalid config to be rejected")
	}
}

func TestLoadRejectsStateInsideWorkspace(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(t.TempDir(), "connector.json")
	writeConfig(t, path, map[string]any{
		"control_url":  "wss://control.example/device",
		"pairing_url":  "https://control.example/pair",
		"token_url":    "https://control.example/token",
		"display_name": "test", "state_dir": filepath.Join(root, ".connector-state"),
		"workspace_roots": []string{root},
		"schema_digest":   PinnedSchemaDigest,
	})
	if _, err := Load(path); err == nil {
		t.Fatal("state directory inside workspace was accepted")
	}
}

func TestLoadRejectsStateOverlappingEffectiveCodexHome(t *testing.T) {
	for _, test := range []struct {
		name     string
		stateDir func(string) string
	}{
		{name: "inside", stateDir: func(codexHome string) string {
			return filepath.Join(codexHome, "connector-state")
		}},
		{name: "ancestor", stateDir: func(codexHome string) string {
			return filepath.Dir(codexHome)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			codexHome := filepath.Join(t.TempDir(), ".codex")
			t.Setenv("CODEX_HOME", codexHome)
			path := filepath.Join(t.TempDir(), "connector.json")
			writeConfig(t, path, map[string]any{
				"control_url":  "wss://control.example/device",
				"pairing_url":  "https://control.example/pair",
				"token_url":    "https://control.example/token",
				"display_name": "test", "state_dir": test.stateDir(codexHome),
				"workspace_roots": []string{t.TempDir()},
				"schema_digest":   PinnedSchemaDigest,
			})
			if _, err := Load(path); err == nil {
				t.Fatal("state directory overlapping CODEX_HOME was accepted")
			}
		})
	}
}

func TestLoadRejectsWorkspaceOverlappingEffectiveCodexHome(t *testing.T) {
	for _, test := range []struct {
		name      string
		workspace func(string) string
	}{
		{name: "inside", workspace: func(codexHome string) string {
			return filepath.Join(codexHome, "workspace")
		}},
		{name: "ancestor", workspace: func(codexHome string) string {
			return filepath.Dir(codexHome)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			codexHome := filepath.Join(t.TempDir(), ".codex")
			workspace := test.workspace(codexHome)
			if err := os.MkdirAll(workspace, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("CODEX_HOME", codexHome)
			path := filepath.Join(t.TempDir(), "connector.json")
			writeConfig(t, path, map[string]any{
				"control_url":  "wss://control.example/device",
				"pairing_url":  "https://control.example/pair",
				"token_url":    "https://control.example/token",
				"display_name": "test", "state_dir": filepath.Join(t.TempDir(), "state"),
				"workspace_roots": []string{workspace},
				"schema_digest":   PinnedSchemaDigest,
			})
			if _, err := Load(path); err == nil {
				t.Fatal("workspace root overlapping CODEX_HOME was accepted")
			}
		})
	}
}

func TestLoadRejectsRelativeCodexHome(t *testing.T) {
	t.Setenv("CODEX_HOME", ".codex")
	path := filepath.Join(t.TempDir(), "connector.json")
	writeConfig(t, path, map[string]any{
		"control_url":  "wss://control.example/device",
		"pairing_url":  "https://control.example/pair",
		"token_url":    "https://control.example/token",
		"display_name": "test", "state_dir": filepath.Join(t.TempDir(), "state"),
		"workspace_roots": []string{t.TempDir()},
		"schema_digest":   PinnedSchemaDigest,
	})
	if _, err := Load(path); err == nil {
		t.Fatal("relative CODEX_HOME was accepted")
	}
}

func TestLoadRejectsCrossOriginCredentialEndpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connector.json")
	writeConfig(t, path, map[string]any{
		"control_url":  "wss://control.example/device",
		"pairing_url":  "https://control.example/pair",
		"token_url":    "https://credential-thief.example/token",
		"display_name": "test", "state_dir": filepath.Join(t.TempDir(), "state"),
		"workspace_roots": []string{t.TempDir()},
		"schema_digest":   PinnedSchemaDigest,
	})
	if _, err := Load(path); err == nil {
		t.Fatal("cross-origin token endpoint was accepted")
	}
}

func TestLoadRejectsUnpinnedSchemaDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connector.json")
	writeConfig(t, path, map[string]any{
		"control_url":  "wss://control.example/device",
		"pairing_url":  "https://control.example/pair",
		"token_url":    "https://control.example/token",
		"display_name": "test", "state_dir": filepath.Join(t.TempDir(), "state"),
		"workspace_roots": []string{t.TempDir()},
		"schema_digest":   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if _, err := Load(path); err == nil {
		t.Fatal("unpinned schema digest was accepted")
	}
}

func TestLoadRejectsTooManyWorkspaceRoots(t *testing.T) {
	roots := make([]string, 33)
	for index := range roots {
		roots[index] = t.TempDir()
	}
	path := filepath.Join(t.TempDir(), "connector.json")
	writeConfig(t, path, map[string]any{
		"control_url":  "wss://control.example/device",
		"pairing_url":  "https://control.example/pair",
		"token_url":    "https://control.example/token",
		"display_name": "test", "state_dir": filepath.Join(t.TempDir(), "state"),
		"workspace_roots": roots,
		"schema_digest":   PinnedSchemaDigest,
	})
	if _, err := Load(path); err == nil {
		t.Fatal("more than 32 workspace roots were accepted")
	}
}

func writeConfig(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
