package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/config"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/statelock"
)

func TestTerminalErrorReportSuppressesDynamicDetails(t *testing.T) {
	var output bytes.Buffer
	reportTerminalError(&output, errors.New(
		"/private/workspace/PATH-SENTINEL Authorization: Bearer TOKEN-SENTINEL ONE-TIME-PAIRING-CODE",
	))
	for _, sentinel := range []string{
		"/private/workspace/PATH-SENTINEL",
		"Authorization: Bearer TOKEN-SENTINEL",
		"ONE-TIME-PAIRING-CODE",
	} {
		if strings.Contains(output.String(), sentinel) {
			t.Fatalf("terminal error report leaked %q", sentinel)
		}
	}
	if output.String() != "connector: terminated with an error (details suppressed)\n" {
		t.Fatalf("terminal error report = %q", output.String())
	}
}

func TestTerminalErrorReportIdentifiesStateDirectoryContentionWithoutDetails(t *testing.T) {
	var output bytes.Buffer
	reportTerminalError(&output, fmt.Errorf("sensitive wrapper: %w", statelock.ErrInUse))
	if output.String() != "connector: state directory is already in use\n" {
		t.Fatalf("terminal lock error report = %q", output.String())
	}
	if strings.Contains(output.String(), "sensitive wrapper") {
		t.Fatal("terminal lock error report leaked wrapped details")
	}
}

func TestStateLockReleaseErrorIsNotHiddenByCancellation(t *testing.T) {
	releaseFailure := errors.New("release failed")
	combined := joinStateLockReleaseError(context.Canceled, releaseFailure)
	if !shouldReportTerminalError(combined) {
		t.Fatal("state lock release error combined with cancellation was suppressed")
	}
	if !errors.Is(combined, releaseFailure) {
		t.Fatal("state lock release cause was lost")
	}
	if shouldReportTerminalError(context.Canceled) {
		t.Fatal("plain graceful cancellation should remain silent")
	}
}

func TestRunAcquiresStateLockBeforeReadingConnectorState(t *testing.T) {
	stateParent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(stateParent, "state")
	workspace := t.TempDir()
	stateLock, err := statelock.Acquire(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stateLock.Release(); err != nil {
			t.Errorf("release state lock: %v", err)
		}
	}()

	// If run reached state loading, this malformed credential would produce a
	// different error. Contention must stop it first.
	if err := os.WriteFile(filepath.Join(stateDir, "device-credentials.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "connector.json")
	configData, err := json.Marshal(map[string]any{
		"control_url":     "wss://control.example/device",
		"pairing_url":     "https://control.example/v1/device-pairings/start",
		"token_url":       "https://control.example/v1/devices/token",
		"display_name":    "test device",
		"state_dir":       stateDir,
		"workspace_roots": []string{workspace},
		"schema_digest":   config.PinnedSchemaDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(configPath, false); !errors.Is(err, statelock.ErrInUse) {
		t.Fatalf("run error = %v, want ErrInUse", err)
	}
}
