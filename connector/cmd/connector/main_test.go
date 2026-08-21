package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/config"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
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

func TestTerminalErrorReportIdentifiesFixableStateDirectoryPlacement(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		cause    error
		expected string
	}{
		{
			name:     "volume without access control lists",
			cause:    securefile.ErrUnsupportedVolume,
			expected: "connector: state_dir is on a volume that cannot record access control lists; choose an NTFS volume\n",
		},
		{
			name:     "location reachable by another principal",
			cause:    securefile.ErrUntrustedLocation,
			expected: "connector: state_dir or a directory above it is reachable by another principal; choose a private location\n",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var output bytes.Buffer
			reportTerminalError(&output, fmt.Errorf(
				"connector state ancestor /private/workspace/PATH-SENTINEL: %w", testCase.cause))
			if output.String() != testCase.expected {
				t.Fatalf("terminal placement error report = %q", output.String())
			}
			if strings.Contains(output.String(), "PATH-SENTINEL") {
				t.Fatal("terminal placement error report leaked the wrapped path")
			}
		})
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
	stateDir := filepath.Join(trustedStateParent(t), "state")
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
	if err := run(configPath, false, "", newStderrSink(io.Discard)); !errors.Is(err, statelock.ErrInUse) {
		t.Fatalf("run error = %v, want ErrInUse", err)
	}
}
