//go:build windows

package approval

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
)

func TestApprovalDetailsNeverCarryAWindowsPath(t *testing.T) {
	emitted := make(chan protocol.ApprovalRequestPayload, 1)
	broker := New(time.Second, func(_ context.Context, _ string, value any) error {
		emitted <- value.(protocol.ApprovalRequestPayload)
		return nil
	})
	broker.SetEpoch("epoch-0123456789abcdef")
	broker.SetConnected(true)
	go func() {
		_, _ = broker.Request(t.Context(), "item/commandExecution/requestApproval", mustJSON(map[string]any{
			"command":   "git status",
			"cwd":       `C:\work\project`,
			"grantRoot": `C:\work`,
			"path":      `\\nas\share\project\file.txt`,
		}))
	}()
	request := <-emitted
	for field, want := range map[string]string{
		"cwd":       "/c/work/project",
		"grantRoot": "/c/work",
		"path":      "/unc/nas/share/project/file.txt",
	} {
		if got := request.Details[field]; got != want {
			t.Fatalf("approval %s = %#v, want %q", field, got, want)
		}
	}
	encoded := string(mustJSON(request.Details))
	if strings.ContainsRune(encoded, '\\') || strings.Contains(encoded, "C:") {
		t.Fatalf("approval details leaked a Windows path: %s", encoded)
	}
}

func TestVolumeRootApprovalPathIsDeniedBeforeEmission(t *testing.T) {
	var emitted int
	broker := New(time.Second, func(context.Context, string, any) error {
		emitted++
		return nil
	})
	broker.SetEpoch("epoch-0123456789abcdef")
	broker.SetConnected(true)
	result, rpcErr := broker.Request(
		t.Context(),
		"item/fileChange/requestApproval",
		mustJSON(map[string]any{"path": `C:\`}),
	)
	if rpcErr != nil || emitted != 0 {
		t.Fatalf("volume root approval path = %#v, %v, emitted=%d", result, rpcErr, emitted)
	}
	if result.(map[string]string)["decision"] != "decline" {
		t.Fatalf("volume root approval path result = %#v", result)
	}
}

func TestFileChangeApprovalProjectsEveryPathItCarries(t *testing.T) {
	emitted := make(chan protocol.ApprovalRequestPayload, 1)
	broker := New(time.Second, func(_ context.Context, _ string, value any) error {
		emitted <- value.(protocol.ApprovalRequestPayload)
		return nil
	})
	broker.SetEpoch("epoch-0123456789abcdef")
	broker.SetConnected(true)
	go func() {
		_, _ = broker.Request(t.Context(), "item/fileChange/requestApproval", mustJSON(map[string]any{
			"cwd": `C:\work\project`,
			"fileChanges": map[string]any{
				`C:\work\project\main.go`: map[string]any{"type": "update"},
				`C:\work\project\old.go`: map[string]any{
					"type": "update", "move_path": `C:\work\project\new.go`,
				},
			},
		}))
	}()
	request := <-emitted
	changes, ok := request.Details["fileChanges"].(map[string]any)
	if !ok || len(changes) != 2 {
		t.Fatalf("file changes = %#v", request.Details["fileChanges"])
	}
	// The map is keyed by the changed file, so the keys are paths too and the
	// browser must never see a Windows one.
	if _, exists := changes["/c/work/project/main.go"]; !exists {
		t.Fatalf("file change key was not projected: %#v", changes)
	}
	moved, ok := changes["/c/work/project/old.go"].(map[string]any)
	if !ok || moved["move_path"] != "/c/work/project/new.go" {
		t.Fatalf("move path was not projected: %#v", changes["/c/work/project/old.go"])
	}
	encoded := string(mustJSON(request.Details))
	if strings.ContainsRune(encoded, '\\') || strings.Contains(encoded, "C:") {
		t.Fatalf("file change approval leaked a Windows path: %s", encoded)
	}
}

func TestApprovalSummaryNeverCarriesAWindowsPath(t *testing.T) {
	emitted := make(chan protocol.ApprovalRequestPayload, 1)
	broker := New(time.Second, func(_ context.Context, _ string, value any) error {
		emitted <- value.(protocol.ApprovalRequestPayload)
		return nil
	})
	broker.SetEpoch("epoch-0123456789abcdef")
	broker.SetConnected(true)
	go func() {
		// A path-only file-change approval is the shape whose summary falls back
		// to the path field.
		_, _ = broker.Request(t.Context(), "item/fileChange/requestApproval", mustJSON(map[string]any{
			"path": `C:\work\project\file.txt`,
		}))
	}()
	request := <-emitted
	if strings.ContainsRune(request.Summary, '\\') || strings.Contains(request.Summary, "C:") {
		t.Fatalf("approval summary leaked a Windows path: %q", request.Summary)
	}
	if !strings.Contains(request.Summary, "/c/work/project/file.txt") {
		t.Fatalf("approval summary = %q, want the projected path", request.Summary)
	}
}
