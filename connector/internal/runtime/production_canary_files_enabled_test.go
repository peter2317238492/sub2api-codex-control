//go:build productioncanary

package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/policy"
)

func TestCanaryFileAttributionIsBoundAndNeverForwarded(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	guard, err := policy.NewGuard([]string{root}, "workspace-write")
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := guard.CanonicalCWD(root)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(canonical, "approval-denied.txt")
	observer := productionCanaryFileObserver(state, guard, []string{root})
	if observer == nil {
		t.Fatal("canary observer is unavailable")
	}
	forwarded := 0
	handler := newNotificationHandler(context.Background(), func(context.Context, string, any) error {
		forwarded++
		return nil
	}, func(string, json.RawMessage) (bool, error) { return true, nil }, func(err error) { t.Error(err) })
	handler.canary = observer
	marker := filepath.Join(state, "production-canary-file-change.json")
	for _, test := range []struct {
		path, status      string
		matched, declined bool
	}{
		{target, "declined", true, true},
		{target, "completed", true, false},
		{filepath.Join(canonical, "other.txt"), "declined", false, true},
	} {
		raw, _ := json.Marshal(map[string]any{
			"threadId": "native-thread", "turnId": "native-turn",
			"item": map[string]any{"id": "native-item", "type": "fileChange", "status": test.status,
				"changes": []any{map[string]any{"path": test.path, "kind": map[string]any{"type": "add"}, "diff": "PRIVATE-PATCH-SENTINEL"}}},
		})
		handler.Handle("item/completed", raw)
		content, err := os.ReadFile(marker)
		if err != nil {
			t.Fatal(err)
		}
		var proof struct {
			Version  int    `json:"version"`
			Identity string `json:"identity_sha256"`
			Target   string `json:"target_sha256"`
			Matched  bool   `json:"target_matches"`
			Declined bool   `json:"declined"`
		}
		if json.Unmarshal(content, &proof) != nil {
			t.Fatal("invalid proof")
		}
		identity, _ := json.Marshal([]string{"native-thread", "native-turn", "native-item"})
		identityHash, targetHash := sha256.Sum256(identity), sha256.Sum256([]byte(target))
		if proof.Version != 1 || proof.Identity != hex.EncodeToString(identityHash[:]) ||
			proof.Target != hex.EncodeToString(targetHash[:]) || proof.Matched != test.matched || proof.Declined != test.declined {
			t.Fatal("file-change proof did not preserve its binding")
		}
		for _, secret := range []string{test.path, "native-thread", "PRIVATE-PATCH-SENTINEL"} {
			if bytes.Contains(content, []byte(secret)) {
				t.Fatal("file-change proof retained private content")
			}
		}
		if forwarded != 0 {
			t.Fatal("instrumented file details reached the event stream")
		}
	}
	if metadata, err := os.Stat(marker); err != nil || metadata.Mode().Perm() != 0600 {
		t.Fatal("proof is not private")
	}
}
