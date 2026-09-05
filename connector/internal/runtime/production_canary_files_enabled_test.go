//go:build productioncanary

package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	for index, test := range []struct {
		path, status      string
		matched, declined bool
	}{
		{target, "declined", true, true},
		{target, "completed", true, false},
		{filepath.Join(canonical, "other.txt"), "declined", false, true},
	} {
		itemID := fmt.Sprintf("item-%d", index)
		raw, _ := json.Marshal(map[string]any{
			"threadId": "native-thread", "turnId": "native-turn",
			"item": map[string]any{"id": itemID, "type": "fileChange", "status": test.status,
				"changes": []any{map[string]any{"path": test.path, "kind": map[string]any{"type": "add"}, "diff": "PRIVATE-PATCH-SENTINEL"}}},
		})
		handler.Handle("item/completed", raw)
		content, err := os.ReadFile(marker)
		if err != nil {
			t.Fatal(err)
		}
		var proof canaryFileProof
		if json.Unmarshal(content, &proof) != nil {
			t.Fatal("invalid proof")
		}
		identity, _ := json.Marshal([]string{"native-thread", "native-turn", itemID})
		identityHash, targetHash := sha256.Sum256(identity), sha256.Sum256([]byte(target))
		record := proof.Records[hex.EncodeToString(identityHash[:])]
		if proof.Version != 2 || proof.Overflow || len(proof.Records) != index+1 ||
			record.Target != hex.EncodeToString(targetHash[:]) || record.Matches != test.matched || record.Declined != test.declined {
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

func TestCanaryFileProofPreservesFailuresAcrossItemsAndRestart(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	guard, err := policy.NewGuard([]string{root}, "workspace-write")
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := guard.CanonicalCWD(root)
	if err != nil {
		t.Fatal(err)
	}
	observer := productionCanaryFileObserver(state, guard, []string{root})
	emit := func(item, path string) error {
		raw, _ := json.Marshal(map[string]any{
			"threadId": "thread", "turnId": "turn",
			"item": map[string]any{"id": item, "type": "fileChange", "status": "declined",
				"changes": []any{map[string]any{"path": path, "kind": map[string]any{"type": "add"}}}},
		})
		return observer("item/completed", raw)
	}
	target := filepath.Join(canonical, "approval-denied.txt")
	if emit("selected", filepath.Join(canonical, "other")) != nil || emit("another", target) != nil || emit("selected", target) != nil {
		t.Fatal("could not record canary items")
	}
	observer = productionCanaryFileObserver(state, guard, []string{root})
	if emit("after-restart", target) != nil {
		t.Fatal("could not resume canary item recording")
	}
	raw, err := os.ReadFile(filepath.Join(state, "production-canary-file-change.json"))
	if err != nil {
		t.Fatal(err)
	}
	var proof canaryFileProof
	if json.Unmarshal(raw, &proof) != nil {
		t.Fatal("invalid proof")
	}
	identity, _ := json.Marshal([]string{"thread", "turn", "selected"})
	digest := sha256.Sum256(identity)
	if len(proof.Records) != 3 || proof.Records[hex.EncodeToString(digest[:])].Matches {
		t.Fatal("an interleaved completion replaced a selected-item failure")
	}
	for index := 3; index < 17; index++ {
		err = emit(fmt.Sprintf("item-%d", index), target)
		if (index == 16) != (err != nil) {
			t.Fatal("proof capacity was not enforced")
		}
	}
	raw, _ = os.ReadFile(filepath.Join(state, "production-canary-file-change.json"))
	if json.Unmarshal(raw, &proof) != nil || !proof.Overflow || len(proof.Records) != 16 {
		t.Fatal("overflow did not leave a bounded failing proof")
	}
}
