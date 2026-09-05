//go:build productioncanary

package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"regexp"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/policy"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

var canaryNativeID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,512}$`)

func productionCanaryFileObserver(stateDir string, guard *policy.Guard, roots []string) func(string, json.RawMessage) {
	if len(roots) != 1 {
		return nil
	}
	root, err := guard.CanonicalCWD(roots[0])
	if err != nil {
		return nil
	}
	target := filepath.Join(root, "approval-denied.txt")
	targetHash := sha256.Sum256([]byte(target))
	return func(method string, raw json.RawMessage) {
		if method != "item/completed" || len(raw) > 64<<10 {
			return
		}
		var event struct {
			ThreadID string `json:"threadId"`
			TurnID   string `json:"turnId"`
			Item     struct {
				ID      string `json:"id"`
				Type    string `json:"type"`
				Status  string `json:"status"`
				Changes []struct {
					Path string `json:"path"`
					Kind struct {
						Type     string  `json:"type"`
						MovePath *string `json:"move_path"`
					} `json:"kind"`
				} `json:"changes"`
			} `json:"item"`
		}
		if json.Unmarshal(raw, &event) != nil || event.Item.Type != "fileChange" ||
			!canaryNativeID.MatchString(event.ThreadID) || !canaryNativeID.MatchString(event.TurnID) ||
			!canaryNativeID.MatchString(event.Item.ID) {
			return
		}
		if event.Item.Status != "declined" && event.Item.Status != "failed" && event.Item.Status != "completed" {
			return
		}
		identity, _ := json.Marshal([]string{event.ThreadID, event.TurnID, event.Item.ID})
		identityHash := sha256.Sum256(identity)
		matched := len(event.Item.Changes) == 1 && event.Item.Changes[0].Path == target &&
			event.Item.Changes[0].Kind.Type == "add" && event.Item.Changes[0].Kind.MovePath == nil
		// Persist only bound booleans and hashes, never paths or patch contents.
		_ = securefile.WriteJSON(filepath.Join(stateDir, "production-canary-file-change.json"), map[string]any{
			"version": 1, "identity_sha256": hex.EncodeToString(identityHash[:]),
			"target_sha256": hex.EncodeToString(targetHash[:]), "target_matches": matched,
			"declined": event.Item.Status == "declined",
		})
	}
}
