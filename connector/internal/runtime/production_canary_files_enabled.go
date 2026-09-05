//go:build productioncanary

package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/policy"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

var canaryNativeID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,512}$`)
var canaryHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

type canaryFileRecord struct {
	Target   string `json:"target_sha256"`
	Matches  bool   `json:"target_matches"`
	Declined bool   `json:"declined"`
}

type canaryFileProof struct {
	Version  int                         `json:"version"`
	Overflow bool                        `json:"overflow"`
	Records  map[string]canaryFileRecord `json:"records"`
}

func productionCanaryFileObserver(stateDir string, guard *policy.Guard, roots []string) func(string, json.RawMessage) error {
	if len(roots) != 1 {
		return nil
	}
	root, err := guard.CanonicalCWD(roots[0])
	if err != nil {
		return nil
	}
	target := filepath.Join(root, "approval-denied.txt")
	targetHash := sha256.Sum256([]byte(target))
	marker := filepath.Join(stateDir, "production-canary-file-change.json")
	proof := canaryFileProof{Version: 2, Records: make(map[string]canaryFileRecord)}
	if err := securefile.ReadJSON(marker, &proof); err != nil && !errors.Is(err, os.ErrNotExist) {
		return func(string, json.RawMessage) error { return errors.New("invalid existing canary file proof") }
	}
	if proof.Version != 2 || proof.Records == nil || len(proof.Records) > 16 {
		return func(string, json.RawMessage) error { return errors.New("invalid existing canary file proof") }
	}
	for id, record := range proof.Records {
		if !canaryHash.MatchString(id) || !canaryHash.MatchString(record.Target) {
			return func(string, json.RawMessage) error { return errors.New("invalid existing canary file proof") }
		}
	}
	var mutex sync.Mutex
	return func(method string, raw json.RawMessage) error {
		if method != "item/completed" || len(raw) > 64<<10 {
			return nil
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
			return nil
		}
		if event.Item.Status != "declined" && event.Item.Status != "failed" && event.Item.Status != "completed" {
			return nil
		}
		identity, _ := json.Marshal([]string{event.ThreadID, event.TurnID, event.Item.ID})
		identityHash := sha256.Sum256(identity)
		matched := len(event.Item.Changes) == 1 && event.Item.Changes[0].Path == target &&
			event.Item.Changes[0].Kind.Type == "add" && event.Item.Changes[0].Kind.MovePath == nil
		mutex.Lock()
		defer mutex.Unlock()
		id := hex.EncodeToString(identityHash[:])
		record := canaryFileRecord{Target: hex.EncodeToString(targetHash[:]), Matches: matched, Declined: event.Item.Status == "declined"}
		if previous, exists := proof.Records[id]; exists {
			record.Matches = record.Matches && previous.Matches && record.Target == previous.Target
			record.Declined = record.Declined && previous.Declined
		} else if len(proof.Records) >= 16 {
			proof.Overflow = true
		}
		if !proof.Overflow {
			proof.Records[id] = record
		}
		// Keep matching-identity failures sticky without retaining paths or diffs.
		if securefile.WriteJSON(marker, proof) != nil {
			return errors.New("canary file proof could not be persisted")
		}
		if proof.Overflow {
			return errors.New("canary file proof capacity exceeded")
		}
		return nil
	}
}
