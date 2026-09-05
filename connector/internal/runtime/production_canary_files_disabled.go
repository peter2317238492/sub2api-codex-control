//go:build !productioncanary

package runtime

import (
	"encoding/json"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/policy"
)

func productionCanaryFileObserver(string, *policy.Guard, []string) func(string, json.RawMessage) {
	return nil
}
