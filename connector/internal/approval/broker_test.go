package approval

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/appserver"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
)

type emittedApproval struct {
	typeName string
	payload  protocol.ApprovalRequestPayload
}

func TestApprovalIsBoundToEpoch(t *testing.T) {
	emitted := make(chan emittedApproval, 1)
	broker := New(time.Second, func(_ context.Context, typeName string, value any) error {
		emitted <- emittedApproval{typeName: typeName, payload: value.(protocol.ApprovalRequestPayload)}
		return nil
	})
	epoch := "epoch-0123456789abcdef"
	broker.SetEpoch(epoch)
	broker.SetConnected(true)
	resultChannel := make(chan any, 1)
	go func() {
		result, rpcErr := broker.Request(t.Context(), "item/commandExecution/requestApproval", json.RawMessage(`{"command":"git status"}`))
		if rpcErr != nil {
			t.Errorf("request error: %v", rpcErr)
		}
		resultChannel <- result
	}()
	request := <-emitted
	if request.typeName != protocol.TypeApprovalRequest || request.payload.Kind != "command" {
		t.Fatalf("approval request = %#v", request)
	}
	decision := protocol.ApprovalDecisionPayload{ApprovalID: request.payload.ApprovalID, Decision: "approve", DecidedAt: time.Now()}
	if err := broker.Resolve("stale-0123456789abcdef", decision); err == nil {
		t.Fatal("stale epoch approved a request")
	}
	if err := broker.Resolve(epoch, decision); err != nil {
		t.Fatal(err)
	}
	result := (<-resultChannel).(map[string]string)
	if result["decision"] != "accept" {
		t.Fatalf("decision = %#v", result)
	}
}

func TestApprovalTimeoutDefaultsToDecline(t *testing.T) {
	broker := New(5*time.Millisecond, func(context.Context, string, any) error { return nil })
	broker.SetEpoch("epoch-0123456789abcdef")
	broker.SetConnected(true)
	request := json.RawMessage(`{"path":` + string(mustJSON(localFixture("/work/x"))) + `}`)
	result, rpcErr := broker.Request(t.Context(), "item/fileChange/requestApproval", request)
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if result.(map[string]string)["decision"] != "decline" {
		t.Fatalf("timeout result = %#v", result)
	}
}

func TestCommandApprovalHonorsAvailableDecisions(t *testing.T) {
	tests := []struct {
		name         string
		available    any
		approve      bool
		wantDecision string
		wantRPCError bool
	}{
		{name: "missing remains compatible", approve: true, wantDecision: "accept"},
		{name: "null remains compatible", available: nil, approve: false, wantDecision: "decline"},
		{name: "accept allows remote approval", available: []any{"accept"}, approve: true, wantDecision: "accept"},
		{name: "decline forbids remote approval", available: []any{"decline"}, approve: true, wantRPCError: true},
		{name: "decline handles remote denial", available: []any{"decline"}, approve: false, wantDecision: "decline"},
		{name: "cancel only handles remote denial", available: []any{"cancel"}, approve: false, wantDecision: "cancel"},
		{name: "accept only cannot encode denial", available: []any{"accept"}, approve: false, wantRPCError: true},
		{name: "cancel handles denial when accept is also available", available: []any{"accept", "cancel"}, approve: false, wantDecision: "cancel"},
		{name: "decline takes priority over cancel", available: []any{"cancel", "decline"}, approve: false, wantDecision: "decline"},
		{name: "empty list cannot encode approval", available: []any{}, approve: true, wantRPCError: true},
		{name: "session approval is not widened to accept", available: []any{"acceptForSession"}, approve: true, wantRPCError: true},
		{name: "amendment object cannot encode approval", available: []any{map[string]any{"acceptWithExecpolicyAmendment": map[string]any{"execpolicy_amendment": []any{"git"}}}}, approve: true, wantRPCError: true},
		{name: "amendment object cannot encode denial", available: []any{map[string]any{"acceptWithExecpolicyAmendment": map[string]any{"execpolicy_amendment": []any{"git"}}}}, approve: false, wantRPCError: true},
		{name: "cancel alongside amendment handles denial", available: []any{map[string]any{"acceptWithExecpolicyAmendment": map[string]any{"execpolicy_amendment": []any{"git"}}}, "cancel"}, approve: false, wantDecision: "cancel"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			details := map[string]any{"command": "git status"}
			if test.name != "missing remains compatible" {
				details["availableDecisions"] = test.available
			}
			options, err := parseCommandDecisionOptions("item/commandExecution/requestApproval", details)
			if err != nil {
				t.Fatal(err)
			}
			var result any
			var rpcErr *appserver.RPCError
			if test.approve {
				result, rpcErr = approvedResultWithOptions("item/commandExecution/requestApproval", nil, options)
			} else {
				result, rpcErr = deniedResultWithOptions("item/commandExecution/requestApproval", "test denial", options)
			}
			if test.wantRPCError {
				if result != nil || rpcErr == nil || rpcErr.Code != -32001 {
					t.Fatalf("result = %#v, RPC error = %#v", result, rpcErr)
				}
				return
			}
			if rpcErr != nil {
				t.Fatal(rpcErr)
			}
			if got := result.(map[string]string)["decision"]; got != test.wantDecision {
				t.Fatalf("decision = %q, want %q", got, test.wantDecision)
			}
		})
	}
}

func TestRemoteApproveFailsClosedWhenAcceptIsUnavailable(t *testing.T) {
	emitted := make(chan protocol.ApprovalRequestPayload, 1)
	broker := New(time.Second, func(_ context.Context, _ string, value any) error {
		emitted <- value.(protocol.ApprovalRequestPayload)
		return nil
	})
	epoch := "epoch-0123456789abcdef"
	broker.SetEpoch(epoch)
	broker.SetConnected(true)
	resultChannel := make(chan any, 1)
	errorChannel := make(chan *appserver.RPCError, 1)
	go func() {
		result, rpcErr := broker.Request(t.Context(), "item/commandExecution/requestApproval", json.RawMessage(`{"command":"git status","availableDecisions":["decline"]}`))
		resultChannel <- result
		errorChannel <- rpcErr
	}()
	request := <-emitted
	if err := broker.Resolve(epoch, protocol.ApprovalDecisionPayload{
		ApprovalID: request.ApprovalID, Decision: "approve", DecidedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if result := <-resultChannel; result != nil {
		t.Fatalf("remote approval returned a result: %#v", result)
	}
	if rpcErr := <-errorChannel; rpcErr == nil || rpcErr.Code != -32001 {
		t.Fatalf("remote approval RPC error = %#v", rpcErr)
	}
}

func TestUnknownServerRequestIsDenied(t *testing.T) {
	broker := New(time.Second, nil)
	broker.SetEpoch("epoch-0123456789abcdef")
	_, rpcErr := broker.Request(t.Context(), "raw/passthrough", json.RawMessage(`{}`))
	if rpcErr == nil || rpcErr.Code != -32601 {
		t.Fatalf("unknown request error = %#v", rpcErr)
	}
}

func TestLegacyApprovalUsesLegacyDecisionEnum(t *testing.T) {
	broker := New(5*time.Millisecond, func(context.Context, string, any) error { return nil })
	broker.SetEpoch("epoch-0123456789abcdef")
	broker.SetConnected(true)
	result, rpcErr := broker.Request(t.Context(), "execCommandApproval", json.RawMessage(`{"conversationId":"t","command":["true"]}`))
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	assertLegacyDenial(t, result, "approval request timed out")
}

func TestLegacyDenialUsesCodex0146ReviewDecisionShape(t *testing.T) {
	for _, method := range []string{"execCommandApproval", "applyPatchApproval"} {
		result, rpcErr := deniedResult(method, "rejected by test")
		if rpcErr != nil {
			t.Fatalf("%s returned an RPC error: %v", method, rpcErr)
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(encoded), `{"decision":{"denied":{"rejection":"rejected by test"}}}`; got != want {
			t.Fatalf("%s denial = %s, want %s", method, got, want)
		}
	}
}

func TestPermissionApprovalReturnsValidatedTurnGrant(t *testing.T) {
	emitted := make(chan protocol.ApprovalRequestPayload, 1)
	broker := New(time.Second, func(_ context.Context, _ string, value any) error {
		emitted <- value.(protocol.ApprovalRequestPayload)
		return nil
	})
	broker.SetValidators(nil, func(profile map[string]any) (map[string]any, error) {
		return map[string]any{"fileSystem": profile["fileSystem"]}, nil
	})
	epoch := "epoch-0123456789abcdef"
	broker.SetEpoch(epoch)
	broker.SetConnected(true)
	resultChannel := make(chan any, 1)
	errorChannel := make(chan *appserver.RPCError, 1)
	go func() {
		result, rpcErr := broker.Request(t.Context(), "item/permissions/requestApproval", mustJSON(map[string]any{
			"permissions": map[string]any{"fileSystem": map[string]any{"write": []any{localFixture("/tmp/project")}}},
		}))
		resultChannel <- result
		errorChannel <- rpcErr
	}()
	request := <-emitted
	if err := broker.Resolve(epoch, protocol.ApprovalDecisionPayload{ApprovalID: request.ApprovalID, Decision: "approve", DecidedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	result := (<-resultChannel).(map[string]any)
	if rpcErr := <-errorChannel; rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if result["scope"] != "turn" || result["strictAutoReview"] != true {
		t.Fatalf("permission result = %#v", result)
	}
	// app-server must receive the local grant, while the spooled request the
	// browser sees carries the projected one.
	granted := result["permissions"].(map[string]any)["fileSystem"].(map[string]any)["write"]
	if fmt.Sprint(granted) != fmt.Sprint([]any{localFixture("/tmp/project")}) {
		t.Fatalf("app-server grant = %#v, want the local path %q", granted, localFixture("/tmp/project"))
	}
	spooled := request.Details["permissions"].(map[string]any)["fileSystem"].(map[string]any)["write"]
	wantRemote := remoteFixture(t, "/tmp/project")
	if fmt.Sprint(spooled) != fmt.Sprint([]string{wantRemote}) {
		t.Fatalf("spooled grant = %#v, want %q", spooled, wantRemote)
	}
}

func TestDisconnectDeniesPendingAndNewApprovals(t *testing.T) {
	emitted := make(chan protocol.ApprovalRequestPayload, 1)
	broker := New(time.Second, func(_ context.Context, _ string, value any) error {
		emitted <- value.(protocol.ApprovalRequestPayload)
		return nil
	})
	broker.SetEpoch("epoch-0123456789abcdef")
	broker.SetConnected(true)
	resultChannel := make(chan any, 1)
	go func() {
		result, _ := broker.Request(t.Context(), "item/commandExecution/requestApproval", json.RawMessage(`{"command":"git status"}`))
		resultChannel <- result
	}()
	request := <-emitted
	broker.SetConnected(false)
	result := (<-resultChannel).(map[string]string)
	if result["decision"] != "decline" {
		t.Fatalf("disconnect result = %#v", result)
	}
	if err := broker.Resolve("epoch-0123456789abcdef", protocol.ApprovalDecisionPayload{
		ApprovalID: request.ApprovalID, Decision: "approve", DecidedAt: time.Now(),
	}); err == nil {
		t.Fatal("stale decision was accepted after disconnect")
	}
	nextResult, rpcErr := broker.Request(t.Context(), "item/fileChange/requestApproval", json.RawMessage(`{"path":"x"}`))
	if rpcErr != nil || nextResult.(map[string]string)["decision"] != "decline" {
		t.Fatalf("disconnected request = %#v, %v", nextResult, rpcErr)
	}
}

func TestOversizedOrDeepApprovalFailsBeforeEmission(t *testing.T) {
	var emitted int
	broker := New(time.Second, func(context.Context, string, any) error {
		emitted++
		return nil
	})
	broker.SetEpoch("epoch-0123456789abcdef")
	broker.SetConnected(true)
	oversized := json.RawMessage(`{"command":` + string(mustJSON(strings.Repeat("x", maxApprovalRequestBytes))) + `}`)
	result, rpcErr := broker.Request(t.Context(), "item/commandExecution/requestApproval", oversized)
	if result != nil || rpcErr == nil || rpcErr.Code != -32001 {
		t.Fatalf("oversized approval result = %#v, %v", result, rpcErr)
	}
	deep := json.RawMessage(strings.Repeat(`{"x":`, maxApprovalJSONDepth+1) + `null` + strings.Repeat(`}`, maxApprovalJSONDepth+1))
	result, rpcErr = broker.Request(t.Context(), "item/fileChange/requestApproval", deep)
	if rpcErr != nil || result.(map[string]string)["decision"] != "decline" || emitted != 0 {
		t.Fatalf("deep approval result = %#v, %v, emitted=%d", result, rpcErr, emitted)
	}
}

func TestFileChangeApprovalProjectsOperationsWithoutContentsOrDiffs(t *testing.T) {
	emitted := make(chan protocol.ApprovalRequestPayload, 1)
	broker := New(time.Second, func(_ context.Context, _ string, value any) error {
		emitted <- value.(protocol.ApprovalRequestPayload)
		return nil
	})
	epoch := "epoch-0123456789abcdef"
	broker.SetEpoch(epoch)
	broker.SetConnected(true)
	resultChannel := make(chan any, 1)
	go func() {
		result, _ := broker.Request(t.Context(), "applyPatchApproval", mustJSON(map[string]any{
			"conversationId": "thread-1",
			"fileChanges": map[string]any{
				localFixture("/work/add.txt"):    map[string]any{"type": "add", "content": "ADD SECRET"},
				localFixture("/work/delete.txt"): map[string]any{"type": "delete", "content": "DELETE SECRET"},
				localFixture("/work/update.txt"): map[string]any{
					"type":         "update",
					"unified_diff": "DIFF SECRET",
					"move_path":    localFixture("/work/moved.txt"),
				},
			},
		}))
		resultChannel <- result
	}()
	request := <-emitted
	changes, ok := request.Details["fileChanges"].(map[string]any)
	if !ok || len(changes) != 3 {
		t.Fatalf("projected file changes = %#v", request.Details["fileChanges"])
	}
	update, ok := changes[remoteFixture(t, "/work/update.txt")].(map[string]any)
	if !ok || update["type"] != "update" || update["move_path"] != remoteFixture(t, "/work/moved.txt") {
		t.Fatalf("projected update = %#v", changes[remoteFixture(t, "/work/update.txt")])
	}
	encoded, err := json.Marshal(request.Details)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"ADD SECRET", "DELETE SECRET", "DIFF SECRET", "content", "unified_diff"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("projected file-change details leaked %q: %s", secret, encoded)
		}
	}
	if err := broker.Resolve(epoch, protocol.ApprovalDecisionPayload{
		ApprovalID: request.ApprovalID, Decision: "deny", DecidedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	assertLegacyDenial(t, <-resultChannel, "approval request was denied")
}

func TestFileChangeApprovalRejectsMalformedOperationBeforeEmission(t *testing.T) {
	var emitted int
	broker := New(time.Second, func(context.Context, string, any) error {
		emitted++
		return nil
	})
	broker.SetEpoch("epoch-0123456789abcdef")
	broker.SetConnected(true)
	result, rpcErr := broker.Request(t.Context(), "applyPatchApproval", json.RawMessage(`{
		"conversationId":"thread-1","fileChanges":{"/work/file.txt":{"type":"replace","content":"secret"}}
	}`))
	if rpcErr != nil || emitted != 0 {
		t.Fatalf("malformed file change result = %#v, %v, emitted=%d", result, rpcErr, emitted)
	}
	assertLegacyDenial(t, result, "approval request exceeds the remote-control contract")
}

func TestApprovalPayloadBudgetIncludesEnvelope(t *testing.T) {
	changes := make(map[string]any, 100)
	for index := range 99 {
		path := localFixture(fmt.Sprintf("/work/%02d-%s", index, strings.Repeat("x", 560)))
		changes[path] = map[string]any{"type": "update", "unified_diff": "local-only"}
	}

	build := func(padding int) (json.RawMessage, int, int) {
		finalPath := localFixture("/work/final-" + strings.Repeat("y", padding))
		changes[finalPath] = map[string]any{"type": "update", "content": "local-only"}
		defer delete(changes, finalPath)
		details := map[string]any{"conversationId": "thread-1", "fileChanges": changes}
		projected, err := projectApprovalDetails("file_change", details, nil)
		if err != nil {
			t.Fatal(err)
		}
		encodedDetails, err := json.Marshal(projected)
		if err != nil {
			t.Fatal(err)
		}
		encodedPayload, err := json.Marshal(protocol.ApprovalRequestPayload{
			ApprovalID: "00000000-0000-4000-8000-000000000000",
			CommandID:  "appserver:00000000-0000-4000-8000-000000000000",
			Kind:       "file_change",
			Summary:    "file_change approval requested by Codex",
			Details:    projected,
			ExpiresAt:  time.Unix(1_750_000_000, 0).UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return mustJSON(details), len(encodedDetails), len(encodedPayload)
	}

	low, high := 1, 4_000
	for low < high {
		middle := low + (high-low)/2
		_, _, payloadBytes := build(middle)
		if payloadBytes > maxApprovalPayloadBytes {
			high = middle
		} else {
			low = middle + 1
		}
	}
	params, detailBytes, payloadBytes := build(low)
	if detailBytes > maxApprovalPayloadBytes || payloadBytes <= maxApprovalPayloadBytes {
		t.Fatalf("could not construct a near-boundary approval payload: details=%d payload=%d", detailBytes, payloadBytes)
	}

	var emitted int
	broker := New(time.Second, func(context.Context, string, any) error {
		emitted++
		return nil
	})
	broker.SetEpoch("epoch-0123456789abcdef")
	broker.SetConnected(true)
	result, rpcErr := broker.Request(t.Context(), "applyPatchApproval", params)
	if rpcErr != nil || emitted != 0 {
		t.Fatalf("near-boundary approval result = %#v, %v, emitted=%d", result, rpcErr, emitted)
	}
	assertLegacyDenial(t, result, "approval request exceeds the remote-control payload limit")
}

func assertLegacyDenial(t *testing.T, result any, wantReason string) {
	t.Helper()
	outer, ok := result.(map[string]any)
	if !ok || len(outer) != 1 {
		t.Fatalf("legacy denial result = %#v", result)
	}
	decision, ok := outer["decision"].(map[string]any)
	if !ok || len(decision) != 1 {
		t.Fatalf("legacy denial decision = %#v", outer["decision"])
	}
	denied, ok := decision["denied"].(map[string]string)
	if !ok || len(denied) != 1 || denied["rejection"] != wantReason {
		t.Fatalf("legacy denial details = %#v, want rejection %q", decision["denied"], wantReason)
	}
}

func TestApprovalDetailPathsAreSentInTheRemoteForm(t *testing.T) {
	emitted := make(chan protocol.ApprovalRequestPayload, 1)
	broker := New(time.Second, func(_ context.Context, _ string, value any) error {
		emitted <- value.(protocol.ApprovalRequestPayload)
		return nil
	})
	broker.SetEpoch("epoch-0123456789abcdef")
	broker.SetConnected(true)
	paths := map[string]string{
		"cwd":       "/work/project",
		"grantRoot": "/work",
		"path":      "/work/project/file.txt",
	}
	details := map[string]any{"command": "git status"}
	for field, posix := range paths {
		details[field] = localFixture(posix)
	}
	go func() {
		_, _ = broker.Request(t.Context(), "item/commandExecution/requestApproval", mustJSON(details))
	}()
	request := <-emitted
	for field, posix := range paths {
		want := remoteFixture(t, posix)
		if got := request.Details[field]; got != want {
			t.Fatalf("approval %s = %#v, want %q", field, got, want)
		}
	}
}

func TestApprovalPathWithoutARemoteFormIsDeniedBeforeEmission(t *testing.T) {
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
		mustJSON(map[string]any{"path": "not-a-root"}),
	)
	if rpcErr != nil || emitted != 0 {
		t.Fatalf("unprojectable approval path = %#v, %v, emitted=%d", result, rpcErr, emitted)
	}
	if result.(map[string]string)["decision"] != "decline" {
		t.Fatalf("unprojectable approval path result = %#v", result)
	}
}

// localFixture builds an absolute local path on the volume that holds the
// temporary directory, so a POSIX-shaped fixture names a real Windows volume.
func localFixture(posix string) string {
	return filepath.VolumeName(os.TempDir()) + filepath.FromSlash(posix)
}

// remoteFixture is the projection of localFixture, which is the form the
// control plane and the PWA are allowed to see.
func remoteFixture(t *testing.T, posix string) string {
	t.Helper()
	remote, err := pathMapper.Remote(localFixture(posix))
	if err != nil {
		t.Fatal(err)
	}
	return remote
}

func mustJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}
