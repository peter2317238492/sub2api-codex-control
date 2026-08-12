package appserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestE2EFakeCodexMatchesContractsAndPersistsThreadsAcrossRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}
	source := filepath.Join("..", "..", "..", "tests", "e2e", "fake_codex.py")
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "codex")
	if err := os.WriteFile(binary, contents, 0o700); err != nil {
		t.Fatal(err)
	}
	providerKey := filepath.Join(dir, "provider-key")
	if err := os.WriteFile(providerKey, []byte("provider-key-schema-canary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_CODEX_AUDIT_LOG", filepath.Join(dir, "methods.log"))
	t.Setenv("FAKE_CODEX_APPROVAL_AUDIT_LOG", filepath.Join(dir, "approvals.log"))
	t.Setenv("FAKE_CODEX_STATE_FILE", filepath.Join(dir, "thread-state.json"))
	t.Setenv("FAKE_SUB2API_PROVIDER_KEY_FILE", providerKey)

	handler := HandlerFuncs{RequestFunc: func(_ context.Context, method string, _ json.RawMessage) (any, *RPCError) {
		switch method {
		case "item/commandExecution/requestApproval":
			return map[string]string{"decision": "accept"}, nil
		case "item/fileChange/requestApproval":
			return map[string]string{"decision": "decline"}, nil
		case "item/permissions/requestApproval":
			return nil, &RPCError{Code: -32001, Message: "approval timed out"}
		default:
			return nil, &RPCError{Code: -32601, Message: "request is not allowed"}
		}
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	options := StartOptions{
		Binary: binary, ExpectedVersion: "0.147.0", ConnectorVersion: "test",
		InitializeTimeout: 5 * time.Second, Handler: handler,
	}
	client, err := Start(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.Close()
		_ = client.Wait()
	})

	call := func(method, params string) json.RawMessage {
		t.Helper()
		callCtx, cancelCall := context.WithTimeout(ctx, 5*time.Second)
		defer cancelCall()
		result, err := client.Call(callCtx, method, json.RawMessage(params))
		if err != nil {
			t.Fatalf("%s failed frozen contract validation: %v", method, err)
		}
		return result
	}
	call("model/list", `{}`)
	started := call("thread/start", `{"cwd":"/workspace"}`)
	var startResult struct {
		Thread struct {
			ID string `json:"id"`
		} `json:"thread"`
	}
	if err := json.Unmarshal(started, &startResult); err != nil || startResult.Thread.ID == "" {
		t.Fatalf("invalid thread/start fixture: %s", started)
	}
	threadID, err := json.Marshal(startResult.Thread.ID)
	if err != nil {
		t.Fatal(err)
	}
	threadParams := `{"threadId":` + string(threadID) + `}`
	call("thread/list", `{}`)
	call("thread/read", threadParams)
	call("thread/resume", threadParams)
	turnStarted := call("turn/start", `{"threadId":`+string(threadID)+`,"input":[{"type":"text","text":"hello"}]}`)
	var turnResult struct {
		Turn struct {
			ID string `json:"id"`
		} `json:"turn"`
	}
	if err := json.Unmarshal(turnStarted, &turnResult); err != nil || turnResult.Turn.ID == "" {
		t.Fatalf("invalid turn/start fixture: %s", turnStarted)
	}
	turnID, err := json.Marshal(turnResult.Turn.ID)
	if err != nil {
		t.Fatal(err)
	}
	call("turn/steer", `{"threadId":`+string(threadID)+`,"expectedTurnId":`+string(turnID)+`}`)
	call("turn/interrupt", `{"threadId":`+string(threadID)+`,"turnId":`+string(turnID)+`}`)

	client.Close()
	_ = client.Wait()
	client, err = Start(ctx, options)
	if err != nil {
		t.Fatalf("restart fake Codex app-server: %v", err)
	}
	listed := call("thread/list", `{}`)
	var listResult struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(listed, &listResult); err != nil || len(listResult.Data) != 1 || listResult.Data[0].ID != startResult.Thread.ID {
		t.Fatalf("persisted thread/list fixture mismatch after restart: %s", listed)
	}
	readAfterRestart := call("thread/read", threadParams)
	var readResult struct {
		Thread struct {
			ID     string `json:"id"`
			Status struct {
				Type string `json:"type"`
			} `json:"status"`
			Turns []struct {
				Status string           `json:"status"`
				Items  []map[string]any `json:"items"`
			} `json:"turns"`
		} `json:"thread"`
	}
	if err := json.Unmarshal(readAfterRestart, &readResult); err != nil ||
		readResult.Thread.ID != startResult.Thread.ID ||
		readResult.Thread.Status.Type != "idle" ||
		len(readResult.Thread.Turns) != 1 ||
		readResult.Thread.Turns[0].Status != "completed" {
		t.Fatalf("persisted thread/read state mismatch after restart: %s", readAfterRestart)
	}
	foundAgentMessage := false
	for _, item := range readResult.Thread.Turns[0].Items {
		if item["type"] == "agentMessage" && item["text"] == "E2E approved response" {
			foundAgentMessage = true
		}
	}
	if !foundAgentMessage {
		t.Fatalf("persisted thread history omitted the agent message after restart: %s", readAfterRestart)
	}
	call("thread/resume", threadParams)
	startedAfterRestart := call("thread/start", `{"cwd":"/workspace"}`)
	var restartResult struct {
		Thread struct {
			ID string `json:"id"`
		} `json:"thread"`
	}
	if err := json.Unmarshal(startedAfterRestart, &restartResult); err != nil || restartResult.Thread.ID != "e2e-thread-2" {
		t.Fatalf("persisted thread sequence was not advanced after restart: %s", startedAfterRestart)
	}
}
