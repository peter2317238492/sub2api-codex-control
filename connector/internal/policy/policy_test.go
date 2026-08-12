package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
)

func TestGuardInjectsSecurityCaps(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "project")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	guard, err := NewGuard([]string{root}, "workspace-write")
	if err != nil {
		t.Fatal(err)
	}
	guarded, err := guard.Enforce("thread/start", json.RawMessage(`{"cwd":`+quote(child)+`}`))
	if err != nil {
		t.Fatal(err)
	}
	var params map[string]any
	if err := json.Unmarshal(guarded, &params); err != nil {
		t.Fatal(err)
	}
	if params["sandbox"] != "workspace-write" || params["approvalPolicy"] != "on-request" {
		t.Fatalf("security defaults not injected: %#v", params)
	}
}

func TestGuardRejectsEscapesAndDangerousSandbox(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	guard, err := NewGuard([]string{root}, "workspace-write")
	if err != nil {
		t.Fatal(err)
	}
	tests := []string{
		`{"cwd":` + quote(outside) + `}`,
		`{"cwd":` + quote(root) + `,"sandbox":"danger-full-access"}`,
		`{"cwd":` + quote(root) + `,"sandboxPolicy":{"type":"workspaceWrite","writableRoots":[` + quote(outside) + `]}}`,
		`{"cwd":` + quote(root) + `,"approvalPolicy":"never"}`,
	}
	for _, raw := range tests {
		if _, err := guard.Enforce("thread/start", json.RawMessage(raw)); err == nil {
			t.Fatalf("expected request to be rejected: %s", raw)
		}
	}
}

func TestGuardCapsWorkspaceRootCount(t *testing.T) {
	root := t.TempDir()
	roots := make([]string, MaxCWDFilter+1)
	for index := range roots {
		roots[index] = root
	}
	if _, err := NewGuard(roots, "workspace-write"); err == nil {
		t.Fatalf("guard accepted more than %d workspace roots", MaxCWDFilter)
	}
}

func TestGuardRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	guard, err := NewGuard([]string{root}, "workspace-write")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.Enforce("thread/start", json.RawMessage(`{"cwd":`+quote(link)+`}`)); err == nil {
		t.Fatal("expected symlink escape to be rejected")
	}
}

func TestDangerousMethodFamiliesFailClosed(t *testing.T) {
	for _, method := range []string{
		"thread/shellCommand", "command/exec", "command/execStreaming", "fs/readFile",
		"process/start", "config/write", "plugin/install", "account/login", "raw/rpc",
		"app/read", "app/installed", "environment/status",
		"externalAgentConfig/import/recordHistory", "thread/searchOccurrences",
		"plugin/search", "thread/section/move", "threadSection/create",
		"threadSection/delete", "threadSection/list", "threadSection/update",
	} {
		if MethodAllowed(method) || DenialReason(method) == "" {
			t.Fatalf("dangerous method %q was not denied", method)
		}
	}
	if !MethodAllowed("turn/interrupt") {
		t.Fatal("documented method was not allowed")
	}
}

func TestProjectorRejectsHiddenOverridesAndNonTextInput(t *testing.T) {
	root := t.TempDir()
	guard, err := NewGuard([]string{root}, "workspace-write")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		method string
		params string
	}{
		{"thread/start", `{"cwd":` + quote(root) + `,"config":{"network_access":true}}`},
		{"thread/resume", `{"threadId":"t","path":"/tmp/rollout.jsonl"}`},
		{"turn/start", `{"threadId":"t","input":[{"type":"localImage","path":"/etc/passwd"}]}`},
		{"turn/start", `{"threadId":"t","input":[{"type":"text","text":"x"}],"sandboxPolicy":{"type":"dangerFullAccess"}}`},
		{"turn/steer", `{"threadId":"t","expectedTurnId":"turn","input":[{"type":"skill","name":"x","path":"/tmp/x"}]}`},
	} {
		if _, err := guard.Enforce(test.method, json.RawMessage(test.params)); err == nil {
			t.Fatalf("%s accepted hidden override: %s", test.method, test.params)
		}
	}
	guarded, err := guard.Enforce("turn/start", json.RawMessage(`{"threadId":"t","input":[{"type":"text","text":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var projected map[string]any
	if err := json.Unmarshal(guarded, &projected); err != nil {
		t.Fatal(err)
	}
	if projected["approvalPolicy"] != "on-request" || projected["approvalsReviewer"] != "user" {
		t.Fatalf("turn policy was not connector-owned: %#v", projected)
	}
	sandbox := projected["sandboxPolicy"].(map[string]any)
	if sandbox["type"] != "workspaceWrite" || sandbox["networkAccess"] != false {
		t.Fatalf("turn sandbox was not capped: %#v", sandbox)
	}
	guarded, err = guard.Enforce("turn/start", json.RawMessage(`{"threadId":"t","input":[{"type":"text","text":"hello","text_elements":[]}]}`))
	if err != nil {
		t.Fatalf("explicit empty text_elements was rejected: %v", err)
	}
	if err := json.Unmarshal(guarded, &projected); err != nil {
		t.Fatal(err)
	}
	input := projected["input"].([]any)[0].(map[string]any)
	if elements, ok := input["text_elements"].([]any); !ok || len(elements) != 0 {
		t.Fatalf("canonical text_elements = %#v", input["text_elements"])
	}
}

func TestMaximalLegalTurnFitsTheEnsureASCIIFrameBudget(t *testing.T) {
	root := t.TempDir()
	guard, err := NewGuard([]string{root}, "workspace-write")
	if err != nil {
		t.Fatal(err)
	}
	opaque := strings.Repeat("😀", MaxOpaqueLength)
	raw, err := json.Marshal(map[string]any{
		"threadId":            opaque,
		"clientUserMessageId": opaque,
		"expectedTurnId":      opaque,
		"input": []any{map[string]any{
			"type": "text", "text": strings.Repeat("a", MaxTextLength),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	params, err := guard.Enforce("turn/steer", raw)
	if err != nil {
		t.Fatal(err)
	}
	paramsSize, err := ensureASCIIJSONSize(params)
	if err != nil {
		t.Fatal(err)
	}
	if paramsSize > MaxEnsureASCIIParamsBytes {
		t.Fatalf("params = %d bytes, max %d", paramsSize, MaxEnsureASCIIParamsBytes)
	}
	envelope := map[string]any{
		"version":   1,
		"id":        "11111111-1111-4111-8111-111111111111",
		"device_id": "22222222-2222-4222-8222-222222222222",
		"epoch":     strings.Repeat("😀", 128),
		"seq":       ^uint64(0),
		"ack":       ^uint64(0),
		"type":      "command",
		"sent_at":   "2026-07-23T23:59:59.999999+00:00",
		"payload": map[string]any{
			"command_id":      "33333333-3333-4333-8333-333333333333",
			"idempotency_key": strings.Repeat("😀", 128),
			"method":          "turn/steer",
			"params":          params,
			"deadline_at":     "2026-07-23T23:59:59.999999+00:00",
		},
	}
	frameSize, err := ensureASCIIJSONSize(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if frameSize > protocol.MaxFrameBytes {
		t.Fatalf("maximal command frame = %d bytes, max %d", frameSize, protocol.MaxFrameBytes)
	}
}

func TestGuardAlsoCapsGoHTMLEscapedJSON(t *testing.T) {
	root := t.TempDir()
	guard, err := NewGuard([]string{root}, "workspace-write")
	if err != nil {
		t.Fatal(err)
	}
	for _, character := range []string{"<", ">", "&"} {
		raw, err := json.Marshal(map[string]any{
			"threadId": "thread-1",
			"input": []any{map[string]any{
				"type": "text", "text": strings.Repeat(character, MaxTextLength),
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := guard.Enforce("turn/start", raw); err == nil || !strings.Contains(err.Error(), "Go JSON budget") {
			t.Fatalf("%q-heavy text was not rejected by the Go JSON budget: %v", character, err)
		}
	}
}

func TestPermissionValidationStaysInsideRootsAndDisablesNetwork(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	guard, _ := NewGuard([]string{root}, "workspace-write")
	validated, err := guard.ValidatePermissions(map[string]any{
		"fileSystem": map[string]any{
			"read": []any{file},
			"entries": []any{
				map[string]any{"access": "read", "path": map[string]any{"type": "path", "path": file}},
				map[string]any{"access": "write", "path": map[string]any{"type": "path", "path": filepath.Join(root, "new.txt")}},
				map[string]any{"access": "deny", "path": map[string]any{"type": "glob_pattern", "pattern": filepath.Join(root, "private", "**")}},
				map[string]any{"access": "read", "path": map[string]any{"type": "special", "value": map[string]any{"kind": "project_roots", "subpath": nil}}},
			},
			"globScanMaxDepth": float64(8),
		},
		"network": map[string]any{"enabled": false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if validated["network"].(map[string]any)["enabled"] != false {
		t.Fatalf("network permission = %#v", validated)
	}
	fileSystem := validated["fileSystem"].(map[string]any)
	if len(fileSystem["entries"].([]map[string]any)) != 4 || fileSystem["globScanMaxDepth"] != 8 {
		t.Fatalf("filesystem entries were not projected: %#v", fileSystem)
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []map[string]any{
		{"network": map[string]any{"enabled": true}},
		{"fileSystem": map[string]any{"write": []any{outside}}},
		{"fileSystem": map[string]any{"entries": []any{map[string]any{"access": "read", "path": map[string]any{"type": "path", "path": outside}}}}},
		{"fileSystem": map[string]any{"entries": []any{map[string]any{"access": "write", "path": map[string]any{"type": "glob_pattern", "pattern": filepath.Join(root, "**")}}}}},
		{"fileSystem": map[string]any{"entries": []any{map[string]any{"access": "read", "path": map[string]any{"type": "special", "value": map[string]any{"kind": "tmpdir"}}}}}},
		{"fileSystem": map[string]any{"entries": []any{}, "globScanMaxDepth": float64(MaxGlobScanDepth + 1)}},
	} {
		if _, err := guard.ValidatePermissions(profile); err == nil {
			t.Fatalf("unsafe permission profile accepted: %#v", profile)
		}
	}
}

func TestReadOnlySandboxCapRejectsWriteAndFileChangeApprovals(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	guard, err := NewGuard([]string{root}, "read-only")
	if err != nil {
		t.Fatal(err)
	}

	validated, err := guard.ValidatePermissions(map[string]any{
		"fileSystem": map[string]any{"read": []any{file}},
	})
	if err != nil {
		t.Fatalf("read permission was rejected: %v", err)
	}
	if len(validated["fileSystem"].(map[string]any)["read"].([]string)) != 1 {
		t.Fatalf("read permission was not preserved: %#v", validated)
	}

	for _, value := range []any{nil, []any{}, []any{file}} {
		if _, err := guard.ValidatePermissions(map[string]any{
			"fileSystem": map[string]any{"write": value},
		}); err == nil || !strings.Contains(err.Error(), "read-only sandbox cap") {
			t.Fatalf("write permission %#v was not rejected: %v", value, err)
		}
	}
	if _, err := guard.ValidatePermissions(map[string]any{
		"fileSystem": map[string]any{"entries": []any{map[string]any{
			"access": "write", "path": map[string]any{"type": "path", "path": filepath.Join(root, "new.txt")},
		}}},
	}); err == nil || !strings.Contains(err.Error(), "read-only sandbox cap") {
		t.Fatalf("write entry was not rejected under read-only cap: %v", err)
	}
	if err := guard.ValidateApprovalDetails("file_change", map[string]any{
		"fileChanges": map[string]any{
			file: map[string]any{"type": "update"},
		},
	}); err == nil || !strings.Contains(err.Error(), "read-only sandbox cap") {
		t.Fatalf("file change approval was not rejected: %v", err)
	}
	if err := guard.ValidateApprovalDetails("command", map[string]any{
		"additionalPermissions": map[string]any{
			"fileSystem": map[string]any{"write": []any{file}},
		},
	}); err == nil || !strings.Contains(err.Error(), "read-only sandbox cap") {
		t.Fatalf("command write permission was not rejected: %v", err)
	}
}

func TestCommandApprovalCannotAmendExecutionPolicy(t *testing.T) {
	root := t.TempDir()
	guard, err := NewGuard([]string{root}, "workspace-write")
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.ValidateApprovalDetails("command", map[string]any{
		"cwd":                         root,
		"proposedExecpolicyAmendment": []any{"allow", "rm"},
	}); err == nil {
		t.Fatal("execution policy amendment was accepted")
	}
}

func quote(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}
