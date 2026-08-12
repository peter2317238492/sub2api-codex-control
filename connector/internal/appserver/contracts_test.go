package appserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/config"
)

const validThreadFixture = `{
  "id":"thread-1","preview":"","modelProvider":"sub2api","createdAt":0,
  "updatedAt":0,"status":{"type":"idle"},"cwd":"/workspace","source":"appServer",
  "cliVersion":"0.147.0","turns":[],"sessionId":"session-1","ephemeral":false
}`

const validTurnFixture = `{"id":"turn-1","items":[],"status":"inProgress"}`

func TestFrozenResultSchemasAcceptPinnedFixtures(t *testing.T) {
	validator := mustContract(t)
	threadStart := fmt.Sprintf(`{
    "thread":%s,"model":"gpt-5.5","modelProvider":"sub2api","cwd":"/workspace",
    "approvalPolicy":"on-request","approvalsReviewer":"user",
    "sandbox":{"type":"workspaceWrite","writableRoots":["/workspace"],"networkAccess":false}
  }`, validThreadFixture)
	fixtures := map[string]string{
		"initialize": `{"codexHome":"/tmp/codex","platformFamily":"unix","platformOs":"linux","userAgent":"codex"}`,
		"model/list": `{"data":[{
      "id":"gpt-5.5","model":"gpt-5.5","displayName":"GPT-5.5","description":"model",
      "isDefault":true,"hidden":false,"defaultReasoningEffort":"medium","supportedReasoningEfforts":[]
    }]}`,
		"thread/start":   threadStart,
		"thread/list":    fmt.Sprintf(`{"data":[%s]}`, validThreadFixture),
		"thread/read":    fmt.Sprintf(`{"thread":%s}`, validThreadFixture),
		"thread/resume":  threadStart,
		"turn/start":     fmt.Sprintf(`{"turn":%s}`, validTurnFixture),
		"turn/steer":     `{"turnId":"turn-1"}`,
		"turn/interrupt": `{}`,
	}
	for method, result := range fixtures {
		t.Run(method, func(t *testing.T) {
			raw := json.RawMessage(fmt.Sprintf(`{"id":1,"result":%s}`, result))
			if err := validator.validateResponse(method, raw, json.RawMessage(result), nil); err != nil {
				t.Fatalf("valid %s fixture was rejected: %v", method, err)
			}
		})
	}
}

func TestFrozenV2BundleMatchesHandshakeDigest(t *testing.T) {
	digest := sha256.Sum256(frozenV2ContractBundle)
	if got := hex.EncodeToString(digest[:]); got != config.PinnedSchemaDigest {
		t.Fatalf("embedded v2 contract digest = %s, want %s", got, config.PinnedSchemaDigest)
	}
}

func TestFrozenV2BundleMatchesCodex0147Surface(t *testing.T) {
	type methodVariant struct {
		Properties struct {
			Method struct {
				Enum []string `json:"enum"`
			} `json:"method"`
		} `json:"properties"`
	}
	type methodUnion struct {
		OneOf []methodVariant `json:"oneOf"`
	}
	var bundle struct {
		Definitions map[string]methodUnion `json:"definitions"`
	}
	if err := json.Unmarshal(frozenV2ContractBundle, &bundle); err != nil {
		t.Fatalf("decode frozen v2 contract: %v", err)
	}
	assertMethods := func(definition string, wantCount int, expected ...string) {
		t.Helper()
		union, ok := bundle.Definitions[definition]
		if !ok {
			t.Fatalf("frozen v2 contract is missing %s", definition)
		}
		methods := make(map[string]struct{}, len(union.OneOf))
		for _, variant := range union.OneOf {
			if len(variant.Properties.Method.Enum) != 1 {
				t.Fatalf("%s contains a method variant without one enum value", definition)
			}
			methods[variant.Properties.Method.Enum[0]] = struct{}{}
		}
		if len(methods) != wantCount {
			t.Fatalf("%s method count = %d, want %d", definition, len(methods), wantCount)
		}
		for _, method := range expected {
			if _, ok := methods[method]; !ok {
				t.Fatalf("%s is missing Codex 0.147.0 method %q", definition, method)
			}
		}
	}
	assertMethods(
		"ClientRequest",
		133,
		"app/read",
		"app/installed",
		"environment/status",
		"externalAgentConfig/import/recordHistory",
		"plugin/search",
		"thread/section/move",
		"thread/searchOccurrences",
		"threadSection/create",
		"threadSection/delete",
		"threadSection/list",
		"threadSection/update",
	)
	assertMethods(
		"ServerNotification",
		70,
		"thread/environment/connected",
		"thread/environment/disconnected",
	)
}

func TestFrozenJSONRPCErrorEnvelopeIsValidated(t *testing.T) {
	validator := mustContract(t)
	valid := json.RawMessage(`{"id":1,"error":{"code":-32601,"message":"not found"}}`)
	if err := validator.validateResponse("model/list", valid, nil, &RPCError{Code: -32601, Message: "not found"}); err != nil {
		t.Fatalf("valid JSON-RPC error was rejected: %v", err)
	}
	invalid := json.RawMessage(`{"id":1,"error":{"code":-32601}}`)
	if err := validator.validateResponse("model/list", invalid, nil, &RPCError{Code: -32601}); err == nil {
		t.Fatal("JSON-RPC error missing its required message was accepted")
	}
}

func TestFrozenServerRequestSchemasAcceptPinnedApprovalFixtures(t *testing.T) {
	validator := mustContract(t)
	fixtures := map[string]string{
		"item/commandExecution/requestApproval": `{"id":1,"method":"item/commandExecution/requestApproval","params":{"threadId":"thread-1","turnId":"turn-1","itemId":"item-1","approvalId":null,"reason":null,"command":"git status","cwd":"/workspace","commandActions":null,"additionalPermissions":null,"proposedExecpolicyAmendment":null,"networkApprovalContext":null,"proposedNetworkPolicyAmendments":null,"availableDecisions":["accept","decline"],"skillMetadata":null,"environmentId":null,"startedAtMs":1785945600000}}`,
		"item/fileChange/requestApproval":       `{"id":2,"method":"item/fileChange/requestApproval","params":{"threadId":"thread-1","turnId":"turn-1","itemId":"item-1","reason":null,"grantRoot":null,"startedAtMs":1785945600000}}`,
		"item/permissions/requestApproval":      validPermissionRequest(3),
		"applyPatchApproval":                    `{"id":4,"method":"applyPatchApproval","params":{"conversationId":"thread-1","callId":"call-1","fileChanges":{"/workspace/file.txt":{"type":"update","unified_diff":"@@"}},"reason":null,"grantRoot":null}}`,
		"execCommandApproval":                   `{"id":5,"method":"execCommandApproval","params":{"conversationId":"thread-1","callId":"call-1","command":["git","status"],"cwd":"/workspace","reason":null,"parsedCmd":[]}}`,
	}
	for method, raw := range fixtures {
		t.Run(method, func(t *testing.T) {
			if err := validator.validateServerRequest(json.RawMessage(raw)); err != nil {
				t.Fatalf("valid server request was rejected: %v", err)
			}
		})
	}
}

func TestFrozenServerResponseSchemasAcceptPinnedApprovalFixtures(t *testing.T) {
	validator := mustContract(t)
	fixtures := map[string]string{
		"item/commandExecution/requestApproval": `{"decision":"accept"}`,
		"item/fileChange/requestApproval":       `{"decision":"accept"}`,
		"item/permissions/requestApproval":      `{"permissions":{"fileSystem":{"entries":[],"globScanMaxDepth":1},"network":{"enabled":false}},"scope":"turn","strictAutoReview":true}`,
		"applyPatchApproval":                    `{"decision":"approved"}`,
		"execCommandApproval":                   `{"decision":"approved"}`,
	}
	for method, result := range fixtures {
		t.Run(method, func(t *testing.T) {
			raw := json.RawMessage(fmt.Sprintf(`{"id":1,"result":%s}`, result))
			if err := validator.validateServerResponse(method, raw, json.RawMessage(result), nil); err != nil {
				t.Fatalf("valid server response was rejected: %v", err)
			}
		})
	}
	if err := validator.validateServerResponse("item/permissions/requestApproval", json.RawMessage(`{"id":1,"error":{"code":-32001,"message":"denied"}}`), nil, &RPCError{Code: -32001, Message: "denied"}); err != nil {
		t.Fatalf("valid approval error was rejected: %v", err)
	}
	if err := validator.validateServerResponse("item/permissions/requestApproval", json.RawMessage(`{"id":1,"result":{"scope":"turn"}}`), json.RawMessage(`{"scope":"turn"}`), nil); err == nil {
		t.Fatal("permission response missing permissions was accepted")
	}
}
