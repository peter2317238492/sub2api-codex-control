package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
)

func TestRPCPolicyMatchesSharedFixture(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate policy test")
	}
	path := filepath.Join(filepath.Dir(filename), "..", "..", "..", "packages", "control-protocol", "fixtures", "rpc-policy.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version                      int                 `json:"version"`
		MaxFrameBytes                int                 `json:"max_frame_bytes"`
		MaxEnsureASCIIParamsBytes    int                 `json:"max_ensure_ascii_params_bytes"`
		MaxEnsureASCIIProjectedBytes int                 `json:"max_ensure_ascii_projected_bytes"`
		MaxEnsureASCIITextBytes      int                 `json:"max_ensure_ascii_text_bytes"`
		MaxPageSize                  int                 `json:"max_page_size"`
		MaxCWDFilter                 int                 `json:"max_cwd_filters"`
		MaxTextItems                 int                 `json:"max_text_items"`
		MaxTextLength                int                 `json:"max_text_length"`
		MaxOpaqueLength              int                 `json:"max_opaque_length"`
		MaxSearchLength              int                 `json:"max_search_length"`
		MaxPathLength                int                 `json:"max_path_length"`
		Methods                      map[string][]string `json:"methods"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 || fixture.MaxFrameBytes != protocol.MaxFrameBytes ||
		fixture.MaxEnsureASCIIParamsBytes != MaxEnsureASCIIParamsBytes ||
		fixture.MaxEnsureASCIIProjectedBytes != MaxEnsureASCIIProjectedBytes ||
		fixture.MaxEnsureASCIITextBytes != MaxEnsureASCIITextBytes ||
		fixture.MaxPageSize != MaxPageSize || fixture.MaxCWDFilter != MaxCWDFilter || fixture.MaxTextItems != MaxTextItems ||
		fixture.MaxTextLength != MaxTextLength || fixture.MaxOpaqueLength != MaxOpaqueLength ||
		fixture.MaxSearchLength != MaxSearchLength || fixture.MaxPathLength != MaxPathLength {
		t.Fatalf("fixture limits drifted: %#v", fixture)
	}
	if len(fixture.Methods) != len(allowedParamFields) {
		t.Fatalf("fixture has %d methods, Go has %d", len(fixture.Methods), len(allowedParamFields))
	}
	for method, expected := range fixture.Methods {
		actualFields, ok := allowedParamFields[method]
		if !ok {
			t.Fatalf("fixture method %q is missing from Go", method)
		}
		actual := make([]string, 0, len(actualFields))
		for field := range actualFields {
			actual = append(actual, field)
		}
		sort.Strings(actual)
		sort.Strings(expected)
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("%s fields = %v, want %v", method, actual, expected)
		}
	}
}

func TestJSONBudgetMatchesSharedBoundaryVectors(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate policy test")
	}
	path := filepath.Join(filepath.Dir(filename), "..", "..", "..", "packages", "control-protocol", "fixtures", "json-budget-vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	type vector struct {
		Name          string `json:"name"`
		Key           string `json:"key"`
		Unit          string `json:"unit"`
		Repeat        int    `json:"repeat"`
		Suffix        string `json:"suffix"`
		ExpectedBytes int    `json:"expected_bytes"`
		Allowed       bool   `json:"allowed"`
	}
	var fixture struct {
		Version       int      `json:"version"`
		Encoding      string   `json:"encoding"`
		StringContent []vector `json:"string_content"`
		EscapeSamples []struct {
			Name          string `json:"name"`
			Value         string `json:"value"`
			ExpectedBytes int    `json:"expected_bytes"`
		} `json:"escape_samples"`
		JSONDocuments []vector `json:"json_documents"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 || fixture.Encoding != "compact-ensure-ascii" {
		t.Fatalf("budget fixture header = %#v", fixture)
	}
	root := t.TempDir()
	guard, err := NewGuard([]string{root}, "workspace-write")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range fixture.StringContent {
		t.Run(test.Name, func(t *testing.T) {
			value := strings.Repeat(test.Unit, test.Repeat) + test.Suffix
			if got := ensureASCIIStringContentSize(value); got != test.ExpectedBytes {
				t.Fatalf("encoded string size = %d, want %d", got, test.ExpectedBytes)
			}
			raw, err := json.Marshal(map[string]any{
				"threadId": "thread-1",
				"input":    []any{map[string]any{"type": "text", "text": value}},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = guard.Enforce("turn/start", raw)
			if (err == nil) != test.Allowed {
				t.Fatalf("allowed = %v, want %v (err=%v)", err == nil, test.Allowed, err)
			}
		})
	}
	for _, test := range fixture.EscapeSamples {
		t.Run(test.Name, func(t *testing.T) {
			if got := ensureASCIIStringContentSize(test.Value); got != test.ExpectedBytes {
				t.Fatalf("encoded string size = %d, want %d", got, test.ExpectedBytes)
			}
		})
	}
	for _, test := range fixture.JSONDocuments {
		t.Run(test.Name, func(t *testing.T) {
			value := map[string]any{test.Key: strings.Repeat(test.Unit, test.Repeat) + test.Suffix}
			size, err := ensureASCIIJSONSize(value)
			if err != nil {
				t.Fatal(err)
			}
			if size != test.ExpectedBytes {
				t.Fatalf("encoded document size = %d, want %d", size, test.ExpectedBytes)
			}
			if (size <= MaxEnsureASCIIParamsBytes) != test.Allowed {
				t.Fatalf("allowed = %v, want %v", size <= MaxEnsureASCIIParamsBytes, test.Allowed)
			}
		})
	}
}

func TestGuardEnforcesSharedTypesAndBounds(t *testing.T) {
	root := t.TempDir()
	guard, err := NewGuard([]string{root}, "workspace-write")
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := guard.Enforce("turn/start", json.RawMessage(`{
		"threadId":"thread-1",
		"clientUserMessageId":"message-1",
		"input":[{"type":"text","text":"hello"}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	var projected map[string]any
	if err := json.Unmarshal(accepted, &projected); err != nil {
		t.Fatal(err)
	}
	input := projected["input"].([]any)[0].(map[string]any)
	if input["type"] != "text" || input["text"] != "hello" || len(input["text_elements"].([]any)) != 0 {
		t.Fatalf("text input = %#v", input)
	}

	tooLong := strings.Repeat("x", MaxTextLength+1)
	rejected := []struct {
		method string
		raw    string
	}{
		{"model/list", `{"limit":0}`},
		{"model/list", `{"limit":101}`},
		{"model/list", `{"limit":1.5}`},
		{"model/list", `{"limit":"1"}`},
		{"thread/list", `{"archived":true}`},
		{"thread/read", `{"threadId":"t","includeTurns":"true"}`},
		{"thread/resume", `{"threadId":"t","excludeTurns":true}`},
		{"turn/start", `{"threadId":"t","input":[]}`},
		{"turn/start", `{"threadId":"t","input":[{"type":"text","text":" "}]}`},
		{"turn/start", `{"threadId":"t","input":[{"type":"text","text":"a"},{"type":"text","text":"b"}]}`},
		{"turn/start", `{"threadId":"t","input":[{"type":"text","text":"x","path":"/etc/passwd"}]}`},
		{"turn/start", `{"threadId":"t","input":[{"type":"text","text":"x","text_elements":null}]}`},
		{"turn/start", `{"threadId":"t","input":[{"type":"text","text":"x","text_elements":[{"byteRange":{"start":0,"end":1}}]}]}`},
		{"turn/start", `{"threadId":"t","input":[{"type":"text","text":` + quote(tooLong) + `}]}`},
		{"turn/steer", `{"threadId":"t","expectedTurnId":7,"input":[{"type":"text","text":"x"}]}`},
	}
	for _, test := range rejected {
		if _, err := guard.Enforce(test.method, json.RawMessage(test.raw)); err == nil || !IsDenied(err) {
			t.Fatalf("%s accepted invalid params: %.200s (err=%v)", test.method, test.raw, err)
		}
	}
}

func TestThreadListAlwaysCarriesCanonicalRoots(t *testing.T) {
	rootA := t.TempDir()
	rootB := t.TempDir()
	guard, err := NewGuard([]string{rootA, rootB}, "read-only")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := guard.Enforce("thread/list", json.RawMessage(`{"limit":100}`))
	if err != nil {
		t.Fatal(err)
	}
	var params map[string]any
	if err := json.Unmarshal(encoded, &params); err != nil {
		t.Fatal(err)
	}
	got := params["cwd"].([]any)
	roots := guard.WorkspaceRoots()
	if len(got) != 2 || got[0] != roots[0] || got[1] != roots[1] {
		t.Fatalf("thread/list cwd = %#v", got)
	}

	encoded, err = guard.Enforce("thread/list", json.RawMessage(`{"cwd":`+quote(rootB)+`}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &params); err != nil {
		t.Fatal(err)
	}
	got = params["cwd"].([]any)
	if len(got) != 1 || got[0] != roots[1] {
		t.Fatalf("single thread/list cwd = %#v", got)
	}

	encoded, err = guard.Enforce(
		"thread/list",
		json.RawMessage(`{"cwd":[`+quote(rootB)+`,`+quote(rootA)+`,`+quote(rootB)+`]}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &params); err != nil {
		t.Fatal(err)
	}
	got = params["cwd"].([]any)
	if len(got) != 2 || got[0] != roots[1] || got[1] != roots[0] {
		t.Fatalf("array thread/list cwd = %#v", got)
	}
	for _, raw := range []string{`{"cwd":[]}`, `{"cwd":[` + quote(rootA) + `,7]}`} {
		if _, err := guard.Enforce("thread/list", json.RawMessage(raw)); err == nil {
			t.Fatalf("thread/list accepted invalid cwd filter: %s", raw)
		}
	}
}
