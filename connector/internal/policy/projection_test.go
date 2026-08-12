package policy

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
)

func TestProjectThreadReadDropsSensitiveItemsAndMetadata(t *testing.T) {
	raw := json.RawMessage(`{
		"thread": {
			"id":"thread-1",
			"cwd":"/workspace/project",
			"name":"Safe title",
			"path":"/private/rollout.jsonl",
			"sessionId":"secret-session",
			"gitInfo":{"repositoryUrl":"secret-repo"},
			"turns":[{"id":"turn-1","status":"completed","items":[
				{"id":"user-1","type":"userMessage","content":[{"type":"text","text":"hello"},{"type":"image","url":"file:///secret.png"}]},
				{"id":"agent-1","type":"agentMessage","text":"answer","memoryCitation":{"path":"secret-memory"}},
				{"id":"cmd-1","type":"commandExecution","command":"cat /etc/passwd","aggregatedOutput":"root:secret"},
				{"id":"diff-1","type":"fileChange","changes":[{"path":"/secret","diff":"TOP SECRET"}]},
				{"id":"reason-1","type":"reasoning","content":["private chain"]}
			]}]
		}
	}`)
	projected, err := ProjectResult("thread/read", raw)
	if err != nil {
		t.Fatal(err)
	}
	text := string(projected)
	for _, secret := range []string{"private/rollout", "secret-session", "secret-repo", "secret.png", "cat /etc", "root:secret", "TOP SECRET", "private chain", "memoryCitation"} {
		if strings.Contains(text, secret) {
			t.Fatalf("projection leaked %q: %s", secret, text)
		}
	}
	for _, expected := range []string{"thread-1", "turn-1", "hello", "answer", `"role":"user"`, `"role":"assistant"`} {
		if !strings.Contains(text, expected) {
			t.Fatalf("projection omitted %q: %s", expected, text)
		}
	}
	if len(projected) > protocol.MaxProjectedPayloadBytes {
		t.Fatalf("projected result is %d bytes", len(projected))
	}
	ensureASCIISize, err := ensureASCIIJSONSize(projected)
	if err != nil {
		t.Fatal(err)
	}
	if ensureASCIISize > MaxEnsureASCIIProjectedBytes {
		t.Fatalf("ensure_ascii projected result is %d bytes", ensureASCIISize)
	}
}

func TestProjectThreadReadTruncatesUnicodeToBothWireBudgets(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"thread": map[string]any{
			"id": "thread-1",
			"turns": []any{map[string]any{
				"id": "turn-1",
				"items": []any{map[string]any{
					"id": "item-1", "type": "agentMessage", "text": strings.Repeat("😀", MaxTextLength),
				}},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	projected, err := ProjectResult("thread/read", raw)
	if err != nil {
		t.Fatal(err)
	}
	ensureASCIISize, err := ensureASCIIJSONSize(projected)
	if err != nil {
		t.Fatal(err)
	}
	if len(projected) > MaxEnsureASCIIProjectedBytes || ensureASCIISize > MaxEnsureASCIIProjectedBytes {
		t.Fatalf("projected sizes go=%d ensure_ascii=%d", len(projected), ensureASCIISize)
	}
	if !strings.Contains(string(projected), "😀") {
		t.Fatal("unicode history was dropped instead of bounded")
	}
}

func TestProjectThreadReadKeepsNewestHistoryInChronologicalOrder(t *testing.T) {
	turns := make([]any, 0, maxHistoryMessages+10)
	for index := 0; index < maxHistoryMessages+10; index++ {
		turns = append(turns, map[string]any{
			"id": fmt.Sprintf("turn-%03d", index),
			"items": []any{map[string]any{
				"id": fmt.Sprintf("item-%03d", index), "type": "agentMessage", "text": fmt.Sprintf("message-%03d", index),
			}},
		})
	}
	raw, err := json.Marshal(map[string]any{"thread": map[string]any{"id": "thread-1", "turns": turns}})
	if err != nil {
		t.Fatal(err)
	}
	projected, err := ProjectResult("thread/read", raw)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Thread struct {
			Turns []struct {
				ID string `json:"id"`
			} `json:"turns"`
		} `json:"thread"`
	}
	if err := json.Unmarshal(projected, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Thread.Turns) != maxHistoryMessages {
		t.Fatalf("projected turn count = %d", len(result.Thread.Turns))
	}
	if got := result.Thread.Turns[0].ID; got != "turn-010" {
		t.Fatalf("oldest retained turn = %q, want turn-010", got)
	}
	if got := result.Thread.Turns[len(result.Thread.Turns)-1].ID; got != "turn-109" {
		t.Fatalf("newest retained turn = %q, want turn-109", got)
	}
}

func TestProjectThreadReadBudgetTrimmingDropsOldestMessagesFirst(t *testing.T) {
	turns := make([]any, 0, maxHistoryMessages)
	for index := 0; index < maxHistoryMessages; index++ {
		turns = append(turns, map[string]any{
			"id": fmt.Sprintf("turn-%03d-%s", index, strings.Repeat("t", MaxOpaqueLength-9)),
			"items": []any{map[string]any{
				"id":   fmt.Sprintf("item-%03d-%s", index, strings.Repeat("i", MaxOpaqueLength-9)),
				"type": "agentMessage",
				"text": fmt.Sprintf("message-%03d-%s", index, strings.Repeat("x", 1_985)),
			}},
		})
	}
	raw, err := json.Marshal(map[string]any{"thread": map[string]any{"id": "thread-1", "turns": turns}})
	if err != nil {
		t.Fatal(err)
	}
	projected, err := ProjectResult("thread/read", raw)
	if err != nil {
		t.Fatal(err)
	}
	text := string(projected)
	if strings.Contains(text, "message-000-") {
		t.Fatal("oldest message survived projected-content budget trimming")
	}
	if !strings.Contains(text, "message-099-") {
		t.Fatal("newest message was removed by projected-content budget trimming")
	}
	if len(projected) > MaxEnsureASCIIProjectedBytes {
		t.Fatalf("projected result is %d bytes", len(projected))
	}
	ensureASCIISize, err := ensureASCIIJSONSize(projected)
	if err != nil {
		t.Fatal(err)
	}
	if ensureASCIISize > MaxEnsureASCIIProjectedBytes {
		t.Fatalf("ensure_ascii projected result is %d bytes", ensureASCIISize)
	}
}

func TestLargeUnicodeListsAreTrimmedInsteadOfExceedingTheFrameBudget(t *testing.T) {
	models := make([]any, 0, MaxPageSize)
	for index := 0; index < MaxPageSize; index++ {
		models = append(models, map[string]any{
			"id":          strings.Repeat("😀", MaxOpaqueLength),
			"displayName": strings.Repeat("界", MaxOpaqueLength),
			"description": strings.Repeat("<", maxDisplayText),
		})
	}
	raw, err := json.Marshal(map[string]any{"data": models})
	if err != nil {
		t.Fatal(err)
	}
	projected, err := ProjectResult("model/list", raw)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(projected, &result); err != nil {
		t.Fatal(err)
	}
	items := result["data"].([]any)
	if len(items) == 0 || len(items) >= MaxPageSize {
		t.Fatalf("trimmed model count = %d", len(items))
	}
	ensureASCIISize, err := ensureASCIIJSONSize(projected)
	if err != nil {
		t.Fatal(err)
	}
	if len(projected) > MaxEnsureASCIIProjectedBytes || ensureASCIISize > MaxEnsureASCIIProjectedBytes {
		t.Fatalf("projected list sizes go=%d ensure_ascii=%d", len(projected), ensureASCIISize)
	}
}

func TestProjectedContentBudgetReservesAFullEnvelope(t *testing.T) {
	content := map[string]any{"padding": strings.Repeat("a", MaxEnsureASCIIProjectedBytes-14)}
	projected, err := marshalProjected(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(projected) != MaxEnsureASCIIProjectedBytes {
		t.Fatalf("projected boundary = %d bytes, want %d", len(projected), MaxEnsureASCIIProjectedBytes)
	}
	envelope := map[string]any{
		"version":   1,
		"id":        "11111111-1111-4111-8111-111111111111",
		"device_id": "22222222-2222-4222-8222-222222222222",
		"epoch":     strings.Repeat("😀", 128),
		"seq":       ^uint64(0),
		"ack":       ^uint64(0),
		"type":      "command_ack",
		"sent_at":   "2026-07-23T23:59:59.999999+00:00",
		"payload": map[string]any{
			"command_id": "33333333-3333-4333-8333-333333333333",
			"state":      "completed",
			"result":     projected,
		},
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	ensureASCIISize, err := ensureASCIIJSONSize(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > protocol.MaxFrameBytes || ensureASCIISize > protocol.MaxFrameBytes {
		t.Fatalf("full envelope sizes go=%d ensure_ascii=%d", len(encoded), ensureASCIISize)
	}
	if _, err := marshalProjected(map[string]any{"padding": strings.Repeat("a", MaxEnsureASCIIProjectedBytes-13)}); err == nil {
		t.Fatal("projected content over the exact boundary was accepted")
	}
}

func TestProjectResultUsesSafeMethodSpecificShapes(t *testing.T) {
	tests := []struct {
		method string
		raw    string
		want   []string
		deny   []string
	}{
		{"model/list", `{"data":[{"id":"gpt-5","displayName":"GPT-5","description":"safe","hidden":"secret"}],"nextCursor":"next","provider":"secret"}`, []string{"gpt-5", "GPT-5", "next"}, []string{"hidden", "provider", "secret"}},
		{"thread/start", `{"thread":{"id":"thread-1","path":"/secret"},"model":"gpt-5","cwd":"/work"}`, []string{"thread-1", "gpt-5", "/work"}, []string{"/secret"}},
		{"turn/start", `{"turn":{"id":"turn-1","status":"inProgress","items":[{"type":"commandExecution","output":"secret"}],"error":null}}`, []string{"turn-1", "inProgress"}, []string{"items", "secret"}},
		{"turn/steer", `{"turnId":"turn-1","extra":"secret"}`, []string{"turn-1"}, []string{"extra", "secret"}},
		{"turn/interrupt", `{"raw":"secret"}`, nil, []string{"raw", "secret"}},
	}
	for _, test := range tests {
		projected, err := ProjectResult(test.method, json.RawMessage(test.raw))
		if err != nil {
			t.Fatalf("%s: %v", test.method, err)
		}
		for _, expected := range test.want {
			if !strings.Contains(string(projected), expected) {
				t.Fatalf("%s omitted %q: %s", test.method, expected, projected)
			}
		}
		for _, denied := range test.deny {
			if strings.Contains(string(projected), denied) {
				t.Fatalf("%s leaked %q: %s", test.method, denied, projected)
			}
		}
	}
}

func TestProjectEventAllowsOnlyBoundedPublicContent(t *testing.T) {
	delta, allowed, err := ProjectEvent("item/agentMessage/delta", json.RawMessage(`{
		"threadId":"thread-1","turnId":"turn-1","itemId":"item-1","delta":"hello","path":"/secret"
	}`))
	if err != nil || !allowed {
		t.Fatalf("delta projection = %s, %v, %v", delta, allowed, err)
	}
	if strings.Contains(string(delta), "/secret") || !strings.Contains(string(delta), "hello") {
		t.Fatalf("delta projection = %s", delta)
	}
	oversized := strings.Repeat("x", maxDeltaBytes+1)
	if _, allowed, err := ProjectEvent("item/agentMessage/delta", json.RawMessage(`{"threadId":"t","turnId":"u","itemId":"i","delta":`+quote(oversized)+`}`)); err == nil || allowed {
		t.Fatalf("oversized delta was allowed: %v", err)
	}
	emoji := strings.Repeat("😀", maxDeltaBytes/12)
	emojiRaw, err := json.Marshal(map[string]any{"threadId": "t", "turnId": "u", "itemId": "i", "delta": emoji})
	if err != nil {
		t.Fatal(err)
	}
	if _, allowed, err := ProjectEvent("item/agentMessage/delta", emojiRaw); err != nil || !allowed {
		t.Fatalf("bounded emoji delta projection = %v, %v", allowed, err)
	}
	emojiRaw, err = json.Marshal(map[string]any{"threadId": "t", "turnId": "u", "itemId": "i", "delta": emoji + "😀"})
	if err != nil {
		t.Fatal(err)
	}
	if _, allowed, err := ProjectEvent("item/agentMessage/delta", emojiRaw); err == nil || allowed {
		t.Fatalf("oversized emoji delta was allowed: %v", err)
	}
	for _, method := range []string{
		"turn/diff/updated", "item/reasoning/textDelta", "item/commandExecution/outputDelta",
		"item/fileChange/outputDelta", "item/started", "item/completed", "serverRequest/resolved",
		"thread/environment/connected", "thread/environment/disconnected",
	} {
		if EventAllowed(method) {
			t.Fatalf("sensitive event %s is allowlisted", method)
		}
		if _, allowed, err := ProjectEvent(method, json.RawMessage(`{"secret":"value"}`)); err != nil || allowed {
			t.Fatalf("sensitive event %s projection = %v, %v", method, allowed, err)
		}
	}
}

func TestProjectionRejectsExcessiveNesting(t *testing.T) {
	nested := strings.Repeat(`{"x":`, maxJSONDepth+1) + `null` + strings.Repeat(`}`, maxJSONDepth+1)
	if _, err := ProjectResult("turn/interrupt", json.RawMessage(nested)); err == nil {
		t.Fatal("excessively nested result was accepted")
	}
}
