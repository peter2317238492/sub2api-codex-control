package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/localstate"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/policy"
)

const testDeviceID = "11111111-1111-4111-8111-111111111111"

type fakeCaller struct {
	calls  int
	method string
	result json.RawMessage
}

type callbackCaller struct {
	call func(context.Context, string, json.RawMessage) (json.RawMessage, error)
}

func (c *callbackCaller) Call(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	return c.call(ctx, method, params)
}

func (f *fakeCaller) Call(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
	f.calls++
	f.method = method
	return f.result, nil
}

func TestRouterOnlyControlsManagedThreads(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	guard, err := policy.NewGuard([]string{root}, "workspace-write")
	if err != nil {
		t.Fatal(err)
	}
	canonicalProject, err := guard.CanonicalCWD(project)
	if err != nil {
		t.Fatal(err)
	}
	threads, err := localstate.OpenThreads(filepath.Join(t.TempDir(), "threads.json"), testDeviceID)
	if err != nil {
		t.Fatal(err)
	}
	caller := &fakeCaller{result: json.RawMessage(`{"thread":{"id":"managed-1","cwd":` + quoted(canonicalProject) + `}}`)}
	router := &Router{App: caller, Guard: guard, Threads: threads}
	if _, err := router.Call(t.Context(), "thread/start", json.RawMessage(`{"cwd":`+quoted(project)+`}`)); err != nil {
		t.Fatal(err)
	}
	if !threads.Contains("managed-1") {
		t.Fatal("thread/start result was not recorded as managed")
	}
	caller.result = json.RawMessage(`{"turn":{"id":"turn-1"}}`)
	if _, err := router.Call(t.Context(), "turn/start", json.RawMessage(`{"threadId":"managed-1","input":[{"type":"text","text":"hello"}]}`)); err != nil {
		t.Fatal(err)
	}
	caller.result = json.RawMessage(`{"turn":{"id":"turn-1"}}`)
	if _, err := router.Call(t.Context(), "turn/steer", json.RawMessage(`{"threadId":"managed-1","expectedTurnId":"turn-1","input":[{"type":"text","text":"more"}]}`)); err != nil {
		t.Fatal(err)
	}
	calls := caller.calls
	if _, err := router.Call(t.Context(), "turn/start", json.RawMessage(`{"threadId":"local-unmanaged","input":[{"type":"text","text":"x"}]}`)); err == nil {
		t.Fatal("unmanaged thread was accepted")
	}
	if caller.calls != calls {
		t.Fatal("unmanaged thread reached app-server")
	}
}

func TestRouterRejectsThreadStartAtCapacityBeforeAppServerDispatch(t *testing.T) {
	root := t.TempDir()
	guard, err := policy.NewGuard([]string{root}, "workspace-write")
	if err != nil {
		t.Fatal(err)
	}
	canonicalRoot, err := guard.CanonicalCWD(root)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(t.TempDir(), "threads.json")
	disk := struct {
		Version  int                          `json:"version"`
		DeviceID string                       `json:"device_id"`
		Threads  map[string]localstate.Thread `json:"threads"`
	}{Version: 2, DeviceID: testDeviceID, Threads: make(map[string]localstate.Thread, 4096)}
	for index := 0; index < 4096; index++ {
		id := fmt.Sprintf("managed-%d", index)
		disk.Threads[id] = localstate.Thread{ID: id, CWD: canonicalRoot}
	}
	encoded, err := json.Marshal(disk)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	threads, err := localstate.OpenThreads(statePath, testDeviceID)
	if err != nil {
		t.Fatal(err)
	}
	caller := &fakeCaller{result: json.RawMessage(`{"thread":{"id":"orphan","cwd":` + quoted(canonicalRoot) + `}}`)}
	router := &Router{App: caller, Guard: guard, Threads: threads}
	_, err = router.Call(t.Context(), "thread/start", json.RawMessage(`{"cwd":`+quoted(root)+`}`))
	if !errors.Is(err, localstate.ErrManagedThreadStoreFull) {
		t.Fatalf("thread/start error = %v, want managed store full", err)
	}
	if caller.calls != 0 {
		t.Fatalf("full managed store dispatched %d app-server calls", caller.calls)
	}
}

func TestRouterRejectsStaleTurnIdentifiers(t *testing.T) {
	root := t.TempDir()
	guard, _ := policy.NewGuard([]string{root}, "workspace-write")
	threads, _ := localstate.OpenThreads(filepath.Join(t.TempDir(), "threads.json"), testDeviceID)
	if err := threads.Add(localstate.Thread{ID: "managed", CWD: root, ActiveTurnID: "current"}); err != nil {
		t.Fatal(err)
	}
	caller := &fakeCaller{result: json.RawMessage(`{}`)}
	router := &Router{App: caller, Guard: guard, Threads: threads}
	if _, err := router.Call(t.Context(), "turn/interrupt", json.RawMessage(`{"threadId":"managed","turnId":"stale"}`)); err == nil {
		t.Fatal("stale turn id was accepted")
	}
	if caller.calls != 0 {
		t.Fatal("stale turn request reached app-server")
	}
}

func TestRouterFiltersThreadList(t *testing.T) {
	root := t.TempDir()
	guard, _ := policy.NewGuard([]string{root}, "workspace-write")
	threads, _ := localstate.OpenThreads(filepath.Join(t.TempDir(), "threads.json"), testDeviceID)
	if err := threads.Add(localstate.Thread{ID: "managed", CWD: root}); err != nil {
		t.Fatal(err)
	}
	caller := &fakeCaller{result: json.RawMessage(`{"data":[{"id":"managed","cwd":` + quoted(root) + `},{"id":"private-local","cwd":` + quoted(root) + `}],"nextCursor":null}`)}
	router := &Router{App: caller, Guard: guard, Threads: threads}
	result, err := router.Call(t.Context(), "thread/list", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(result) == "" || containsJSON(result, "private-local") {
		t.Fatalf("unmanaged thread leaked from list: %s", result)
	}
}

func TestRouterRejectsMismatchedResultIdentityAndEventTurns(t *testing.T) {
	root := t.TempDir()
	guard, err := policy.NewGuard([]string{root}, "workspace-write")
	if err != nil {
		t.Fatal(err)
	}
	canonicalRoot, err := guard.CanonicalCWD(root)
	if err != nil {
		t.Fatal(err)
	}
	threads, _ := localstate.OpenThreads(filepath.Join(t.TempDir(), "threads.json"), testDeviceID)
	if err := threads.Add(localstate.Thread{ID: "managed", CWD: canonicalRoot, ActiveTurnID: "turn-current"}); err != nil {
		t.Fatal(err)
	}
	caller := &fakeCaller{result: json.RawMessage(`{"thread":{"id":"other","cwd":` + quoted(canonicalRoot) + `}}`)}
	router := &Router{App: caller, Guard: guard, Threads: threads}
	if _, err := router.Call(t.Context(), "thread/read", json.RawMessage(`{"threadId":"managed","includeTurns":true}`)); err == nil {
		t.Fatal("mismatched thread/read result was accepted")
	}
	if router.ObserveNotification("item/agentMessage/delta", json.RawMessage(`{"threadId":"managed","turnId":"turn-stale","itemId":"item","delta":"x"}`)) {
		t.Fatal("stale turn event was accepted")
	}
	if !router.ObserveNotification("item/agentMessage/delta", json.RawMessage(`{"threadId":"managed","turnId":"turn-current","itemId":"item","delta":"x"}`)) {
		t.Fatal("active managed turn event was rejected")
	}
	if router.ObserveNotification("item/agentMessage/delta", json.RawMessage(`{"threadId":"unmanaged","turnId":"turn-current","itemId":"item","delta":"x"}`)) {
		t.Fatal("unmanaged event was accepted")
	}
}

func TestRouterRejectsUnsolicitedTurnStarted(t *testing.T) {
	root := t.TempDir()
	guard, _ := policy.NewGuard([]string{root}, "workspace-write")
	canonicalRoot, _ := guard.CanonicalCWD(root)
	threads, _ := localstate.OpenThreads(filepath.Join(t.TempDir(), "threads.json"), testDeviceID)
	if err := threads.Add(localstate.Thread{ID: "managed", CWD: canonicalRoot}); err != nil {
		t.Fatal(err)
	}
	router := &Router{App: &fakeCaller{}, Guard: guard, Threads: threads}
	if router.ObserveNotification("turn/started", json.RawMessage(`{"threadId":"managed","turn":{"id":"local-turn"}}`)) {
		t.Fatal("unsolicited turn/started was accepted")
	}
	if thread, _ := threads.Get("managed"); thread.ActiveTurnID != "" {
		t.Fatalf("unsolicited turn became active: %#v", thread)
	}
}

func TestRouterCorrelatesEarlyTurnStartedWithPendingRemoteStart(t *testing.T) {
	for _, test := range []struct {
		name           string
		notification   string
		response       string
		wantError      bool
		wantActiveTurn string
	}{
		{name: "matching", notification: "turn-1", response: "turn-1", wantActiveTurn: "turn-1"},
		{name: "mismatch", notification: "turn-local", response: "turn-remote", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			guard, _ := policy.NewGuard([]string{root}, "workspace-write")
			canonicalRoot, _ := guard.CanonicalCWD(root)
			threads, _ := localstate.OpenThreads(filepath.Join(t.TempDir(), "threads.json"), testDeviceID)
			if err := threads.Add(localstate.Thread{ID: "managed", CWD: canonicalRoot}); err != nil {
				t.Fatal(err)
			}
			caller := &callbackCaller{}
			router := &Router{App: caller, Guard: guard, Threads: threads}
			caller.call = func(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
				if method != "turn/start" {
					t.Fatalf("method = %s", method)
				}
				if !router.ObserveNotification("turn/started", json.RawMessage(`{"threadId":"managed","turn":{"id":`+quoted(test.notification)+`}}`)) {
					t.Fatal("early pending turn/started was rejected")
				}
				return json.RawMessage(`{"turn":{"id":` + quoted(test.response) + `}}`), nil
			}
			_, err := router.Call(t.Context(), "turn/start", json.RawMessage(`{"threadId":"managed","input":[{"type":"text","text":"hello"}]}`))
			if (err != nil) != test.wantError {
				t.Fatalf("turn/start error = %v", err)
			}
			thread, _ := threads.Get("managed")
			if thread.ActiveTurnID != test.wantActiveTurn {
				t.Fatalf("active turn = %q, want %q", thread.ActiveTurnID, test.wantActiveTurn)
			}
		})
	}
}

func quoted(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func containsJSON(data []byte, needle string) bool {
	var value any
	if json.Unmarshal(data, &value) != nil {
		return false
	}
	encoded, _ := json.Marshal(value)
	for i := 0; i+len(needle) <= len(encoded); i++ {
		if string(encoded[i:i+len(needle)]) == needle {
			return true
		}
	}
	return false
}
