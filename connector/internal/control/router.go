package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/localstate"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/policy"
)

type Router struct {
	App     Caller
	Guard   *policy.Guard
	Threads *localstate.Threads

	pendingMu         sync.Mutex
	pendingTurnStarts map[string]string
}

type Caller interface {
	Call(context.Context, string, json.RawMessage) (json.RawMessage, error)
}

func (r *Router) Call(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	if r.App == nil || r.Guard == nil || r.Threads == nil {
		return nil, errors.New("app-server router is unavailable")
	}
	guarded, err := r.Guard.Enforce(method, params)
	if err != nil {
		return nil, err
	}
	reservedThread := false
	if method == "thread/start" {
		if err := r.Threads.ReserveAdd(); err != nil {
			return nil, err
		}
		reservedThread = true
		defer func() {
			if reservedThread {
				r.Threads.ReleaseAdd()
			}
		}()
	}
	if requiresManagedThread(method) {
		threadID := extractThreadID(guarded)
		thread, managed := r.Threads.Get(threadID)
		if threadID == "" || !managed || !r.Guard.ContainsCWD(thread.CWD) {
			return nil, policy.Denied("method may only target a thread created by this connector")
		}
		if method == "turn/steer" {
			expectedTurnID := extractStringParam(guarded, "expectedTurnId")
			if expectedTurnID == "" || expectedTurnID != thread.ActiveTurnID {
				return nil, policy.Denied("turn/steer must target the connector-bound active turn")
			}
		}
		if method == "turn/start" && thread.ActiveTurnID != "" {
			return nil, policy.Denied("turn/start requires an idle connector-managed thread")
		}
		if method == "turn/interrupt" {
			turnID := extractStringParam(guarded, "turnId")
			if turnID == "" || turnID != thread.ActiveTurnID {
				return nil, policy.Denied("turn/interrupt must target the connector-bound active turn")
			}
		}
	}
	pendingTurnThread := ""
	if method == "turn/start" {
		pendingTurnThread = extractThreadID(guarded)
		if !r.beginTurnStart(pendingTurnThread) {
			return nil, policy.Denied("turn/start is already pending for this thread")
		}
	}
	result, err := r.App.Call(ctx, method, guarded)
	if err != nil {
		if pendingTurnThread != "" {
			r.finishTurnStart(pendingTurnThread, "")
		}
		return nil, err
	}
	switch method {
	case "thread/start":
		threadID := extractResultThreadID(result)
		cwd := extractStringParam(guarded, "cwd")
		if threadID == "" || extractResultCWD(result) != cwd {
			return nil, errors.New("app-server returned thread/start with inconsistent thread identity or cwd")
		}
		reservedThread = false
		if err := r.Threads.AddReserved(localstate.Thread{ID: threadID, CWD: cwd, CreatedAt: time.Now().UTC()}); err != nil {
			return nil, fmt.Errorf("persist managed thread: %w", err)
		}
	case "thread/read", "thread/resume":
		threadID := extractThreadID(guarded)
		managed, ok := r.Threads.Get(threadID)
		if !ok || extractResultThreadID(result) != threadID || extractResultCWD(result) != managed.CWD {
			return nil, errors.New("app-server returned a thread outside the managed binding")
		}
	case "thread/list":
		managed := make(map[string]localstate.Thread)
		for id := range r.Threads.IDs() {
			thread, ok := r.Threads.Get(id)
			if ok && r.Guard.ContainsCWD(thread.CWD) {
				managed[id] = thread
			}
		}
		return filterManagedThreads(result, managed)
	case "turn/start":
		threadID := extractThreadID(guarded)
		turnID := extractResultTurnID(result)
		if turnID == "" {
			r.finishTurnStart(threadID, "")
			return nil, errors.New("app-server returned turn/start without a turn id")
		}
		if !r.finishTurnStart(threadID, turnID) {
			return nil, errors.New("app-server turn/start response did not match the pending turn notification")
		}
		if err := r.Threads.SetActiveTurn(threadID, turnID); err != nil {
			return nil, err
		}
	case "turn/interrupt":
		if err := r.Threads.SetActiveTurn(extractThreadID(guarded), ""); err != nil {
			return nil, err
		}
	case "turn/steer":
		if extractResultTurnID(result) != extractStringParam(guarded, "expectedTurnId") {
			return nil, errors.New("app-server returned turn/steer for a different active turn")
		}
	}
	return result, nil
}

func (r *Router) ObserveNotification(method string, params json.RawMessage) bool {
	threadID := extractThreadID(params)
	thread, managed := r.Threads.Get(threadID)
	if threadID == "" || !managed || !r.Guard.ContainsCWD(thread.CWD) {
		return false
	}
	if method != "turn/started" && method != "turn/completed" {
		if method == "item/agentMessage/delta" || method == "turn/plan/updated" || method == "error" {
			turnID := extractResultTurnID(params)
			return turnID != "" && thread.ActiveTurnID != "" && turnID == thread.ActiveTurnID
		}
		return true
	}
	turnID := extractResultTurnID(params)
	if method == "turn/started" && turnID != "" && thread.ActiveTurnID == turnID {
		return true
	}
	if method == "turn/started" && turnID != "" && thread.ActiveTurnID == "" && r.observePendingTurnStart(threadID, turnID) {
		return r.Threads.SetActiveTurn(threadID, turnID) == nil
	}
	if method == "turn/completed" && turnID != "" && thread.ActiveTurnID == turnID {
		return r.Threads.SetActiveTurn(threadID, "") == nil
	}
	return false
}

func (r *Router) beginTurnStart(threadID string) bool {
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()
	if r.pendingTurnStarts == nil {
		r.pendingTurnStarts = make(map[string]string)
	}
	if _, exists := r.pendingTurnStarts[threadID]; exists {
		return false
	}
	r.pendingTurnStarts[threadID] = ""
	return true
}

func (r *Router) observePendingTurnStart(threadID, turnID string) bool {
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()
	observed, exists := r.pendingTurnStarts[threadID]
	if !exists || (observed != "" && observed != turnID) {
		return false
	}
	r.pendingTurnStarts[threadID] = turnID
	return true
}

func (r *Router) finishTurnStart(threadID, resultTurnID string) bool {
	r.pendingMu.Lock()
	observed, exists := r.pendingTurnStarts[threadID]
	delete(r.pendingTurnStarts, threadID)
	r.pendingMu.Unlock()
	matched := exists && (observed == "" || observed == resultTurnID) && resultTurnID != ""
	if !matched && observed != "" {
		if thread, ok := r.Threads.Get(threadID); ok && thread.ActiveTurnID == observed {
			_ = r.Threads.SetActiveTurn(threadID, "")
		}
	}
	return matched
}

func requiresManagedThread(method string) bool {
	switch method {
	case "thread/read", "thread/resume", "turn/start", "turn/steer", "turn/interrupt":
		return true
	default:
		return false
	}
}

func extractThreadID(raw json.RawMessage) string {
	var params map[string]any
	if json.Unmarshal(raw, &params) != nil {
		return ""
	}
	for _, key := range []string{"threadId", "thread_id"} {
		if value, ok := params[key].(string); ok {
			return value
		}
	}
	if thread, ok := params["thread"].(map[string]any); ok {
		for _, key := range []string{"id", "threadId", "thread_id"} {
			if value, ok := thread[key].(string); ok {
				return value
			}
		}
	}
	return ""
}

func extractStringParam(raw json.RawMessage, key string) string {
	var params map[string]any
	if json.Unmarshal(raw, &params) != nil {
		return ""
	}
	value, _ := params[key].(string)
	return value
}

func extractResultThreadID(raw json.RawMessage) string {
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil {
		return ""
	}
	for _, key := range []string{"threadId", "thread_id", "id"} {
		if value, ok := result[key].(string); ok {
			return value
		}
	}
	if thread, ok := result["thread"].(map[string]any); ok {
		if value, ok := thread["id"].(string); ok {
			return value
		}
	}
	return ""
}

func extractResultTurnID(raw json.RawMessage) string {
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil {
		return ""
	}
	for _, key := range []string{"turnId", "turn_id"} {
		if value, ok := result[key].(string); ok {
			return value
		}
	}
	if turn, ok := result["turn"].(map[string]any); ok {
		if value, ok := turn["id"].(string); ok {
			return value
		}
	}
	return ""
}

func extractResultCWD(raw json.RawMessage) string {
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil {
		return ""
	}
	if value, ok := result["cwd"].(string); ok {
		return value
	}
	if thread, ok := result["thread"].(map[string]any); ok {
		if value, ok := thread["cwd"].(string); ok {
			return value
		}
	}
	return ""
}

func filterManagedThreads(raw json.RawMessage, managed map[string]localstate.Thread) (json.RawMessage, error) {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, errors.New("thread/list returned an unexpected result")
	}
	field := "data"
	listRaw, ok := result[field]
	if !ok {
		field = "threads"
		listRaw, ok = result[field]
	}
	if !ok {
		return nil, errors.New("thread/list result has no recognized thread collection")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(listRaw, &items); err != nil {
		return nil, errors.New("thread/list collection is invalid")
	}
	filtered := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		thread, ok := managed[extractResultThreadID(item)]
		if ok && extractResultCWD(item) == thread.CWD {
			filtered = append(filtered, item)
		}
	}
	encoded, err := json.Marshal(filtered)
	if err != nil {
		return nil, err
	}
	result[field] = encoded
	return json.Marshal(result)
}
