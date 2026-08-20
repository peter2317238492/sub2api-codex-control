package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	maxUpstreamJSONBytes = 16 << 20
	maxJSONDepth         = 16
	maxHistoryMessages   = 100
	maxHistoryText       = MaxEnsureASCIITextBytes
	maxDeltaBytes        = 64 << 10
	maxDisplayText       = 1_024
	maxErrorText         = 4_096
	maxPlanSteps         = 100
	maxProjectedContent  = MaxEnsureASCIIProjectedBytes
)

// ProjectResult converts app-server responses into the small public contract
// that can be persisted by the control plane.
func ProjectResult(method string, raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > maxUpstreamJSONBytes {
		return nil, errors.New("app-server result has an invalid size")
	}
	if err := validateJSONDepth(raw, maxJSONDepth); err != nil {
		return nil, fmt.Errorf("app-server result nesting is invalid: %w", err)
	}
	value, err := decodeJSON(raw)
	if err != nil {
		return nil, errors.New("app-server result is not valid JSON")
	}
	var projected any
	switch method {
	case "model/list":
		projected, err = projectModelList(value)
	case "thread/start", "thread/resume":
		projected, err = projectThreadIdentityEnvelope(value)
	case "thread/list":
		projected, err = projectThreadList(value)
	case "thread/read":
		projected, err = projectThreadRead(value)
	case "turn/start":
		projected, err = projectTurnEnvelope(value)
	case "turn/steer":
		projected, err = projectTurnSteer(value)
	case "turn/interrupt":
		projected = map[string]any{}
	default:
		return nil, errors.New("cannot project a result for a denied method")
	}
	if err != nil {
		return nil, err
	}
	return marshalProjected(projected)
}

// ProjectEvent returns a sanitized event payload. The bool is false when the
// method is intentionally internal-only or unsafe for the remote surface.
func ProjectEvent(method string, raw json.RawMessage) (json.RawMessage, bool, error) {
	if !EventAllowed(method) {
		return nil, false, nil
	}
	if len(raw) == 0 || len(raw) > maxUpstreamJSONBytes {
		return nil, false, errors.New("app-server event has an invalid size")
	}
	if err := validateJSONDepth(raw, maxJSONDepth); err != nil {
		return nil, false, fmt.Errorf("app-server event nesting is invalid: %w", err)
	}
	value, err := decodeJSON(raw)
	if err != nil {
		return nil, false, errors.New("app-server event is not valid JSON")
	}
	params, ok := value.(map[string]any)
	if !ok {
		return nil, false, errors.New("app-server event params must be an object")
	}
	threadID, err := requiredProjectedString(params, []string{"threadId", "thread_id"}, MaxOpaqueLength)
	if err != nil {
		return nil, false, err
	}
	projected := map[string]any{"threadId": threadID}
	switch method {
	case "thread/status/changed":
		status := normalizeStatus(params["status"])
		if status == "" {
			return nil, false, errors.New("thread status event is invalid")
		}
		projected["status"] = status
	case "thread/name/updated":
		name := firstString(params, "threadName", "name", "title")
		projected["name"] = truncateRunes(name, MaxOpaqueLength)
	case "turn/started", "turn/completed":
		turn := nestedObject(params, "turn")
		turnID := firstString(params, "turnId", "turn_id", "id")
		if turnID == "" {
			turnID = firstString(turn, "id", "turnId", "turn_id")
		}
		if turnID == "" || utf8.RuneCountInString(turnID) > MaxOpaqueLength {
			return nil, false, errors.New("turn lifecycle event is missing a bounded turn id")
		}
		projected["turnId"] = turnID
		if status := normalizeStatus(turn["status"]); status != "" {
			projected["status"] = status
		}
	case "item/agentMessage/delta":
		turnID, err := requiredProjectedString(params, []string{"turnId", "turn_id"}, MaxOpaqueLength)
		if err != nil {
			return nil, false, err
		}
		itemID, err := requiredProjectedString(params, []string{"itemId", "item_id", "id"}, MaxOpaqueLength)
		if err != nil {
			return nil, false, err
		}
		delta, ok := params["delta"].(string)
		if !ok || delta == "" || wireJSONStringContentSize(delta) > maxDeltaBytes {
			return nil, false, fmt.Errorf("agent message delta must contain 1 to %d bytes", maxDeltaBytes)
		}
		projected["turnId"] = turnID
		projected["itemId"] = itemID
		projected["delta"] = delta
	case "turn/plan/updated":
		turnID, err := requiredProjectedString(params, []string{"turnId", "turn_id"}, MaxOpaqueLength)
		if err != nil {
			return nil, false, err
		}
		projected["turnId"] = turnID
		if explanation := firstString(params, "explanation"); explanation != "" {
			projected["explanation"] = truncateRunes(explanation, maxErrorText)
		}
		plan, ok := params["plan"].([]any)
		if !ok {
			return nil, false, errors.New("turn plan event is invalid")
		}
		steps := make([]map[string]string, 0, min(len(plan), maxPlanSteps))
		for _, rawStep := range plan {
			if len(steps) == maxPlanSteps {
				break
			}
			step, ok := rawStep.(map[string]any)
			if !ok {
				continue
			}
			text := firstString(step, "step")
			status := firstString(step, "status")
			if text == "" || !allowedPlanStatus(status) {
				continue
			}
			steps = append(steps, map[string]string{"step": truncateRunes(text, maxErrorText), "status": status})
		}
		projected["plan"] = steps
		for len(steps) > 0 {
			withinBudget, sizeErr := projectedJSONWithinBudget(projected)
			if sizeErr != nil {
				return nil, false, sizeErr
			}
			if withinBudget {
				break
			}
			steps = steps[:len(steps)-1]
			projected["plan"] = steps
		}
	case "error":
		turnID, err := requiredProjectedString(params, []string{"turnId", "turn_id"}, MaxOpaqueLength)
		if err != nil {
			return nil, false, err
		}
		projected["turnId"] = turnID
		projected["message"] = "Codex reported an error"
		if willRetry, ok := params["willRetry"].(bool); ok {
			projected["willRetry"] = willRetry
		}
	default:
		return nil, false, nil
	}
	encoded, err := marshalProjected(projected)
	return encoded, err == nil, err
}

func projectModelList(value any) (any, error) {
	collection, field, envelope, err := extractCollection(value, "data", "models", "items")
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, min(len(collection), MaxPageSize))
	for _, rawItem := range collection {
		if len(items) == MaxPageSize {
			break
		}
		item, ok := rawItem.(map[string]any)
		if !ok {
			continue
		}
		id := firstString(item, "id", "model", "slug")
		if id == "" || utf8.RuneCountInString(id) > MaxOpaqueLength {
			continue
		}
		projected := map[string]any{"id": id}
		if displayName := firstString(item, "displayName", "display_name", "name"); displayName != "" {
			projected["displayName"] = truncateRunes(displayName, MaxOpaqueLength)
		}
		if description := firstString(item, "description"); description != "" {
			projected["description"] = truncateRunes(description, maxDisplayText)
		}
		items = append(items, projected)
	}
	if envelope == nil {
		for {
			withinBudget, sizeErr := projectedJSONWithinBudget(items)
			if sizeErr != nil {
				return nil, sizeErr
			}
			if withinBudget || len(items) == 0 {
				return items, nil
			}
			items = items[:len(items)-1]
		}
	}
	result := map[string]any{field: items}
	copyCursorFields(result, envelope)
	for {
		withinBudget, sizeErr := projectedJSONWithinBudget(result)
		if sizeErr != nil {
			return nil, sizeErr
		}
		if withinBudget || len(items) == 0 {
			return result, nil
		}
		items = items[:len(items)-1]
		result[field] = items
	}
}

func projectThreadList(value any) (any, error) {
	collection, field, envelope, err := extractCollection(value, "data", "threads", "items")
	if err != nil || envelope == nil {
		return nil, errors.New("thread/list result has no recognized collection")
	}
	items := make([]map[string]any, 0, min(len(collection), MaxPageSize))
	for _, rawItem := range collection {
		if len(items) == MaxPageSize {
			break
		}
		item, ok := rawItem.(map[string]any)
		if !ok {
			continue
		}
		projected, err := projectThreadSummary(item)
		if err == nil {
			items = append(items, projected)
		}
	}
	result := map[string]any{field: items}
	copyCursorFields(result, envelope)
	for {
		withinBudget, sizeErr := projectedJSONWithinBudget(result)
		if sizeErr != nil {
			return nil, sizeErr
		}
		if withinBudget || len(items) == 0 {
			return result, nil
		}
		items = items[:len(items)-1]
		result[field] = items
	}
}

func projectThreadIdentityEnvelope(value any) (any, error) {
	envelope, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("thread result must be an object")
	}
	thread := nestedObject(envelope, "thread")
	if thread == nil {
		thread = envelope
	}
	id := firstString(thread, "id", "threadId", "thread_id")
	if id == "" || utf8.RuneCountInString(id) > MaxOpaqueLength {
		return nil, errors.New("thread result is missing a bounded id")
	}
	result := map[string]any{"thread": map[string]string{"id": id}}
	if model := firstString(envelope, "model"); model != "" {
		result["model"] = truncateRunes(model, MaxOpaqueLength)
	}
	cwd := firstString(envelope, "cwd")
	if cwd == "" {
		cwd = firstString(thread, "cwd")
	}
	if err := projectCWD(result, cwd); err != nil {
		return nil, err
	}
	return result, nil
}

// projectCWD replaces a local app-server path with the POSIX form the control
// plane accepts. A path with no remote form fails the projection instead of
// travelling to the control plane unchanged.
func projectCWD(result map[string]any, cwd string) error {
	if cwd == "" {
		return nil
	}
	remote, err := pathMapper.Remote(cwd)
	if err != nil {
		return fmt.Errorf("project thread cwd: %w", err)
	}
	result["cwd"] = truncateRunes(remote, MaxPathLength)
	return nil
}

func projectThreadRead(value any) (any, error) {
	envelope, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("thread/read result must be an object")
	}
	thread := nestedObject(envelope, "thread")
	if thread == nil {
		thread = envelope
	}
	projected, err := projectThreadSummary(thread)
	if err != nil {
		return nil, err
	}
	projected["turns"] = projectTurns(thread["turns"])
	result := map[string]any{"thread": projected}
	for {
		withinBudget, sizeErr := projectedJSONWithinBudget(result)
		if sizeErr != nil {
			return nil, sizeErr
		}
		if withinBudget {
			return result, nil
		}
		turns := projected["turns"].([]map[string]any)
		if len(turns) == 0 {
			return nil, fmt.Errorf("thread/read identity exceeds %d bytes", maxProjectedContent)
		}
		oldest := turns[0]
		items := oldest["items"].([]map[string]any)
		if len(items) > 0 {
			oldest["items"] = items[1:]
			continue
		}
		projected["turns"] = turns[1:]
	}
}

func projectThreadSummary(thread map[string]any) (map[string]any, error) {
	id := firstString(thread, "id", "threadId", "thread_id")
	if id == "" || utf8.RuneCountInString(id) > MaxOpaqueLength {
		return nil, errors.New("thread result is missing a bounded id")
	}
	result := map[string]any{"id": id}
	copyBoundedString(result, thread, "name", MaxOpaqueLength, "name", "title")
	copyBoundedString(result, thread, "preview", maxDisplayText, "preview")
	if err := projectCWD(result, firstString(thread, "cwd")); err != nil {
		return nil, err
	}
	if status := normalizeStatus(thread["status"]); status != "" {
		result["status"] = status
	}
	copyScalar(result, thread, "createdAt")
	copyScalar(result, thread, "updatedAt")
	return result, nil
}

func projectTurns(value any) []map[string]any {
	turns, _ := value.([]any)
	reversed := make([]map[string]any, 0, min(len(turns), maxHistoryMessages))
	remainingText := maxHistoryText
	messageCount := 0
	for turnIndex := len(turns) - 1; turnIndex >= 0; turnIndex-- {
		if len(reversed) >= maxHistoryMessages || messageCount >= maxHistoryMessages || remainingText <= 0 {
			break
		}
		rawTurn := turns[turnIndex]
		turn, ok := rawTurn.(map[string]any)
		if !ok {
			continue
		}
		turnID := firstString(turn, "id", "turnId", "turn_id")
		if turnID == "" || utf8.RuneCountInString(turnID) > MaxOpaqueLength {
			continue
		}
		projectedTurn := map[string]any{"id": turnID}
		if status := normalizeStatus(turn["status"]); status != "" {
			projectedTurn["status"] = status
		}
		items, _ := turn["items"].([]any)
		reversedItems := make([]map[string]any, 0, min(len(items), maxHistoryMessages-messageCount))
		for itemIndex := len(items) - 1; itemIndex >= 0; itemIndex-- {
			if messageCount >= maxHistoryMessages || remainingText <= 0 {
				break
			}
			rawItem := items[itemIndex]
			item, ok := rawItem.(map[string]any)
			if !ok {
				continue
			}
			projectedItem, textLength, ok := projectMessageItem(item, remainingText)
			if !ok {
				continue
			}
			reversedItems = append(reversedItems, projectedItem)
			remainingText -= textLength
			messageCount++
		}
		projectedItems := make([]map[string]any, len(reversedItems))
		for index := range reversedItems {
			projectedItems[len(reversedItems)-1-index] = reversedItems[index]
		}
		projectedTurn["items"] = projectedItems
		reversed = append(reversed, projectedTurn)
	}
	result := make([]map[string]any, len(reversed))
	for index := range reversed {
		result[len(reversed)-1-index] = reversed[index]
	}
	return result
}

func projectMessageItem(item map[string]any, remaining int) (map[string]any, int, bool) {
	typeName := firstString(item, "type")
	role := ""
	text := ""
	switch typeName {
	case "agentMessage":
		role = "assistant"
		text = firstString(item, "text")
	case "userMessage":
		role = "user"
		content, _ := item["content"].([]any)
		parts := make([]string, 0, min(len(content), maxHistoryMessages))
		for _, rawPart := range content {
			if len(parts) == maxHistoryMessages {
				break
			}
			part, ok := rawPart.(map[string]any)
			if ok && part["type"] == "text" {
				if value, ok := part["text"].(string); ok {
					parts = append(parts, value)
				}
			}
		}
		text = strings.Join(parts, "\n")
	default:
		return nil, 0, false
	}
	if text == "" {
		return nil, 0, false
	}
	text = truncateWireString(text, remaining)
	length := wireJSONStringContentSize(text)
	if length == 0 {
		return nil, 0, false
	}
	id := firstString(item, "id")
	if id == "" || utf8.RuneCountInString(id) > MaxOpaqueLength {
		id = typeName
	}
	return map[string]any{"id": id, "type": typeName, "role": role, "text": text}, length, true
}

func projectTurnEnvelope(value any) (any, error) {
	envelope, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("turn/start result must be an object")
	}
	turn := nestedObject(envelope, "turn")
	if turn == nil {
		turn = envelope
	}
	projected, err := projectTurn(turn)
	if err != nil {
		return nil, err
	}
	return map[string]any{"turn": projected}, nil
}

func projectTurn(value map[string]any) (map[string]any, error) {
	id := firstString(value, "id", "turnId", "turn_id")
	if id == "" || utf8.RuneCountInString(id) > MaxOpaqueLength {
		return nil, errors.New("turn result is missing a bounded id")
	}
	result := map[string]any{"id": id}
	if status := normalizeStatus(value["status"]); status != "" {
		result["status"] = status
	}
	for _, field := range []string{"startedAt", "completedAt", "durationMs"} {
		copyScalar(result, value, field)
	}
	if errorObject := nestedObject(value, "error"); errorObject != nil {
		if message := firstString(errorObject, "message"); message != "" {
			result["error"] = map[string]string{"message": "Codex turn failed"}
		}
	}
	return result, nil
}

func projectTurnSteer(value any) (any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("turn/steer result must be an object")
	}
	id := firstString(object, "turnId", "turn_id", "id")
	if id == "" || utf8.RuneCountInString(id) > MaxOpaqueLength {
		return nil, errors.New("turn/steer result is missing a bounded turn id")
	}
	return map[string]any{"turnId": id}, nil
}

func extractCollection(value any, fields ...string) ([]any, string, map[string]any, error) {
	if direct, ok := value.([]any); ok {
		return direct, "", nil, nil
	}
	envelope, ok := value.(map[string]any)
	if !ok {
		return nil, "", nil, errors.New("list result must be an object or array")
	}
	for _, field := range fields {
		if collection, ok := envelope[field].([]any); ok {
			return collection, field, envelope, nil
		}
	}
	return nil, "", envelope, errors.New("list result has no recognized collection")
}

func copyCursorFields(destination, source map[string]any) {
	for _, field := range []string{"nextCursor", "backwardsCursor"} {
		if value := firstString(source, field); value != "" {
			destination[field] = truncateRunes(value, MaxOpaqueLength)
		}
	}
}

func copyBoundedString(destination, source map[string]any, output string, maximum int, inputs ...string) {
	if value := firstString(source, inputs...); value != "" {
		destination[output] = truncateRunes(value, maximum)
	}
}

func copyScalar(destination, source map[string]any, field string) {
	switch value := source[field].(type) {
	case json.Number, float64:
		destination[field] = value
	}
}

func requiredProjectedString(source map[string]any, fields []string, maximum int) (string, error) {
	value := firstString(source, fields...)
	if value == "" || utf8.RuneCountInString(value) > maximum {
		return "", fmt.Errorf("%s is missing or too long", fields[0])
	}
	return value, nil
}

func firstString(source map[string]any, fields ...string) string {
	if source == nil {
		return ""
	}
	for _, field := range fields {
		if value, ok := source[field].(string); ok {
			return value
		}
	}
	return ""
}

func nestedObject(source map[string]any, field string) map[string]any {
	value, _ := source[field].(map[string]any)
	return value
}

func normalizeStatus(value any) string {
	if status, ok := value.(string); ok {
		return truncateRunes(status, MaxOpaqueLength)
	}
	if object, ok := value.(map[string]any); ok {
		return truncateRunes(firstString(object, "type", "status"), MaxOpaqueLength)
	}
	return ""
}

func allowedPlanStatus(status string) bool {
	return status == "pending" || status == "inProgress" || status == "completed"
}

func truncateRunes(value string, maximum int) string {
	if maximum <= 0 {
		return ""
	}
	if utf8.RuneCountInString(value) <= maximum {
		return value
	}
	runes := []rune(value)
	return string(runes[:maximum])
}

func decodeJSON(raw json.RawMessage) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("JSON contains trailing data")
		}
		return nil, err
	}
	return value, nil
}

func validateJSONDepth(raw []byte, maximum int) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	depth := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			continue
		}
		switch delimiter {
		case '{', '[':
			depth++
			if depth > maximum {
				return fmt.Errorf("JSON depth exceeds %d", maximum)
			}
		case '}', ']':
			depth--
		}
	}
}

func marshalProjected(value any) (json.RawMessage, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	ensureASCIISize, err := ensureASCIIJSONSize(value)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxProjectedContent || ensureASCIISize > maxProjectedContent {
		return nil, fmt.Errorf(
			"projected content exceeds %d bytes (go=%d, ensure_ascii=%d)",
			maxProjectedContent,
			len(encoded),
			ensureASCIISize,
		)
	}
	return json.RawMessage(encoded), nil
}
